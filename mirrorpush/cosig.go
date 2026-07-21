package mirrorpush

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/letsencrypt/cactus/cert"
)

// sigLinePrefix is the c2sp.org/signed-note signature line marker: an
// EM DASH (U+2014, UTF-8 E2 80 94) followed by a single space. It is
// not a hyphen and not an EN DASH; a mismatch here silently drops every
// cosignature, so it is spelled out with its codepoint.
const sigLinePrefix = "— "

// Cosignature is one parsed c2sp.org/signed-note signature line.
type Cosignature struct {
	// Name is the cosigner's key name, e.g.
	// "oid/1.3.6.1.4.1.44363.47.1.99".
	Name string
	// KeyID is the 4-byte c2sp signed-note key ID that prefixes the
	// signature blob.
	KeyID [4]byte
	// Timestamp is the c2sp.org/tlog-cosignature timestamped_signature
	// timestamp: zero for subtree cosignatures, non-zero (seconds since
	// the UNIX epoch) for checkpoint cosignatures.
	Timestamp uint64
	// Signature is the bare algorithm signature, with the key ID and
	// timestamp stripped.
	Signature []byte
	// Line is the verbatim line as received, without its newline. It is
	// retained so a verified cosignature can be appended to a signed
	// note byte-for-byte, which is what turns an add-entries 200 into a
	// reference checkpoint a mirror will accept on sign-subtree.
	Line string
}

// ParseCosignatureLines parses a response body consisting of one or
// more signed-note signature lines.
//
// Structurally malformed lines are an error rather than something to
// skip: per c2sp.org/signed-note such a note is malformed, and the
// "ignore what you don't recognise" rule is about *unknown keys*, not
// about unparseable bytes.
func ParseCosignatureLines(body []byte) ([]Cosignature, error) {
	var out []Cosignature
	for _, line := range strings.Split(strings.TrimSuffix(string(body), "\n"), "\n") {
		if line == "" {
			continue
		}
		rest, ok := strings.CutPrefix(line, sigLinePrefix)
		if !ok {
			return nil, fmt.Errorf("mirrorpush: not a signature line: %q", line)
		}
		name, b64, ok := strings.Cut(rest, " ")
		if !ok || name == "" {
			return nil, fmt.Errorf("mirrorpush: malformed signature line: %q", line)
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("mirrorpush: signature line base64: %w", err)
		}
		if len(raw) < 4 {
			return nil, errors.New("mirrorpush: signature blob too short for a key ID")
		}
		ts, sig, err := cert.ParseTimestampedSignature(raw[4:])
		if err != nil {
			return nil, fmt.Errorf("mirrorpush: %w", err)
		}
		out = append(out, Cosignature{
			Name:      name,
			KeyID:     [4]byte(raw[:4]),
			Timestamp: ts,
			Signature: sig,
			Line:      line,
		})
	}
	if len(out) == 0 {
		return nil, errors.New("mirrorpush: response contained no signature lines")
	}
	return out, nil
}

// TimestampRule says which of the two mutually exclusive timestamp
// requirements applies to a batch of cosignatures.
type TimestampRule int

const (
	// TimestampZero is the sign-subtree rule: "If the cosignature
	// format supports timestamps, the timestamp MUST be zero." It is
	// also what MTC §6.2 requires of the cosignatures embedded in an
	// MTCProof, which is precisely why a sign-subtree response can be
	// dropped into a certificate unmodified.
	TimestampZero TimestampRule = iota
	// TimestampNonZero is the checkpoint-cosignature rule: "The
	// cosignature MUST NOT omit the timestamp, i.e. the timestamp MUST
	// NOT be zero."
	TimestampNonZero
)

// VerifyCosignatures returns the cosignatures in body that were made by
// key over subtree, and verifies each one.
//
// The matching rule has a sharp edge that this function exists to get
// right. A line whose key name or key ID differs from ours is from a
// cosigner we don't know and MUST be ignored — a mirror may legitimately
// return witness cosignatures alongside its mirror ones, and a key ID
// collision on a name we don't hold is not our business. But a line that
// matches *both* the name and the key ID claims to be from us and then
// fails to verify: that is a malformed note, and the correct response is
// to reject the entire body rather than fall through to the next line.
// Skipping it would let a mirror pair one bad signature with one good
// one and have us quietly accept.
//
// timestamp carries into the signed message, so the CosignedMessage is
// rebuilt per line from the timestamp on the wire; the rule argument is
// then applied to reject a timestamp the protocol forbids.
func VerifyCosignatures(
	body []byte,
	key cert.CosignerKey,
	subtree *cert.MTCSubtree,
	rule TimestampRule,
) ([]Cosignature, error) {
	if subtree == nil {
		return nil, errors.New("mirrorpush: nil subtree")
	}
	// The c2sp cosignature path is ML-DSA-44 only; refuse to fabricate
	// a key ID for an algorithm that could never appear here.
	if key.Algorithm != cert.AlgMLDSA44 {
		return nil, fmt.Errorf("mirrorpush: cosigner %q must be ML-DSA-44, got 0x%04x",
			key.ID, uint16(key.Algorithm))
	}
	wantName := cert.OIDName(key.ID)
	wantKeyID, err := cert.CosignatureKeyID(wantName, key.Algorithm, key.PublicKey)
	if err != nil {
		return nil, err
	}

	lines, err := ParseCosignatureLines(body)
	if err != nil {
		return nil, err
	}
	var out []Cosignature
	for _, c := range lines {
		if c.Name != wantName || c.KeyID != wantKeyID {
			continue // an unknown key: ignore, per signed-note.
		}
		switch rule {
		case TimestampZero:
			if c.Timestamp != 0 {
				return nil, fmt.Errorf("mirrorpush: subtree cosignature from %q has non-zero timestamp %d",
					c.Name, c.Timestamp)
			}
		case TimestampNonZero:
			if c.Timestamp == 0 {
				return nil, fmt.Errorf("mirrorpush: checkpoint cosignature from %q has a zero timestamp", c.Name)
			}
		}
		msg, err := cert.MarshalSignatureInputAt(key.ID, subtree, c.Timestamp)
		if err != nil {
			return nil, err
		}
		sig := cert.MTCSignature{CosignerID: key.ID, Signature: c.Signature}
		if err := cert.VerifyMTCSignature(key, sig, msg); err != nil {
			// Name and key ID matched, so this line asserts it is ours.
			// Reject the whole response.
			return nil, fmt.Errorf("mirrorpush: cosignature from %q (key ID %x) failed to verify: %w",
				c.Name, c.KeyID, err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("mirrorpush: no cosignature from %q in response", wantName)
	}
	return out, nil
}
