package cert

import (
	"fmt"
	"strconv"
	"strings"
)

// This file centralizes the three on-wire encodings of a trust anchor ID
// used by Merkle Tree Certificates, all derived from one canonical
// in-memory form.
//
// Canonical form: cactus stores a TrustAnchorID as the *relative*
// trust-anchor-ID ASCII (Section 3 of draft-ietf-tls-trust-anchor-ids),
// e.g. "32473.1" — the dotted-decimal OID arcs *relative to the
// 1.3.6.1.4.1 base*, exactly as draft-04 §5.1 shows in the DN example.
// From this single form we derive:
//
//   - the DN attribute value: UTF8String(<relative ASCII>)         (§5.1)
//   - the cosigner_name / log_origin: "oid/1.3.6.1.4.1."+<rel ASCII> (§5.3.1)
//   - the binary representation: DER content octets of the
//     RELATIVE-OID, used in MTCProof.cosigner_id (§6.1), the
//     trust_anchor_id certificate property, and the CA cert subjectKeyId.
//
// Keeping the relative form canonical is what lets all three be
// simultaneously spec-exact (review finding 2): "oid/"+full and
// UTF8String(relative) cannot both be produced from a single string
// unless that string is the relative form and the 1.3.6.1.4.1 base is
// re-attached only for the "oid/" name.

// TrustAnchorOIDBase is the absolute OID prefix that every Merkle Tree
// Certificate trust anchor ID is relative to (§5.3.1 fixes the 16-byte
// ASCII prefix "oid/1.3.6.1.4.1."). Trust anchor IDs are expressed
// relative to this base.
const TrustAnchorOIDBase = "1.3.6.1.4.1"

// OIDNamePrefix is the four-byte ASCII prefix of a cosigner_name /
// log_origin (§5.3.1). It precedes the full dotted-decimal OID.
const OIDNamePrefix = "oid/"

// Binary returns the trust anchor ID's binary representation per Section
// 3 of draft-ietf-tls-trust-anchor-ids: the DER content octets of the
// RELATIVE-OID (X.690 §8.20), i.e. each arc base-128 encoded with the
// high bit set on every octet but the last of the arc, concatenated.
// This is the form draft-04 §6.1 requires for MTCProof.cosigner_id and
// TAI §7 requires for the trust_anchor_id certificate property.
//
// For example, TrustAnchorID("32473.1").Binary() == {0x81,0xfd,0x59,0x01}.
//
// It returns an error if the ID is not a non-empty dotted-decimal string
// of non-negative integers (a trust anchor ID is a relative OID, so
// non-numeric components such as "foo" cannot be represented on the
// wire).
func (id TrustAnchorID) Binary() ([]byte, error) {
	s := string(id)
	if s == "" {
		return nil, fmt.Errorf("cert: empty trust anchor ID")
	}
	var out []byte
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return nil, fmt.Errorf("cert: trust anchor ID %q has empty arc", s)
		}
		v, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("cert: trust anchor ID %q arc %q is not a non-negative integer: %w", s, part, err)
		}
		out = appendBase128(out, v)
	}
	return out, nil
}

// TrustAnchorIDFromBinary is the inverse of Binary: it decodes the DER
// content octets of a RELATIVE-OID into the canonical relative-ASCII
// TrustAnchorID. It rejects non-minimal (leading 0x80) and truncated
// (trailing continuation) encodings.
func TrustAnchorIDFromBinary(b []byte) (TrustAnchorID, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("cert: empty binary trust anchor ID")
	}
	var arcs []string
	var v uint64
	started := false
	bits := 0
	for _, c := range b {
		if !started && c == 0x80 {
			return nil, fmt.Errorf("cert: non-minimal base-128 encoding in trust anchor ID")
		}
		started = true
		bits += 7
		if bits > 64 {
			return nil, fmt.Errorf("cert: trust anchor ID arc overflows uint64")
		}
		v = v<<7 | uint64(c&0x7f)
		if c&0x80 == 0 {
			arcs = append(arcs, strconv.FormatUint(v, 10))
			v = 0
			started = false
			bits = 0
		}
	}
	if started {
		return nil, fmt.Errorf("cert: truncated base-128 encoding in trust anchor ID")
	}
	return TrustAnchorID(strings.Join(arcs, ".")), nil
}

// appendBase128 appends v to dst as a base-128, big-endian, minimal-
// length integer with the continuation bit (0x80) set on every octet
// but the last (X.690 §8.19.2, used for OID/RELATIVE-OID arcs).
func appendBase128(dst []byte, v uint64) []byte {
	var buf [10]byte
	n := len(buf)
	n--
	buf[n] = byte(v & 0x7f)
	for v >>= 7; v > 0; v >>= 7 {
		n--
		buf[n] = byte(v&0x7f) | 0x80
	}
	return append(dst, buf[n:]...)
}
