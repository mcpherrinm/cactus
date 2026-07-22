package pollinate

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/tlogx"
)

// Note is a parsed c2sp.org/tlog-checkpoint signed note. Unlike the log
// package's parser, the origin is returned rather than checked against
// an expected log ID: pollinate learns which log it is looking at *from*
// the checkpoint, and some real-world origins are not oid-derived.
type Note struct {
	Origin string
	Size   uint64
	Root   tlogx.Hash
	// Raw is the verbatim note, retained so the exact signed bytes can
	// be forwarded to a mirror's add-checkpoint endpoint.
	Raw  []byte
	Sigs []NoteSig
}

// NoteSig is one signature line of a note. Blob is the base64-decoded
// signature with the 4-byte key ID stripped; its interpretation depends
// on the key's algorithm, so it is kept opaque here.
type NoteSig struct {
	Name  string
	KeyID [4]byte
	Blob  []byte
}

// ParseNote parses a checkpoint note body plus signature lines.
func ParseNote(data []byte) (*Note, error) {
	body, sigText, ok := strings.Cut(string(data), "\n\n")
	if !ok {
		return nil, errors.New("pollinate: note has no signature separator")
	}
	lines := strings.Split(body, "\n")
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) < 3 {
		return nil, fmt.Errorf("pollinate: note body has %d lines, want at least 3", len(lines))
	}
	n := &Note{
		Origin: lines[0],
		Raw:    append([]byte(nil), data...),
	}
	if n.Origin == "" {
		return nil, errors.New("pollinate: note has empty origin")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("pollinate: note size: %w", err)
	}
	n.Size = size
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, fmt.Errorf("pollinate: note root: %w", err)
	}
	if len(root) != tlogx.HashSize {
		return nil, fmt.Errorf("pollinate: note root is %d bytes, want %d", len(root), tlogx.HashSize)
	}
	copy(n.Root[:], root)

	for _, line := range strings.Split(sigText, "\n") {
		if line == "" {
			continue
		}
		rest, ok := strings.CutPrefix(line, "— ")
		if !ok {
			return nil, fmt.Errorf("pollinate: note has non-signature line %q", line)
		}
		name, b64, ok := strings.Cut(rest, " ")
		if !ok || name == "" {
			return nil, fmt.Errorf("pollinate: malformed signature line %q", line)
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("pollinate: signature base64: %w", err)
		}
		if len(raw) < 4 {
			return nil, errors.New("pollinate: signature too short for a key ID")
		}
		n.Sigs = append(n.Sigs, NoteSig{
			Name:  name,
			KeyID: [4]byte(raw[:4]),
			Blob:  raw[4:],
		})
	}
	return n, nil
}

// VerifySignature checks that the note carries a valid ML-DSA-44
// cosignature from the signer with the given trust anchor ID and raw
// public key. Both timestamp flavours are accepted: an issuer signing
// its own checkpoint uses timestamp 0 (an MTC subtree cosignature over
// [0, size)), while a mirror's retained checkpoint cosignature carries
// a non-zero timestamp.
func (n *Note) VerifySignature(signerID cert.TrustAnchorID, rawKey []byte) error {
	name := cert.OIDName(signerID)
	keyID, err := cert.CosignatureKeyID(name, cert.AlgMLDSA44, rawKey)
	if err != nil {
		return err
	}
	key := cert.CosignerKey{ID: signerID, Algorithm: cert.AlgMLDSA44, PublicKey: rawKey}
	found := false
	for _, s := range n.Sigs {
		if s.Name != name || s.KeyID != keyID {
			continue
		}
		found = true
		ts, sig, err := cert.ParseTimestampedSignature(s.Blob)
		if err != nil {
			return fmt.Errorf("pollinate: signature from %q: %w", name, err)
		}
		msg, err := cert.MarshalCosignedMessage(name, n.Origin, ts, 0, n.Size, n.Root)
		if err != nil {
			return err
		}
		if err := cert.VerifyMTCSignature(key, cert.MTCSignature{CosignerID: signerID, Signature: sig}, msg); err == nil {
			return nil
		}
	}
	if !found {
		return fmt.Errorf("pollinate: no signature from %q on checkpoint for %q", name, n.Origin)
	}
	return fmt.Errorf("pollinate: signature from %q on checkpoint for %q failed to verify", name, n.Origin)
}
