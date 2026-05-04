package log

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/tlogx"
)

// buildSignedNote returns a c2sp signed-note for the checkpoint, using
// the cosigner's signature over the §5.4.1 MTCSubtreeSignatureInput for
// [0, size).
//
// Body lines (each terminated by \n):
//
//	<origin>
//	<size>
//	<base64 root>
//
// Origin is "oid/<logID>" per Appendix C.1 of the draft.
//
// Trailing signature line: "— <key-name> <base64 sig>\n".
func buildSignedNote(logID, cosignerID cert.TrustAnchorID,
	size uint64, root tlogx.Hash, sig []byte) ([]byte, error) {
	if len(logID) == 0 {
		return nil, errors.New("buildSignedNote: empty logID")
	}
	origin := "oid/" + string(logID)
	cosigner := "oid/" + string(cosignerID)
	body := fmt.Sprintf("%s\n%d\n%s\n",
		origin, size,
		base64.StdEncoding.EncodeToString(root[:]))

	// Per draft Appendix C.1: key ID = SHA-256(key name || 0x0A || 0xFF
	// || "mtc-checkpoint/v1")[:4]. We emit the standard signed-note
	// format with a 4-byte key ID prefixed onto the signature.
	keyID := mtcCheckpointKeyID(cosigner)
	sigWithID := append(append([]byte(nil), keyID[:]...), sig...)
	sigB64 := base64.StdEncoding.EncodeToString(sigWithID)

	out := body + "\n" // blank line separating body from signatures
	out += "— " + cosigner + " " + sigB64 + "\n"
	return []byte(out), nil
}

// parseSignedNote extracts (size, root) from a signed note, ignoring
// signatures. logID is verified against the origin line.
func parseSignedNote(data []byte, logID cert.TrustAnchorID) (uint64, tlogx.Hash, error) {
	size, root, _, err := parseSignedNoteFull(data, logID)
	return size, root, err
}

// parseSignedNoteFull is like parseSignedNote but also returns the raw
// signature records (each is keyName + base64-decoded sig-with-keyID
// bytes). Used by the loaded-checkpoint verification path.
func parseSignedNoteFull(data []byte, logID cert.TrustAnchorID) (uint64, tlogx.Hash, []parsedNoteSig, error) {
	s := string(data)
	parts := strings.SplitN(s, "\n\n", 2)
	if len(parts) < 1 {
		return 0, tlogx.Hash{}, nil, errors.New("parseSignedNote: no body")
	}
	lines := strings.Split(parts[0], "\n")
	// Body is "<origin>\n<size>\n<base64 root>\n" — three non-empty lines.
	// Drop empty trailing entry from terminal \n if present.
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) != 3 {
		return 0, tlogx.Hash{}, nil, fmt.Errorf("parseSignedNote: %d body lines, want 3", len(lines))
	}
	wantOrigin := "oid/" + string(logID)
	if lines[0] != wantOrigin {
		return 0, tlogx.Hash{}, nil, fmt.Errorf("parseSignedNote: origin %q != %q", lines[0], wantOrigin)
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return 0, tlogx.Hash{}, nil, fmt.Errorf("parseSignedNote: bad size: %w", err)
	}
	rootBytes, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return 0, tlogx.Hash{}, nil, fmt.Errorf("parseSignedNote: bad root b64: %w", err)
	}
	if len(rootBytes) != tlogx.HashSize {
		return 0, tlogx.Hash{}, nil, fmt.Errorf("parseSignedNote: root len %d, want %d", len(rootBytes), tlogx.HashSize)
	}
	var root tlogx.Hash
	copy(root[:], rootBytes)

	var sigs []parsedNoteSig
	if len(parts) == 2 {
		for _, line := range strings.Split(parts[1], "\n") {
			if line == "" {
				continue
			}
			rest, ok := strings.CutPrefix(line, "— ")
			if !ok {
				return 0, tlogx.Hash{}, nil, fmt.Errorf("parseSignedNote: non-signature line %q", line)
			}
			fields := strings.SplitN(rest, " ", 2)
			if len(fields) != 2 {
				return 0, tlogx.Hash{}, nil, fmt.Errorf("parseSignedNote: malformed sig line %q", line)
			}
			raw, err := base64.StdEncoding.DecodeString(fields[1])
			if err != nil {
				return 0, tlogx.Hash{}, nil, fmt.Errorf("parseSignedNote: sig b64: %w", err)
			}
			if len(raw) < 4 {
				return 0, tlogx.Hash{}, nil, fmt.Errorf("parseSignedNote: sig too short for keyID")
			}
			sigs = append(sigs, parsedNoteSig{
				keyName: fields[0],
				keyID:   [4]byte{raw[0], raw[1], raw[2], raw[3]},
				sig:     raw[4:],
			})
		}
	}
	return size, root, sigs, nil
}

type parsedNoteSig struct {
	keyName string
	keyID   [4]byte
	sig     []byte
}

// mtcCheckpointKeyID computes the §C.1 key ID for a checkpoint
// signature: SHA-256(keyName || 0x0A || 0xFF || "mtc-checkpoint/v1")[:4].
func mtcCheckpointKeyID(keyName string) [4]byte {
	return signedNoteKeyID(keyName, "mtc-checkpoint/v1")
}

// MTCSubtreeKeyID is exposed for tests; computes the §C.1 subtree key
// ID for a given cosigner's signed-note key name.
func MTCSubtreeKeyID(keyName string) [4]byte {
	return signedNoteKeyID(keyName, "mtc-subtree/v1")
}

func signedNoteKeyID(keyName, suffix string) [4]byte {
	// SHA-256(keyName || 0x0A || 0xFF || suffix)[:4].
	buf := append([]byte(keyName), 0x0A, 0xFF)
	buf = append(buf, []byte(suffix)...)
	sum := sha256Hash(buf)
	var out [4]byte
	copy(out[:], sum[:4])
	return out
}
