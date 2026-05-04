// Package mirror implements the cosigning-mirror operating mode from
// PROJECT_PLAN Phase 9, conforming to c2sp tlog-mirror and
// tlog-cosignature.
//
// The follower (this file's neighbor follower.go) tails an upstream
// log via the tlog-tiles convention, verifying the CA cosigner's
// signature on each new checkpoint and recomputing the root from the
// upstream's data tiles before accepting an advance. Refusing to
// advance — i.e. halting — is the correct response to any check
// failure; we never paper over corruption.
package mirror

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/letsencrypt/cactus/tlogx"
)

// parseSignedNote pulls (size, root, signature, keyName) out of a
// c2sp signed-note checkpoint. Body lines: origin, size, base64 root.
// Then a blank line + signature lines beginning with the em-dash.
//
// Returns the first signature only; mirrors expect exactly one CA
// cosignature per checkpoint here. Multi-signature notes (e.g. with
// witnesses already attached) work the same — we just pick out the
// CA-named one.
func parseSignedNote(data []byte, expectKey string) (
	size uint64, root tlogx.Hash, sig []byte, err error,
) {
	parts := strings.SplitN(string(data), "\n\n", 2)
	if len(parts) < 2 {
		return 0, tlogx.Hash{}, nil, errors.New("mirror: signed note missing body separator")
	}
	bodyLines := strings.Split(strings.TrimRight(parts[0], "\n"), "\n")
	if len(bodyLines) != 3 {
		return 0, tlogx.Hash{}, nil, fmt.Errorf("mirror: %d body lines, want 3", len(bodyLines))
	}
	size, err = strconv.ParseUint(bodyLines[1], 10, 64)
	if err != nil {
		return 0, tlogx.Hash{}, nil, fmt.Errorf("mirror: bad size: %w", err)
	}
	rb, err := base64.StdEncoding.DecodeString(bodyLines[2])
	if err != nil {
		return 0, tlogx.Hash{}, nil, fmt.Errorf("mirror: bad root b64: %w", err)
	}
	if len(rb) != tlogx.HashSize {
		return 0, tlogx.Hash{}, nil, fmt.Errorf("mirror: root size %d, want %d", len(rb), tlogx.HashSize)
	}
	copy(root[:], rb)

	// Find the signature line for expectKey.
	const dash = "—"
	prefix := dash + " " + expectKey + " "
	for _, line := range strings.Split(strings.TrimRight(parts[1], "\n"), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, prefix))
		if err != nil {
			return 0, tlogx.Hash{}, nil, fmt.Errorf("mirror: sig b64: %w", err)
		}
		if len(raw) < 5 {
			return 0, tlogx.Hash{}, nil, fmt.Errorf("mirror: sig too short")
		}
		// First 4 bytes are the c2sp keyID; the rest is the signature.
		sig = raw[4:]
		return size, root, sig, nil
	}
	return 0, tlogx.Hash{}, nil, fmt.Errorf("mirror: no signature line for %q", expectKey)
}
