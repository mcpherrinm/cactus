package mirror

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

// FuzzParseSignSubtreeRequest feeds random bytes to the §C.2 request
// parser and asserts that it never panics. The §C.2 format is fiddly
// (three sections separated by blank lines, with signed-note
// signatures inside each), so any unchecked length or index could
// surface as a panic.
func FuzzParseSignSubtreeRequest(f *testing.F) {
	// Seed corpus: a handful of legal + suggestive shapes.
	f.Add([]byte(""))
	f.Add([]byte("\n\n"))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte(buildMinimal("oid/test", 0, 1)))

	// A shape with 64 proof lines (1 over the §C.2 cap).
	manyProofs := buildMinimal("oid/test", 0, 1)
	for i := 0; i < 64; i++ {
		manyProofs += base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	}
	f.Add([]byte(manyProofs))

	// A shape with a malformed signature line.
	bad := buildMinimal("oid/test", 0, 1)
	bad += "this isn't a signature\n"
	f.Add([]byte(bad))

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParseSignSubtreeRequestForFuzz(data)
	})
}

// buildMinimal returns a §C.2 body with a no-sig subtree note + a
// no-sig checkpoint note + zero proof lines. Both notes use the
// given log_id; the checkpoint is at size 1 with a SHA-256 zero hash.
func buildMinimal(origin string, start, end uint64) string {
	var b bytes.Buffer
	b.WriteString(origin + "\n")
	fmt.Fprintf(&b, "%d %d\n", start, end)
	b.WriteString(base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)) + "\n")
	b.WriteString("\n\n")
	b.WriteString(origin + "\n")
	b.WriteString("1\n")
	b.WriteString(base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)) + "\n")
	b.WriteString("\n\n")
	return b.String()
}
