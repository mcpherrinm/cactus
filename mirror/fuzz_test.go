package mirror

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
)

// FuzzParseSignSubtreeRequest feeds random bytes to the
// c2sp.org/tlog-witness sign-subtree request parser and asserts that it
// never panics. The format is fiddly (a range line, a hash line, a
// variable run of cosignature/proof lines, an empty line, then a signed
// checkpoint), so any unchecked length or index could surface as a panic.
func FuzzParseSignSubtreeRequest(f *testing.F) {
	// Seed corpus: a handful of legal + suggestive shapes.
	f.Add([]byte(""))
	f.Add([]byte("\n\n"))
	f.Add([]byte("\n\n\n"))
	f.Add([]byte(buildMinimal("oid/test", 0, 1)))

	// A shape with 64 proof lines (1 over the cap).
	var manyProofs bytes.Buffer
	manyProofs.WriteString("subtree 0 1\n")
	manyProofs.WriteString(base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)) + "\n")
	for i := 0; i < 64; i++ {
		manyProofs.WriteString(base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	}
	manyProofs.WriteString("\n")
	manyProofs.WriteString("oid/test\n1\n" + base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)) + "\n\n")
	f.Add(manyProofs.Bytes())

	// A shape with a malformed line where the checkpoint should be.
	bad := buildMinimal("oid/test", 0, 1)
	bad += "this isn't a signature\n"
	f.Add([]byte(bad))

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = ParseSignSubtreeRequestForFuzz(data)
	})
}

// buildMinimal returns a sign-subtree body with a subtree range + hash,
// no cosignature or proof lines, an empty line, then a no-signature
// checkpoint at size 1 with a SHA-256 zero hash.
func buildMinimal(origin string, start, end uint64) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "subtree %d %d\n", start, end)
	b.WriteString(base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)) + "\n")
	b.WriteString("\n") // empty line before the checkpoint
	b.WriteString(origin + "\n")
	b.WriteString("1\n")
	b.WriteString(base64.StdEncoding.EncodeToString(make([]byte, sha256.Size)) + "\n")
	b.WriteString("\n") // checkpoint body/sig separator (zero sigs)
	return b.String()
}
