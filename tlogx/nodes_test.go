package tlogx

import (
	"fmt"
	"testing"
)

// TestGenerateConsistencyProofFromNodes checks the node-reading
// generator produces byte-identical proofs to the leaf-hashing one, and
// that they verify, across every valid (start, end) subtree of trees up
// to 70 leaves plus a few larger spot checks.
func TestGenerateConsistencyProofFromNodes(t *testing.T) {
	leaves := makeLeaves(600)

	// nodeHash serves the stored-hash addressing scheme: the hash of the
	// complete subtree [index<<level, (index+1)<<level).
	nodeHash := func(level int, index uint64) (Hash, error) {
		lo := index << level
		hi := lo + 1<<level
		if hi > uint64(len(leaves)) {
			return Hash{}, fmt.Errorf("node (%d,%d) beyond %d leaves", level, index, len(leaves))
		}
		return subtreeOf(leaves, lo, hi), nil
	}
	leafHash := func(i uint64) (Hash, error) { return leaves[i], nil }

	check := func(start, end, n uint64) {
		t.Helper()
		want, err := GenerateConsistencyProof(sha, start, end, n, leafHash)
		if err != nil {
			t.Fatalf("leaf proof [%d,%d) in %d: %v", start, end, n, err)
		}
		got, err := GenerateConsistencyProofFromNodes(sha, start, end, n, nodeHash)
		if err != nil {
			t.Fatalf("node proof [%d,%d) in %d: %v", start, end, n, err)
		}
		if len(got) != len(want) {
			t.Fatalf("[%d,%d) in %d: node proof has %d hashes, leaf proof %d", start, end, n, len(got), len(want))
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("[%d,%d) in %d: proofs differ at %d", start, end, n, i)
			}
		}
		if err := VerifyConsistencyProof(sha, start, end, n, got,
			subtreeOf(leaves, start, end), rootOf(leaves, n)); err != nil {
			t.Fatalf("[%d,%d) in %d: proof does not verify: %v", start, end, n, err)
		}
	}

	for n := uint64(1); n <= 70; n++ {
		for start := uint64(0); start < n; start++ {
			for end := start + 1; end <= n; end++ {
				if !IsValid(start, end) {
					continue
				}
				check(start, end, n)
			}
		}
	}
	// Larger trees, including sizes crossing the 256 tile boundary.
	for _, c := range []struct{ start, end, n uint64 }{
		{0, 256, 600}, {256, 512, 600}, {512, 600, 600},
		{256, 300, 599}, {384, 400, 401}, {0, 512, 513},
	} {
		check(c.start, c.end, c.n)
	}
}
