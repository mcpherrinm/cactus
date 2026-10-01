package tlogx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// Appendix C.1 of draft-ietf-plants-merkle-tree-certs-07 supplies
// "accumulated" test vectors for the §4 subtree algorithms: rather than
// tabulating individual cases, each vector is a single rolling SHA-256
// over the formatted output of every valid input (including, since
// draft-07, the empty subtrees [x, x)) for trees up to size 130. Matching the accumulator is strong evidence that our indexing,
// ordering, and proof shapes agree with the draft everywhere, not just
// at the handful of examples the other tests pin.
//
// The tree is D_n with leaf values d[0] = 0x00, d[1] = 0x01, ....

// appendixCMaxSize is the largest tree the vectors cover (inclusive).
const appendixCMaxSize = 130

// appendixCLeafData returns d[i], a one-byte leaf whose value is i.
// The vectors stop at 130, so a single byte always suffices.
func appendixCLeafData(i uint64) []byte { return []byte{byte(i)} }

// appendixCLeaves returns the leaf hashes for D[0:appendixCMaxSize].
func appendixCLeaves() []Hash {
	out := make([]Hash, appendixCMaxSize)
	for i := range out {
		out[i] = HashLeaf(sha, appendixCLeafData(uint64(i)))
	}
	return out
}

// appendixCHashReader builds a tlog.HashReader holding every stored hash
// for D[0:appendixCMaxSize], which GenerateInclusionProof needs.
func appendixCHashReader(t *testing.T) tlog.HashReader {
	t.Helper()
	var stored []tlog.Hash
	hr := tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		for i, idx := range indexes {
			if idx < 0 || idx >= int64(len(stored)) {
				return nil, fmt.Errorf("hash index %d out of range [0,%d)", idx, len(stored))
			}
			out[i] = stored[idx]
		}
		return out, nil
	})
	for i := uint64(0); i < appendixCMaxSize; i++ {
		hs, err := tlog.StoredHashes(int64(i), appendixCLeafData(i), hr)
		if err != nil {
			t.Fatalf("StoredHashes(%d): %v", i, err)
		}
		stored = append(stored, hs...)
	}
	return hr
}

// checkAccumulated compares a rolling hash against the draft's value.
func checkAccumulated(t *testing.T, section string, got [32]byte, want string) {
	t.Helper()
	if h := hex.EncodeToString(got[:]); h != want {
		t.Errorf("Appendix %s accumulated hash =\n\t%s\nwant\n\t%s", section, h, want)
	}
}

// TestAppendixC11SubtreeHashes checks the §C.1.1 vector: for every valid
// subtree [start, end), the line "[START, END) HASH\n".
func TestAppendixC11SubtreeHashes(t *testing.T) {
	leaves := appendixCLeaves()
	h := sha256.New()
	for end := uint64(0); end <= appendixCMaxSize; end++ {
		for start := uint64(0); start <= end; start++ {
			if !IsValid(start, end) {
				continue
			}
			sh := subtreeOf(leaves, start, end)
			fmt.Fprintf(h, "[%d, %d) %s\n", start, end, hex.EncodeToString(sh[:]))
		}
	}
	checkAccumulated(t, "C.1.1", [32]byte(h.Sum(nil)),
		"b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81")
}

// TestAppendixC12SubtreeInclusionProofs checks the §C.1.2 vector: for
// every valid subtree and every index within it, the line
// "INDEX [START, END)" followed by a space-prefixed hash per proof
// element. It also exercises the relying-party side as §C.1.2
// recommends: each proof must evaluate to the subtree hash, and the
// proof truncated or extended by a hash must fail to evaluate. (The
// byte-level truncations are MTCProof parsing concerns, covered in
// package cert.)
func TestAppendixC12SubtreeInclusionProofs(t *testing.T) {
	leaves := appendixCLeaves()
	hr := appendixCHashReader(t)
	h := sha256.New()
	for end := uint64(0); end <= appendixCMaxSize; end++ {
		for start := uint64(0); start <= end; start++ {
			if !IsValid(start, end) {
				continue
			}
			want := subtreeOf(leaves, start, end)
			for index := start; index < end; index++ {
				proof, err := GenerateInclusionProof(start, end, index, hr)
				if err != nil {
					t.Fatalf("GenerateInclusionProof(%d,%d,%d): %v", start, end, index, err)
				}
				got, err := EvaluateInclusionProof(sha, start, end, index, leaves[index], proof)
				if err != nil {
					t.Fatalf("EvaluateInclusionProof(%d,%d,%d): %v", start, end, index, err)
				}
				if got != want {
					t.Fatalf("inclusion proof for %d in [%d,%d) evaluates to %x, want %x",
						index, start, end, got, want)
				}
				if len(proof) > 0 {
					if _, err := EvaluateInclusionProof(sha, start, end, index, leaves[index], proof[:len(proof)-1]); err == nil {
						t.Fatalf("truncated inclusion proof for %d in [%d,%d) evaluated", index, start, end)
					}
				}
				extended := append(append([]Hash(nil), proof...), Hash{0x42})
				if _, err := EvaluateInclusionProof(sha, start, end, index, leaves[index], extended); err == nil {
					t.Fatalf("extended inclusion proof for %d in [%d,%d) evaluated", index, start, end)
				}
				fmt.Fprintf(h, "%d [%d, %d)", index, start, end)
				for _, p := range proof {
					fmt.Fprintf(h, " %s", hex.EncodeToString(p[:]))
				}
				fmt.Fprint(h, "\n")
			}
		}
	}
	checkAccumulated(t, "C.1.2", [32]byte(h.Sum(nil)),
		"ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f")
}

// TestAppendixC13SubtreeConsistencyProofs checks the §C.1.3 vector: for
// every tree size n, and every valid subtree [start, end) with end <= n,
// the line "[START, END) N" followed by a space-prefixed hash per proof
// element. The loops cover empty subtrees (including those of the empty
// tree, n = 0) and the whole-tree base case start=0,end=n, both of
// whose proofs are empty per §4.4.1. Each proof is also run through the
// §C.1.3 verifier checks: it must verify, and truncating or extending it
// by a hash, or flipping a bit in the subtree hash (or, for a non-empty
// subtree, the tree hash), must make it fail.
func TestAppendixC13SubtreeConsistencyProofs(t *testing.T) {
	leaves := appendixCLeaves()
	leafHash := func(i uint64) (Hash, error) {
		if i >= uint64(len(leaves)) {
			return Hash{}, fmt.Errorf("leaf %d out of range", i)
		}
		return leaves[i], nil
	}
	flip := func(h Hash) Hash { h[0] ^= 1; return h }
	h := sha256.New()
	for n := uint64(0); n <= appendixCMaxSize; n++ {
		root := subtreeOf(leaves, 0, n)
		for end := uint64(0); end <= n; end++ {
			for start := uint64(0); start <= end; start++ {
				if !IsValid(start, end) {
					continue
				}
				proof, err := GenerateConsistencyProof(sha, start, end, n, leafHash)
				if err != nil {
					t.Fatalf("GenerateConsistencyProof(%d,%d,%d): %v", start, end, n, err)
				}
				node := subtreeOf(leaves, start, end)
				verify := func(p []Hash, node, root Hash) error {
					return VerifyConsistencyProof(sha, start, end, n, p, node, root)
				}
				if err := verify(proof, node, root); err != nil {
					t.Fatalf("VerifyConsistencyProof(%d,%d,%d): %v", start, end, n, err)
				}
				if len(proof) > 0 && verify(proof[:len(proof)-1], node, root) == nil {
					t.Fatalf("truncated consistency proof for [%d,%d) in %d verified", start, end, n)
				}
				if verify(append(append([]Hash(nil), proof...), Hash{0x42}), node, root) == nil {
					t.Fatalf("extended consistency proof for [%d,%d) in %d verified", start, end, n)
				}
				if verify(proof, flip(node), root) == nil {
					t.Fatalf("consistency proof for [%d,%d) in %d verified a flipped subtree hash", start, end, n)
				}
				if start != end && verify(proof, node, flip(root)) == nil {
					t.Fatalf("consistency proof for [%d,%d) in %d verified a flipped tree hash", start, end, n)
				}
				fmt.Fprintf(h, "[%d, %d) %d", start, end, n)
				for _, p := range proof {
					fmt.Fprintf(h, " %s", hex.EncodeToString(p[:]))
				}
				fmt.Fprint(h, "\n")
			}
		}
	}
	checkAccumulated(t, "C.1.3", [32]byte(h.Sum(nil)),
		"10fa99b37bf9bf9ffa26b412fbd98bd75363256d0b75d61bc4538b9c9c5a0a74")
}

// TestAppendixC14EfficientCoveringSubtrees checks the §C.1.4 vector.
// Unlike the others this covers *all* [start, end) pairs, not just
// valid subtrees, and since draft-07 every pair emits the two covering
// subtrees from §4.5.1, even when [start, end) is itself a subtree.
func TestAppendixC14EfficientCoveringSubtrees(t *testing.T) {
	h := sha256.New()
	for end := uint64(0); end <= appendixCMaxSize; end++ {
		for start := uint64(0); start <= end; start++ {
			subs := FindSubtrees(start, end)
			fmt.Fprintf(h, "[%d, %d) [%d, %d)\n",
				subs[0].Start, subs[0].End, subs[1].Start, subs[1].End)
		}
	}
	checkAccumulated(t, "C.1.4", [32]byte(h.Sum(nil)),
		"7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0")
}
