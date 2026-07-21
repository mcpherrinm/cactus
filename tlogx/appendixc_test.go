package tlogx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

// Appendix C of draft-ietf-plants-merkle-tree-certs-05 supplies
// "accumulated" test vectors for the §4 subtree algorithms: rather than
// tabulating individual cases, each vector is a single rolling SHA-256
// over the formatted output of every valid input for trees up to size
// 130. Matching the accumulator is strong evidence that our indexing,
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

// TestAppendixC1SubtreeHashes checks the §C.1 vector: for every valid
// subtree [start, end), the line "[START, END) HASH\n".
func TestAppendixC1SubtreeHashes(t *testing.T) {
	leaves := appendixCLeaves()
	h := sha256.New()
	for end := uint64(1); end <= appendixCMaxSize; end++ {
		for start := uint64(0); start < end; start++ {
			if !IsValid(start, end) {
				continue
			}
			sh := subtreeOf(leaves, start, end)
			fmt.Fprintf(h, "[%d, %d) %s\n", start, end, hex.EncodeToString(sh[:]))
		}
	}
	checkAccumulated(t, "C.1", [32]byte(h.Sum(nil)),
		"94a95384a8c69acea9b50d035a58285b3a777cb7a724005faa5e1f1e1190007f")
}

// TestAppendixC2SubtreeInclusionProofs checks the §C.2 vector: for every
// valid subtree and every index within it, the line
// "INDEX [START, END)" followed by a space-prefixed hash per proof
// element. It also round-trips each proof through
// EvaluateInclusionProof, so a proof that is correctly *ordered* but
// wrong, or vice versa, is caught here rather than only in the digest.
func TestAppendixC2SubtreeInclusionProofs(t *testing.T) {
	leaves := appendixCLeaves()
	hr := appendixCHashReader(t)
	h := sha256.New()
	for end := uint64(1); end <= appendixCMaxSize; end++ {
		for start := uint64(0); start < end; start++ {
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
				fmt.Fprintf(h, "%d [%d, %d)", index, start, end)
				for _, p := range proof {
					fmt.Fprintf(h, " %s", hex.EncodeToString(p[:]))
				}
				fmt.Fprint(h, "\n")
			}
		}
	}
	checkAccumulated(t, "C.2", [32]byte(h.Sum(nil)),
		"ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f")
}

// TestAppendixC3SubtreeConsistencyProofs checks the §C.3 vector: for
// every tree size n, and every valid subtree [start, end) with end <= n,
// the line "[START, END) N" followed by a space-prefixed hash per proof
// element. Note the loop covers n = 0, for which the inner loops are
// empty, and the whole-tree base case start=0,end=n, whose proof is
// empty per §4.4.1.
func TestAppendixC3SubtreeConsistencyProofs(t *testing.T) {
	leaves := appendixCLeaves()
	leafHash := func(i uint64) (Hash, error) {
		if i >= uint64(len(leaves)) {
			return Hash{}, fmt.Errorf("leaf %d out of range", i)
		}
		return leaves[i], nil
	}
	h := sha256.New()
	for n := uint64(0); n <= appendixCMaxSize; n++ {
		for end := uint64(1); end <= n; end++ {
			for start := uint64(0); start < end; start++ {
				if !IsValid(start, end) {
					continue
				}
				proof, err := GenerateConsistencyProof(sha, start, end, n, leafHash)
				if err != nil {
					t.Fatalf("GenerateConsistencyProof(%d,%d,%d): %v", start, end, n, err)
				}
				fmt.Fprintf(h, "[%d, %d) %d", start, end, n)
				for _, p := range proof {
					fmt.Fprintf(h, " %s", hex.EncodeToString(p[:]))
				}
				fmt.Fprint(h, "\n")
			}
		}
	}
	checkAccumulated(t, "C.3", [32]byte(h.Sum(nil)),
		"c586ebbb73a5621baf2140095d87dde934e3b6503a562a1a5215b8209edd083d")
}

// TestAppendixC4EfficientCoveringSubtrees checks the §C.4 vector. Unlike
// the others this covers *all* [start, end) pairs, not just valid
// subtrees: a valid subtree emits "[START, END)\n", anything else emits
// the two covering subtrees from §4.5.
func TestAppendixC4EfficientCoveringSubtrees(t *testing.T) {
	h := sha256.New()
	for end := uint64(1); end <= appendixCMaxSize; end++ {
		for start := uint64(0); start < end; start++ {
			if IsValid(start, end) {
				fmt.Fprintf(h, "[%d, %d)\n", start, end)
				continue
			}
			subs := FindSubtrees(start, end)
			if len(subs) != 2 {
				t.Fatalf("FindSubtrees(%d,%d) returned %d subtrees, want 2",
					start, end, len(subs))
			}
			fmt.Fprintf(h, "[%d, %d) [%d, %d)\n",
				subs[0].Start, subs[0].End, subs[1].Start, subs[1].End)
		}
	}
	checkAccumulated(t, "C.4", [32]byte(h.Sum(nil)),
		"e0aecb912a10c57d753b6ecc64db73217f9bc4ed10fcb4e9062be3b6fbe1ebfd")
}
