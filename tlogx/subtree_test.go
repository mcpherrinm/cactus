package tlogx

import (
	"crypto/sha256"
	"reflect"
	"testing"
)

func sha(b []byte) Hash {
	return Hash(sha256.Sum256(b))
}

func TestIsValid(t *testing.T) {
	cases := []struct {
		start, end uint64
		want       bool
	}{
		{0, 1, true},
		{0, 13, true},
		{4, 8, true},  // size 4, multiple of bit_ceil(4)=4
		{8, 13, true}, // size 5, bit_ceil=8, start=8 multiple of 8 ✓
		{2, 4, true},  // size 2, start multiple of 2
		{4, 6, true},  // size 2, start multiple of 2
		{2, 8, false}, // size 6, bit_ceil=8, start=2 not multiple of 8
		{1, 4, false}, // size 3, bit_ceil=4, start=1 not multiple of 4
		{5, 7, false}, // size 2, start=5 not multiple of 2
		{4, 4, false}, // empty
	}
	for _, tc := range cases {
		if got := IsValid(tc.start, tc.end); got != tc.want {
			t.Errorf("IsValid(%d,%d) = %v, want %v", tc.start, tc.end, got, tc.want)
		}
	}
}

func TestFullSubtree(t *testing.T) {
	if !(Subtree{Start: 4, End: 8}).Full() {
		t.Error("[4,8) should be full")
	}
	if (Subtree{Start: 8, End: 13}).Full() {
		t.Error("[8,13) should be partial")
	}
}

// TestFindSubtreesDraftFigures pins the FindSubtrees result against the
// example in §4.5 of the draft: cover [5,13) of a 13-element tree with
// [4,8) and [8,13).
func TestFindSubtreesDraftFigures(t *testing.T) {
	got := FindSubtrees(5, 13)
	want := []Subtree{{Start: 4, End: 8}, {Start: 8, End: 13}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("FindSubtrees(5,13) = %+v, want %+v", got, want)
	}
}

// TestFindSubtreesAdditional pins extra cases derived from the draft
// example trees and the algorithm's invariants.
func TestFindSubtreesAdditional(t *testing.T) {
	cases := []struct {
		start, end uint64
		want       []Subtree
	}{
		// Single-entry case.
		{7, 8, []Subtree{{Start: 7, End: 8}}},
		// Already a power-of-two-aligned subtree of size 1.
		{0, 1, []Subtree{{Start: 0, End: 1}}},
		// Figure 10: [7,9) covered by [7,8) and [8,9).
		{7, 9, []Subtree{{Start: 7, End: 8}, {Start: 8, End: 9}}},
		// Whole tree of size 8: [0,8).
		{0, 8, []Subtree{{Start: 0, End: 4}, {Start: 4, End: 8}}},
		// New checkpoint adds three at the end of an empty tree.
		{0, 3, []Subtree{{Start: 0, End: 2}, {Start: 2, End: 3}}},
	}
	for _, tc := range cases {
		got := FindSubtrees(tc.start, tc.end)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("FindSubtrees(%d,%d) = %+v, want %+v", tc.start, tc.end, got, tc.want)
		}
	}
}

func TestFindSubtreesInvariants(t *testing.T) {
	// Spec invariants (§4.5): every result must
	//   - cover [start, end) (left.start <= start, right.end == end)
	//   - left.end == right.start (adjacent)
	//   - left be full
	//   - left.size < 2*(end-start) and right.size <= (end-start)
	for start := uint64(0); start < 32; start++ {
		for end := start + 1; end <= 64; end++ {
			subs := FindSubtrees(start, end)
			if len(subs) == 1 {
				if subs[0].Start != start || subs[0].End != end {
					t.Errorf("single subtree mismatch: got %+v for [%d,%d)", subs[0], start, end)
				}
				continue
			}
			l, r := subs[0], subs[1]
			if l.Start > start {
				t.Errorf("[%d,%d): left.start %d > start", start, end, l.Start)
			}
			if r.End != end {
				t.Errorf("[%d,%d): right.end %d != end", start, end, r.End)
			}
			if l.End != r.Start {
				t.Errorf("[%d,%d): non-adjacent %+v %+v", start, end, l, r)
			}
			if !l.Full() {
				t.Errorf("[%d,%d): left %+v not full", start, end, l)
			}
			width := end - start
			if l.Size() >= 2*width {
				t.Errorf("[%d,%d): left %+v too wide", start, end, l)
			}
			if r.Size() > width {
				t.Errorf("[%d,%d): right %+v too wide", start, end, r)
			}
			if !IsValid(l.Start, l.End) {
				t.Errorf("[%d,%d): left %+v not valid subtree", start, end, l)
			}
			if !IsValid(r.Start, r.End) {
				t.Errorf("[%d,%d): right %+v not valid subtree", start, end, r)
			}
		}
	}
}

// hashTree builds a subtree hash for [start, end) over a list of entry
// hashes (where leaves[i] is the leaf hash of index i). Used as the
// reference oracle for inclusion-proof tests.
func hashTree(leaves []Hash, start, end uint64) Hash {
	if end-start == 1 {
		return leaves[start]
	}
	// Largest power of two strictly less than end-start.
	n := end - start
	k := uint64(1) << (bits63(n - 1))
	left := hashTree(leaves, start, start+k)
	right := hashTree(leaves, start+k, end)
	return HashChildren(sha, left, right)
}

func bits63(n uint64) uint {
	return uint(63 - leadingZeros(n))
}

func leadingZeros(n uint64) uint {
	if n == 0 {
		return 64
	}
	c := uint(0)
	for n&(uint64(1)<<63) == 0 {
		n <<= 1
		c++
	}
	return c
}

// makeProof builds a subtree inclusion proof using the same procedure as
// hashTree. This is the minimal generator used to feed
// EvaluateInclusionProof in tests.
func makeProof(leaves []Hash, start, end, index uint64) []Hash {
	if end-start == 1 {
		return nil
	}
	n := end - start
	k := uint64(1) << bits63(n-1)
	if index < start+k {
		// Index is in the left subtree; sibling is the right subtree hash.
		var proof []Hash
		proof = append(proof, makeProof(leaves, start, start+k, index)...)
		proof = append(proof, hashTree(leaves, start+k, end))
		return proof
	}
	// Index is in the right subtree; sibling is the left subtree hash.
	var proof []Hash
	proof = append(proof, makeProof(leaves, start+k, end, index)...)
	proof = append(proof, hashTree(leaves, start, start+k))
	return proof
}

func TestEvaluateInclusionProof(t *testing.T) {
	// Build leaves for a 13-entry tree.
	const treeSize = 13
	leaves := make([]Hash, treeSize)
	for i := range leaves {
		leaves[i] = HashLeaf(sha, []byte{byte(i)})
	}

	// Subtree [8, 13) — Figure 6 of the draft.
	const start, end uint64 = 8, 13
	for idx := start; idx < end; idx++ {
		proof := makeProof(leaves, start, end, idx)
		got, err := EvaluateInclusionProof(sha, start, end, idx, leaves[idx], proof)
		if err != nil {
			t.Fatalf("EvaluateInclusionProof(idx=%d): %v", idx, err)
		}
		want := hashTree(leaves, start, end)
		if got != want {
			t.Errorf("idx=%d: got %x, want %x", idx, got, want)
		}
		if len(proof) != ProofLen(start, end, idx) {
			t.Errorf("idx=%d: ProofLen=%d, generator=%d", idx, ProofLen(start, end, idx), len(proof))
		}
	}
}

func TestEvaluateInclusionProofFullSubtrees(t *testing.T) {
	// Sweep small full subtrees [start, end) with end-start ∈ {1,2,4,8}.
	leaves := make([]Hash, 64)
	for i := range leaves {
		leaves[i] = HashLeaf(sha, []byte{byte(i)})
	}
	for _, size := range []uint64{1, 2, 4, 8} {
		for start := uint64(0); start+size <= 64; start += size {
			end := start + size
			for idx := start; idx < end; idx++ {
				proof := makeProof(leaves, start, end, idx)
				got, err := EvaluateInclusionProof(sha, start, end, idx, leaves[idx], proof)
				if err != nil {
					t.Fatalf("[%d,%d) idx=%d: %v", start, end, idx, err)
				}
				if got != hashTree(leaves, start, end) {
					t.Errorf("[%d,%d) idx=%d: hash mismatch", start, end, idx)
				}
			}
		}
	}
}

func TestEvaluateInclusionProofErrors(t *testing.T) {
	leaves := make([]Hash, 8)
	for i := range leaves {
		leaves[i] = HashLeaf(sha, []byte{byte(i)})
	}
	if _, err := EvaluateInclusionProof(sha, 1, 4, 1, leaves[1], nil); err == nil {
		t.Error("expected error for invalid subtree")
	}
	if _, err := EvaluateInclusionProof(sha, 0, 8, 9, leaves[0], nil); err == nil {
		t.Error("expected error for out-of-range index")
	}
	// Too-short proof.
	if _, err := EvaluateInclusionProof(sha, 0, 8, 0, leaves[0], nil); err == nil {
		t.Error("expected error for too-short proof")
	}
}
