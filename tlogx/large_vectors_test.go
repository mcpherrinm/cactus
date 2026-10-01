package tlogx

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

// Appendix C.2 of draft-ietf-plants-merkle-tree-certs-07 supplies test
// vectors for trees far larger than the exhaustive C.1 vectors reach, up
// to 2^64-1 elements, to exercise overflow handling. That matters most to
// a relying party, which acts on untrusted tree sizes. The inclusion and
// consistency proof vectors live outside the draft, in the
// ietf-plants-wg/merkle-tree-certs repository; testdata/ holds copies of
// demo/large_inclusion_proofs.json and demo/large_consistency_proofs.json
// from commit 651dd62.

// TestAppendixC21SubtreeValidity pins the §C.2.1 list. The cases with
// end > 2^63 are the ones where BIT_CEIL(end - start) would overflow.
func TestAppendixC21SubtreeValidity(t *testing.T) {
	const p = uint64(1)
	cases := []struct {
		start, end uint64
		want       bool
	}{
		{0, p<<47 + 1, true},
		{0, p<<48 - 1, true},
		{0, p<<62 + 1, true},
		{0, p<<63 - 1, true},
		{0, p<<63 + 1, true},
		{0, ^uint64(0), true},
		{p << 46, p<<47 + 1, false},
		{p << 46, p<<48 - 1, false},
		{p << 61, p<<62 + 1, false},
		{p << 61, p<<63 - 1, false},
		{p << 62, p<<63 + 1, false},
		{p << 62, ^uint64(0), false},
	}
	for _, tc := range cases {
		if got := IsValid(tc.start, tc.end); got != tc.want {
			t.Errorf("IsValid(%#x, %#x) = %v, want %v", tc.start, tc.end, got, tc.want)
		}
	}
}

// TestAppendixC24EfficientCoveringSubtrees pins the §C.2.4 samples.
func TestAppendixC24EfficientCoveringSubtrees(t *testing.T) {
	cases := []struct {
		start, end uint64
		want       [2]Subtree
	}{
		{0x0, 0x800000000000, [2]Subtree{{Start: 0x0, End: 0x400000000000}, {Start: 0x400000000000, End: 0x800000000000}}},
		{0x500000000000, 0xd00000000000, [2]Subtree{{Start: 0x400000000000, End: 0x800000000000}, {Start: 0x800000000000, End: 0xd00000000000}}},
		{0x7fffffffffff, 0x800000000001, [2]Subtree{{Start: 0x7fffffffffff, End: 0x800000000000}, {Start: 0x800000000000, End: 0x800000000001}}},
		{0xfffffffffffe, 0xffffffffffff, [2]Subtree{{Start: 0xfffffffffffe, End: 0xffffffffffff}, {Start: 0xffffffffffff, End: 0xffffffffffff}}},
		{0xffffffffffff, 0xffffffffffff, [2]Subtree{{Start: 0xffffffffffff, End: 0xffffffffffff}, {Start: 0xffffffffffff, End: 0xffffffffffff}}},
		{0x0, 0x4000000000000000, [2]Subtree{{Start: 0x0, End: 0x2000000000000000}, {Start: 0x2000000000000000, End: 0x4000000000000000}}},
		{0x2800000000000000, 0x6800000000000000, [2]Subtree{{Start: 0x2000000000000000, End: 0x4000000000000000}, {Start: 0x4000000000000000, End: 0x6800000000000000}}},
		{0x3fffffffffffffff, 0x4000000000000001, [2]Subtree{{Start: 0x3fffffffffffffff, End: 0x4000000000000000}, {Start: 0x4000000000000000, End: 0x4000000000000001}}},
		{0x7ffffffffffffffe, 0x7fffffffffffffff, [2]Subtree{{Start: 0x7ffffffffffffffe, End: 0x7fffffffffffffff}, {Start: 0x7fffffffffffffff, End: 0x7fffffffffffffff}}},
		{0x7fffffffffffffff, 0x7fffffffffffffff, [2]Subtree{{Start: 0x7fffffffffffffff, End: 0x7fffffffffffffff}, {Start: 0x7fffffffffffffff, End: 0x7fffffffffffffff}}},
		{0x0, 0x8000000000000000, [2]Subtree{{Start: 0x0, End: 0x4000000000000000}, {Start: 0x4000000000000000, End: 0x8000000000000000}}},
		{0x5000000000000000, 0xd000000000000000, [2]Subtree{{Start: 0x4000000000000000, End: 0x8000000000000000}, {Start: 0x8000000000000000, End: 0xd000000000000000}}},
		{0x7fffffffffffffff, 0x8000000000000001, [2]Subtree{{Start: 0x7fffffffffffffff, End: 0x8000000000000000}, {Start: 0x8000000000000000, End: 0x8000000000000001}}},
		{0xfffffffffffffffe, 0xffffffffffffffff, [2]Subtree{{Start: 0xfffffffffffffffe, End: 0xffffffffffffffff}, {Start: 0xffffffffffffffff, End: 0xffffffffffffffff}}},
		{0xffffffffffffffff, 0xffffffffffffffff, [2]Subtree{{Start: 0xffffffffffffffff, End: 0xffffffffffffffff}, {Start: 0xffffffffffffffff, End: 0xffffffffffffffff}}},
	}
	for _, tc := range cases {
		if got := FindSubtrees(tc.start, tc.end); got != tc.want {
			t.Errorf("FindSubtrees(%#x, %#x) = %#v, want %#v", tc.start, tc.end, got, tc.want)
		}
	}
}

// decimalUint64 is a uint64 the vector files encode as a JSON string,
// since the values exceed what a JSON number holds exactly.
type decimalUint64 uint64

func (d *decimalUint64) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := strconv.ParseUint(s, 10, 64)
	*d = decimalUint64(v)
	return err
}

// proofHashes splits a concatenated proof into hashes.
func proofHashes(t *testing.T, b []byte) []Hash {
	t.Helper()
	if len(b)%HashSize != 0 {
		t.Fatalf("proof length %d is not a multiple of %d", len(b), HashSize)
	}
	out := make([]Hash, len(b)/HashSize)
	for i := range out {
		copy(out[i][:], b[i*HashSize:])
	}
	return out
}

func readVectors(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

// TestAppendixC22LargeInclusionProofs evaluates every §C.2.2 inclusion
// proof, and checks that truncating or extending it by a hash fails.
func TestAppendixC22LargeInclusionProofs(t *testing.T) {
	var vectors []struct {
		Index, Start, End decimalUint64
		EntryHash         []byte
		SubtreeHash       []byte
		Proof             []byte
	}
	readVectors(t, "large_inclusion_proofs.json", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vectors {
		start, end, index := uint64(v.Start), uint64(v.End), uint64(v.Index)
		proof := proofHashes(t, v.Proof)
		got, err := EvaluateInclusionProof(sha, start, end, index, Hash(v.EntryHash), proof)
		if err != nil {
			t.Errorf("EvaluateInclusionProof(%#x in [%#x, %#x)): %v", index, start, end, err)
			continue
		}
		if got != Hash(v.SubtreeHash) {
			t.Errorf("EvaluateInclusionProof(%#x in [%#x, %#x)) = %x, want %x", index, start, end, got, v.SubtreeHash)
		}
		if len(proof) > 0 {
			if _, err := EvaluateInclusionProof(sha, start, end, index, Hash(v.EntryHash), proof[:len(proof)-1]); err == nil {
				t.Errorf("truncated proof for %#x in [%#x, %#x) evaluated", index, start, end)
			}
		}
		extended := append(append([]Hash(nil), proof...), Hash{0x42})
		if _, err := EvaluateInclusionProof(sha, start, end, index, Hash(v.EntryHash), extended); err == nil {
			t.Errorf("extended proof for %#x in [%#x, %#x) evaluated", index, start, end)
		}
	}
}

// TestAppendixC23LargeConsistencyProofs verifies every §C.2.3
// consistency proof, and checks the negative cases from §C.1.3.
func TestAppendixC23LargeConsistencyProofs(t *testing.T) {
	var vectors []struct {
		Start, End, TreeSize decimalUint64
		SubtreeHash          []byte
		TreeHash             []byte
		Proof                []byte
	}
	readVectors(t, "large_consistency_proofs.json", &vectors)
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	flip := func(h Hash) Hash { h[0] ^= 1; return h }
	for _, v := range vectors {
		start, end, n := uint64(v.Start), uint64(v.End), uint64(v.TreeSize)
		proof := proofHashes(t, v.Proof)
		node, root := Hash(v.SubtreeHash), Hash(v.TreeHash)
		verify := func(p []Hash, node, root Hash) error {
			return VerifyConsistencyProof(sha, start, end, n, p, node, root)
		}
		if err := verify(proof, node, root); err != nil {
			t.Errorf("VerifyConsistencyProof([%#x, %#x) in %#x): %v", start, end, n, err)
			continue
		}
		if len(proof) > 0 && verify(proof[:len(proof)-1], node, root) == nil {
			t.Errorf("truncated proof for [%#x, %#x) in %#x verified", start, end, n)
		}
		if verify(append(append([]Hash(nil), proof...), Hash{0x42}), node, root) == nil {
			t.Errorf("extended proof for [%#x, %#x) in %#x verified", start, end, n)
		}
		if verify(proof, flip(node), root) == nil {
			t.Errorf("proof for [%#x, %#x) in %#x verified a flipped subtree hash", start, end, n)
		}
		if start != end && verify(proof, node, flip(root)) == nil {
			t.Errorf("proof for [%#x, %#x) in %#x verified a flipped tree hash", start, end, n)
		}
	}
}
