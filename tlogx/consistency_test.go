package tlogx

import "testing"

// makeLeaves builds n unique leaf hashes for a fake tree.
func makeLeaves(n uint64) []Hash {
	out := make([]Hash, n)
	for i := uint64(0); i < n; i++ {
		out[i] = HashLeaf(sha, []byte{byte(i), byte(i >> 8)})
	}
	return out
}

// rootOf computes MTH(D[0:n]) directly.
func rootOf(leaves []Hash, n uint64) Hash {
	if n == 1 {
		return leaves[0]
	}
	k := uint64(1) << (bits63(n - 1))
	left := rootOf(leaves[:k], k)
	right := rootOf(leaves[k:n], n-k)
	return HashChildren(sha, left, right)
}

func subtreeOf(leaves []Hash, start, end uint64) Hash {
	if end-start == 1 {
		return leaves[start]
	}
	size := end - start
	k := uint64(1) << (bits63(size - 1))
	left := subtreeOf(leaves, start, start+k)
	right := subtreeOf(leaves, start+k, end)
	return HashChildren(sha, left, right)
}

func TestConsistencyProofRoundTrip(t *testing.T) {
	cases := []struct {
		start, end, n uint64
	}{
		// Whole-tree base case.
		{0, 8, 8},
		// Subtree directly contained.
		{4, 8, 13},
		// Subtree not directly contained.
		{8, 13, 14},
		// §4.4.2 example: [4,8) in tree of 14.
		{4, 8, 14},
		// §B.3 example: [0,6) in tree of 8.
		{0, 6, 8},
		// §B.3 example: [0,6) in tree of 7.
		{0, 6, 7},
		// Random-ish.
		{16, 24, 100},
		{0, 32, 32},
		{32, 48, 50},
	}

	for _, tc := range cases {
		leaves := makeLeaves(tc.n)
		nodeHash := subtreeOf(leaves, tc.start, tc.end)
		rootHash := rootOf(leaves, tc.n)
		proof, err := GenerateConsistencyProof(sha, tc.start, tc.end, tc.n,
			func(i uint64) (Hash, error) { return leaves[i], nil })
		if err != nil {
			t.Errorf("Generate(%d,%d,%d): %v", tc.start, tc.end, tc.n, err)
			continue
		}
		if err := VerifyConsistencyProof(sha, tc.start, tc.end, tc.n, proof, nodeHash, rootHash); err != nil {
			t.Errorf("Verify(%d,%d,%d): %v", tc.start, tc.end, tc.n, err)
		}
	}
}

func TestConsistencyProofRejectsBadHash(t *testing.T) {
	const start, end, n = 4, 8, 14
	leaves := makeLeaves(n)
	nodeHash := subtreeOf(leaves, start, end)
	rootHash := rootOf(leaves, n)
	proof, err := GenerateConsistencyProof(sha, start, end, n,
		func(i uint64) (Hash, error) { return leaves[i], nil })
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the rootHash.
	bad := rootHash
	bad[0] ^= 1
	if err := VerifyConsistencyProof(sha, start, end, n, proof, nodeHash, bad); err == nil {
		t.Error("expected failure with tampered root_hash")
	}

	// Tamper with the subtree hash.
	bad2 := nodeHash
	bad2[0] ^= 1
	if err := VerifyConsistencyProof(sha, start, end, n, proof, bad2, rootHash); err == nil {
		t.Error("expected failure with tampered node_hash")
	}
}

func TestConsistencyProofValidityChecks(t *testing.T) {
	// Invalid subtree (start not multiple of bit_ceil(end-start)).
	if err := VerifyConsistencyProof(sha, 1, 4, 8, nil, Hash{}, Hash{}); err == nil {
		t.Error("expected error for invalid subtree")
	}
	// end > n.
	if err := VerifyConsistencyProof(sha, 0, 8, 4, nil, Hash{}, Hash{}); err == nil {
		t.Error("expected error for end > n")
	}
}
