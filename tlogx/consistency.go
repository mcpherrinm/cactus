package tlogx

import (
	"errors"
	"fmt"
	"math/bits"
)

// VerifyConsistencyProof implements §4.4.3: given a Merkle Tree of n
// elements, a subtree [start, end), a consistency proof, the subtree's
// hash node_hash, and the full tree's root_hash, the procedure either
// succeeds (proof is valid) or returns an error.
func VerifyConsistencyProof(
	hash func([]byte) Hash,
	start, end, n uint64,
	proof []Hash,
	nodeHash, rootHash Hash,
) error {
	// Step 1: validity checks.
	if !IsValid(start, end) {
		return fmt.Errorf("tlogx: invalid subtree [%d,%d)", start, end)
	}
	if end > n {
		return fmt.Errorf("tlogx: end %d > tree size %d", end, n)
	}

	// Step 2: initialize fn=start, sn=end-1, tn=n-1.
	fn := start
	sn := end - 1
	tn := n - 1

	// Step 3 & 4.
	if sn == tn {
		// fn == sn after some right-shifts; equalize.
		for fn != sn {
			fn >>= 1
			sn >>= 1
			tn >>= 1
		}
	} else {
		for fn != sn && sn&1 != 0 {
			fn >>= 1
			sn >>= 1
			tn >>= 1
		}
	}

	// Steps 5-6: initialize fr, sr.
	var fr, sr Hash
	if fn == sn {
		// node_hash starts the reconstruction; consistency proof omits
		// it (§B.4 first optimization).
		fr = nodeHash
		sr = nodeHash
	} else {
		if len(proof) == 0 {
			return errors.New("tlogx: empty proof for incomplete subtree start")
		}
		fr = proof[0]
		sr = proof[0]
		proof = proof[1:]
	}

	// Step 7: incorporate remaining proof entries.
	for _, c := range proof {
		if tn == 0 {
			return errors.New("tlogx: proof has extra elements (tn=0)")
		}
		if sn&1 != 0 || sn == tn {
			if fn < sn {
				fr = HashChildren(hash, c, fr)
			}
			sr = HashChildren(hash, c, sr)
			for sn&1 == 0 && tn != 0 {
				fn >>= 1
				sn >>= 1
				tn >>= 1
			}
		} else {
			sr = HashChildren(hash, sr, c)
		}
		fn >>= 1
		sn >>= 1
		tn >>= 1
	}

	// Step 8: compare.
	if tn != 0 {
		return errors.New("tlogx: proof too short (tn != 0 at end)")
	}
	if fr != nodeHash {
		return fmt.Errorf("tlogx: reconstructed subtree hash %x != node_hash %x", fr[:8], nodeHash[:8])
	}
	if sr != rootHash {
		return fmt.Errorf("tlogx: reconstructed root hash %x != root_hash %x", sr[:8], rootHash[:8])
	}
	return nil
}

// GenerateConsistencyProof implements §4.4.1's SUBTREE_PROOF: builds
// the consistency proof for [start, end) within a tree of n elements,
// using leafHashFn(i) to retrieve the i-th leaf hash.
//
// The simplest correct implementation here just rebuilds subtrees by
// recursion; for a test server the cost is acceptable. Callers that can
// read stored interior hashes (e.g. from tiles) should prefer
// GenerateConsistencyProofFromNodes, which reads O(log n) node hashes
// instead of hashing O(n) leaves.
func GenerateConsistencyProof(
	hash func([]byte) Hash,
	start, end, n uint64,
	leafHash func(uint64) (Hash, error),
) ([]Hash, error) {
	rangeFn := func(lo, hi uint64) (Hash, error) {
		return computeRange(hash, lo, hi, leafHash)
	}
	return generateConsistencyProof(start, end, n, rangeFn)
}

// GenerateConsistencyProofFromNodes is GenerateConsistencyProof reading
// stored interior node hashes instead of leaves. nodeHash(level, index)
// must return the Merkle tree hash of the complete subtree
// [index<<level, (index+1)<<level) — the node addressing scheme of
// tlog.StoredHashIndex — so a proof costs O(log n) node reads instead of
// O(n) leaf hashes. That is what makes proof generation over a *remote*
// tree practical: every read maps to a (cached, authenticated) hash-tile
// lookup rather than a replay of the whole log.
func GenerateConsistencyProofFromNodes(
	hash func([]byte) Hash,
	start, end, n uint64,
	nodeHash func(level int, index uint64) (Hash, error),
) ([]Hash, error) {
	var rangeFn func(lo, hi uint64) (Hash, error)
	rangeFn = func(lo, hi uint64) (Hash, error) {
		size := hi - lo
		if size == 0 {
			return Hash{}, errors.New("tlogx: empty range")
		}
		// A complete, aligned range is exactly a stored tree node.
		if size&(size-1) == 0 && lo%size == 0 {
			level := bits.TrailingZeros64(size)
			return nodeHash(level, lo>>level)
		}
		// Otherwise split per the RFC 6962 MTH recursion: k is the
		// largest power of two strictly smaller than the range size.
		k := uint64(1) << (bits.Len64(size-1) - 1)
		left, err := rangeFn(lo, lo+k)
		if err != nil {
			return Hash{}, err
		}
		right, err := rangeFn(lo+k, hi)
		if err != nil {
			return Hash{}, err
		}
		return HashChildren(hash, left, right), nil
	}
	return generateConsistencyProof(start, end, n, rangeFn)
}

// generateConsistencyProof is the shared §4.4.1 SUBTREE_PROOF skeleton;
// rangeFn(lo, hi) must return MTH(D[lo:hi]).
func generateConsistencyProof(
	start, end, n uint64,
	rangeFn func(lo, hi uint64) (Hash, error),
) ([]Hash, error) {
	if !IsValid(start, end) {
		return nil, fmt.Errorf("tlogx: invalid subtree [%d,%d)", start, end)
	}
	if end > n {
		return nil, fmt.Errorf("tlogx: end %d > tree size %d", end, n)
	}
	if start == 0 && end == n {
		return nil, nil // §4.4.1 base case
	}
	return subtreeSubproof(start, end, 0, n, true, rangeFn)
}

// subtreeSubproof is the SUBTREE_SUBPROOF helper from §4.4.1, expressed
// with absolute indices throughout. Conceptually, we are producing the
// consistency proof for [start, end) within D[lo:hi]. The `known` flag
// records whether the verifier already has MTH(D[start:end])
// (true at the outermost call).
func subtreeSubproof(
	start, end, lo, hi uint64,
	known bool,
	rangeFn func(lo, hi uint64) (Hash, error),
) ([]Hash, error) {
	// Base case: the current range D[lo:hi] is exactly the subtree.
	if start == lo && end == hi {
		if known {
			return nil, nil
		}
		h, err := rangeFn(lo, hi)
		if err != nil {
			return nil, err
		}
		return []Hash{h}, nil
	}

	size := hi - lo
	k := uint64(1) << (bits.Len64(size-1) - 1)
	mid := lo + k

	switch {
	case end <= mid:
		// Subtree fits entirely in left half D[lo:mid].
		left, err := subtreeSubproof(start, end, lo, mid, known, rangeFn)
		if err != nil {
			return nil, err
		}
		rightHash, err := rangeFn(mid, hi)
		if err != nil {
			return nil, err
		}
		return append(left, rightHash), nil

	case mid <= start:
		// Subtree fits entirely in right half D[mid:hi].
		right, err := subtreeSubproof(start, end, mid, hi, known, rangeFn)
		if err != nil {
			return nil, err
		}
		leftHash, err := rangeFn(lo, mid)
		if err != nil {
			return nil, err
		}
		return append(right, leftHash), nil

	default:
		// start < mid < end. §4.4.1 states this implies start is at the
		// left edge of the current range — i.e. start == lo.
		if start != lo {
			return nil, errors.New("tlogx: internal: subtree spans pivot but start != lo")
		}
		// Recurse looking for the right portion [mid, end), which is a
		// strict subtree of D[mid:hi] — and one the verifier does NOT
		// already know.
		cross, err := subtreeSubproof(mid, end, mid, hi, false, rangeFn)
		if err != nil {
			return nil, err
		}
		leftHash, err := rangeFn(lo, mid)
		if err != nil {
			return nil, err
		}
		return append(cross, leftHash), nil
	}
}

// computeRange returns MTH(D[lo:hi]) by hashing leaves and applying
// HashChildren recursively. O(hi-lo) hash operations.
func computeRange(
	hash func([]byte) Hash,
	lo, hi uint64,
	leafHash func(uint64) (Hash, error),
) (Hash, error) {
	if hi-lo == 1 {
		return leafHash(lo)
	}
	size := hi - lo
	k := uint64(1) << (bits.Len64(size-1) - 1)
	left, err := computeRange(hash, lo, lo+k, leafHash)
	if err != nil {
		return Hash{}, err
	}
	right, err := computeRange(hash, lo+k, hi, leafHash)
	if err != nil {
		return Hash{}, err
	}
	return HashChildren(hash, left, right), nil
}
