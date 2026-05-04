package tlogx

import (
	"crypto/sha256"
	"fmt"
	"hash"
	"math/bits"

	"golang.org/x/mod/sumdb/tlog"
)

// sha256New is a typed alias kept here to avoid pulling crypto/sha256
// into every file that wants the default hash.
var sha256New = func() hash.Hash { return sha256.New() }

// GenerateInclusionProof builds a §4.3 subtree inclusion proof for
// entry `index` within subtree [start, end). The hash reader must
// hold every stored hash up through the subtree.
//
// This is the generation counterpart to EvaluateInclusionProof: feed
// the result back into EvaluateInclusionProof and you should get the
// subtree hash.
func GenerateInclusionProof(start, end, index uint64, hr tlog.HashReader) ([]Hash, error) {
	if !IsValid(start, end) {
		return nil, fmt.Errorf("tlogx: invalid subtree [%d,%d)", start, end)
	}
	if index < start || index >= end {
		return nil, fmt.Errorf("tlogx: index %d outside [%d,%d)", index, start, end)
	}
	var proof []Hash
	for end-start > 1 {
		k := largestPowerOfTwoLT(end - start)
		mid := start + k
		if index < mid {
			sib, err := subtreeHashFromHR(mid, end, hr)
			if err != nil {
				return nil, err
			}
			proof = append(proof, sib)
			end = mid
		} else {
			sib, err := subtreeHashFromHR(start, mid, hr)
			if err != nil {
				return nil, err
			}
			proof = append(proof, sib)
			start = mid
		}
	}
	// Reverse: above we emit root-down; EvaluateInclusionProof expects leaf-up.
	for i, j := 0, len(proof)-1; i < j; i, j = i+1, j-1 {
		proof[i], proof[j] = proof[j], proof[i]
	}
	return proof, nil
}

// SubtreeHash returns the Merkle subtree hash for [start, end) using
// a tlog.HashReader. For a [start, end) that is a complete
// power-of-two-aligned subtree, this is one ReadHashes call;
// otherwise it recursively combines two halves.
func SubtreeHash(start, end uint64, hr tlog.HashReader) (Hash, error) {
	return subtreeHashFromHR(start, end, hr)
}

func largestPowerOfTwoLT(n uint64) uint64 {
	if n <= 1 {
		return 0
	}
	return uint64(1) << (bits.Len64(n-1) - 1)
}

func subtreeHashFromHR(start, end uint64, hr tlog.HashReader) (Hash, error) {
	if start >= end {
		return Hash{}, fmt.Errorf("empty subtree [%d,%d)", start, end)
	}
	width := end - start
	// Power-of-two-aligned subtree: exactly one stored hash.
	if width&(width-1) == 0 && start%width == 0 {
		level := bits.Len64(width) - 1
		n := start / width
		idx := tlog.StoredHashIndex(level, int64(n))
		hs, err := hr.ReadHashes([]int64{idx})
		if err != nil {
			return Hash{}, err
		}
		return Hash(hs[0]), nil
	}
	k := largestPowerOfTwoLT(width)
	mid := start + k
	left, err := subtreeHashFromHR(start, mid, hr)
	if err != nil {
		return Hash{}, err
	}
	right, err := subtreeHashFromHR(mid, end, hr)
	if err != nil {
		return Hash{}, err
	}
	// Use SHA-256 directly since callers always use it.
	return HashChildren(sha256Hash, left, right), nil
}

// sha256Hash is the default hash for tlogx callers that want one.
var sha256Hash = func(b []byte) Hash {
	var out Hash
	h := sha256New()
	h.Write(b)
	copy(out[:], h.Sum(nil))
	return out
}
