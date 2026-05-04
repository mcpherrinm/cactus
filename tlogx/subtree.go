// Package tlogx implements the subtree primitives from §4 of
// draft-ietf-plants-merkle-tree-certs-03.
//
// It complements golang.org/x/mod/sumdb/tlog (used elsewhere as the
// authoritative tile/Merkle implementation) with the few operations the
// upstream package does not provide:
//
//   - FindSubtrees: §4.5, the up-to-two subtrees that cover [start, end).
//   - EvaluateInclusionProof: §4.3.2, evaluation of a subtree inclusion proof.
//   - HashChildren: the leaf/interior hash with §2.1.1-of-RFC9162 prefixes.
//
// All functions are pure; storage and signing are layered on top.
package tlogx

import (
	"errors"
	"fmt"
	"math/bits"
)

// HashSize is the SHA-256 output size, which is the only hash the
// cactus log uses today.
const HashSize = 32

// Hash is a single Merkle tree hash value.
type Hash [HashSize]byte

// Subtree describes a [start, end) range plus its hash. start and end
// MUST satisfy the validity constraint from §4.1: 0 <= start < end and
// start is a multiple of BIT_CEIL(end - start).
type Subtree struct {
	Start, End uint64
	Hash       Hash
}

// Size returns end - start.
func (s Subtree) Size() uint64 { return s.End - s.Start }

// Full reports whether end-start is a power of two (§4.1).
func (s Subtree) Full() bool {
	n := s.Size()
	return n != 0 && n&(n-1) == 0
}

// IsValid reports whether [start, end) is a valid subtree per §4.1:
// start < end and start is a multiple of BIT_CEIL(end - start).
func IsValid(start, end uint64) bool {
	if start >= end {
		return false
	}
	size := end - start
	cap := bitCeil(size)
	return start%cap == 0
}

// bitCeil returns the smallest power of 2 that is >= n. bitCeil(0) is 1
// (the natural extension; we never pass 0 in valid inputs).
func bitCeil(n uint64) uint64 {
	if n == 0 {
		return 1
	}
	if n&(n-1) == 0 {
		return n
	}
	return uint64(1) << bits.Len64(n-1)
}

// FindSubtrees implements the §4.5 algorithm: returns the one or two
// subtree intervals that efficiently cover [start, end).
//
// Each returned interval is (start, end) and it is the caller's job to
// look up the hash. Calling code that only needs the intervals can
// ignore the Hash field of Subtree.
func FindSubtrees(start, end uint64) []Subtree {
	if start >= end {
		panic(fmt.Sprintf("tlogx: FindSubtrees requires start<end, got [%d,%d)", start, end))
	}
	if end-start == 1 {
		return []Subtree{{Start: start, End: end}}
	}
	last := end - 1
	// `split` = highest bit position where start and last differ.
	split := bits.Len64(start^last) - 1
	mask := uint64(1)<<split - 1
	mid := last &^ mask

	// `left_split` = bit_width of the most significant zero bit of start
	// within the low `split` bits. Equivalently, bit_length of (~start &
	// mask) when interpreted within `split` bits.
	leftSplit := bits.Len64(^start & mask)
	leftStart := start &^ ((uint64(1) << leftSplit) - 1)
	return []Subtree{
		{Start: leftStart, End: mid},
		{Start: mid, End: end},
	}
}

// HashLeaf returns the Merkle tree hash of a single entry per
// §2.1.1 of RFC 9162: HASH(0x00 || entry).
func HashLeaf(hash func([]byte) Hash, entry []byte) Hash {
	buf := make([]byte, 1+len(entry))
	buf[0] = 0x00
	copy(buf[1:], entry)
	return hash(buf)
}

// HashChildren returns the interior node hash from RFC 9162:
// HASH(0x01 || left || right).
func HashChildren(hash func([]byte) Hash, left, right Hash) Hash {
	var buf [1 + 2*HashSize]byte
	buf[0] = 0x01
	copy(buf[1:], left[:])
	copy(buf[1+HashSize:], right[:])
	return hash(buf[:])
}

// EvaluateInclusionProof implements §4.3.2: given a subtree inclusion
// proof, returns the reconstructed subtree hash. The caller is
// responsible for checking [start, end) is a valid subtree and that
// start <= index < end.
//
// hash is the underlying compression function (typically a closure over
// SHA-256). entryHash is the leaf hash MTH({d[index]}).
func EvaluateInclusionProof(
	hash func([]byte) Hash,
	start, end, index uint64,
	entryHash Hash,
	proof []Hash,
) (Hash, error) {
	if !IsValid(start, end) {
		return Hash{}, fmt.Errorf("tlogx: invalid subtree [%d,%d)", start, end)
	}
	if index < start || index >= end {
		return Hash{}, fmt.Errorf("tlogx: index %d outside subtree [%d,%d)", index, start, end)
	}
	fn := index - start
	sn := end - start - 1
	r := entryHash

	for _, p := range proof {
		if sn == 0 {
			return Hash{}, errors.New("tlogx: proof has extra elements")
		}
		if fn&1 == 1 || fn == sn {
			r = HashChildren(hash, p, r)
			for fn&1 == 0 && sn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = HashChildren(hash, r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return Hash{}, errors.New("tlogx: proof too short")
	}
	return r, nil
}

// ProofLen returns the number of nodes that a valid subtree inclusion
// proof must contain for entry `index` of subtree [start, end), per
// Appendix B.2.
func ProofLen(start, end, index uint64) int {
	fn := index - start
	sn := end - start - 1
	l1 := bits.Len64(fn ^ sn)
	l2 := bits.OnesCount64(fn >> l1)
	return l1 + l2
}
