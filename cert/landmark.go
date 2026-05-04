package cert

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"

	"github.com/letsencrypt/cactus/tlogx"
)

// BuildLandmarkRelativeCert builds a landmark-relative certificate
// (§6.3.3) from an existing standalone cert.
//
// Per §6.3.3 the landmark-relative cert has the same TBSCertificate
// fields as the standalone cert; only the signatureValue changes:
// the new MTCProof points to the chosen landmark subtree, includes
// the §4.3 inclusion proof from the entry up to that subtree, and
// has an empty signatures slice.
//
// Inputs:
//   - originalDER: the standalone cert's DER (we reuse its TBS verbatim)
//   - logID: the issuance log's trust anchor ID (§5.2)
//   - subtree: the chosen landmark subtree's [start, end)
//   - subtreeHash: the Merkle hash of that subtree
//   - inclusionProof: §4.3 inclusion proof from the entry (cert serial)
//     to the subtree
//
// The resulting cert is *exactly* like the standalone cert except for
// signatureValue. A test should diff the two and confirm only that
// field differs.
func BuildLandmarkRelativeCert(
	originalDER []byte,
	logID TrustAnchorID,
	subtree MTCSubtree,
	inclusionProof []tlogx.Hash,
) ([]byte, error) {
	if subtree.LogID == nil {
		subtree.LogID = logID
	}
	tbs, sigAlg, _, err := SplitCertificate(originalDER)
	if err != nil {
		return nil, fmt.Errorf("cert: split standalone: %w", err)
	}

	proof := &MTCProof{
		Start:          subtree.Start,
		End:            subtree.End,
		InclusionProof: inclusionProof,
		Signatures:     nil, // §6.3.3: no signatures
	}
	proofBytes, err := proof.MarshalTLS()
	if err != nil {
		return nil, fmt.Errorf("cert: marshal landmark proof: %w", err)
	}

	// Reassemble Certificate { tbs, sigAlg, BIT STRING(proofBytes) }.
	var outer cryptobyte.Builder
	outer.AddBytes(tbs)
	outer.AddBytes(sigAlg)
	outer.AddASN1BitString(proofBytes)
	outerBody, err := outer.Bytes()
	if err != nil {
		return nil, err
	}
	return wrapDERSequence(outerBody), nil
}

// wrapDERSequence wraps body in an outer DER SEQUENCE with the same
// minimum-form length encoding rules used by entry.go.
func wrapDERSequence(body []byte) []byte {
	out := make([]byte, 0, 1+5+len(body))
	out = append(out, 0x30)
	out = appendDERLen(out, len(body))
	return append(out, body...)
}

func appendDERLen(b []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(b, byte(n))
	case n <= 0xff:
		return append(b, 0x81, byte(n))
	case n <= 0xffff:
		return append(b, 0x82, byte(n>>8), byte(n))
	case n <= 0xffffff:
		return append(b, 0x83, byte(n>>16), byte(n>>8), byte(n))
	default:
		return append(b, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

// ErrSubtreeMismatch is returned when the inclusion proof doesn't
// reconstruct the expected subtree hash. Callers can use this to
// distinguish "your inputs are inconsistent" from other errors.
var ErrSubtreeMismatch = errors.New("cert: inclusion proof did not reconstruct subtree hash")
