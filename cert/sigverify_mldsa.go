//go:build mldsa

// ML-DSA cosignature verification, gated behind the `mldsa` build tag —
// the verifier-side counterpart of signer/mldsa.go. We use
// cloudflare/circl as the reference implementation until Go's
// crypto/mldsa lands; the seam is the mldsaVerify hook installed here.
//
// To build a relying party / verifier with ML-DSA support:
//
//	go build -tags mldsa ./...
//	go test  -tags mldsa ./cert/...
//
// draft-04 §5.3.3 / RFC 9881 §3: Merkle Tree Certificate cosignatures use
// pure ML-DSA (FIPS 204) with an empty context string.

package cert

import (
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func init() { mldsaVerify = verifyMLDSA }

// verifyMLDSA verifies a pure ML-DSA signature with an empty context. pub
// is the raw FIPS 204 public key as extracted from the cosigner SPKI by
// cosignerKeyFromSPKI.
func verifyMLDSA(alg SignatureAlgorithm, pub, msg, sig []byte) error {
	switch alg {
	case AlgMLDSA44:
		var pk mldsa44.PublicKey
		if err := pk.UnmarshalBinary(pub); err != nil {
			return fmt.Errorf("cert: parse ML-DSA-44 key: %w", err)
		}
		if !mldsa44.Verify(&pk, msg, nil, sig) {
			return fmt.Errorf("cert: ML-DSA-44 signature did not verify")
		}
		return nil
	case AlgMLDSA65:
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(pub); err != nil {
			return fmt.Errorf("cert: parse ML-DSA-65 key: %w", err)
		}
		if !mldsa65.Verify(&pk, msg, nil, sig) {
			return fmt.Errorf("cert: ML-DSA-65 signature did not verify")
		}
		return nil
	case AlgMLDSA87:
		var pk mldsa87.PublicKey
		if err := pk.UnmarshalBinary(pub); err != nil {
			return fmt.Errorf("cert: parse ML-DSA-87 key: %w", err)
		}
		if !mldsa87.Verify(&pk, msg, nil, sig) {
			return fmt.Errorf("cert: ML-DSA-87 signature did not verify")
		}
		return nil
	default:
		return fmt.Errorf("cert: verifyMLDSA called with non-ML-DSA algorithm 0x%04x", uint16(alg))
	}
}
