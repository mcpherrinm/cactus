//go:build go1.27

// ML-DSA cosignature verification — the verifier-side counterpart of
// signer/mldsa.go, compiled in automatically on Go 1.27+ (the `go1.27`
// build constraint), where Go's built-in crypto/mldsa (FIPS 204) is
// available. Until Go 1.27 is released a gotip 1.27-devel toolchain
// satisfies the constraint:
//
//	gotip build ./...
//	gotip test  ./cert/...
//
// draft-04 §5.3.3 / RFC 9881 §3: Merkle Tree Certificate cosignatures use
// pure ML-DSA (FIPS 204) with an empty context string.

package cert

import (
	"crypto/mldsa"
	"fmt"
)

func init() { mldsaVerify = verifyMLDSA }

// verifyMLDSA verifies a pure ML-DSA signature with an empty context. pub
// is the raw FIPS 204 public key as extracted from the cosigner SPKI by
// cosignerKeyFromSPKI.
func verifyMLDSA(alg SignatureAlgorithm, pub, msg, sig []byte) error {
	var params mldsa.Parameters
	switch alg {
	case AlgMLDSA44:
		params = mldsa.MLDSA44()
	case AlgMLDSA65:
		params = mldsa.MLDSA65()
	case AlgMLDSA87:
		params = mldsa.MLDSA87()
	default:
		return fmt.Errorf("cert: verifyMLDSA called with non-ML-DSA algorithm 0x%04x", uint16(alg))
	}
	pk, err := mldsa.NewPublicKey(params, pub)
	if err != nil {
		return fmt.Errorf("cert: parse %s key: %w", params, err)
	}
	// A nil Options verifies against the empty context (§5.3.3).
	if err := mldsa.Verify(pk, msg, sig, nil); err != nil {
		return fmt.Errorf("cert: %s signature did not verify: %w", params, err)
	}
	return nil
}
