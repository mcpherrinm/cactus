package cert

import (
	"crypto/mldsa"
	"fmt"
)

// SignatureAlgorithm identifies how to interpret an MTCSignature's
// public key + signature bytes. draft-04 §5.3.3 no longer fixes an
// algorithm registry — a cosigner's algorithm is a PKIX
// AlgorithmIdentifier carried in the CA certificate's sigAlg (§5.5),
// resolved out-of-band. Per the MTC-with-tlog profile, cosigners use
// ML-DSA-44 (with -65/-87 reserved for experiments). Requires a Go 1.27+
// build for the built-in crypto/mldsa.
type SignatureAlgorithm uint16

const (
	AlgUnknown SignatureAlgorithm = 0
	AlgMLDSA44 SignatureAlgorithm = 0x0904 // placeholder
	AlgMLDSA65 SignatureAlgorithm = 0x0905 // placeholder
	AlgMLDSA87 SignatureAlgorithm = 0x0906 // placeholder
)

// CosignerKey describes a known cosigner.
type CosignerKey struct {
	ID        TrustAnchorID
	Algorithm SignatureAlgorithm
	// PublicKey is the raw FIPS 204 ML-DSA public key bytes.
	PublicKey []byte
}

// VerifyMTCSignature checks an MTCSignature.Signature against the signing
// message (a CosignedMessage per §5.3.1). The caller supplies a
// CosignerKey carrying the algorithm + key bytes so the cosigner ID is
// resolved out-of-band.
func VerifyMTCSignature(key CosignerKey, sig MTCSignature, signedMessage []byte) error {
	if string(sig.CosignerID) != string(key.ID) {
		return fmt.Errorf("cert: cosigner ID mismatch: sig=%q key=%q", sig.CosignerID, key.ID)
	}
	switch key.Algorithm {
	case AlgMLDSA44, AlgMLDSA65, AlgMLDSA87:
		return verifyMLDSA(key.Algorithm, key.PublicKey, signedMessage, sig.Signature)
	default:
		return fmt.Errorf("cert: algorithm 0x%04x not recognised", uint16(key.Algorithm))
	}
}

// verifyMLDSA verifies a pure ML-DSA signature with an empty context
// (draft-04 §5.3.3 / RFC 9881 §3). pub is the raw FIPS 204 public key as
// extracted from the cosigner SPKI by cosignerKeyFromSPKI.
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
