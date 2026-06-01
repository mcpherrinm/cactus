package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
)

// SignatureAlgorithm identifies how to interpret an MTCSignature's
// public key + signature bytes. draft-04 §5.3.3 no longer fixes an
// algorithm registry — a cosigner's algorithm is a PKIX
// AlgorithmIdentifier carried in the CA certificate's sigAlg (§5.5),
// resolved out-of-band. These constants are a cactus-internal mapping
// (TLS SignatureScheme code points) for the algorithms the verifier
// implements; ML-DSA values require the optional `mldsa` build tag.
type SignatureAlgorithm uint16

const (
	AlgUnknown         SignatureAlgorithm = 0
	AlgECDSAP256SHA256 SignatureAlgorithm = 0x0403
	AlgECDSAP384SHA384 SignatureAlgorithm = 0x0503
	AlgMLDSA44         SignatureAlgorithm = 0x0904 // placeholder
	AlgMLDSA65         SignatureAlgorithm = 0x0905 // placeholder
	AlgMLDSA87         SignatureAlgorithm = 0x0906 // placeholder
)

// mldsaVerify verifies a pure ML-DSA (FIPS 204, empty context) signature.
// It is installed by the `mldsa` build-tagged file (sigverify_mldsa.go);
// in a build without that tag it stays nil and AlgMLDSA* verification
// returns ErrUnsupportedAlgorithm. pub is the raw FIPS 204 public key
// (as extracted from the cosigner SPKI), matching what signer.Signer
// returns for ML-DSA keys.
var mldsaVerify func(alg SignatureAlgorithm, pub, msg, sig []byte) error

// CosignerKey describes a known cosigner.
type CosignerKey struct {
	ID        TrustAnchorID
	Algorithm SignatureAlgorithm
	// PublicKey is the algorithm-canonical key encoding:
	//   - ECDSA: SPKI DER (parseable by x509.ParsePKIXPublicKey)
	//   - ML-DSA: raw FIPS 204 public key bytes
	PublicKey []byte
}

// VerifyMTCSignature checks an MTCSignature.Signature against the
// signing message (an CosignedMessage per §5.3.1). The
// caller supplies a CosignerKey carrying the algorithm + key bytes so
// the cosigner ID is resolved out-of-band.
//
// ECDSA-P256-SHA256 and ECDSA-P384-SHA384 are always implemented.
// ML-DSA-44/65/87 verification requires a Go 1.27+ build (for the
// built-in crypto/mldsa); on older toolchains AlgMLDSA* returns
// ErrUnsupportedAlgorithm.
func VerifyMTCSignature(key CosignerKey, sig MTCSignature, signedMessage []byte) error {
	if string(sig.CosignerID) != string(key.ID) {
		return fmt.Errorf("cert: cosigner ID mismatch: sig=%q key=%q", sig.CosignerID, key.ID)
	}
	switch key.Algorithm {
	case AlgECDSAP256SHA256:
		return verifyECDSA(key.PublicKey, elliptic.P256(), signedMessage, sig.Signature, sha256Sum)
	case AlgECDSAP384SHA384:
		return verifyECDSA(key.PublicKey, elliptic.P384(), signedMessage, sig.Signature, sha384Sum)
	case AlgMLDSA44, AlgMLDSA65, AlgMLDSA87:
		if mldsaVerify == nil {
			return ErrUnsupportedAlgorithm
		}
		return mldsaVerify(key.Algorithm, key.PublicKey, signedMessage, sig.Signature)
	default:
		return fmt.Errorf("cert: algorithm 0x%04x not recognised", uint16(key.Algorithm))
	}
}

// ErrUnsupportedAlgorithm is returned when the verifier doesn't have
// support for the cosigner's algorithm in the current build (e.g.
// ML-DSA on a pre-1.27 toolchain).
var ErrUnsupportedAlgorithm = errors.New("cert: signature algorithm not supported in this build")

func verifyECDSA(spki []byte, wantCurve elliptic.Curve, msg, sig []byte, hashFn func([]byte) []byte) error {
	pubAny, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return fmt.Errorf("cert: parse SPKI: %w", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("cert: SPKI is not ECDSA (%T)", pubAny)
	}
	if pub.Curve != wantCurve {
		return fmt.Errorf("cert: ECDSA curve %s != expected %s",
			pub.Curve.Params().Name, wantCurve.Params().Name)
	}
	if !ecdsa.VerifyASN1(pub, hashFn(msg), sig) {
		return errors.New("cert: ECDSA signature did not verify")
	}
	return nil
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

func sha384Sum(b []byte) []byte {
	h := sha512.Sum384(b)
	return h[:]
}
