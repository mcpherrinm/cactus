package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
)

// SignatureAlgorithm identifies how to interpret an MTCSignature's
// public key + signature bytes. Mirrors the §5.4.2 algorithm registry
// — ML-DSA values are not yet implemented in the verifier; callers can
// supply a custom verifier via VerifyMTCSignatureWith.
type SignatureAlgorithm uint16

const (
	AlgUnknown         SignatureAlgorithm = 0
	AlgECDSAP256SHA256 SignatureAlgorithm = 0x0403
	AlgECDSAP384SHA384 SignatureAlgorithm = 0x0503
	AlgEd25519         SignatureAlgorithm = 0x0807
	AlgMLDSA44         SignatureAlgorithm = 0x0904 // placeholder
	AlgMLDSA65         SignatureAlgorithm = 0x0905 // placeholder
)

// CosignerKey describes a known cosigner.
type CosignerKey struct {
	ID        TrustAnchorID
	Algorithm SignatureAlgorithm
	// PublicKey is the algorithm-canonical key encoding:
	//   - ECDSA: SPKI DER (parseable by x509.ParsePKIXPublicKey)
	//   - Ed25519: 32 raw bytes
	PublicKey []byte
}

// VerifyMTCSignature checks an MTCSignature.Signature against the
// signing message (an MTCSubtreeSignatureInput per §5.4.1). The
// caller supplies a CosignerKey carrying the algorithm + key bytes so
// the cosigner ID is resolved out-of-band.
//
// Only ECDSA-P256-SHA256, ECDSA-P384-SHA384, and Ed25519 are
// implemented today. ML-DSA verification requires the optional `mldsa`
// build tag; until then, AlgMLDSA* returns ErrUnsupportedAlgorithm.
func VerifyMTCSignature(key CosignerKey, sig MTCSignature, signedMessage []byte) error {
	if string(sig.CosignerID) != string(key.ID) {
		return fmt.Errorf("cert: cosigner ID mismatch: sig=%q key=%q", sig.CosignerID, key.ID)
	}
	switch key.Algorithm {
	case AlgECDSAP256SHA256:
		return verifyECDSA(key.PublicKey, elliptic.P256(), signedMessage, sig.Signature, sha256Sum)
	case AlgECDSAP384SHA384:
		return verifyECDSA(key.PublicKey, elliptic.P384(), signedMessage, sig.Signature, sha384Sum)
	case AlgEd25519:
		if len(key.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("cert: ed25519 key has %d bytes, want %d", len(key.PublicKey), ed25519.PublicKeySize)
		}
		if !ed25519.Verify(ed25519.PublicKey(key.PublicKey), signedMessage, sig.Signature) {
			return errors.New("cert: ed25519 signature did not verify")
		}
		return nil
	case AlgMLDSA44, AlgMLDSA65:
		return ErrUnsupportedAlgorithm
	default:
		return fmt.Errorf("cert: algorithm 0x%04x not recognised", uint16(key.Algorithm))
	}
}

// ErrUnsupportedAlgorithm is returned when the verifier doesn't have
// support for the cosigner's algorithm in the current build (e.g.
// ML-DSA without the mldsa tag).
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
