// Package signer defines the cosigner signing abstraction. The CA cosigner
// (§5.5 of draft-ietf-plants-merkle-tree-certs-03) signs the
// MTCSubtreeSignatureInput defined in §5.4.1, and this package provides
// the concrete ECDSA-P256-SHA256 implementation plus a stable interface
// so other algorithms (Ed25519, ML-DSA-44/65/87) can be added later.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

// Algorithm enumerates cosigner signature algorithms. The numeric values
// are TLS SignatureScheme codepoints where they are defined; placeholder
// values are used for ML-DSA until IANA-assigned.
type Algorithm uint16

const (
	AlgECDSAP256SHA256 Algorithm = 0x0403
	AlgECDSAP384SHA384 Algorithm = 0x0503
	AlgEd25519         Algorithm = 0x0807
	AlgMLDSA44         Algorithm = 0x0904
	AlgMLDSA65         Algorithm = 0x0905
	AlgMLDSA87         Algorithm = 0x0906
)

func (a Algorithm) String() string {
	switch a {
	case AlgECDSAP256SHA256:
		return "ecdsa-p256-sha256"
	case AlgECDSAP384SHA384:
		return "ecdsa-p384-sha384"
	case AlgEd25519:
		return "ed25519"
	case AlgMLDSA44:
		return "mldsa-44"
	case AlgMLDSA65:
		return "mldsa-65"
	case AlgMLDSA87:
		return "mldsa-87"
	default:
		return fmt.Sprintf("unknown(0x%04x)", uint16(a))
	}
}

// ParseAlgorithm parses an algorithm name as it appears in config files.
func ParseAlgorithm(name string) (Algorithm, error) {
	switch name {
	case "ecdsa-p256-sha256":
		return AlgECDSAP256SHA256, nil
	case "ecdsa-p384-sha384":
		return AlgECDSAP384SHA384, nil
	case "ed25519":
		return AlgEd25519, nil
	case "mldsa-44":
		return AlgMLDSA44, nil
	case "mldsa-65":
		return AlgMLDSA65, nil
	case "mldsa-87":
		return AlgMLDSA87, nil
	default:
		return 0, fmt.Errorf("unknown signer algorithm %q", name)
	}
}

// Signer signs a message with a specific algorithm. Cactus passes the
// already-prepared MTCSubtreeSignatureInput here.
type Signer interface {
	Algorithm() Algorithm
	// PublicKey returns the cosigner's public key in the algorithm's
	// canonical wire format (e.g. SPKI for ECDSA, raw 32 bytes for Ed25519).
	PublicKey() []byte
	Sign(rand io.Reader, msg []byte) ([]byte, error)
}

// SeedSize is the recommended size for the per-cosigner seed file.
const SeedSize = 32

// hkdfInfo for the P-256 scalar derivation. Different algorithms use
// distinct info strings so the same seed can derive multiple keys
// without correlation.
const hkdfInfoECDSAP256 = "cactus/v1/ecdsa-p256-sha256"

// extraConstructors is populated by build-tag-gated init() functions
// (e.g. mldsa.go).
var extraConstructors = map[Algorithm]func([]byte) (Signer, error){}

// registerAlg associates an algorithm with a constructor.
// Intended to be called from init() in build-tag-gated files.
func registerAlg(alg Algorithm, fn func([]byte) (Signer, error)) {
	extraConstructors[alg] = fn
}

// FromSeed builds a Signer for alg from a 32-byte seed.
func FromSeed(alg Algorithm, seed []byte) (Signer, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", SeedSize, len(seed))
	}
	switch alg {
	case AlgECDSAP256SHA256:
		return newECDSAP256(seed)
	}
	if fn, ok := extraConstructors[alg]; ok {
		return fn(seed)
	}
	return nil, fmt.Errorf("algorithm %s not implemented (rebuild with -tags mldsa for ML-DSA)", alg)
}

type ecdsaP256 struct {
	priv *ecdsa.PrivateKey
	spki []byte
}

func newECDSAP256(seed []byte) (*ecdsaP256, error) {
	curve := elliptic.P256()
	r := hkdf.New(sha256.New, seed, nil, []byte(hkdfInfoECDSAP256))

	// Sample a scalar in [1, N-1] using rejection sampling, drawing
	// 32-byte chunks from the HKDF stream until one fits.
	n := curve.Params().N
	var d *big.Int
	for {
		var buf [32]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return nil, fmt.Errorf("hkdf: %w", err)
		}
		d = new(big.Int).SetBytes(buf[:])
		if d.Sign() > 0 && d.Cmp(n) < 0 {
			break
		}
	}
	priv := &ecdsa.PrivateKey{D: d}
	priv.PublicKey.Curve = curve
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	spki, err := marshalP256SPKI(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &ecdsaP256{priv: priv, spki: spki}, nil
}

func (s *ecdsaP256) Algorithm() Algorithm { return AlgECDSAP256SHA256 }
func (s *ecdsaP256) PublicKey() []byte    { return s.spki }

func (s *ecdsaP256) Sign(r io.Reader, msg []byte) ([]byte, error) {
	if r == nil {
		r = rand.Reader
	}
	digest := sha256.Sum256(msg)
	return s.priv.Sign(r, digest[:], crypto.SHA256)
}

// marshalP256SPKI returns the DER SubjectPublicKeyInfo for an ECDSA P-256
// public key. It's small enough to inline rather than pull in
// crypto/x509 just for this.
func marshalP256SPKI(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub.Curve != elliptic.P256() {
		return nil, errors.New("not a P-256 key")
	}
	// Use stdlib via crypto/x509 import would create a wider dep surface;
	// however the simplest correct path *is* x509.MarshalPKIXPublicKey.
	return marshalPKIXPublicKey(pub)
}
