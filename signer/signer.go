// Package signer defines the cosigner signing abstraction. The CA cosigner
// (§5.5 of draft-ietf-plants-merkle-tree-certs-04) signs the
// CosignedMessage defined in §5.3.1, and this package provides
// the concrete ECDSA-P256-SHA256 implementation plus a stable interface
// so other algorithms (ML-DSA-44/65/87) can be added later.
package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
// already-prepared CosignedMessage here.
type Signer interface {
	Algorithm() Algorithm
	// PublicKey returns the cosigner's public key in the algorithm's
	// canonical wire format (e.g. SPKI for ECDSA, raw FIPS 204 key for ML-DSA).
	PublicKey() []byte
	Sign(rand io.Reader, msg []byte) ([]byte, error)
}

// SeedSize is the recommended size for the per-cosigner seed file.
const SeedSize = 32

// hkdfInfo strings for ECDSA scalar derivation. Different algorithms use
// distinct info strings so the same seed can derive multiple keys
// without correlation.
const (
	hkdfInfoECDSAP256 = "cactus/v1/ecdsa-p256-sha256"
	hkdfInfoECDSAP384 = "cactus/v1/ecdsa-p384-sha384"
)

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
		return newECDSA(alg, elliptic.P256(), crypto.SHA256, hkdfInfoECDSAP256, seed)
	case AlgECDSAP384SHA384:
		return newECDSA(alg, elliptic.P384(), crypto.SHA384, hkdfInfoECDSAP384, seed)
	}
	if fn, ok := extraConstructors[alg]; ok {
		return fn(seed)
	}
	return nil, fmt.Errorf("algorithm %s not implemented (build with Go 1.27+ for ML-DSA)", alg)
}

// ecdsaSigner is the ECDSA cosigner for any NIST curve / hash pair cactus
// supports (P-256/SHA-256 and P-384/SHA-384).
type ecdsaSigner struct {
	alg  Algorithm
	priv *ecdsa.PrivateKey
	spki []byte
	hash crypto.Hash
}

// newECDSA deterministically derives an ECDSA signer for the given curve
// and hash from a 32-byte seed via HKDF.
func newECDSA(alg Algorithm, curve elliptic.Curve, hash crypto.Hash, info string, seed []byte) (*ecdsaSigner, error) {
	r := hkdf.New(sha256.New, seed, nil, []byte(info))

	// Sample a scalar in [1, N-1] using rejection sampling, drawing
	// curve-order-sized chunks from the HKDF stream until one fits.
	n := curve.Params().N
	byteLen := (n.BitLen() + 7) / 8
	buf := make([]byte, byteLen)
	var d *big.Int
	for {
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, fmt.Errorf("hkdf: %w", err)
		}
		d = new(big.Int).SetBytes(buf)
		if d.Sign() > 0 && d.Cmp(n) < 0 {
			break
		}
	}
	priv := &ecdsa.PrivateKey{D: d}
	priv.PublicKey.Curve = curve
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())

	spki, err := marshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &ecdsaSigner{alg: alg, priv: priv, spki: spki, hash: hash}, nil
}

func (s *ecdsaSigner) Algorithm() Algorithm { return s.alg }
func (s *ecdsaSigner) PublicKey() []byte    { return s.spki }

func (s *ecdsaSigner) Sign(r io.Reader, msg []byte) ([]byte, error) {
	if r == nil {
		r = rand.Reader
	}
	h := s.hash.New()
	h.Write(msg)
	return s.priv.Sign(r, h.Sum(nil), s.hash)
}
