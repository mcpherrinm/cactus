// Package signer defines the cosigner signing abstraction. Per the
// MTC-with-tlog profile, every MTC cosigner — including the CA cosigner
// (§5.5 of draft-ietf-plants-merkle-tree-certs-04) that signs checkpoints
// — uses an ML-DSA-44 key and produces the §5.3.1 CosignedMessage. This
// package provides the concrete ML-DSA implementation (FIPS 204, via the
// built-in crypto/mldsa, which requires Go 1.27+) behind a stable
// interface.
package signer

import (
	"fmt"
	"io"
)

// Algorithm enumerates cosigner signature algorithms. The numeric values
// are placeholder TLS SignatureScheme codepoints until IANA assignment.
type Algorithm uint16

const (
	AlgMLDSA44 Algorithm = 0x0904
	AlgMLDSA65 Algorithm = 0x0905
	AlgMLDSA87 Algorithm = 0x0906
)

func (a Algorithm) String() string {
	switch a {
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
	// canonical wire format: the raw FIPS 204 key for ML-DSA.
	PublicKey() []byte
	Sign(rand io.Reader, msg []byte) ([]byte, error)
}

// SeedSize is the recommended size for the per-cosigner seed file.
const SeedSize = 32

// FromSeed builds a Signer for alg from a 32-byte seed.
func FromSeed(alg Algorithm, seed []byte) (Signer, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", SeedSize, len(seed))
	}
	return newMLDSA(alg, seed)
}
