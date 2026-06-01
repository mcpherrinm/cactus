//go:build go1.27

// ML-DSA signer support, compiled in automatically on Go 1.27+ (the
// `go1.27` build constraint), where Go's built-in crypto/mldsa (FIPS 204)
// is available. Until Go 1.27 is released a gotip 1.27-devel toolchain
// satisfies the constraint, so no extra build flags are needed:
//
//	gotip build ./...
//	gotip test  ./signer/...
//
// On older toolchains these algorithms are unregistered and FromSeed
// returns an error pointing the operator at the Go version requirement.

package signer

import (
	"crypto/mldsa"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	hkdfInfoMLDSA44 = "cactus/v1/mldsa-44"
	hkdfInfoMLDSA65 = "cactus/v1/mldsa-65"
	hkdfInfoMLDSA87 = "cactus/v1/mldsa-87"
)

// mldsaSeedSize is the ML-DSA key-generation seed (ξ) length in bytes
// (FIPS 204). crypto/mldsa.NewPrivateKey requires exactly this many bytes.
const mldsaSeedSize = 32

// init registers ML-DSA-44/65/87 with FromSeed.
func init() {
	registerAlg(AlgMLDSA44, newMLDSA(AlgMLDSA44, mldsa.MLDSA44(), hkdfInfoMLDSA44))
	registerAlg(AlgMLDSA65, newMLDSA(AlgMLDSA65, mldsa.MLDSA65(), hkdfInfoMLDSA65))
	registerAlg(AlgMLDSA87, newMLDSA(AlgMLDSA87, mldsa.MLDSA87(), hkdfInfoMLDSA87))
}

type mldsaSigner struct {
	alg  Algorithm
	priv *mldsa.PrivateKey
	pub  []byte
}

// newMLDSA returns a FromSeed constructor for the given ML-DSA parameter
// set. The cactus seed is expanded with HKDF (per-algorithm info string,
// so one seed yields uncorrelated keys) into the 32-byte ML-DSA seed.
func newMLDSA(alg Algorithm, params mldsa.Parameters, info string) func([]byte) (Signer, error) {
	return func(seed []byte) (Signer, error) {
		if len(seed) != SeedSize {
			return nil, fmt.Errorf("seed must be %d bytes, got %d", SeedSize, len(seed))
		}
		r := hkdf.New(sha256.New, seed, nil, []byte(info))
		ks := make([]byte, mldsaSeedSize)
		if _, err := io.ReadFull(r, ks); err != nil {
			return nil, err
		}
		priv, err := mldsa.NewPrivateKey(params, ks)
		if err != nil {
			return nil, fmt.Errorf("derive %s key: %w", params, err)
		}
		return &mldsaSigner{alg: alg, priv: priv, pub: priv.PublicKey().Bytes()}, nil
	}
}

func (s *mldsaSigner) Algorithm() Algorithm { return s.alg }
func (s *mldsaSigner) PublicKey() []byte    { return s.pub }
func (s *mldsaSigner) Sign(r io.Reader, msg []byte) ([]byte, error) {
	// draft-04 §5.3.3 / RFC 9881 §3: Merkle Tree Certificate cosignatures
	// use pure ML-DSA (FIPS 204) with an empty context string. A nil
	// Options signs with the empty-context default; crypto/mldsa ignores
	// the io.Reader argument.
	return s.priv.Sign(r, msg, nil)
}
