// ML-DSA signer support (FIPS 204), using Go's built-in crypto/mldsa.
// This requires a Go 1.27+ toolchain; cactus only supports ML-DSA-44
// cosigners (with -65/-87 available for experiments), so a cactus build
// requires Go 1.27+.

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

type mldsaSigner struct {
	alg  Algorithm
	priv *mldsa.PrivateKey
	pub  []byte
}

// newMLDSA derives an ML-DSA signer for the given parameter set from a
// 32-byte cactus seed, expanded with HKDF (per-algorithm info string, so
// one seed yields uncorrelated keys) into the 32-byte ML-DSA seed.
func newMLDSA(alg Algorithm, seed []byte) (Signer, error) {
	var params mldsa.Parameters
	var info string
	switch alg {
	case AlgMLDSA44:
		params, info = mldsa.MLDSA44(), hkdfInfoMLDSA44
	case AlgMLDSA65:
		params, info = mldsa.MLDSA65(), hkdfInfoMLDSA65
	case AlgMLDSA87:
		params, info = mldsa.MLDSA87(), hkdfInfoMLDSA87
	default:
		return nil, fmt.Errorf("not an ML-DSA algorithm: %s", alg)
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

func (s *mldsaSigner) Algorithm() Algorithm { return s.alg }
func (s *mldsaSigner) PublicKey() []byte    { return s.pub }
func (s *mldsaSigner) Sign(r io.Reader, msg []byte) ([]byte, error) {
	// draft-05 §5.3.3 / RFC 9881 §3: Merkle Tree Certificate cosignatures
	// use pure ML-DSA (FIPS 204) with an empty context string. A nil
	// Options signs with the empty-context default; crypto/mldsa ignores
	// the io.Reader argument.
	return s.priv.Sign(r, msg, nil)
}
