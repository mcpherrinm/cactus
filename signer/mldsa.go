//go:build mldsa

// ML-DSA signer support, gated behind the `mldsa` build tag. We use
// cloudflare/circl as the reference implementation until Go's
// `crypto/mldsa` package lands; the seam is the same once it does.
//
// To build with ML-DSA support:
//
//	go build -tags mldsa ./...
//
// or
//
//	go test -tags mldsa ./signer/...

package signer

import (
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/hkdf"
)

const (
	hkdfInfoMLDSA44 = "cactus/v1/mldsa-44"
	hkdfInfoMLDSA65 = "cactus/v1/mldsa-65"
)

// init registers ML-DSA-44 and ML-DSA-65 with FromSeed.
func init() {
	registerAlg(AlgMLDSA44, newMLDSA44)
	registerAlg(AlgMLDSA65, newMLDSA65)
}

type mldsa44Signer struct {
	priv *mldsa44.PrivateKey
	pub  []byte
}

func newMLDSA44(seed []byte) (Signer, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", SeedSize, len(seed))
	}
	r := hkdf.New(sha256.New, seed, nil, []byte(hkdfInfoMLDSA44))
	var ks [mldsa44.SeedSize]byte
	if _, err := io.ReadFull(r, ks[:]); err != nil {
		return nil, err
	}
	pub, priv := mldsa44.NewKeyFromSeed(&ks)
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &mldsa44Signer{priv: priv, pub: pubBytes}, nil
}

func (s *mldsa44Signer) Algorithm() Algorithm { return AlgMLDSA44 }
func (s *mldsa44Signer) PublicKey() []byte    { return s.pub }
func (s *mldsa44Signer) Sign(_ io.Reader, msg []byte) ([]byte, error) {
	sig := make([]byte, mldsa44.SignatureSize)
	if err := mldsa44.SignTo(s.priv, msg, nil, false, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

type mldsa65Signer struct {
	priv *mldsa65.PrivateKey
	pub  []byte
}

func newMLDSA65(seed []byte) (Signer, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", SeedSize, len(seed))
	}
	r := hkdf.New(sha256.New, seed, nil, []byte(hkdfInfoMLDSA65))
	var ks [mldsa65.SeedSize]byte
	if _, err := io.ReadFull(r, ks[:]); err != nil {
		return nil, err
	}
	pub, priv := mldsa65.NewKeyFromSeed(&ks)
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &mldsa65Signer{priv: priv, pub: pubBytes}, nil
}

func (s *mldsa65Signer) Algorithm() Algorithm { return AlgMLDSA65 }
func (s *mldsa65Signer) PublicKey() []byte    { return s.pub }
func (s *mldsa65Signer) Sign(_ io.Reader, msg []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(s.priv, msg, nil, false, sig); err != nil {
		return nil, err
	}
	return sig, nil
}
