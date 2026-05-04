//go:build mldsa

package signer

import (
	"bytes"
	"testing"
)

func TestMLDSA44SeedDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, SeedSize)
	a, err := FromSeed(AlgMLDSA44, seed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromSeed(AlgMLDSA44, seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.PublicKey(), b.PublicKey()) {
		t.Errorf("derivation not deterministic")
	}
	if a.Algorithm() != AlgMLDSA44 {
		t.Errorf("Algorithm() = %v, want MLDSA44", a.Algorithm())
	}
}

func TestMLDSA65SignAndAlgUnique(t *testing.T) {
	seed := bytes.Repeat([]byte{0x33}, SeedSize)
	s, err := FromSeed(AlgMLDSA65, seed)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign(nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) == 0 {
		t.Errorf("empty signature")
	}

	// Different algorithms with the same seed must yield different keys
	// (HKDF info string differentiates them).
	s44, _ := FromSeed(AlgMLDSA44, seed)
	if bytes.Equal(s.PublicKey(), s44.PublicKey()) {
		t.Errorf("MLDSA44 and MLDSA65 derived the same key")
	}
}
