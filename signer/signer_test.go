package signer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"path/filepath"
	"testing"
)

func TestParseAlgorithm(t *testing.T) {
	for _, name := range []string{"ecdsa-p256-sha256", "ecdsa-p384-sha384", "ed25519", "mldsa-44", "mldsa-65", "mldsa-87"} {
		alg, err := ParseAlgorithm(name)
		if err != nil {
			t.Errorf("ParseAlgorithm(%q): %v", name, err)
			continue
		}
		if alg.String() != name {
			t.Errorf("alg.String() = %q, want %q", alg.String(), name)
		}
	}
	if _, err := ParseAlgorithm("rsa"); err == nil {
		t.Error("ParseAlgorithm(rsa): want error")
	}
}

func TestECDSAP256SeedDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, SeedSize)
	a, err := FromSeed(AlgECDSAP256SHA256, seed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromSeed(AlgECDSAP256SHA256, seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.PublicKey(), b.PublicKey()) {
		t.Errorf("derivation not deterministic")
	}
}

func TestECDSAP256SeedDifferentSeedsDifferKey(t *testing.T) {
	seed1 := bytes.Repeat([]byte{0x01}, SeedSize)
	seed2 := bytes.Repeat([]byte{0x02}, SeedSize)
	a, _ := FromSeed(AlgECDSAP256SHA256, seed1)
	b, _ := FromSeed(AlgECDSAP256SHA256, seed2)
	if bytes.Equal(a.PublicKey(), b.PublicKey()) {
		t.Errorf("expected distinct keys for distinct seeds")
	}
}

func TestECDSAP256SignVerify(t *testing.T) {
	seed := bytes.Repeat([]byte{0xab}, SeedSize)
	s, err := FromSeed(AlgECDSAP256SHA256, seed)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello-mtc")
	sig, err := s.Sign(nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	pub := pubAny.(*ecdsa.PublicKey)
	digest := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Errorf("signature failed to verify")
	}
}

func TestSeedWriteLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "seed")
	if err := WriteSeed(p); err != nil {
		t.Fatal(err)
	}
	data, err := LoadSeed(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != SeedSize {
		t.Errorf("seed size = %d, want %d", len(data), SeedSize)
	}

	// Refuses overwrite.
	if err := WriteSeed(p); err == nil {
		t.Errorf("WriteSeed expected to refuse existing file")
	}
}

func TestSeedWrongSize(t *testing.T) {
	if _, err := FromSeed(AlgECDSAP256SHA256, []byte{1, 2, 3}); err == nil {
		t.Error("expected error for wrong-size seed")
	}
}
