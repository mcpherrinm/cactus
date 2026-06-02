package signer

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestParseAlgorithm(t *testing.T) {
	for _, name := range []string{"mldsa-44", "mldsa-65", "mldsa-87"} {
		alg, err := ParseAlgorithm(name)
		if err != nil {
			t.Errorf("ParseAlgorithm(%q): %v", name, err)
			continue
		}
		if alg.String() != name {
			t.Errorf("alg.String() = %q, want %q", alg.String(), name)
		}
	}
	for _, bad := range []string{"rsa", "ecdsa-p256-sha256", "ed25519", ""} {
		if _, err := ParseAlgorithm(bad); err == nil {
			t.Errorf("ParseAlgorithm(%q): want error", bad)
		}
	}
}

func TestSeedDeterministic(t *testing.T) {
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
}

func TestSeedDifferentSeedsDifferKey(t *testing.T) {
	seed1 := bytes.Repeat([]byte{0x01}, SeedSize)
	seed2 := bytes.Repeat([]byte{0x02}, SeedSize)
	a, _ := FromSeed(AlgMLDSA44, seed1)
	b, _ := FromSeed(AlgMLDSA44, seed2)
	if bytes.Equal(a.PublicKey(), b.PublicKey()) {
		t.Errorf("expected distinct keys for distinct seeds")
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
	if _, err := FromSeed(AlgMLDSA44, []byte{1, 2, 3}); err == nil {
		t.Error("expected error for wrong-size seed")
	}
}
