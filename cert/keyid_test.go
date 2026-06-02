package cert

import (
	"crypto/sha256"
	"testing"
)

// TestCosignatureKeyID pins the c2sp.org/signed-note key-ID derivations
// cactus relies on, so a regression can't silently change the bytes that
// appear on checkpoint and sign-subtree signature lines.
func TestCosignatureKeyID(t *testing.T) {
	name := "oid/1.3.6.1.4.1.32473.1"

	t.Run("mldsa-44 uses name||0x0A||0x06||pub", func(t *testing.T) {
		pub := make([]byte, 1312) // raw FIPS 204 key; contents irrelevant here
		for i := range pub {
			pub[i] = byte(i)
		}
		h := sha256.New()
		h.Write([]byte(name))
		h.Write([]byte{0x0A, 0x06})
		h.Write(pub)
		var want [4]byte
		copy(want[:], h.Sum(nil)[:4])

		got, err := CosignatureKeyID(name, AlgMLDSA44, pub)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("ML-DSA-44 key ID = %x, want %x", got, want)
		}
	})

	t.Run("mldsa-65/87 use the 0xff escape with the key", func(t *testing.T) {
		pub := []byte("raw-mldsa-key-bytes")
		for _, tc := range []struct {
			alg SignatureAlgorithm
			id  string
		}{{AlgMLDSA65, "ml-dsa-65"}, {AlgMLDSA87, "ml-dsa-87"}} {
			h := sha256.New()
			h.Write([]byte(name))
			h.Write([]byte{0x0A, 0xff})
			h.Write([]byte(tc.id))
			h.Write(pub)
			var want [4]byte
			copy(want[:], h.Sum(nil)[:4])
			got, err := CosignatureKeyID(name, tc.alg, pub)
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("%s key ID = %x, want %x", tc.id, got, want)
			}
		}
	})

	t.Run("unknown algorithm errors", func(t *testing.T) {
		if _, err := CosignatureKeyID(name, AlgUnknown, nil); err == nil {
			t.Error("expected error for AlgUnknown")
		}
	})
}
