//go:build mldsa

package cert

import (
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// In a build WITH the `mldsa` tag, VerifyMTCSignature verifies pure
// ML-DSA (FIPS 204, empty context) cosignatures. We round-trip each
// parameter set: sign a CosignedMessage-shaped message with circl and
// verify it through VerifyMTCSignature, using the raw FIPS 204 public
// key as cosignerKeyFromSPKI would supply it.
func TestVerifyMTCSignatureMLDSARoundTrip(t *testing.T) {
	id := TrustAnchorID("32473.9")
	msg := []byte("subtree/v1\x00cosigned message bytes for the ml-dsa round trip")

	t.Run("mldsa44", func(t *testing.T) {
		pub, priv, err := mldsa44.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, mldsa44.SignatureSize)
		if err := mldsa44.SignTo(priv, msg, nil, false, sig); err != nil {
			t.Fatal(err)
		}
		raw, _ := pub.MarshalBinary()
		key := CosignerKey{ID: id, Algorithm: AlgMLDSA44, PublicKey: raw}
		if err := VerifyMTCSignature(key, MTCSignature{CosignerID: id, Signature: sig}, msg); err != nil {
			t.Errorf("verify: %v", err)
		}
		// Tamper: flip a message byte → must fail.
		bad := append([]byte(nil), msg...)
		bad[0] ^= 1
		if err := VerifyMTCSignature(key, MTCSignature{CosignerID: id, Signature: sig}, bad); err == nil {
			t.Errorf("tampered message verified")
		}
	})

	t.Run("mldsa65", func(t *testing.T) {
		pub, priv, err := mldsa65.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(priv, msg, nil, false, sig); err != nil {
			t.Fatal(err)
		}
		raw, _ := pub.MarshalBinary()
		key := CosignerKey{ID: id, Algorithm: AlgMLDSA65, PublicKey: raw}
		if err := VerifyMTCSignature(key, MTCSignature{CosignerID: id, Signature: sig}, msg); err != nil {
			t.Errorf("verify: %v", err)
		}
	})

	t.Run("mldsa87", func(t *testing.T) {
		pub, priv, err := mldsa87.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		sig := make([]byte, mldsa87.SignatureSize)
		if err := mldsa87.SignTo(priv, msg, nil, false, sig); err != nil {
			t.Fatal(err)
		}
		raw, _ := pub.MarshalBinary()
		key := CosignerKey{ID: id, Algorithm: AlgMLDSA87, PublicKey: raw}
		if err := VerifyMTCSignature(key, MTCSignature{CosignerID: id, Signature: sig}, msg); err != nil {
			t.Errorf("verify: %v", err)
		}
	})
}
