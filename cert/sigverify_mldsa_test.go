package cert

import (
	"crypto/mldsa"
	"testing"
)

// On Go 1.27+ (where crypto/mldsa is available), VerifyMTCSignature verifies pure
// ML-DSA (FIPS 204, empty context) cosignatures. We round-trip each
// parameter set: sign a CosignedMessage-shaped message with crypto/mldsa
// and verify it through VerifyMTCSignature, using the raw FIPS 204 public
// key as cosignerKeyFromSPKI would supply it.
func TestVerifyMTCSignatureMLDSARoundTrip(t *testing.T) {
	id := TrustAnchorID("32473.9")
	msg := []byte("subtree/v1\x00cosigned message bytes for the ml-dsa round trip")

	cases := []struct {
		name   string
		alg    SignatureAlgorithm
		params mldsa.Parameters
	}{
		{"mldsa44", AlgMLDSA44, mldsa.MLDSA44()},
		{"mldsa65", AlgMLDSA65, mldsa.MLDSA65()},
		{"mldsa87", AlgMLDSA87, mldsa.MLDSA87()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := mldsa.GenerateKey(tc.params)
			if err != nil {
				t.Fatal(err)
			}
			// draft-05 §5.3.3: empty context (nil Options); the reader is
			// ignored by crypto/mldsa.
			sig, err := priv.Sign(nil, msg, nil)
			if err != nil {
				t.Fatal(err)
			}
			raw := priv.PublicKey().Bytes()
			key := CosignerKey{ID: id, Algorithm: tc.alg, PublicKey: raw}
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
	}
}
