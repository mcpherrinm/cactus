package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

func TestVerifyMTCSignatureECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("test message")
	digest := sha256.Sum256(msg)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	key := CosignerKey{
		ID:        TrustAnchorID("test.cosigner"),
		Algorithm: AlgECDSAP256SHA256,
		PublicKey: spki,
	}
	sig := MTCSignature{
		CosignerID: TrustAnchorID("test.cosigner"),
		Signature:  sigBytes,
	}
	if err := VerifyMTCSignature(key, sig, msg); err != nil {
		t.Errorf("verify: %v", err)
	}

	// Tamper.
	bad := append([]byte(nil), msg...)
	bad[0] ^= 1
	if err := VerifyMTCSignature(key, sig, bad); err == nil {
		t.Error("expected verify to fail with tampered message")
	}
}

func TestVerifyMTCSignatureCosignerIDMismatch(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	digest := sha256.Sum256([]byte("m"))
	sigBytes, _ := ecdsa.SignASN1(rand.Reader, priv, digest[:])

	key := CosignerKey{ID: TrustAnchorID("a"), Algorithm: AlgECDSAP256SHA256, PublicKey: spki}
	sig := MTCSignature{CosignerID: TrustAnchorID("b"), Signature: sigBytes}
	if err := VerifyMTCSignature(key, sig, []byte("m")); err == nil {
		t.Error("expected mismatch error")
	}
}
