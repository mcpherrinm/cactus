package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/letsencrypt/cactus/acme"
)

// TestRSALeafKeyIssuance issues a cert whose leaf key is RSA-2048 (not
// the ECDSA-P256 the rest of the tests use). The cosigner remains
// ECDSA-P256 — only the subject public key changes. Confirms the
// issuer's SPKI handling is algorithm-neutral and the resulting cert
// still verifies via §7.2.
func TestRSALeafKeyIssuance(t *testing.T) {
	if testing.Short() {
		t.Skip("RSA-2048 keygen is slow; skip in -short mode")
	}
	s := bringUp(t, t.TempDir())
	defer s.close()

	// Account key still ECDSA — that's only used for JWS, not the leaf.
	acctKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acctJWK := &jose.JSONWebKey{Key: acctKey.Public(), Algorithm: "ES256"}

	resp, err := http.Head(s.acmeBase + "/new-nonce")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	nonce := resp.Header.Get("Replay-Nonce")

	jws, _ := jwsCompact(acctKey, acctJWK, "", nonce, s.acmeBase+"/new-account",
		mustJSON(acme.NewAccountReq{TermsOfServiceAgreed: true}))
	resp, _, err = postJWS(s.acmeBase+"/new-account", jws)
	if err != nil {
		t.Fatal(err)
	}
	kid := resp.Header.Get("Location")
	nonce = resp.Header.Get("Replay-Nonce")

	jws, _ = jwsCompact(acctKey, nil, kid, nonce, s.acmeBase+"/new-order",
		mustJSON(acme.NewOrderReq{Identifiers: []acme.Identifier{{Type: "dns", Value: "rsa.test"}}}))
	resp, body, err := postJWS(s.acmeBase+"/new-order", jws)
	if err != nil {
		t.Fatal(err)
	}
	var ord acme.OrderResp
	json.Unmarshal(body, &ord)
	nonce = resp.Header.Get("Replay-Nonce")

	// THE relevant part: RSA-2048 leaf key.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrTmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "rsa.test"},
		DNSNames:           []string{"rsa.test"},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, rsaKey)
	if err != nil {
		t.Fatal(err)
	}

	jws, _ = jwsCompact(acctKey, nil, kid, nonce, ord.Finalize,
		mustJSON(acme.FinalizeReq{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}))
	resp, body, err = postJWS(ord.Finalize, jws)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	var ord2 acme.OrderResp
	json.Unmarshal(body, &ord2)
	if ord2.Status != "valid" {
		t.Fatalf("order status = %q, want valid", ord2.Status)
	}
	if ord2.Certificate == "" {
		t.Fatal("missing cert URL")
	}

	nonce = resp.Header.Get("Replay-Nonce")
	jws, _ = jwsCompact(acctKey, nil, kid, nonce, ord2.Certificate, []byte{})
	_, pemBytes, err := postJWS(ord2.Certificate, jws)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("not PEM: %q", pemBytes)
	}

	// Verify: the cert's TBS contains an RSA SubjectPublicKeyInfo, the
	// inclusion proof + cosignature still check out via the standard
	// path — proving the issuer's SPKI handling didn't bake in ECDSA.
	if err := verifyAgainstLog(block.Bytes, s); err != nil {
		t.Errorf("verify RSA-leaf cert: %v", err)
	}

	// Confirm the cert's SubjectPublicKeyInfo really is RSA, not
	// silently rewritten.
	if !strings.Contains(fmt.Sprintf("%x", block.Bytes), "2a864886f70d010101") {
		// rsaEncryption OID 1.2.840.113549.1.1.1 in DER.
		t.Errorf("cert does not contain RSA SPKI OID")
	}
}
