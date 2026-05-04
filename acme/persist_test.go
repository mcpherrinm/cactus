package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/letsencrypt/cactus/ca"
	"github.com/letsencrypt/cactus/cert"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
)

// TestRestartResume verifies that, after a server restart, an order
// that finished issuing before the restart can still serve its cert.
func TestRestartResume(t *testing.T) {
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}

	seed := make([]byte, signer.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	logSigner, err := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	if err != nil {
		t.Fatal(err)
	}

	// First server run.
	l1, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1.ca"),
		Signer:      logSigner,
		FS:          fs,
		FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer1, _ := ca.New(l1, "32473.1")
	srv1, _ := New(Config{Issuer: issuer1, ChallengeMode: ChallengeAutoPass})
	if err := srv1.AttachStorage(fs); err != nil {
		t.Fatal(err)
	}
	hsrv1 := httptest.NewServer(srv1.Handler())
	srv1.SetExternalURL(hsrv1.URL)

	certURL, certID, acctKey, kid := finalizeOneCert(t, hsrv1.URL, "example.test")

	// Stop everything.
	hsrv1.Close()
	l1.Stop()

	// Re-open storage and bring up a new server.
	fs2, _ := storage.New(dir)
	l2, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1.ca"),
		Signer:      logSigner,
		FS:          fs2,
		FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Stop()
	issuer2, _ := ca.New(l2, "32473.1")
	srv2, _ := New(Config{Issuer: issuer2, ChallengeMode: ChallengeAutoPass})
	if err := srv2.AttachStorage(fs2); err != nil {
		t.Fatal(err)
	}
	hsrv2 := httptest.NewServer(srv2.Handler())
	defer hsrv2.Close()
	srv2.SetExternalURL(hsrv2.URL)

	// Cert ID survived; rewrite the URL with the new server's prefix
	// and verify the cert is still served. The kid (account URL) also
	// shifts to the new server's prefix.
	newCertURL := hsrv2.URL + strings.TrimPrefix(certURL, hsrv1.URL)
	newKID := hsrv2.URL + strings.TrimPrefix(kid, hsrv1.URL)
	resp, body := postAsGet(t, hsrv2.URL, newCertURL, acctKey, newKID, "")
	if resp.StatusCode != 200 {
		t.Fatalf("post-restart cert fetch status = %d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "BEGIN CERTIFICATE") {
		t.Errorf("not a PEM cert: %q", string(body))
	}
	_ = certID
}

// finalizeOneCert drives a full ACME flow against base and returns the
// certificate URL, its ID, plus the (acctKey, kid) needed to download
// the cert via POST-as-GET.
func finalizeOneCert(t *testing.T, base, dnsName string) (certURL, certID string, acctKey *ecdsa.PrivateKey, kid string) {
	t.Helper()
	acctKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acctJWK := &jose.JSONWebKey{Key: acctKey.Public(), Algorithm: "ES256"}

	// new-account.
	nonce := nonceFor(t, base)
	jws := jwsSign(t, acctKey, acctJWK, "", nonce, base+"/new-account",
		mustMarshal(NewAccountReq{TermsOfServiceAgreed: true}))
	resp, _ := post(t, base, "/new-account", jws)
	kid = resp.Header.Get("Location")

	// new-order.
	nonce = resp.Header.Get("Replay-Nonce")
	jws = jwsSign(t, acctKey, nil, kid, nonce, base+"/new-order",
		mustMarshal(NewOrderReq{Identifiers: []Identifier{{Type: "dns", Value: dnsName}}}))
	resp, body := post(t, base, "/new-order", jws)
	var ord OrderResp
	json.Unmarshal(body, &ord)

	// CSR.
	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: dnsName},
		DNSNames: []string{dnsName},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTmpl, csrKey)

	// finalize.
	nonce = resp.Header.Get("Replay-Nonce")
	jws = jwsSign(t, acctKey, nil, kid, nonce, ord.Finalize,
		mustMarshal(FinalizeReq{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}))
	resp, body = post(t, base, strings.TrimPrefix(ord.Finalize, base), jws)
	var ord2 OrderResp
	json.Unmarshal(body, &ord2)
	return ord2.Certificate, lastSegment(ord2.Certificate), acctKey, kid
}

func mustMarshal(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
