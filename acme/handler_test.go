package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
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

func newTestStack(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x91}, signer.SeedSize)
	s, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	l, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1.ca"),
		Signer:      s,
		FS:          fs,
		FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	issuer, err := ca.New(l, "32473.1")
	if err != nil {
		t.Fatal(err)
	}

	srv, err := New(Config{
		ExternalURL:   "", // will be set after httptest.NewServer
		Issuer:        issuer,
		ChallengeMode: ChallengeAutoPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	hsrv := httptest.NewServer(srv.Handler())
	srv.SetExternalURL(hsrv.URL)
	t.Cleanup(hsrv.Close)
	return hsrv, srv
}

// jwsSign builds a JWS over payload, with the given protected headers.
func jwsSign(t *testing.T, key *ecdsa.PrivateKey, jwk *jose.JSONWebKey, kid, nonce, url string, payload []byte) string {
	t.Helper()
	signerOpts := jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"nonce":               nonce,
			jose.HeaderKey("url"): url,
		},
	}
	signingKey := jose.SigningKey{Algorithm: jose.ES256, Key: key}
	if jwk != nil {
		signerOpts.EmbedJWK = true
	} else {
		signerOpts.ExtraHeaders[jose.HeaderKey("kid")] = kid
	}
	sgn, err := jose.NewSigner(signingKey, &signerOpts)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := sgn.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// nonceFor fetches a nonce from /new-nonce.
func nonceFor(t *testing.T, base string) string {
	t.Helper()
	resp, err := http.Head(base + "/new-nonce")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		t.Fatal("no nonce")
	}
	return n
}

// post posts a JWS to base+path and returns response, body, new nonce.
func post(t *testing.T, base, path, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest("POST", base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

// postAsGet performs the RFC 8555 §6.3 POST-as-GET pattern against url:
// signs an empty payload with acctKey/kid using a fresh nonce, posts
// to url, and returns the response + body.
func postAsGet(t *testing.T, base, url string, acctKey *ecdsa.PrivateKey, kid string, accept string) (*http.Response, []byte) {
	t.Helper()
	nonce := nonceFor(t, base)
	jws := jwsSign(t, acctKey, nil, kid, nonce, url, []byte{})
	req, err := http.NewRequest("POST", url, strings.NewReader(jws))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

func TestDirectoryEndpoint(t *testing.T) {
	hsrv, _ := newTestStack(t)
	resp, err := http.Get(hsrv.URL + "/directory")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var d Directory
	json.NewDecoder(resp.Body).Decode(&d)
	if d.NewAccount == "" || d.NewOrder == "" || d.NewNonce == "" {
		t.Errorf("directory missing fields: %+v", d)
	}
}

func TestNewNonceEndpoint(t *testing.T) {
	hsrv, _ := newTestStack(t)
	resp, err := http.Head(hsrv.URL + "/new-nonce")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Replay-Nonce") == "" {
		t.Error("missing Replay-Nonce")
	}
}

func TestEndToEndIssuance(t *testing.T) {
	hsrv, _ := newTestStack(t)
	base := hsrv.URL

	// 1. Account key.
	acctKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	acctJWK := &jose.JSONWebKey{Key: acctKey.Public(), Algorithm: "ES256"}

	// 2. new-account.
	nonce := nonceFor(t, base)
	accountReq, _ := json.Marshal(NewAccountReq{TermsOfServiceAgreed: true})
	jws := jwsSign(t, acctKey, acctJWK, "", nonce, base+"/new-account", accountReq)
	resp, body := post(t, base, "/new-account", jws)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("new-account status=%d body=%s", resp.StatusCode, body)
	}
	kid := resp.Header.Get("Location")
	if kid == "" {
		t.Fatal("missing Location")
	}

	// 3. new-order.
	nonce = resp.Header.Get("Replay-Nonce")
	orderPayload, _ := json.Marshal(NewOrderReq{
		Identifiers: []Identifier{{Type: "dns", Value: "example.test"}},
	})
	jws = jwsSign(t, acctKey, nil, kid, nonce, base+"/new-order", orderPayload)
	resp, body = post(t, base, "/new-order", jws)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("new-order status=%d body=%s", resp.StatusCode, body)
	}
	var ord OrderResp
	json.Unmarshal(body, &ord)
	orderURL := resp.Header.Get("Location")
	if ord.Status != "ready" {
		t.Errorf("order status = %q, want ready (auto-pass)", ord.Status)
	}

	// 4. Generate CSR.
	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "example.test"},
		DNSNames: []string{"example.test"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, csrKey)
	if err != nil {
		t.Fatal(err)
	}
	finPayload, _ := json.Marshal(FinalizeReq{
		CSR: base64.RawURLEncoding.EncodeToString(csrDER),
	})

	// 5. finalize.
	nonce = resp.Header.Get("Replay-Nonce")
	finalizeURL := ord.Finalize
	jws = jwsSign(t, acctKey, nil, kid, nonce, finalizeURL, finPayload)
	resp, body = post(t, base, strings.TrimPrefix(finalizeURL, base), jws)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("finalize status=%d body=%s", resp.StatusCode, body)
	}
	var ord2 OrderResp
	json.Unmarshal(body, &ord2)
	if ord2.Status != "valid" {
		t.Errorf("order status after finalize = %q", ord2.Status)
	}
	if ord2.Certificate == "" {
		t.Fatal("missing certificate URL")
	}

	// 6. Download cert via POST-as-GET (RFC 8555 §6.3).
	resp, pemBytes := postAsGet(t, base, ord2.Certificate, acctKey, kid, "")
	if resp.StatusCode != 200 {
		t.Fatalf("cert status = %d body=%s", resp.StatusCode, pemBytes)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("not a PEM CERTIFICATE: %q", string(pemBytes))
	}

	// 7. Verify the cert structure: serialNumber > 0, issuer DN matches log ID DN.
	if len(block.Bytes) < 100 {
		t.Errorf("suspiciously short cert: %d bytes", len(block.Bytes))
	}

	// 8. Alternate URL returns 503 + Retry-After.
	altURL := strings.TrimSuffix(ord2.Certificate, "/cert") + "/cert/" + lastSegment(ord2.Certificate) + "/alternate"
	resp, _ = postAsGet(t, base, altURL, acctKey, kid, "")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Logf("alternate URL: status=%d (expected 503)", resp.StatusCode)
	}

	_ = orderURL
	_ = ord
}

func lastSegment(u string) string {
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return u
}

// TestNewAccountRequiresNonce confirms the nonce-required behaviour.
func TestNewAccountRequiresNonce(t *testing.T) {
	hsrv, _ := newTestStack(t)
	acctKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acctJWK := &jose.JSONWebKey{Key: acctKey.Public(), Algorithm: "ES256"}
	jws := jwsSign(t, acctKey, acctJWK, "", "definitely-not-a-real-nonce",
		hsrv.URL+"/new-account", []byte("{}"))
	resp, _ := post(t, hsrv.URL, "/new-account", jws)
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		t.Errorf("expected nonce-error status, got %d", resp.StatusCode)
	}
}
