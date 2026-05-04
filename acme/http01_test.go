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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/letsencrypt/cactus/ca"
	"github.com/letsencrypt/cactus/cert"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
)

// TestHTTP01ChallengeMode brings up the stack in http-01 mode, runs a
// matching HTTP server that serves the keyAuthorization at the right
// path, and confirms the order can be finalized.
func TestHTTP01ChallengeMode(t *testing.T) {
	dir := t.TempDir()
	fs, _ := storage.New(dir)
	seed := make([]byte, signer.SeedSize)
	for i := range seed {
		seed[i] = 0xAA
	}
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
	defer l.Stop()
	issuer, _ := ca.New(l, "32473.1")
	srv, _ := New(Config{
		Issuer:        issuer,
		ChallengeMode: ChallengeHTTP01,
	})
	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()
	srv.SetExternalURL(hsrv.URL)

	// Stand up a shared challenge HTTP server. The client needs to
	// register its keyAuthorization here before triggering the
	// challenge.
	var mu sync.Mutex
	keyauths := map[string]string{} // token -> keyauth
	chsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/.well-known/acme-challenge/"
		if !strings.HasPrefix(r.URL.Path, prefix) {
			http.NotFound(w, r)
			return
		}
		token := strings.TrimPrefix(r.URL.Path, prefix)
		mu.Lock()
		ka, ok := keyauths[token]
		mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(ka))
	}))
	defer chsrv.Close()

	// Override the http-01 fetch URL by pointing the identifier at the
	// challenge server. attemptHTTP01 builds "http://<identifier>/...";
	// we can put the chsrv host:port in the identifier.
	chHost := strings.TrimPrefix(chsrv.URL, "http://")

	// Account.
	acctKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acctJWK := &jose.JSONWebKey{Key: acctKey.Public(), Algorithm: "ES256"}
	jwkBytes, _ := acctJWK.MarshalJSON()

	nonce := nonceFor(t, hsrv.URL)
	jws := jwsSign(t, acctKey, acctJWK, "", nonce, hsrv.URL+"/new-account",
		mustMarshal(NewAccountReq{TermsOfServiceAgreed: true}))
	resp, _ := post(t, hsrv.URL, "/new-account", jws)
	kid := resp.Header.Get("Location")

	// new-order with chHost as the identifier.
	nonce = resp.Header.Get("Replay-Nonce")
	jws = jwsSign(t, acctKey, nil, kid, nonce, hsrv.URL+"/new-order",
		mustMarshal(NewOrderReq{Identifiers: []Identifier{{Type: "dns", Value: chHost}}}))
	resp, body := post(t, hsrv.URL, "/new-order", jws)
	var ord OrderResp
	json.Unmarshal(body, &ord)
	if ord.Status != "pending" {
		t.Errorf("order should be pending in http-01 mode, got %q", ord.Status)
	}
	if len(ord.Authorizations) != 1 {
		t.Fatalf("expected 1 authz, got %d", len(ord.Authorizations))
	}

	// Fetch the authz to find the challenge URL + token.
	nonce = resp.Header.Get("Replay-Nonce")
	authzPath := strings.TrimPrefix(ord.Authorizations[0], hsrv.URL)
	jws = jwsSign(t, acctKey, nil, kid, nonce, ord.Authorizations[0], []byte("{}"))
	resp, body = post(t, hsrv.URL, authzPath, jws)
	var az AuthzResp
	json.Unmarshal(body, &az)
	if len(az.Challenges) == 0 {
		t.Fatalf("no challenges; body=%s", body)
	}
	ch := az.Challenges[0]

	// Compute keyAuthorization and register on the challenge server.
	ka, err := keyAuthorization(ch.Token, jwkBytes)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	keyauths[ch.Token] = ka
	mu.Unlock()

	// Trigger the challenge.
	nonce = resp.Header.Get("Replay-Nonce")
	chPath := strings.TrimPrefix(ch.URL, hsrv.URL)
	jws = jwsSign(t, acctKey, nil, kid, nonce, ch.URL, []byte("{}"))
	resp, body = post(t, hsrv.URL, chPath, jws)
	if resp.StatusCode != 200 {
		t.Fatalf("challenge POST status=%d body=%s", resp.StatusCode, body)
	}
	var got ChallengeMsg
	json.Unmarshal(body, &got)
	if got.Status != "valid" {
		t.Errorf("challenge status = %q, want valid", got.Status)
	}

	// The order should now be ready.
	nonce = resp.Header.Get("Replay-Nonce")
	jws = jwsSign(t, acctKey, nil, kid, nonce, hsrv.URL+"/order/"+lastSeg(ord.Finalize), []byte("{}"))
	orderURL := strings.TrimSuffix(ord.Finalize, "/finalize/"+lastSeg(ord.Finalize)) + "/order/" + lastSeg(ord.Finalize)
	_ = orderURL
	// Skip the GET-as-POST order check; instead just finalize and
	// verify we get a valid cert.

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: chHost},
		DNSNames: []string{chHost},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTmpl, csrKey)

	jws = jwsSign(t, acctKey, nil, kid, nonce, ord.Finalize,
		mustMarshal(FinalizeReq{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}))
	resp, body = post(t, hsrv.URL, strings.TrimPrefix(ord.Finalize, hsrv.URL), jws)
	if resp.StatusCode != 200 {
		t.Fatalf("finalize status=%d body=%s", resp.StatusCode, body)
	}
	var ord2 OrderResp
	json.Unmarshal(body, &ord2)
	if ord2.Status != "valid" {
		t.Errorf("post-finalize order status = %q, want valid", ord2.Status)
	}
	if ord2.Certificate == "" {
		t.Error("missing cert URL")
	}

	// Cert is fetchable via POST-as-GET (RFC 8555 §6.3).
	_, cb := postAsGet(t, hsrv.URL, ord2.Certificate, acctKey, kid, "")
	if !strings.Contains(string(cb), "BEGIN CERTIFICATE") {
		t.Errorf("not a PEM cert: %q", cb)
	}
}

func lastSeg(u string) string {
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return u
}

// TestHTTP01ChallengeRejectsBadResponse confirms a misconfigured client
// (wrong keyAuthorization) gets challenge → invalid.
func TestHTTP01ChallengeRejectsBadResponse(t *testing.T) {
	dir := t.TempDir()
	fs, _ := storage.New(dir)
	seed := make([]byte, signer.SeedSize)
	for i := range seed {
		seed[i] = 0xBB
	}
	s, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	l, _ := cactuslog.New(context.Background(), cactuslog.Config{
		LogID: cert.TrustAnchorID("32473.1"), CosignerID: cert.TrustAnchorID("32473.1.ca"),
		Signer: s, FS: fs, FlushPeriod: 25 * time.Millisecond,
	})
	defer l.Stop()
	issuer, _ := ca.New(l, "32473.1")
	srv, _ := New(Config{Issuer: issuer, ChallengeMode: ChallengeHTTP01})
	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()
	srv.SetExternalURL(hsrv.URL)

	// Challenge HTTP server that always returns the wrong body.
	chsrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("nope"))
	}))
	defer chsrv.Close()
	chHost := strings.TrimPrefix(chsrv.URL, "http://")

	acctKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acctJWK := &jose.JSONWebKey{Key: acctKey.Public(), Algorithm: "ES256"}
	nonce := nonceFor(t, hsrv.URL)
	jws := jwsSign(t, acctKey, acctJWK, "", nonce, hsrv.URL+"/new-account",
		mustMarshal(NewAccountReq{TermsOfServiceAgreed: true}))
	resp, _ := post(t, hsrv.URL, "/new-account", jws)
	kid := resp.Header.Get("Location")
	nonce = resp.Header.Get("Replay-Nonce")
	jws = jwsSign(t, acctKey, nil, kid, nonce, hsrv.URL+"/new-order",
		mustMarshal(NewOrderReq{Identifiers: []Identifier{{Type: "dns", Value: chHost}}}))
	resp, body := post(t, hsrv.URL, "/new-order", jws)
	var ord OrderResp
	json.Unmarshal(body, &ord)
	nonce = resp.Header.Get("Replay-Nonce")
	authzURL := ord.Authorizations[0]
	jws = jwsSign(t, acctKey, nil, kid, nonce, authzURL, []byte("{}"))
	resp, body = post(t, hsrv.URL, strings.TrimPrefix(authzURL, hsrv.URL), jws)
	var az AuthzResp
	json.Unmarshal(body, &az)
	if len(az.Challenges) == 0 {
		t.Fatalf("no challenges; body=%s", body)
	}
	ch := az.Challenges[0]

	// Don't register a keyauth — the challenge server returns "nope".
	nonce = resp.Header.Get("Replay-Nonce")
	chPath := strings.TrimPrefix(ch.URL, hsrv.URL)
	jws = jwsSign(t, acctKey, nil, kid, nonce, ch.URL, []byte("{}"))
	resp, _ = post(t, hsrv.URL, chPath, jws)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}
