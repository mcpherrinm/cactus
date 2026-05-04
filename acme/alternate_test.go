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
	"strconv"
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

// TestAlternateURLReturns503WithRetryAfter pins the §9-permitted
// behavior: the alternate (landmark-relative) cert URL returns
// HTTP 503 with a Retry-After header parseable as either an integer
// number of seconds or an HTTP-date.
func TestAlternateURLReturns503WithRetryAfter(t *testing.T) {
	dir := t.TempDir()
	fs, _ := storage.New(dir)
	seed := make([]byte, signer.SeedSize)
	for i := range seed {
		seed[i] = 0xDE
	}
	s, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	l, _ := cactuslog.New(context.Background(), cactuslog.Config{
		LogID: cert.TrustAnchorID("32473.1"), CosignerID: cert.TrustAnchorID("32473.1.ca"),
		Signer: s, FS: fs, FlushPeriod: 25 * time.Millisecond,
	})
	defer l.Stop()
	issuer, _ := ca.New(l, "32473.1")
	srv, _ := New(Config{Issuer: issuer, ChallengeMode: ChallengeAutoPass})
	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()
	srv.SetExternalURL(hsrv.URL)

	// Issue one cert end-to-end so we have a real /cert/{id}/alternate URL.
	acctKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acctJWK := &jose.JSONWebKey{Key: acctKey.Public(), Algorithm: "ES256"}
	nonce := nonceFor(t, hsrv.URL)
	jws := jwsSign(t, acctKey, acctJWK, "", nonce, hsrv.URL+"/new-account",
		mustMarshal(NewAccountReq{TermsOfServiceAgreed: true}))
	resp, _ := post(t, hsrv.URL, "/new-account", jws)
	kid := resp.Header.Get("Location")
	nonce = resp.Header.Get("Replay-Nonce")
	jws = jwsSign(t, acctKey, nil, kid, nonce, hsrv.URL+"/new-order",
		mustMarshal(NewOrderReq{Identifiers: []Identifier{{Type: "dns", Value: "alt.test"}}}))
	resp, body := post(t, hsrv.URL, "/new-order", jws)
	var ord OrderResp
	json.Unmarshal(body, &ord)
	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "alt.test"}, DNSNames: []string{"alt.test"},
	}, csrKey)
	nonce = resp.Header.Get("Replay-Nonce")
	jws = jwsSign(t, acctKey, nil, kid, nonce, ord.Finalize,
		mustMarshal(FinalizeReq{CSR: base64.RawURLEncoding.EncodeToString(csr)}))
	resp, body = post(t, hsrv.URL, strings.TrimPrefix(ord.Finalize, hsrv.URL), jws)
	var ord2 OrderResp
	json.Unmarshal(body, &ord2)
	if ord2.Certificate == "" {
		t.Fatal("missing cert URL")
	}

	// The Link header on /finalize should advertise the alternate URL.
	if got := resp.Header.Get("Link"); !strings.Contains(got, `rel="alternate"`) {
		t.Errorf("Link header missing alternate: %q", got)
	}

	// /cert/{id}/alternate must return 503 + Retry-After.
	altURL := ord2.Certificate + "/alternate"
	r2, _ := postAsGet(t, hsrv.URL, altURL, acctKey, kid, "")
	if r2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", r2.StatusCode)
	}
	ra := r2.Header.Get("Retry-After")
	if ra == "" {
		t.Fatal("missing Retry-After header")
	}
	// Retry-After is either a delta-seconds integer or an HTTP-date.
	if _, err := strconv.Atoi(ra); err != nil {
		// Fall back: try HTTP-date format.
		if _, err := http.ParseTime(ra); err != nil {
			t.Errorf("Retry-After %q is neither integer nor HTTP-date", ra)
		}
	}
}
