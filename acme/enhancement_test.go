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
	"github.com/letsencrypt/cactus/landmark"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
)

// TestEnhancementURLPending pins the draft §9 "enhancement" behaviour
// before a covering landmark exists: the standalone cert advertises the
// landmark-relative cert via rel="enhancement" at a URL pinned to the
// landmark number it will be relative to, and that URL returns HTTP 202
// (Accepted) + Retry-After — non-blocking, never the rel="alternate" +
// 503 that stalled clients.
func TestEnhancementURLPending(t *testing.T) {
	dir := t.TempDir()
	fs, _ := storage.New(dir)
	seed := make([]byte, signer.SeedSize)
	for i := range seed {
		seed[i] = 0xDE
	}
	sgn, _ := signer.FromSeed(signer.AlgMLDSA44, seed)
	logID := cert.TrustAnchorID("32473.1")
	l, _ := cactuslog.New(context.Background(), cactuslog.Config{
		LogID: logID, CosignerID: logID,
		Signer: sgn, FS: fs, FlushPeriod: 25 * time.Millisecond,
	})
	defer l.Stop()
	issuer, _ := ca.New(l, "32473.1", 1)

	// TimeBetweenLandmarks is long: no landmark is allocated during the
	// test, so the enhancement URL stays in the pending (202) state.
	seq, err := landmark.New(landmark.Config{
		CAID: logID, LogNumber: 1,
		TimeBetweenLandmarks: time.Hour, MaxCertLifetime: time.Hour,
	}, fs, time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := New(Config{
		Issuer: issuer, ChallengeMode: ChallengeAutoPass,
		Landmarks: seq, SubtreeProof: l.SubtreeProof,
		LogID: logID, CAID: logID, LogNumber: 1,
	})
	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()
	srv.SetExternalURL(hsrv.URL)

	// Issue one cert end-to-end so we have a real cert URL.
	acctKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acctJWK := &jose.JSONWebKey{Key: acctKey.Public(), Algorithm: "ES256"}
	nonce := nonceFor(t, hsrv.URL)
	jws := jwsSign(t, acctKey, acctJWK, "", nonce, hsrv.URL+"/new-account",
		mustMarshal(NewAccountReq{TermsOfServiceAgreed: true}))
	resp, _ := post(t, hsrv.URL, "/new-account", jws)
	kid := resp.Header.Get("Location")
	nonce = resp.Header.Get("Replay-Nonce")
	jws = jwsSign(t, acctKey, nil, kid, nonce, hsrv.URL+"/new-order",
		mustMarshal(NewOrderReq{Identifiers: []Identifier{{Type: "dns", Value: "enh.test"}}}))
	resp, body := post(t, hsrv.URL, "/new-order", jws)
	var ord OrderResp
	json.Unmarshal(body, &ord)
	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "enh.test"}, DNSNames: []string{"enh.test"},
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

	// The standalone cert response advertises the landmark-relative cert
	// as an enhancement, pinned to a landmark number.
	certResp, _ := postAsGet(t, hsrv.URL, ord2.Certificate, acctKey, kid, "")
	link := certResp.Header.Get("Link")
	if !strings.Contains(link, `rel="enhancement"`) {
		t.Errorf("cert Link missing rel=enhancement: %q", link)
	}
	enh := linkURL(link)
	if !strings.Contains(enh, "/landmark-relative/") {
		t.Fatalf("enhancement URL not a landmark-relative URL: %q", enh)
	}
	// Index 0's covering landmark is the next one to be allocated (1).
	if !strings.HasSuffix(enh, "/landmark-relative/1") {
		t.Errorf("enhancement URL = %q, want it pinned to landmark 1", enh)
	}

	// Before the landmark is allocated, the enhancement URL returns 202 +
	// Retry-After.
	r2, _ := postAsGet(t, hsrv.URL, enh, acctKey, kid, "")
	if r2.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want 202", r2.StatusCode)
	}
	ra := r2.Header.Get("Retry-After")
	if ra == "" {
		t.Fatal("missing Retry-After header")
	}
	if _, err := strconv.Atoi(ra); err != nil {
		if _, err := http.ParseTime(ra); err != nil {
			t.Errorf("Retry-After %q is neither integer nor HTTP-date", ra)
		}
	}

	// A landmark number this cert is not relative to is a permanent 404.
	wrong := strings.TrimSuffix(enh, "/1") + "/2"
	r3, _ := postAsGet(t, hsrv.URL, wrong, acctKey, kid, "")
	if r3.StatusCode != http.StatusNotFound {
		t.Errorf("wrong-landmark status = %d, want 404", r3.StatusCode)
	}
}

// linkURL returns the URL inside a `<url>;rel="..."` Link header value.
func linkURL(link string) string {
	start := strings.Index(link, "<")
	end := strings.Index(link, ">")
	if start < 0 || end < 0 || end < start {
		return ""
	}
	return link[start+1 : end]
}
