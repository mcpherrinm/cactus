// Package integration drives the cactus stack end-to-end: spins up
// the issuance log + ACME server in-process, requests N certs in
// parallel via raw HTTP+JWS, and verifies each cert against the live
// log using the §7.2 procedure.
//
// Build/run with:  go test -race -count=1 ./integration/...
package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/letsencrypt/cactus/acme"
	"github.com/letsencrypt/cactus/ca"
	"github.com/letsencrypt/cactus/cert"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tile"
	"github.com/letsencrypt/cactus/tlogx"
)

type stack struct {
	acmeBase string
	tileBase string
	log      *cactuslog.Log
	issuer   *ca.Issuer
	signer   signer.Signer
	logIDDN  []byte
	close    func()
	cosigner cert.TrustAnchorID
	logID    cert.TrustAnchorID
}

func bringUp(t *testing.T, dir string) *stack {
	t.Helper()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, signer.SeedSize)
	for i := range seed {
		seed[i] = byte(i * 7)
	}
	s, err := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	if err != nil {
		t.Fatal(err)
	}
	logID := cert.TrustAnchorID("32473.1")
	cosignerID := cert.TrustAnchorID("32473.1.ca")
	l, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID:       logID,
		CosignerID:  cosignerID,
		Signer:      s,
		FS:          fs,
		FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := ca.New(l, "32473.1")
	if err != nil {
		t.Fatal(err)
	}

	acmeSrv, err := acme.New(acme.Config{
		Issuer:        issuer,
		ChallengeMode: acme.ChallengeAutoPass,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := acmeSrv.AttachStorage(fs); err != nil {
		t.Fatal(err)
	}
	hAcme := httptest.NewServer(acmeSrv.Handler())
	acmeSrv.SetExternalURL(hAcme.URL)

	hTile := httptest.NewServer(tile.New(l, fs).Handler())

	return &stack{
		acmeBase: hAcme.URL,
		tileBase: hTile.URL,
		log:      l,
		issuer:   issuer,
		signer:   s,
		logIDDN:  issuer.LogIDDN,
		close: func() {
			hAcme.Close()
			hTile.Close()
			l.Stop()
		},
		cosigner: cosignerID,
		logID:    logID,
	}
}

// TestParallelIssuance issues 100 certs concurrently and verifies each
// — the §9 Definition-of-Done cardinality.
func TestParallelIssuance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	s := bringUp(t, t.TempDir())
	defer s.close()

	const n = 100
	var wg sync.WaitGroup
	var errs sync.Map
	sem := make(chan struct{}, 16) // bound concurrency to keep client side sane
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			name := fmt.Sprintf("h%d.example.test", i)
			der, err := acmeIssueOne(s.acmeBase, name)
			if err != nil {
				errs.Store(i, fmt.Errorf("issue %d: %w", i, err))
				return
			}
			if err := verifyAgainstLog(der, s); err != nil {
				errs.Store(i, fmt.Errorf("verify %d: %w", i, err))
			}
		}(i)
	}
	wg.Wait()

	var failures []string
	errs.Range(func(_, v any) bool {
		failures = append(failures, v.(error).Error())
		return true
	})
	if len(failures) > 0 {
		t.Fatalf("%d failures:\n%s", len(failures), strings.Join(failures, "\n"))
	}
}

// TestRestartContinuesIssuance issues N certs, restarts the stack
// against the same data dir, and issues N more — verifying both halves
// remain valid. The §9 Definition-of-Done case is N=50.
func TestRestartContinuesIssuance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	const half = 50
	dir := t.TempDir()
	s1 := bringUp(t, dir)
	var ders [][]byte
	for i := 0; i < half; i++ {
		der, err := acmeIssueOne(s1.acmeBase, fmt.Sprintf("a%d.test", i))
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyAgainstLog(der, s1); err != nil {
			t.Fatal(err)
		}
		ders = append(ders, der)
	}
	s1.close()

	s2 := bringUp(t, dir)
	defer s2.close()
	for i := 0; i < half; i++ {
		der, err := acmeIssueOne(s2.acmeBase, fmt.Sprintf("b%d.test", i))
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyAgainstLog(der, s2); err != nil {
			t.Fatal(err)
		}
		ders = append(ders, der)
	}

	// Pre-restart certs must still verify against the (now larger) log.
	for i, der := range ders[:half] {
		if err := verifyAgainstLog(der, s2); err != nil {
			t.Errorf("pre-restart cert %d failed: %v", i, err)
		}
	}
}

// TestCheckpointEndpoint asserts the read-path serves a parseable
// checkpoint after issuance.
func TestCheckpointEndpoint(t *testing.T) {
	s := bringUp(t, t.TempDir())
	defer s.close()
	if _, err := acmeIssueOne(s.acmeBase, "x.test"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(s.tileBase + "/checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.HasPrefix(string(body), "oid/32473.1\n") {
		t.Errorf("unexpected origin: %q", string(body))
	}
}

// acmeIssueOne drives a full ACME flow against base for a single
// dNSName and returns the cert DER. See acmeIssueOneFull for both
// the DER and the cert URL.
func acmeIssueOne(base, dnsName string) ([]byte, error) {
	der, _, err := acmeIssueOneFull(base, dnsName)
	return der, err
}

// acmeIssueOneFull is acmeIssueOne but also returns the certificate URL.
// Phase 8.4 tests need both — the DER to verify and the URL to fetch
// the alternate-URL variant.
func acmeIssueOneFull(base, dnsName string) ([]byte, string, error) {
	der, certURL, _, _, err := acmeIssueOneInner(base, dnsName)
	return der, certURL, err
}

// doFullFlow returns just the cert URL from a full ACME flow.
func doFullFlow(base, dnsName string) (string, error) {
	_, url, _, _, err := acmeIssueOneInner(base, dnsName)
	return url, err
}

// acmeIssueOneWithKeys is the full-flow helper for tests that need to
// re-download the cert via POST-as-GET (RFC 8555 §6.3).
func acmeIssueOneWithKeys(base, dnsName string) ([]byte, string, *ecdsa.PrivateKey, string, error) {
	return acmeIssueOneInner(base, dnsName)
}

// postAsGetWithAccept performs RFC 8555 §6.3 POST-as-GET on url with
// an Accept header. Tests use this to fetch /cert/{id} with the
// with-properties media type.
func postAsGetWithAccept(t *testing.T, base, url, accept string, acctKey *ecdsa.PrivateKey, kid string) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Head(base + "/new-nonce")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	nonce := resp.Header.Get("Replay-Nonce")
	jws, err := jwsCompact(acctKey, nil, kid, nonce, url, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", url, strings.NewReader(jws))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/jose+json")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	respOut, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer respOut.Body.Close()
	body, _ := io.ReadAll(respOut.Body)
	return respOut, body
}

func acmeIssueOneInner(base, dnsName string) ([]byte, string, *ecdsa.PrivateKey, string, error) {
	acctKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acctJWK := &jose.JSONWebKey{Key: acctKey.Public(), Algorithm: "ES256"}

	// /new-nonce
	resp, err := http.Head(base + "/new-nonce")
	if err != nil {
		return nil, "", nil, "", err
	}
	resp.Body.Close()
	nonce := resp.Header.Get("Replay-Nonce")

	// /new-account
	jws, err := jwsCompact(acctKey, acctJWK, "", nonce, base+"/new-account",
		mustJSON(acme.NewAccountReq{TermsOfServiceAgreed: true}))
	if err != nil {
		return nil, "", nil, "", err
	}
	resp, _, err = postJWS(base+"/new-account", jws)
	if err != nil {
		return nil, "", nil, "", err
	}
	kid := resp.Header.Get("Location")
	nonce = resp.Header.Get("Replay-Nonce")

	// /new-order
	jws, err = jwsCompact(acctKey, nil, kid, nonce, base+"/new-order",
		mustJSON(acme.NewOrderReq{Identifiers: []acme.Identifier{{Type: "dns", Value: dnsName}}}))
	if err != nil {
		return nil, "", nil, "", err
	}
	resp, body, err := postJWS(base+"/new-order", jws)
	if err != nil {
		return nil, "", nil, "", err
	}
	var ord acme.OrderResp
	if err := json.Unmarshal(body, &ord); err != nil {
		return nil, "", nil, "", err
	}
	if ord.Status != "ready" {
		return nil, "", nil, "", fmt.Errorf("order not ready: %s", ord.Status)
	}
	nonce = resp.Header.Get("Replay-Nonce")

	// CSR.
	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: dnsName},
		DNSNames: []string{dnsName},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, csrKey)
	if err != nil {
		return nil, "", nil, "", err
	}

	// /finalize
	jws, err = jwsCompact(acctKey, nil, kid, nonce, ord.Finalize,
		mustJSON(acme.FinalizeReq{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}))
	if err != nil {
		return nil, "", nil, "", err
	}
	resp, body, err = postJWS(ord.Finalize, jws)
	if err != nil {
		return nil, "", nil, "", err
	}
	var ord2 acme.OrderResp
	if err := json.Unmarshal(body, &ord2); err != nil {
		return nil, "", nil, "", err
	}
	if ord2.Status != "valid" || ord2.Certificate == "" {
		return nil, "", nil, "", fmt.Errorf("order not valid: %+v", ord2)
	}
	nonce = resp.Header.Get("Replay-Nonce")

	// Download cert via POST-as-GET (RFC 8555 §6.3).
	jws, err = jwsCompact(acctKey, nil, kid, nonce, ord2.Certificate, []byte{})
	if err != nil {
		return nil, "", nil, "", err
	}
	_, pemBytes, err := postJWS(ord2.Certificate, jws)
	if err != nil {
		return nil, "", nil, "", err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, "", nil, "", fmt.Errorf("not a PEM cert: %q", string(pemBytes))
	}
	return block.Bytes, ord2.Certificate, acctKey, kid, nil
}

// verifyAgainstLog runs the §7.2 verification: split cert, decode
// MTCProof, recompute leaf hash, evaluate inclusion proof, verify CA
// cosignature via cert.VerifyMTCSignature.
func verifyAgainstLog(der []byte, s *stack) error {
	tbs, _, sigValue, err := cert.SplitCertificate(der)
	if err != nil {
		return err
	}
	proof, err := cert.ParseMTCProof(sigValue)
	if err != nil {
		return err
	}
	tbsContents, serial, err := cert.RebuildLogEntryFromTBS(tbs, s.logIDDN)
	if err != nil {
		return err
	}
	leafHash := cert.EntryHash(tbsContents)
	got, err := tlogx.EvaluateInclusionProof(
		func(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) },
		proof.Start, proof.End, serial, leafHash, proof.InclusionProof,
	)
	if err != nil {
		return err
	}
	subtree := &cert.MTCSubtree{LogID: s.logID, Start: proof.Start, End: proof.End, Hash: got}
	sigInput, err := cert.MarshalSignatureInput(s.cosigner, subtree)
	if err != nil {
		return err
	}
	if len(proof.Signatures) != 1 {
		return fmt.Errorf("got %d signatures", len(proof.Signatures))
	}
	return cert.VerifyMTCSignature(cert.CosignerKey{
		ID:        s.cosigner,
		Algorithm: cert.AlgECDSAP256SHA256,
		PublicKey: s.signer.PublicKey(),
	}, proof.Signatures[0], sigInput)
}

// jwsCompact builds a Compact-Serialized JWS over payload.
func jwsCompact(key *ecdsa.PrivateKey, jwk *jose.JSONWebKey, kid, nonce, url string, payload []byte) (string, error) {
	opts := jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			"nonce":               nonce,
			jose.HeaderKey("url"): url,
		},
	}
	if jwk != nil {
		opts.EmbedJWK = true
	} else {
		opts.ExtraHeaders[jose.HeaderKey("kid")] = kid
	}
	sgn, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, &opts)
	if err != nil {
		return "", err
	}
	jws, err := sgn.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

func postJWS(url, body string) (*http.Response, []byte, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/jose+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return resp, b, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	return resp, b, nil
}

func mustJSON(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// httpGetBody is a tiny helper used by metrics_test.go.
func httpGetBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
