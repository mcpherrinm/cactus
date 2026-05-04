package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// TestConcurrentFinalizeOnSameOrder confirms that two finalize calls
// racing on the same order do not produce two distinct cert IDs.
// Exactly one wins; the other gets orderNotReady.
func TestConcurrentFinalizeOnSameOrder(t *testing.T) {
	hsrv, _ := newTestStack(t)
	base := hsrv.URL

	acctKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	acctJWK := &jose.JSONWebKey{Key: acctKey.Public(), Algorithm: "ES256"}

	nonce := nonceFor(t, base)
	jws := jwsSign(t, acctKey, acctJWK, "", nonce, base+"/new-account",
		mustMarshal(NewAccountReq{TermsOfServiceAgreed: true}))
	resp, _ := post(t, base, "/new-account", jws)
	kid := resp.Header.Get("Location")
	nonce = resp.Header.Get("Replay-Nonce")

	jws = jwsSign(t, acctKey, nil, kid, nonce, base+"/new-order",
		mustMarshal(NewOrderReq{Identifiers: []Identifier{{Type: "dns", Value: "race.test"}}}))
	resp, body := post(t, base, "/new-order", jws)
	var ord OrderResp
	json.Unmarshal(body, &ord)

	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "race.test"},
		DNSNames: []string{"race.test"},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTmpl, csrKey)

	// Pre-build TWO finalize JWS bodies with distinct nonces; we'll
	// fire them concurrently. Each call needs its own nonce.
	fin := func() string {
		n := nonceFor(t, base)
		return jwsSign(t, acctKey, nil, kid, n, ord.Finalize,
			mustMarshal(FinalizeReq{CSR: base64.RawURLEncoding.EncodeToString(csrDER)}))
	}
	jws1 := fin()
	jws2 := fin()

	type result struct {
		statusCode int
		body       []byte
	}
	results := make([]result, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		r, b := post(t, base, "/finalize/"+lastSeg(ord.Finalize), jws1)
		results[0] = result{r.StatusCode, b}
	}()
	go func() {
		defer wg.Done()
		r, b := post(t, base, "/finalize/"+lastSeg(ord.Finalize), jws2)
		results[1] = result{r.StatusCode, b}
	}()
	wg.Wait()

	// Exactly one should be 200 (winner) and the other 403 (loser).
	wins := 0
	losses := 0
	for _, r := range results {
		switch r.statusCode {
		case 200:
			wins++
		case 403:
			losses++
		default:
			t.Errorf("unexpected status %d: %s", r.statusCode, r.body)
		}
	}
	if wins != 1 || losses != 1 {
		t.Errorf("got %d wins, %d losses (want 1, 1)", wins, losses)
	}
}
