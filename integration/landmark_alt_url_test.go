package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/acme"
	"github.com/letsencrypt/cactus/ca"
	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/landmark"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"
)

// TestAltURLServesLandmarkRelativeCert wires Phase 8.4 end-to-end:
// when a landmark sequence is configured and a covering landmark
// exists, GET /cert/{id}/alternate stops returning 503 and returns a
// real landmark-relative cert. Without the landmark, the existing
// stub still applies.
func TestAltURLServesLandmarkRelativeCert(t *testing.T) {
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, signer.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	s, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	logID := cert.TrustAnchorID("32473.1")
	cosigID := cert.TrustAnchorID("32473.1.ca")

	l, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID:       logID,
		CosignerID:  cosigID,
		Signer:      s,
		FS:          fs,
		FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()
	issuer, _ := ca.New(l, "32473.1")

	// Build a landmark sequence in the same data dir. Time interval
	// is 1ms so we can append immediately in tests.
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	seq, err := landmark.New(landmark.Config{
		BaseID:               cert.TrustAnchorID("32473.1.lm"),
		TimeBetweenLandmarks: time.Millisecond,
		MaxCertLifetime:      time.Hour,
	}, fs, t0)
	if err != nil {
		t.Fatal(err)
	}

	srv, _ := acme.New(acme.Config{
		Issuer:        issuer,
		ChallengeMode: acme.ChallengeAutoPass,
		Landmarks:     seq,
		SubtreeProof:  l.SubtreeProof,
		LogID:         logID,
	})
	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()
	srv.SetExternalURL(hsrv.URL)

	// Issue a few certs.
	const n = 4
	var certURLs []string
	for i := 0; i < n; i++ {
		der, err := acmeIssueOne(hsrv.URL, "alt"+strconv.Itoa(i)+".test")
		if err != nil {
			t.Fatal(err)
		}
		_ = der // we only need URLs; helper returned the DER, not the URL
		// Re-fetch the order's certificate URL via the directory? Not
		// needed — acmeIssueOne returns the cert DER but we want to
		// hit /alternate, so we need the cert ID. Easiest: parse the
		// DER, look up the cert by index in the certs map.
	}

	// Recover certificate URLs (and per-cert account keys) by hitting
	// the order via finalize body. Simpler: just re-issue and capture
	// finalize's response.
	type certCtx struct {
		url     string
		acctKey *ecdsa.PrivateKey
		kid     string
	}
	var certCtxs []certCtx
	{
		base := hsrv.URL
		certURLs = nil
		for i := 0; i < n; i++ {
			url, acctKey, kid, err := acmeIssueOneURL(t, base, "alt-real-"+strconv.Itoa(i)+".test")
			if err != nil {
				t.Fatal(err)
			}
			certURLs = append(certURLs, url)
			certCtxs = append(certCtxs, certCtx{url: url, acctKey: acctKey, kid: kid})
		}
	}

	// Wait for one flush cycle so all entries are committed.
	time.Sleep(100 * time.Millisecond)

	// Before allocating a landmark, /alternate must return 503.
	altURL := certURLs[0] + "/alternate"
	resp, _ := postAsGetWithAccept(t, hsrv.URL, altURL, "", certCtxs[0].acctKey, certCtxs[0].kid)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("pre-landmark alt status = %d, want 503", resp.StatusCode)
	}

	// Allocate a landmark covering the issued range.
	cp := l.CurrentCheckpoint()
	if _, ok, err := seq.Append(context.Background(), cp.Size, t0.Add(time.Second)); err != nil || !ok {
		t.Fatalf("Append: ok=%v err=%v", ok, err)
	}

	// Now /alternate must serve a real landmark-relative cert for
	// every issued cert.
	for i, ctx := range certCtxs {
		altURL := ctx.url + "/alternate"
		resp, body := postAsGetWithAccept(t, hsrv.URL, altURL, "", ctx.acctKey, ctx.kid)
		if resp.StatusCode != 200 {
			t.Fatalf("cert %d alt status = %d, body=%s", i, resp.StatusCode, body)
		}
		block, _ := pem.Decode(body)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatalf("cert %d not PEM CERTIFICATE: %q", i, body)
		}
		// Verify the §7.2 fast path: leaf hash + inclusion proof
		// reconstructs the subtree hash. No cosigner check needed.
		tbs, _, sigValue, err := cert.SplitCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := cert.ParseMTCProof(sigValue)
		if err != nil {
			t.Fatal(err)
		}
		if len(proof.Signatures) != 0 {
			t.Errorf("cert %d landmark variant has %d signatures, want 0", i, len(proof.Signatures))
		}
		tbsContents, serial, err := cert.RebuildLogEntryFromTBS(tbs, issuer.LogIDDN)
		if err != nil {
			t.Fatal(err)
		}
		leaf := cert.EntryHash(tbsContents)
		got, err := tlogx.EvaluateInclusionProof(
			func(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) },
			proof.Start, proof.End, serial, leaf, proof.InclusionProof,
		)
		if err != nil {
			t.Errorf("cert %d EvaluateInclusionProof: %v", i, err)
			continue
		}
		// The hash must equal what the live log returns for that
		// subtree — that's the relying-party invariant.
		want, _, err := l.SubtreeProof(proof.Start, proof.End, serial)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("cert %d: reconstructed hash %x != live %x", i, got[:8], want[:8])
		}
	}
}

// acmeIssueOneURL is acmeIssueOne but returns the cert URL plus the
// account key+kid needed to download it via POST-as-GET.
func acmeIssueOneURL(t *testing.T, base, dnsName string) (string, *ecdsa.PrivateKey, string, error) {
	t.Helper()
	_, certURL, acctKey, kid, err := acmeIssueOneInner(base, dnsName)
	return certURL, acctKey, kid, err
}
