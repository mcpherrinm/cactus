package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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

// TestEnhancementURLSwitchover wires the draft §9 landmark-relative
// "acme-optional-alternate" URL end-to-end:
//
//   - The standalone cert response advertises the landmark-relative cert
//     via rel="acme-optional-alternate", at a URL pinned to the landmark number it
//     will be relative to (an immutable resource).
//   - Before a covering landmark exists, that URL returns HTTP 202
//     (Accepted) + Retry-After — non-blocking, never a 5xx.
//   - Once a covering landmark is allocated, the *same* URL returns the
//     signature-free landmark-relative cert, which verifies against the
//     live log (the §7.2 fast path: no cosigner key consulted).
func TestEnhancementURLSwitchover(t *testing.T) {
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, signer.SeedSize)
	for i := range seed {
		seed[i] = 0x42
	}
	sgn, _ := signer.FromSeed(signer.AlgMLDSA44, seed)
	logID := cert.TrustAnchorID("32473.1")

	l, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID: logID, CosignerID: logID,
		Signer: sgn, FS: fs, FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()
	issuer, _ := ca.New(l, "32473.1", 1)

	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	// Nothing auto-allocates landmarks in this test — we call Append
	// explicitly — so a short interval just lets that manual Append clear
	// the §6.4.2 minimum-gap check.
	seq, err := landmark.New(landmark.Config{
		CAID: logID, LogNumber: 1,
		TimeBetweenLandmarks: time.Millisecond,
		MaxCertLifetime:      time.Hour,
	}, fs, t0)
	if err != nil {
		t.Fatal(err)
	}

	srv, _ := acme.New(acme.Config{
		Issuer: issuer, ChallengeMode: acme.ChallengeAutoPass,
		Landmarks: seq, SubtreeProof: l.SubtreeProof,
		LogID: logID, CAID: logID, LogNumber: 1,
	})
	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()
	srv.SetExternalURL(hsrv.URL)

	type certCtx struct {
		url     string // standalone cert URL
		enh     string // pinned landmark-relative (optional alternate) URL
		acctKey *ecdsa.PrivateKey
		kid     string
	}
	const n = 4
	var ctxs []certCtx
	for i := 0; i < n; i++ {
		_, certURL, acctKey, kid, err := acmeIssueOneWithKeys(hsrv.URL, "enh"+strconv.Itoa(i)+".test")
		if err != nil {
			t.Fatal(err)
		}
		// The standalone cert response advertises the optional-alternate URL.
		certResp, _ := postAsGetWithAccept(t, hsrv.URL, certURL, "", acctKey, kid)
		link := certResp.Header.Get("Link")
		if !strings.Contains(link, `rel="acme-optional-alternate"`) {
			t.Fatalf("cert %d Link missing rel=acme-optional-alternate: %q", i, link)
		}
		enh := linkURL(link)
		// Every cert here lands in landmark 1 (the first allocated), so
		// the pinned URL is stable and identical across certs.
		if !strings.HasSuffix(enh, "/landmark-relative/1") {
			t.Fatalf("cert %d optional-alternate URL = %q, want pinned to landmark 1", i, enh)
		}
		ctxs = append(ctxs, certCtx{url: certURL, enh: enh, acctKey: acctKey, kid: kid})
	}

	// Let all entries commit.
	time.Sleep(100 * time.Millisecond)

	// Before a covering landmark exists, the optional-alternate URL returns 202
	// + Retry-After (non-blocking).
	r0, _ := postAsGetWithAccept(t, hsrv.URL, ctxs[0].enh, "", ctxs[0].acctKey, ctxs[0].kid)
	if r0.StatusCode != http.StatusAccepted {
		t.Errorf("pre-landmark status = %d, want 202", r0.StatusCode)
	}
	if r0.Header.Get("Retry-After") == "" {
		t.Error("202 response missing Retry-After")
	}

	// Allocate a landmark covering everything issued so far.
	cp := l.CurrentCheckpoint()
	if _, ok, err := seq.Append(context.Background(), cp.Size, t0.Add(time.Second)); err != nil || !ok {
		t.Fatalf("landmark Append: ok=%v err=%v", ok, err)
	}

	// The same URLs now serve the real landmark-relative certs.
	for i, c := range ctxs {
		resp, body := postAsGetWithAccept(t, hsrv.URL, c.enh, "", c.acctKey, c.kid)
		if resp.StatusCode != 200 {
			t.Fatalf("cert %d post-landmark status = %d, body=%s", i, resp.StatusCode, body)
		}
		block, _ := pem.Decode(body)
		if block == nil || block.Type != "CERTIFICATE" {
			t.Fatalf("cert %d not PEM CERTIFICATE: %q", i, body)
		}
		// §7.2 fast path: 0 signatures, and the inclusion proof
		// reconstructs the live log's subtree hash — no cosigner key.
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
		tbsContents, serial, err := cert.RebuildLogEntryFromTBS(tbs, issuer.CADN)
		if err != nil {
			t.Fatal(err)
		}
		_, index, err := cert.SplitSerial(serial)
		if err != nil {
			t.Fatal(err)
		}
		leaf := cert.EntryHash(tbsContents)
		got, err := tlogx.EvaluateInclusionProof(
			func(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) },
			proof.Start, proof.End, index, leaf, proof.InclusionProof,
		)
		if err != nil {
			t.Errorf("cert %d EvaluateInclusionProof: %v", i, err)
			continue
		}
		want, _, err := l.SubtreeProof(proof.Start, proof.End, index)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("cert %d: reconstructed hash %x != live %x", i, got[:8], want[:8])
		}
	}

	// With the properties Accept header, the landmark-relative cert
	// carries trust_anchor_id = the landmark ID (CA-ID.1.logNumber.L,
	// draft-05 §8.2). Landmark 1 of log 1 under CA 32473.1 → 32473.1.1.1.1.
	resp, body := postAsGetWithAccept(t, hsrv.URL, ctxs[0].enh,
		"application/pem-certificate-chain-with-properties", ctxs[0].acctKey, ctxs[0].kid)
	if resp.StatusCode != 200 {
		t.Fatalf("with-properties status = %d", resp.StatusCode)
	}
	pBlock, _ := pem.Decode(body)
	if pBlock == nil || pBlock.Type != cert.PEMBlockProperties {
		t.Fatalf("first block not %s: %+v", cert.PEMBlockProperties, pBlock)
	}
	props, err := cert.ParsePropertyList(pBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(props) != 1 || props[0].Type != cert.PropertyTrustAnchorID ||
		string(props[0].TrustAnchorID) != "32473.1.1.1.1" {
		t.Errorf("landmark-relative properties = %+v, want trust_anchor_id 32473.1.1.1.1", props)
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
