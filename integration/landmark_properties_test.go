package integration

import (
	"context"
	"encoding/pem"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/acme"
	"github.com/letsencrypt/cactus/ca"
	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/landmark"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
)

// TestPEMWithPropertiesContent confirms that when the client sends
// `Accept: application/pem-certificate-chain-with-properties`, both
// the standalone /cert/{id} and the landmark-relative /alternate URL
// reply with a PEM CERTIFICATE block followed by a PEM `MTC PROPERTIES`
// block whose contents round-trip back to the expected
// CertificatePropertyList.
func TestPEMWithPropertiesContent(t *testing.T) {
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, signer.SeedSize)
	for i := range seed {
		seed[i] = 0x99
	}
	sgn, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	logID := cert.TrustAnchorID("32473.1")
	cosigID := cert.TrustAnchorID("32473.1.ca")
	baseLM := cert.TrustAnchorID("32473.1.lm")
	l, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID: logID, CosignerID: cosigID,
		Signer: sgn, FS: fs, FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()
	issuer, _ := ca.New(l, "32473.1")

	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	seq, err := landmark.New(landmark.Config{
		BaseID:               baseLM,
		TimeBetweenLandmarks: 5 * time.Millisecond,
		MaxCertLifetime:      20 * time.Millisecond, // MaxActive = 5
	}, fs, t0)
	if err != nil {
		t.Fatal(err)
	}

	srv, _ := acme.New(acme.Config{
		Issuer:         issuer,
		ChallengeMode:  acme.ChallengeAutoPass,
		Landmarks:      seq,
		SubtreeProof:   l.SubtreeProof,
		LogID:          logID,
		LandmarkBaseID: baseLM,
	})
	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()
	srv.SetExternalURL(hsrv.URL)

	// Issue, allocate landmark.
	_, certURL, acctKey, kid, err := acmeIssueOneWithKeys(hsrv.URL, "props.test")
	if err != nil {
		t.Fatal(err)
	}
	cp := l.CurrentCheckpoint()
	if _, ok, err := seq.Append(context.Background(), cp.Size, t0.Add(time.Second)); err != nil || !ok {
		t.Fatal(err)
	}

	// /cert/{id} with the with-properties Accept header (POST-as-GET).
	resp, body := postAsGetWithAccept(t, hsrv.URL, certURL,
		"application/pem-certificate-chain-with-properties", acctKey, kid)
	if resp.StatusCode != 200 {
		t.Fatalf("cert status = %d body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/pem-certificate-chain-with-properties" {
		t.Errorf("Content-Type = %q", got)
	}
	cBlock, rest := pem.Decode(body)
	if cBlock == nil || cBlock.Type != "CERTIFICATE" {
		t.Fatalf("first block not CERTIFICATE: %+v", cBlock)
	}
	pBlock, _ := pem.Decode(rest)
	if pBlock == nil || pBlock.Type != cert.PEMBlockProperties {
		t.Fatalf("missing %s block: %+v", cert.PEMBlockProperties, pBlock)
	}
	props, err := cert.ParsePropertyList(pBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(props) != 1 || props[0].Type != cert.PropertyTrustAnchorID ||
		string(props[0].TrustAnchorID) != string(logID) {
		t.Errorf("standalone properties = %+v, want one trust_anchor_id = %q", props, logID)
	}

	// /cert/{id}/alternate with the with-properties Accept header (POST-as-GET).
	altResp, altBody := postAsGetWithAccept(t, hsrv.URL, certURL+"/alternate",
		"application/pem-certificate-chain-with-properties", acctKey, kid)
	if altResp.StatusCode != 200 {
		t.Fatalf("alt status = %d body=%s", altResp.StatusCode, altBody)
	}
	c2, rest2 := pem.Decode(altBody)
	if c2 == nil || c2.Type != "CERTIFICATE" {
		t.Fatalf("alt: first block not CERTIFICATE")
	}
	p2, _ := pem.Decode(rest2)
	if p2 == nil || p2.Type != cert.PEMBlockProperties {
		t.Fatalf("alt: missing properties block")
	}
	altProps, err := cert.ParsePropertyList(p2.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// Expect: trust_anchor_id = "32473.1.lm.1" (landmark 1) +
	// additional_trust_anchor_ranges base="32473.1.lm" min=1 max=1+5-1=5
	if len(altProps) != 2 {
		t.Fatalf("alt properties len = %d, want 2", len(altProps))
	}
	if altProps[0].Type != cert.PropertyTrustAnchorID {
		t.Errorf("altProps[0].Type = %d", altProps[0].Type)
	}
	if string(altProps[0].TrustAnchorID) != "32473.1.lm.1" {
		t.Errorf("altProps[0].TrustAnchorID = %q, want 32473.1.lm.1", altProps[0].TrustAnchorID)
	}
	if altProps[1].Type != cert.PropertyAdditionalTAnchorRanges {
		t.Errorf("altProps[1].Type = %d", altProps[1].Type)
	}
	if len(altProps[1].Ranges) != 1 {
		t.Fatalf("altProps[1].Ranges len = %d", len(altProps[1].Ranges))
	}
	r := altProps[1].Ranges[0]
	if string(r.Base) != "32473.1.lm" {
		t.Errorf("range base = %q, want 32473.1.lm", r.Base)
	}
	if r.Min != 1 || r.Max != 5 {
		t.Errorf("range = [%d, %d], want [1, 5]", r.Min, r.Max)
	}
}
