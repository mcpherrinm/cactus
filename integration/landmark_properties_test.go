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
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
)

// TestPEMWithPropertiesContent confirms that when the client sends
// `Accept: application/pem-certificate-chain-with-properties`, the
// standalone /cert/{id} URL replies with a PEM `CERTIFICATE PROPERTIES`
// block (whose contents round-trip back to the expected
// CertificatePropertyList) followed by the PEM CERTIFICATE block, per
// trust-anchor-ids §6.1.
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
	sgn, _ := signer.FromSeed(signer.AlgMLDSA44, seed)
	logID := cert.TrustAnchorID("32473.1")
	cosigID := cert.TrustAnchorID("32473.1")
	l, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID: logID, CosignerID: cosigID,
		Signer: sgn, FS: fs, FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()
	issuer, _ := ca.New(l, "32473.1", 1)

	srv, _ := acme.New(acme.Config{
		Issuer:        issuer,
		ChallengeMode: acme.ChallengeAutoPass,
		LogID:         logID,
		CAID:          logID,
	})
	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()
	srv.SetExternalURL(hsrv.URL)

	_, certURL, acctKey, kid, err := acmeIssueOneWithKeys(hsrv.URL, "props.test")
	if err != nil {
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
	// Per trust-anchor-ids §6.1 the property list is first, cert second.
	pBlock, rest := pem.Decode(body)
	if pBlock == nil || pBlock.Type != cert.PEMBlockProperties {
		t.Fatalf("first block not %s: %+v", cert.PEMBlockProperties, pBlock)
	}
	cBlock, _ := pem.Decode(rest)
	if cBlock == nil || cBlock.Type != "CERTIFICATE" {
		t.Fatalf("missing CERTIFICATE block: %+v", cBlock)
	}
	props, err := cert.ParsePropertyList(pBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// draft-05 §8.1: a standalone cert carries a single trust_anchor_id
	// naming the CA.
	if len(props) != 1 || props[0].Type != cert.PropertyTrustAnchorID ||
		string(props[0].TrustAnchorID) != string(logID) {
		t.Errorf("standalone properties = %+v, want one trust_anchor_id = %q", props, logID)
	}
}
