package ca

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"
)

// newDerivedLog builds a log wired the spec-correct way (the cosigner ID
// is the CA ID, §5.4, and the log ID is derived CA-ID.0.logNumber, §5.2)
// so the §7.2 verifier — which re-derives the log ID from the CA ID —
// reconstructs the same cosigner_name / log_origin.
func newDerivedLog(t *testing.T, caID cert.TrustAnchorID, logNumber uint16) (*cactuslog.Log, signer.Signer) {
	t.Helper()
	fs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0xCD}, signer.SeedSize)
	sgn, err := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	if err != nil {
		t.Fatal(err)
	}
	logID, err := cert.LogID(caID, logNumber)
	if err != nil {
		t.Fatal(err)
	}
	l, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID:       logID,
		CosignerID:  caID, // §5.4: CA cosigner ID == CA ID
		Signer:      sgn,
		FS:          fs,
		FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	return l, sgn
}

// TestRelyingPartyVerifyFromCACertificate ties findings 1, 2, 4 and 5
// together end-to-end: issue a real standalone certificate, represent the
// CA as a §5.5 CA certificate, derive a relying-party configuration from
// it (§7.1), and run the full §7.2 verification — including the binary
// cosigner_id, the re-derived cosigner_name/log_origin, revoked ranges
// (§7.5), and the trusted-subtree fast path (§7.4).
func TestRelyingPartyVerifyFromCACertificate(t *testing.T) {
	caID := cert.TrustAnchorID("32473.1")
	l, sgn := newDerivedLog(t, caID, 1)
	issuer, err := New(l, string(caID), 1)
	if err != nil {
		t.Fatal(err)
	}

	csr, _ := makeCSR(t, "rp.test")
	der, err := issuer.Issue(context.Background(), csr, OrderInput{
		AuthorizedDNSNames: []string{"rp.test"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Build the §5.5 CA certificate from the cosigner key + parameters.
	sigAlgOID, err := cert.SigAlgOID(cert.AlgECDSAP256SHA256)
	if err != nil {
		t.Fatal(err)
	}
	caCertDER, err := cert.BuildCACertificate(cert.CACertificateInput{
		CAID:         caID,
		CosignerSPKI: sgn.PublicKey(),
		LogHash:      cert.OIDDigestSHA256,
		SigAlg:       sigAlgOID,
		MinSerial:    0,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("BuildCACertificate: %v", err)
	}

	// Derive RP config from the CA certificate (§7.1).
	cfg, err := cert.ConfigFromCACertificate(caCertDER)
	if err != nil {
		t.Fatalf("ConfigFromCACertificate: %v", err)
	}
	if string(cfg.CAID) != "32473.1" {
		t.Errorf("cfg.CAID = %q, want 32473.1", cfg.CAID)
	}
	if !cfg.LogHash.Equal(cert.OIDDigestSHA256) {
		t.Errorf("cfg.LogHash = %v, want id-sha256", cfg.LogHash)
	}
	if len(cfg.Cosigners) != 1 || string(cfg.Cosigners[0].ID) != "32473.1" {
		t.Fatalf("cfg.Cosigners = %+v, want one cosigner with ID 32473.1", cfg.Cosigners)
	}

	// (1) Full §7.2 verification via cosignature must succeed.
	if err := cert.VerifyCertificate(der, cfg); err != nil {
		t.Fatalf("VerifyCertificate (cosignature path): %v", err)
	}

	// Pull out the serial / subtree for the next cases.
	tbs, _, sigValue, err := cert.SplitCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := cert.ParseMTCProof(sigValue)
	if err != nil {
		t.Fatal(err)
	}
	_, serial, err := cert.RebuildLogEntryFromTBS(tbs, cfg.CADN)
	if err != nil {
		t.Fatal(err)
	}
	logNumber, index, err := cert.SplitSerial(serial)
	if err != nil {
		t.Fatal(err)
	}
	if index != 0 {
		t.Errorf("first issued cert index = %d, want 0", index)
	}

	// (2) Revoked range covering the serial must reject (§7.5).
	revoked := cfg
	revoked.RevokedRanges = cert.RevokedRanges{{Start: 0, End: serial + 1}}
	if err := cert.VerifyCertificate(der, revoked); !errors.Is(err, cert.ErrRevoked) {
		t.Errorf("revoked serial: got %v, want ErrRevoked", err)
	}

	// (3) Trusted-subtree fast path (§7.4): with the subtree predistributed
	// the certificate verifies without consulting any cosigner key.
	subtreeHash, _, err := l.SubtreeProof(proof.Start, proof.End, index)
	if err != nil {
		t.Fatal(err)
	}
	fast := cfg
	fast.Cosigners = nil
	fast.RequiredCosigners = nil
	fast.TrustedSubtrees = map[cert.TrustedSubtreeKey]tlogx.Hash{
		{LogNumber: logNumber, Start: proof.Start, End: proof.End}: subtreeHash,
	}
	if err := cert.VerifyCertificate(der, fast); err != nil {
		t.Errorf("VerifyCertificate (trusted-subtree fast path): %v", err)
	}

	// (4) A wrong trusted-subtree hash must reject with ErrSubtreeMismatch.
	bad := cfg
	bad.Cosigners = nil
	bad.TrustedSubtrees = map[cert.TrustedSubtreeKey]tlogx.Hash{
		{LogNumber: logNumber, Start: proof.Start, End: proof.End}: {0x01},
	}
	if err := cert.VerifyCertificate(der, bad); !errors.Is(err, cert.ErrSubtreeMismatch) {
		t.Errorf("bad subtree hash: got %v, want ErrSubtreeMismatch", err)
	}
}
