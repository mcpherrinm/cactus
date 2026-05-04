package ca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"
)

// makeCSR returns a fresh ECDSA-P256 CSR with the given dNSName SAN.
func makeCSR(t *testing.T, name string) (*x509.CertificateRequest, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: name},
		DNSNames: []string{name},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr, priv
}

func newTestLog(t *testing.T) (*cactuslog.Log, signer.Signer, cert.TrustAnchorID, cert.TrustAnchorID) {
	t.Helper()
	fs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0xAB}, signer.SeedSize)
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
	t.Cleanup(l.Stop)
	return l, s, logID, cosignerID
}

// TestIssueRoundTripFullValidation is the §7.2 / Phase 3.3 invariant:
// after Issue(...) returns a DER cert,
//
//  1. parse the cert structure;
//  2. confirm signatureAlgorithm is id-alg-mtcProof;
//  3. decode the signatureValue as MTCProof;
//  4. recompute TBSCertificateLogEntry from the cert (substituting SPKI
//     with HASH(SPKI));
//  5. compute leaf hash = HASH(0x00 || 0x00 0x01 || tbsContents);
//  6. evaluate the inclusion proof and compare to MTCProof.subtree.hash;
//  7. verify the CA cosigner signature over MTCSubtreeSignatureInput.
//
// All seven checks must pass.
func TestIssueRoundTripFullValidation(t *testing.T) {
	l, sgn, logID, cosignerID := newTestLog(t)
	issuer, err := New(l, string(logID))
	if err != nil {
		t.Fatal(err)
	}

	csr, _ := makeCSR(t, "example.test")
	der, err := issuer.Issue(context.Background(), csr, OrderInput{
		AuthorizedDNSNames: []string{"example.test"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// (1) Parse cert.
	parsed, err := x509.ParseCertificate(der)
	// We expect ParseCertificate to fail because id-alg-mtcProof is
	// not a known signature algorithm; the parse should succeed enough
	// to give us a structure or fail with a recognizable error.
	if err == nil {
		t.Logf("ParseCertificate succeeded (alg recognized?): %v", parsed.SignatureAlgorithm)
	}

	// (2) & (3) Decode certificate structure.
	tbs, sigAlg, sigValue, err := cert.SplitCertificate(der)
	if err != nil {
		t.Fatalf("SplitCertificate: %v", err)
	}
	if !algIsMTCProof(sigAlg) {
		t.Errorf("signatureAlgorithm = %x, expected id-alg-mtcProof", sigAlg)
	}
	mtcProof, err := cert.ParseMTCProof(sigValue)
	if err != nil {
		t.Fatalf("ParseMTCProof: %v", err)
	}

	// (4) Reconstruct TBSCertificateLogEntry from the TBS by
	// stripping the serialNumber + signature, and replacing
	// subjectPublicKeyInfo with subjectPublicKeyAlgorithm + OCTET
	// STRING(HASH(SPKI)).
	rebuilt, serialFromCert, err := cert.RebuildLogEntryFromTBS(tbs, issuer.LogIDDN)
	if err != nil {
		t.Fatalf("RebuildLogEntryFromTBS: %v", err)
	}
	if serialFromCert != mtcProof.End-1-(mtcProof.End-mtcProof.Start-1) && serialFromCert == 0 {
		// trivial sanity: serial > 0 (entry 0 is null)
		t.Errorf("cert serial = %d (must be > 0)", serialFromCert)
	}
	if serialFromCert == 0 {
		t.Errorf("cert serial = 0 — must skip null entry")
	}

	// (5) Leaf hash = HASH(0x00 || 0x00 0x01 || tbsContents)
	leafHash := cert.EntryHash(rebuilt)

	// (6) Evaluate inclusion proof.
	got, err := tlogx.EvaluateInclusionProof(
		func(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) },
		mtcProof.Start, mtcProof.End,
		serialFromCert,
		leafHash,
		mtcProof.InclusionProof,
	)
	if err != nil {
		t.Fatalf("EvaluateInclusionProof: %v", err)
	}
	// The MTCProof embeds start/end but not the subtree hash itself —
	// it's reconstructed by the verifier. We compare against the value
	// the cosigner signed.
	subtree := &cert.MTCSubtree{
		LogID: logID,
		Start: mtcProof.Start,
		End:   mtcProof.End,
		Hash:  got,
	}
	sigInput, err := cert.MarshalSignatureInput(cosignerID, subtree)
	if err != nil {
		t.Fatal(err)
	}

	// (7) Verify cosignature.
	if len(mtcProof.Signatures) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(mtcProof.Signatures))
	}
	if !bytes.Equal(mtcProof.Signatures[0].CosignerID, cosignerID) {
		t.Errorf("cosigner ID = %q, want %q", mtcProof.Signatures[0].CosignerID, cosignerID)
	}
	if !verifySignature(t, sgn.PublicKey(), sigInput, mtcProof.Signatures[0].Signature) {
		t.Errorf("CA cosignature failed to verify")
	}
}

// algIsMTCProof returns true if the AlgorithmIdentifier DER algID
// matches id-alg-mtcProof with absent parameters.
func algIsMTCProof(algID []byte) bool {
	type alg struct {
		Algorithm asn1.ObjectIdentifier
	}
	var a alg
	if _, err := asn1.Unmarshal(algID, &a); err != nil {
		return false
	}
	return a.Algorithm.Equal(cert.OIDAlgMTCProof)
}

// verifySignature verifies an ECDSA-P256-SHA256 signature given an SPKI
// public key, message, and signature.
func verifySignature(t *testing.T, spki []byte, msg, sig []byte) bool {
	t.Helper()
	pubAny, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Errorf("parse SPKI: %v", err)
		return false
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		t.Errorf("not ECDSA")
		return false
	}
	digest := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}
