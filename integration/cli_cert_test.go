package integration

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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
	"github.com/letsencrypt/cactus/tile"
	"github.com/letsencrypt/cactus/tlogx"
)

// TestCLICertText issues a standalone cert and checks `cactus-cli cert
// text` renders the entry fields, the decoded serial, and the MTC
// proof (standalone form, with cosigner signatures).
func TestCLICertText(t *testing.T) {
	s := bringUp(t, t.TempDir())
	defer s.close()

	der, err := acmeIssueOne(s.acmeBase, "text.test")
	if err != nil {
		t.Fatal(err)
	}
	pemPath := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(pemPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	bin := buildCLI(t)
	out, err := exec.Command(bin, "cert", "text", pemPath).CombinedOutput()
	if err != nil {
		t.Fatalf("cert text: %v\n%s", err, out)
	}
	str := string(out)
	for _, want := range []string{
		"Merkle Tree Certificate",
		"entry index 0",
		"subject:",
		"DNS:text.test",
		"form:            standalone",
		"subtree:         [0,",
	} {
		if !strings.Contains(str, want) {
			t.Errorf("cert text output missing %q:\n%s", want, str)
		}
	}
}

// TestCLICertLandmarkRelative issues a standalone cert, allocates a
// covering landmark, then runs `cactus-cli cert landmark-relative` and
// verifies the converted cert against the live log (the §7.2 fast path:
// the inclusion proof reconstructs the live subtree hash, with no
// cosigner signatures).
func TestCLICertLandmarkRelative(t *testing.T) {
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
		LogID:       logID,
		CosignerID:  logID,
		Signer:      sgn,
		FS:          fs,
		FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()
	issuer, _ := ca.New(l, "32473.1", 1)

	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	seq, err := landmark.New(landmark.Config{
		CAID:                 cert.TrustAnchorID("32473.1"),
		LogNumber:            1,
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
	if err := srv.AttachStorage(fs); err != nil {
		t.Fatal(err)
	}
	hAcme := httptest.NewServer(srv.Handler())
	defer hAcme.Close()
	srv.SetExternalURL(hAcme.URL)
	hTile := httptest.NewServer(tile.New(l, fs).WithLandmarks(seq).Handler())
	defer hTile.Close()

	// Issue a few certs so the inclusion proof inside the chosen subtree
	// is non-trivial.
	const n = 3
	for i := 0; i < n; i++ {
		if _, err := acmeIssueOne(hAcme.URL, "lr"+strconv.Itoa(i)+".test"); err != nil {
			t.Fatal(err)
		}
	}
	// Convert the index-1 cert (middle of the [0,2) subtree).
	der, err := acmeIssueOne(hAcme.URL, "lr-target.test")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let entries commit

	// Allocate a landmark covering everything issued so far.
	cp := l.CurrentCheckpoint()
	if _, ok, err := seq.Append(context.Background(), cp.Size, t0.Add(time.Second)); err != nil || !ok {
		t.Fatalf("landmark Append: ok=%v err=%v", ok, err)
	}

	pemPath := filepath.Join(t.TempDir(), "standalone.pem")
	if err := os.WriteFile(pemPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	bin := buildCLI(t)
	// Output() captures stdout only (the PEM); the status line goes to stderr.
	cmd := exec.Command(bin, "cert", "landmark-relative", pemPath, hTile.URL)
	outPEM, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("cert landmark-relative: %v\nstderr=%s", err, stderr)
	}

	block, _ := pem.Decode(outPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("output is not a PEM CERTIFICATE:\n%s", outPEM)
	}

	// The converted cert must verify against the live log: 0 signatures,
	// and the inclusion proof reconstructs the log's subtree hash.
	tbs, _, sigValue, err := cert.SplitCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := cert.ParseMTCProof(sigValue)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.Signatures) != 0 {
		t.Errorf("landmark-relative cert has %d signatures, want 0", len(proof.Signatures))
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
		t.Fatalf("EvaluateInclusionProof: %v", err)
	}
	want, _, err := l.SubtreeProof(proof.Start, proof.End, index)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("reconstructed subtree hash %x != live %x", got[:8], want[:8])
	}

	// `cert text` on the converted cert should report the landmark-relative form.
	lrPath := filepath.Join(t.TempDir(), "lr.pem")
	if err := os.WriteFile(lrPath, outPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	txt, err := exec.Command(bin, "cert", "text", lrPath).CombinedOutput()
	if err != nil {
		t.Fatalf("cert text (lr): %v\n%s", err, txt)
	}
	if !strings.Contains(string(txt), "form:            landmark-relative") {
		t.Errorf("converted cert text not reported landmark-relative:\n%s", txt)
	}
}
