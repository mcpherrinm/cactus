package log

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
)

// TestCheckpointSignatureVerifies brings up a log, fetches the latest
// signed-note checkpoint, and verifies the cosigner's signature against
// the §5.4.1 MTCSubtreeSignatureInput for [0, size). This exercises a
// path the integration test only covers indirectly (it verifies subtree
// signatures, not checkpoint signatures).
func TestCheckpointSignatureVerifies(t *testing.T) {
	fs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x77}, signer.SeedSize)
	s, err := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	if err != nil {
		t.Fatal(err)
	}
	logID := cert.TrustAnchorID("32473.1")
	cosignerID := cert.TrustAnchorID("32473.1.ca")
	l, err := New(context.Background(), Config{
		LogID:       logID,
		CosignerID:  cosignerID,
		Signer:      s,
		FS:          fs,
		FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	// Append one entry so the checkpoint covers something non-trivial.
	idem := sha256.Sum256([]byte("entry-1"))
	idx, err := l.Append(context.Background(), cert.EncodeTBSCertEntry([]byte("entry-1")), idem)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := l.Wait(ctx, idx); err != nil {
		t.Fatal(err)
	}

	cp := l.CurrentCheckpoint()
	if cp.Size < 2 {
		t.Fatalf("expected size >= 2 (null + entry), got %d", cp.Size)
	}

	// Parse the signed note: 3 body lines, blank line, 1 signature line.
	body := string(cp.SignedNote)
	parts := strings.SplitN(body, "\n\n", 2)
	if len(parts) != 2 {
		t.Fatalf("checkpoint missing blank-line separator: %q", body)
	}
	bodyLines := strings.Split(strings.TrimRight(parts[0], "\n"), "\n")
	if len(bodyLines) != 3 {
		t.Fatalf("expected 3 body lines, got %d", len(bodyLines))
	}
	if bodyLines[0] != "oid/"+string(logID) {
		t.Errorf("origin = %q, want %q", bodyLines[0], "oid/"+string(logID))
	}

	// Signature line: "— <key> <base64(keyID(4) || sig)>".
	sigLines := strings.Split(strings.TrimRight(parts[1], "\n"), "\n")
	if len(sigLines) < 1 {
		t.Fatal("no signature lines")
	}
	const emDash = "—"
	sigLine := sigLines[0]
	if !strings.HasPrefix(sigLine, emDash+" ") {
		t.Fatalf("signature line missing em-dash prefix: %q", sigLine)
	}
	sigParts := strings.SplitN(sigLine[len(emDash)+1:], " ", 2)
	if len(sigParts) != 2 {
		t.Fatalf("malformed sig line: %q", sigLine)
	}
	sigKeyName := sigParts[0]
	if sigKeyName != "oid/"+string(cosignerID) {
		t.Errorf("sig key = %q, want %q", sigKeyName, "oid/"+string(cosignerID))
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigParts[1])
	if err != nil {
		t.Fatalf("decode sig b64: %v", err)
	}
	if len(sigBytes) < 5 {
		t.Fatalf("sig too short: %d bytes", len(sigBytes))
	}
	// First 4 bytes are the §C.1 keyID; rest is the raw signature.
	wantKeyID := MTCCheckpointKeyID("oid/" + string(cosignerID))
	if !bytes.Equal(sigBytes[:4], wantKeyID[:]) {
		t.Errorf("keyID mismatch: got %x, want %x", sigBytes[:4], wantKeyID)
	}
	rawSig := sigBytes[4:]

	// Build MTCSubtreeSignatureInput for [0, size) with the checkpoint root.
	subtree := &cert.MTCSubtree{
		LogID: logID, Start: 0, End: cp.Size, Hash: cp.Root,
	}
	sigInput, err := cert.MarshalSignatureInput(cosignerID, subtree)
	if err != nil {
		t.Fatal(err)
	}

	// Verify ECDSA signature.
	pubAny, err := x509.ParsePKIXPublicKey(s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	pub := pubAny.(*ecdsa.PublicKey)
	digest := sha256.Sum256(sigInput)
	if !ecdsa.VerifyASN1(pub, digest[:], rawSig) {
		t.Errorf("checkpoint cosignature failed to verify")
	}
}

// MTCCheckpointKeyID exposes the §C.1 checkpoint keyID for tests.
// (Internal helper; promoted here as the lowercase variant lives in
// note.go.)
func MTCCheckpointKeyID(keyName string) [4]byte {
	return mtcCheckpointKeyID(keyName)
}
