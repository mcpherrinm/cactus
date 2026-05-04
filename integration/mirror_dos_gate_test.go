package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/mirror"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"

	"golang.org/x/mod/sumdb/tlog"
)

// TestMirrorRequireCASignatureGate covers the DoS-mitigation gate
// in mirror.Server. With RequireCASignatureOnSubtree=true:
//   - A request lacking the CA's signature on the subtree note → 400.
//   - A request whose CA-sig fails verification → 400.
//   - A request with a valid CA-sig → 200, signature returned.
func TestMirrorRequireCASignatureGate(t *testing.T) {
	ca := bringUp(t, t.TempDir())
	defer ca.close()
	for i := 0; i < 3; i++ {
		if _, err := acmeIssueOne(ca.acmeBase, fmt.Sprintf("dos%d.test", i)); err != nil {
			t.Fatal(err)
		}
	}

	mfs, _ := storage.New(t.TempDir())
	follower, _ := mirror.NewFollower(mirror.FollowerConfig{
		Upstream: mirror.Upstream{
			TileURL: ca.tileBase, LogID: ca.logID,
			CACosignerID:  ca.cosigner,
			CACosignerKey: ca.signer.PublicKey(),
		},
		FS: mfs, PollInterval: 25 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = follower.Run(ctx) }()
	caSize := waitFollowerCatchUp(t, follower, ca.log.CurrentCheckpoint().Size, 3*time.Second)

	// Mirror with the gate ON.
	mSeed := bytes.Repeat([]byte{0xDE}, signer.SeedSize)
	mSigner, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, mSeed)
	mirrorID := cert.TrustAnchorID("dos.mirror")
	srv, err := mirror.NewServer(mirror.ServerConfig{
		Follower:                    follower,
		Signer:                      mSigner,
		CosignerID:                  mirrorID,
		RequireCASignatureOnSubtree: true,
		UpstreamCAKey: &cert.CosignerKey{
			ID:        ca.cosigner,
			Algorithm: cert.AlgECDSAP256SHA256,
			PublicKey: ca.signer.PublicKey(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	hSrv := httptest.NewServer(srv.Handler())
	defer hSrv.Close()

	// Common: subtree, hash, proof, and the cosigned-checkpoint
	// section of the request body.
	subtreeStart, subtreeEnd := uint64(0), uint64(1)
	subtreeHash, err := follower.SubtreeHash(subtreeStart, subtreeEnd)
	if err != nil {
		t.Fatal(err)
	}
	hashes, _, err := loadAllStoredHashes(ca.tileBase, caSize)
	if err != nil {
		t.Fatal(err)
	}
	hr := hashReaderFromSlice(hashes)
	proof, err := tlogx.GenerateConsistencyProof(
		sha256Hash, subtreeStart, subtreeEnd, caSize,
		func(i uint64) (tlogx.Hash, error) {
			hs, err := hr.ReadHashes([]int64{tlog.StoredHashIndex(0, int64(i))})
			if err != nil {
				return tlogx.Hash{}, err
			}
			return tlogx.Hash(hs[0]), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	cpBody := ca.log.CurrentCheckpoint().SignedNote

	// (1) Request without any CA signature on the subtree → 400.
	noCASigBody := buildSignSubtreeRequest(t, ca.logID, subtreeStart, subtreeEnd, subtreeHash, cpBody, proof)
	resp1, err := http.Post(hSrv.URL, "text/plain", bytes.NewReader(noCASigBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadRequest {
		t.Errorf("no-CA-sig: status = %d, want 400", resp1.StatusCode)
	}

	// (2) Request with a *bogus* CA signature (corrupt bytes) → 400.
	bogusCASig := bytes.Repeat([]byte{0xFF}, 64)
	bogusBody := buildSignSubtreeRequestWithCASig(t, ca.logID, ca.cosigner,
		subtreeStart, subtreeEnd, subtreeHash, bogusCASig, cpBody, proof)
	resp2, err := http.Post(hSrv.URL, "text/plain", bytes.NewReader(bogusBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("bogus-CA-sig: status = %d, want 400", resp2.StatusCode)
	}

	// (3) Request with a *real* CA signature on the subtree → 200.
	mtcSubtree := &cert.MTCSubtree{
		LogID: ca.logID, Start: subtreeStart, End: subtreeEnd, Hash: subtreeHash,
	}
	caMsg, err := cert.MarshalSignatureInput(ca.cosigner, mtcSubtree)
	if err != nil {
		t.Fatal(err)
	}
	caSig, err := ca.signer.Sign(rand.Reader, caMsg)
	if err != nil {
		t.Fatal(err)
	}
	goodBody := buildSignSubtreeRequestWithCASig(t, ca.logID, ca.cosigner,
		subtreeStart, subtreeEnd, subtreeHash, caSig, cpBody, proof)
	resp3, err := http.Post(hSrv.URL, "text/plain", bytes.NewReader(goodBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	body3, _ := io.ReadAll(resp3.Body)
	if resp3.StatusCode != 200 {
		t.Fatalf("valid-CA-sig: status = %d, body=%s", resp3.StatusCode, body3)
	}
	if !strings.Contains(string(body3), "oid/"+string(mirrorID)) {
		t.Errorf("valid-CA-sig: response missing mirror sig line: %q", body3)
	}
}

// buildSignSubtreeRequestWithCASig is the same as
// buildSignSubtreeRequest but injects a CA signature line into the
// subtree note's signature section.
func buildSignSubtreeRequestWithCASig(
	t *testing.T,
	logID, caCosignerID cert.TrustAnchorID,
	start, end uint64, subtreeHash tlogx.Hash,
	caSig []byte,
	cpBody []byte, proof []tlogx.Hash,
) []byte {
	t.Helper()
	caKey := "oid/" + string(caCosignerID)
	keyID := mtcSubtreeKeyIDInline(caKey)
	blob := append(append([]byte(nil), keyID[:]...), caSig...)

	var b bytes.Buffer
	b.WriteString("oid/" + string(logID) + "\n")
	fmt.Fprintf(&b, "%d %d\n", start, end)
	b.WriteString(base64.StdEncoding.EncodeToString(subtreeHash[:]) + "\n")
	b.WriteString("\n") // body/sigs delimiter
	fmt.Fprintf(&b, "— %s %s\n", caKey, base64.StdEncoding.EncodeToString(blob))
	b.WriteString("\n") // §C.2 inter-section blank line
	b.Write(cpBody)
	if !bytes.HasSuffix(cpBody, []byte("\n")) {
		b.WriteString("\n")
	}
	if !bytes.HasSuffix(cpBody, []byte("\n\n")) {
		b.WriteString("\n")
	}
	for _, h := range proof {
		b.WriteString(base64.StdEncoding.EncodeToString(h[:]) + "\n")
	}
	return b.Bytes()
}

// mtcSubtreeKeyIDInline computes the §C.1 keyID for a subtree
// signature. Duplicates the helper in mirror/server.go and
// cert/cosigner_request.go but kept local to test code.
func mtcSubtreeKeyIDInline(keyName string) [4]byte {
	buf := append([]byte(keyName), 0x0A, 0xFF)
	buf = append(buf, []byte("mtc-subtree/v1")...)
	sum := sha256Sum(buf)
	var out [4]byte
	copy(out[:], sum[:4])
	return out
}
