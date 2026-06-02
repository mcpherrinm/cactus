package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/mirror"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"

	"golang.org/x/mod/sumdb/tlog"
)

// TestMirrorRequireCASignatureGate covers the DoS-mitigation gate
// in mirror.Server. With RequireCASignatureOnSubtree=true:
//   - A request lacking the CA's signature on the subtree note → 403.
//   - A request whose CA-sig fails verification → 403.
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
	startFollower(t, ctx, follower)
	caSize := waitFollowerCatchUp(t, follower, ca.log.CurrentCheckpoint().Size, 3*time.Second)

	// Mirror with the gate ON. The witness key is ML-DSA-44. The CA's
	// subtree cosigner is also ML-DSA-44 (distinct from its ECDSA
	// checkpoint key); the gate requires that cosignature.
	mirrorID := cert.TrustAnchorID("32473.23")
	mSigner, _ := mldsaCosigner(t, mirrorID, 0xDE)
	caSubSigner, caSubKey := mldsaCosigner(t, ca.cosigner, 0x77)
	srv, err := mirror.NewServer(mirror.ServerConfig{
		Follower:                    follower,
		Signer:                      mSigner,
		CosignerID:                  mirrorID,
		RequireCASignatureOnSubtree: true,
		UpstreamCAKey:               &caSubKey,
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
	noCASigBody := buildSignSubtreeRequest(t, subtreeStart, subtreeEnd, subtreeHash, cpBody, proof)
	resp1, err := http.Post(hSrv.URL, "text/plain", bytes.NewReader(noCASigBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusForbidden {
		t.Errorf("no-CA-sig: status = %d, want 403", resp1.StatusCode)
	}

	// (2) Request with a *bogus* CA signature (right key ID, corrupt
	// bytes that fail to verify) → 400.
	bogusCASig := bytes.Repeat([]byte{0xFF}, 64)
	bogusBody := buildSignSubtreeRequestWithCASig(t, ca.cosigner, cert.AlgMLDSA44, caSubKey.PublicKey,
		subtreeStart, subtreeEnd, subtreeHash, bogusCASig, cpBody, proof)
	resp2, err := http.Post(hSrv.URL, "text/plain", bytes.NewReader(bogusBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("bogus-CA-sig: status = %d, want 403", resp2.StatusCode)
	}

	// (3) Request with a *real* CA signature on the subtree → 200.
	mtcSubtree := &cert.MTCSubtree{
		LogID: ca.logID, Start: subtreeStart, End: subtreeEnd, Hash: subtreeHash,
	}
	caMsg, err := cert.MarshalSignatureInput(ca.cosigner, mtcSubtree)
	if err != nil {
		t.Fatal(err)
	}
	caSig, err := caSubSigner.Sign(rand.Reader, caMsg)
	if err != nil {
		t.Fatal(err)
	}
	goodBody := buildSignSubtreeRequestWithCASig(t, ca.cosigner, cert.AlgMLDSA44, caSubKey.PublicKey,
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
	if !strings.Contains(string(body3), cert.OIDName(mirrorID)) {
		t.Errorf("valid-CA-sig: response missing mirror sig line: %q", body3)
	}
}
