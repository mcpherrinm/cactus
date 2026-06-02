package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"

	"golang.org/x/mod/sumdb/tlog"
)

// sha256Sum is just sha256.Sum256, kept short for the helper above.
func sha256Sum(b []byte) [32]byte { return sha256.Sum256(b) }

// TestMirrorSignSubtreeHappyPath: stand up a CA + a follower, advance
// the follower, then send a well-formed sign-subtree request to the
// mirror's server and confirm the returned cosignature verifies.
func TestMirrorSignSubtreeHappyPath(t *testing.T) {
	ca := bringUp(t, t.TempDir())
	defer ca.close()

	for i := 0; i < 5; i++ {
		if _, err := acmeIssueOne(ca.acmeBase, fmt.Sprintf("ms%d.test", i)); err != nil {
			t.Fatal(err)
		}
	}

	mfs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	follower, err := mirror.NewFollower(mirror.FollowerConfig{
		Upstream: mirror.Upstream{
			TileURL: ca.tileBase, LogID: ca.logID,
			CACosignerID:  ca.cosigner,
			CACosignerKey: ca.signer.PublicKey(),
		},
		FS: mfs, PollInterval: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFollower(t, ctx, follower)
	caSize := waitFollowerCatchUp(t, follower, ca.log.CurrentCheckpoint().Size, 3*time.Second)

	// Mirror's own cosigner key (different from the CA's). The witness
	// path is ML-DSA-44 only.
	mirrorID := cert.TrustAnchorID("32473.21")
	mSigner, mKey := mldsaCosigner(t, mirrorID, 0xCC)

	srv, err := mirror.NewServer(mirror.ServerConfig{
		Follower:                    follower,
		Signer:                      mSigner,
		CosignerID:                  mirrorID,
		RequireCASignatureOnSubtree: false, // off so we don't have to forge a CA sig on the subtree
	})
	if err != nil {
		t.Fatal(err)
	}
	hSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sign-subtree" {
			srv.Handler().ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer hSrv.Close()

	// Pick a subtree the mirror can verify. [0, 1) (just the null entry).
	subtreeStart, subtreeEnd := uint64(0), uint64(1)
	subtreeHash, err := follower.SubtreeHash(subtreeStart, subtreeEnd)
	if err != nil {
		t.Fatal(err)
	}

	// Fetch the CA's current signed checkpoint as the cosigned-checkpoint
	// section of our request. The mirror's stateful check requires
	// (size, root) to match its current view, which equals the CA's
	// signed checkpoint that the follower just verified.
	cpResp, err := http.Get(ca.tileBase + "/checkpoint")
	if err != nil {
		t.Fatal(err)
	}
	cpBody, _ := io.ReadAll(cpResp.Body)
	cpResp.Body.Close()

	// Build the consistency proof from [start, end) up to the CA's
	// current size + root, using the CA's stored hashes.
	hashes, _, err := loadAllStoredHashes(ca.tileBase, caSize)
	if err != nil {
		t.Fatal(err)
	}
	hr := hashReaderFromSlice(hashes)
	proof, err := tlogx.GenerateConsistencyProof(
		sha256Hash, subtreeStart, subtreeEnd, caSize,
		func(i uint64) (tlogx.Hash, error) {
			// Look up leaf hash directly: stored index for level 0, n=i.
			hs, err := hr.ReadHashes([]int64{tlog.StoredHashIndex(0, int64(i))})
			if err != nil {
				return tlogx.Hash{}, err
			}
			return tlogx.Hash(hs[0]), nil
		})
	if err != nil {
		t.Fatal(err)
	}

	// Build the request body.
	body := buildSignSubtreeRequest(t, subtreeStart, subtreeEnd, subtreeHash, cpBody, proof)
	req, _ := http.NewRequest("POST", hSrv.URL+"/sign-subtree", bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, body=%s", resp.StatusCode, respBody)
	}

	// The body is one signature line:
	// "— oid/<mirrorID> base64(keyID || timestamped_signature)\n".
	line := strings.TrimRight(string(respBody), "\n")
	wantPrefix := "— " + cert.OIDName(mirrorID) + " "
	if !strings.HasPrefix(line, wantPrefix) {
		t.Fatalf("response missing expected prefix: %q", line)
	}
	rawWithKeyID, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, wantPrefix))
	if err != nil {
		t.Fatal(err)
	}
	if len(rawWithKeyID) < 5 {
		t.Fatalf("sig too short: %d", len(rawWithKeyID))
	}
	_, rawSig, err := cert.ParseTimestampedSignature(rawWithKeyID[4:])
	if err != nil {
		t.Fatalf("parse timestamped_signature: %v", err)
	}
	// Verify the signature against CosignedMessage.
	subtree := &cert.MTCSubtree{
		LogID: ca.logID,
		Start: subtreeStart, End: subtreeEnd, Hash: subtreeHash,
	}
	msg, err := cert.MarshalSignatureInput(mirrorID, subtree)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyMTCSignature(mKey,
		cert.MTCSignature{CosignerID: mirrorID, Signature: rawSig}, msg); err != nil {
		t.Errorf("mirror cosignature verify: %v", err)
	}
}

// TestMirrorSignSubtreeRejectsStaleCheckpoint: when the requester
// sends a checkpoint that doesn't match our verified state, return 409.
func TestMirrorSignSubtreeRejectsStaleCheckpoint(t *testing.T) {
	ca := bringUp(t, t.TempDir())
	defer ca.close()
	for i := 0; i < 3; i++ {
		_, _ = acmeIssueOne(ca.acmeBase, fmt.Sprintf("stale%d.test", i))
	}
	mfs, _ := storage.New(t.TempDir())
	follower, _ := mirror.NewFollower(mirror.FollowerConfig{
		Upstream: mirror.Upstream{
			TileURL: ca.tileBase, LogID: ca.logID,
			CACosignerID: ca.cosigner, CACosignerKey: ca.signer.PublicKey(),
		},
		FS: mfs, PollInterval: 25 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startFollower(t, ctx, follower)
	waitFollowerCatchUp(t, follower, ca.log.CurrentCheckpoint().Size, 2*time.Second)

	mSigner, _ := mldsaCosigner(t, cert.TrustAnchorID("32473.21"), 0x00)
	srv, _ := mirror.NewServer(mirror.ServerConfig{
		Follower: follower, Signer: mSigner,
		CosignerID: cert.TrustAnchorID("32473.21"),
	})
	hSrv := httptest.NewServer(srv.Handler())
	defer hSrv.Close()

	// Build a request whose reference checkpoint has the right origin but
	// the wrong size/root, so we pass the origin (404) and range (400)
	// checks but fail the stateful checkpoint comparison (409). The
	// checkpoint is a zero-signature note: body + a trailing blank line.
	bogusCP := []byte(cert.OIDName(ca.logID) + "\n9999\n" +
		base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n\n")
	body := buildSignSubtreeRequest(t, 0, 1, tlogx.Hash{}, bogusCP, nil)

	req, _ := http.NewRequest("POST", hSrv.URL, bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("status = %d, want 409", resp.StatusCode)
	}
}

func sha256Hash(b []byte) tlogx.Hash {
	return tlogx.Hash(sha256Sum(b))
}

func waitFollowerCatchUp(t *testing.T, f *mirror.Follower, want uint64, dur time.Duration) uint64 {
	t.Helper()
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		got, _, _ := f.Current()
		if got == want {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	got, _, _ := f.Current()
	t.Fatalf("follower never caught up: have %d want %d", got, want)
	return 0
}
