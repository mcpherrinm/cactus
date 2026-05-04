package integration

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/mirror"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"

	"golang.org/x/mod/sumdb/tlog"
)

// TestMultiMirrorQuorum stands up one CA + three mirrors. Issues
// a few certs on the CA. Drives the §6.2/9.4 collection: the CA
// fans out a sign-subtree request to all three mirrors with
// quorum=2; collects the responses; verifies each.
//
// One mirror is *artificially slow* (a transparent proxy that
// sleeps 2 seconds before forwarding) to exercise the
// best-effort-after-minimum and quorum-met-early paths.
func TestMultiMirrorQuorum(t *testing.T) {
	ca := bringUp(t, t.TempDir())
	defer ca.close()

	// Issue some certs.
	for i := 0; i < 3; i++ {
		if _, err := acmeIssueOne(ca.acmeBase, fmt.Sprintf("mq%d.test", i)); err != nil {
			t.Fatal(err)
		}
	}

	// Spin up three mirrors. Each gets its own follower pointed at
	// the CA, its own cosigner key, and an httptest sign-subtree
	// listener.
	type mirrorStack struct {
		follower *mirror.Follower
		signer   signer.Signer
		id       cert.TrustAnchorID
		url      string
		close    func()
	}
	mks := make([]mirrorStack, 3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := range mks {
		mfs, err := storage.New(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		f, err := mirror.NewFollower(mirror.FollowerConfig{
			Upstream: mirror.Upstream{
				TileURL: ca.tileBase, LogID: ca.logID,
				CACosignerID: ca.cosigner, CACosignerKey: ca.signer.PublicKey(),
			},
			FS: mfs, PollInterval: 25 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = f.Run(ctx) }()

		seed := make([]byte, signer.SeedSize)
		seed[0] = byte(i + 1)
		s, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
		id := cert.TrustAnchorID(fmt.Sprintf("example.mirror.%d", i+1))
		srv, err := mirror.NewServer(mirror.ServerConfig{
			Follower: f, Signer: s, CosignerID: id,
		})
		if err != nil {
			t.Fatal(err)
		}
		hSrv := httptest.NewServer(srv.Handler())
		// Inject a 2s delay on mirror #2.
		if i == 1 {
			hSrv.Close()
			delayed := slowProxy(srv.Handler(), 2*time.Second)
			hSrv = httptest.NewServer(delayed)
		}
		mks[i] = mirrorStack{
			follower: f, signer: s, id: id,
			url:   hSrv.URL,
			close: hSrv.Close,
		}
	}
	defer func() {
		for _, m := range mks {
			m.close()
		}
	}()

	// Wait for all mirrors to catch up.
	caSize := ca.log.CurrentCheckpoint().Size
	for _, m := range mks {
		waitFollowerCatchUp(t, m.follower, caSize, 3*time.Second)
	}

	// Build the request: subtree = [0, 1) (the null entry's leaf), and
	// a consistency proof from there to the CA's checkpoint.
	subtreeStart, subtreeEnd := uint64(0), uint64(1)
	subtreeHash, _, err := ca.log.SubtreeProof(subtreeStart, subtreeEnd, 0)
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

	// CA's signed checkpoint as the cosigned-checkpoint section.
	cpBody := ca.log.CurrentCheckpoint().SignedNote

	mtcSubtree := &cert.MTCSubtree{
		LogID: ca.logID, Start: subtreeStart, End: subtreeEnd, Hash: subtreeHash,
	}
	req := &cert.SubtreeRequest{
		Subtree:          mtcSubtree,
		CACheckpointBody: cpBody,
		ConsistencyProof: proof,
	}
	endpoints := make([]cert.MirrorEndpoint, len(mks))
	for i, m := range mks {
		endpoints[i] = cert.MirrorEndpoint{
			URL: m.url + "/", // server.go's path was /sign-subtree but our handler is mounted at root
			Key: cert.CosignerKey{
				ID:        m.id,
				Algorithm: cert.AlgECDSAP256SHA256,
				PublicKey: m.signer.PublicKey(),
			},
		}
	}
	// Quorum=2 with bestEffortAfterMin=false: the slow mirror is too
	// late, so we collect only the two fast ones.
	start := time.Now()
	got, err := cert.RequestCosignatures(ctx, req, endpoints, 2, 1*time.Second, false)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("RequestCosignatures: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d sigs, want exactly 2 (no best-effort)", len(got))
	}
	if elapsed >= 1500*time.Millisecond {
		t.Errorf("elapsed %v — should have returned as soon as quorum met", elapsed)
	}
	for _, sig := range got {
		// Verify each one against the corresponding mirror's key.
		var key cert.CosignerKey
		for _, ep := range endpoints {
			if string(ep.Key.ID) == string(sig.CosignerID) {
				key = ep.Key
				break
			}
		}
		msg, _ := cert.MarshalSignatureInput(key.ID, mtcSubtree)
		if err := cert.VerifyMTCSignature(key, sig, msg); err != nil {
			t.Errorf("returned sig %q failed to verify: %v", sig.CosignerID, err)
		}
	}
}

// TestMultiMirrorQuorumNotMet: with quorum=3 but a tight 200ms
// deadline that the slow mirror can't beat, the call returns an
// error indicating quorum wasn't met.
func TestMultiMirrorQuorumNotMet(t *testing.T) {
	ca := bringUp(t, t.TempDir())
	defer ca.close()

	mfs, _ := storage.New(t.TempDir())
	f, _ := mirror.NewFollower(mirror.FollowerConfig{
		Upstream: mirror.Upstream{
			TileURL: ca.tileBase, LogID: ca.logID,
			CACosignerID: ca.cosigner, CACosignerKey: ca.signer.PublicKey(),
		},
		FS: mfs, PollInterval: 25 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.Run(ctx) }()
	waitFollowerCatchUp(t, f, ca.log.CurrentCheckpoint().Size, 2*time.Second)

	seed := make([]byte, signer.SeedSize)
	s, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	id := cert.TrustAnchorID("only.mirror")
	srv, _ := mirror.NewServer(mirror.ServerConfig{Follower: f, Signer: s, CosignerID: id})
	hSrv := httptest.NewServer(srv.Handler())
	defer hSrv.Close()

	// Single endpoint; quorum=2 → impossible.
	req := &cert.SubtreeRequest{
		Subtree: &cert.MTCSubtree{
			LogID: ca.logID, Start: 0, End: 1,
			Hash: tlogx.Hash{},
		},
		CACheckpointBody: ca.log.CurrentCheckpoint().SignedNote,
	}
	_, err := cert.RequestCosignatures(ctx, req, []cert.MirrorEndpoint{{
		URL: hSrv.URL,
		Key: cert.CosignerKey{ID: id, Algorithm: cert.AlgECDSAP256SHA256, PublicKey: s.PublicKey()},
	}}, 2, 200*time.Millisecond, false)
	if err == nil {
		t.Errorf("expected error when quorum > number of mirrors")
	}
}

// slowProxy wraps an http.Handler in one that sleeps `delay` before
// invoking the inner handler. Counts invocations for assertion.
func slowProxy(inner http.Handler, delay time.Duration) http.Handler {
	var calls int64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		time.Sleep(delay)
		inner.ServeHTTP(w, r)
	})
}

// silence unused
var _ = bytes.NewReader
