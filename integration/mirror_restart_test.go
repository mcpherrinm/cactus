package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/mirror"
	"github.com/letsencrypt/cactus/storage"
)

// TestMirrorRestartResume implements the v3-DoD restart line item:
// stop a mirror mid-follow, restart it with the same data dir, and
// confirm it catches up to the (now-larger) upstream without
// double-counting entries.
//
// The simplest correctness check: after restart, the mirror's local
// SubtreeHash for [0, size) must equal the CA's signed root. If we
// double-counted any entry we'd land on a different root.
func TestMirrorRestartResume(t *testing.T) {
	ca := bringUp(t, t.TempDir())
	defer ca.close()

	mirrorDir := t.TempDir()
	mfs1, err := storage.New(mirrorDir)
	if err != nil {
		t.Fatal(err)
	}
	upstream := mirror.Upstream{
		TileURL:       ca.tileBase,
		LogID:         ca.logID,
		CACosignerID:  ca.cosigner,
		CACosignerKey: ca.signer.PublicKey(),
	}

	// First mirror process: follow until caught up to a few certs.
	f1, err := mirror.NewFollower(mirror.FollowerConfig{
		Upstream:     upstream,
		FS:           mfs1,
		PollInterval: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	go func() { _ = f1.Run(ctx1) }()

	for i := 0; i < 4; i++ {
		if _, err := acmeIssueOne(ca.acmeBase, fmt.Sprintf("mr-pre-%d.test", i)); err != nil {
			t.Fatal(err)
		}
	}
	cpAfterFirstBatch := ca.log.CurrentCheckpoint().Size
	waitFollowerCatchUp(t, f1, cpAfterFirstBatch, 3*time.Second)

	// Stop the mirror mid-life. cancel1 unblocks Run, but the in-memory
	// state of f1 is gone. Persisted state (state/mirror/upstream/{checkpoint,size})
	// remains on disk under mirrorDir.
	cancel1()
	time.Sleep(50 * time.Millisecond) // let the goroutine exit cleanly

	// CA keeps going.
	for i := 0; i < 4; i++ {
		if _, err := acmeIssueOne(ca.acmeBase, fmt.Sprintf("mr-post-%d.test", i)); err != nil {
			t.Fatal(err)
		}
	}
	cpAfterSecondBatch := ca.log.CurrentCheckpoint().Size
	if cpAfterSecondBatch <= cpAfterFirstBatch {
		t.Fatal("CA did not advance after restart")
	}

	// Reopen the mirror against the same data dir.
	mfs2, err := storage.New(mirrorDir)
	if err != nil {
		t.Fatal(err)
	}
	f2, err := mirror.NewFollower(mirror.FollowerConfig{
		Upstream:     upstream,
		FS:           mfs2,
		PollInterval: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if f2.Halted() {
		t.Fatal("follower restarted in halted state")
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	go func() { _ = f2.Run(ctx2) }()

	// Catch up.
	waitFollowerCatchUp(t, f2, cpAfterSecondBatch, 3*time.Second)
	if f2.Halted() {
		t.Fatal("follower halted during catch-up — possible double-count")
	}

	// Cross-check: the mirror's [0, size) subtree hash must equal the
	// CA's checkpoint root. Any double-count or off-by-one would land
	// on a different root.
	mSize, mRoot, _ := f2.Current()
	if mSize != cpAfterSecondBatch {
		t.Fatalf("mirror size = %d, CA = %d", mSize, cpAfterSecondBatch)
	}
	caCp := ca.log.CurrentCheckpoint()
	if mRoot != caCp.Root {
		t.Errorf("mirror root %x != CA root %x", mRoot[:8], caCp.Root[:8])
	}
}

// TestMirrorHaltedSurvivesRestart: when the follower halts on a
// consistency failure, the halted marker on disk survives a restart
// — the follower comes back up halted and refuses to advance.
func TestMirrorHaltedSurvivesRestart(t *testing.T) {
	ca := bringUp(t, t.TempDir())
	defer ca.close()

	if _, err := acmeIssueOne(ca.acmeBase, "halt.test"); err != nil {
		t.Fatal(err)
	}

	mirrorDir := t.TempDir()
	mfs1, _ := storage.New(mirrorDir)

	bogusKey := make([]byte, len(ca.signer.PublicKey()))
	for i := range bogusKey {
		bogusKey[i] = byte(i ^ 0x44)
	}
	f1, err := mirror.NewFollower(mirror.FollowerConfig{
		Upstream: mirror.Upstream{
			TileURL: ca.tileBase, LogID: ca.logID,
			CACosignerID: ca.cosigner, CACosignerKey: bogusKey,
		},
		FS: mfs1, PollInterval: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	go func() { _ = f1.Run(ctx1) }()

	// Wait for halt.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !f1.Halted() {
		time.Sleep(25 * time.Millisecond)
	}
	if !f1.Halted() {
		t.Fatal("follower did not halt")
	}
	cancel1()

	// Restart: should come up halted from the persisted marker, even
	// with a (now correct) key.
	mfs2, _ := storage.New(mirrorDir)
	f2, err := mirror.NewFollower(mirror.FollowerConfig{
		Upstream: mirror.Upstream{
			TileURL: ca.tileBase, LogID: ca.logID,
			CACosignerID: ca.cosigner, CACosignerKey: ca.signer.PublicKey(),
		},
		FS: mfs2, PollInterval: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !f2.Halted() {
		t.Errorf("follower should still be halted after restart")
	}
}
