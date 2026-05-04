package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/mirror"
	"github.com/letsencrypt/cactus/storage"
)

// TestMirrorFollowerHappyPath stands up a CA cactus + a mirror
// follower pointed at its tile URL. Issues some certs on the CA,
// gives the follower time to advance, and confirms the mirror's
// verified state matches the CA's checkpoint.
func TestMirrorFollowerHappyPath(t *testing.T) {
	ca := bringUp(t, t.TempDir())
	defer ca.close()

	mirrorDir := t.TempDir()
	mfs, err := storage.New(mirrorDir)
	if err != nil {
		t.Fatal(err)
	}

	follower, err := mirror.NewFollower(mirror.FollowerConfig{
		Upstream: mirror.Upstream{
			TileURL:       ca.tileBase,
			LogID:         ca.logID,
			CACosignerID:  ca.cosigner,
			CACosignerKey: ca.signer.PublicKey(),
		},
		FS:           mfs,
		PollInterval: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = follower.Run(ctx) }()

	// Issue some certs on the CA.
	const n = 5
	for i := 0; i < n; i++ {
		if _, err := acmeIssueOne(ca.acmeBase, fmt.Sprintf("mf%d.test", i)); err != nil {
			t.Fatal(err)
		}
	}

	// Wait for the mirror to catch up.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		size, _, _ := follower.Current()
		caSize := ca.log.CurrentCheckpoint().Size
		if size > 0 && size == caSize {
			// Verify subtree hashes match the CA's. Pick a random
			// non-empty subtree.
			if size >= 2 {
				h1, err := follower.SubtreeHash(0, 1)
				if err != nil {
					t.Fatal(err)
				}
				if got, _, err := ca.log.SubtreeProof(0, 1, 0); err == nil && got != h1 {
					t.Fatalf("mirror SubtreeHash != CA: %x vs %x", h1[:8], got[:8])
				}
			}
			if follower.Halted() {
				t.Errorf("follower halted: should not have")
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	size, _, _ := follower.Current()
	t.Fatalf("mirror never caught up: mirror size=%d, CA size=%d",
		size, ca.log.CurrentCheckpoint().Size)
}

// TestMirrorFollowerHaltsOnBadKey: when the mirror is given the wrong
// CA cosigner public key, the very first poll should fail signature
// verification and halt the follower.
func TestMirrorFollowerHaltsOnBadKey(t *testing.T) {
	ca := bringUp(t, t.TempDir())
	defer ca.close()

	mirrorDir := t.TempDir()
	mfs, err := storage.New(mirrorDir)
	if err != nil {
		t.Fatal(err)
	}

	// Issue something so the CA has a non-trivial checkpoint that's
	// signed.
	if _, err := acmeIssueOne(ca.acmeBase, "haltkey.test"); err != nil {
		t.Fatal(err)
	}

	// Random/wrong public key.
	bogusKey := make([]byte, len(ca.signer.PublicKey()))
	for i := range bogusKey {
		bogusKey[i] = byte(i ^ 0x55)
	}
	follower, err := mirror.NewFollower(mirror.FollowerConfig{
		Upstream: mirror.Upstream{
			TileURL:       ca.tileBase,
			LogID:         ca.logID,
			CACosignerID:  ca.cosigner,
			CACosignerKey: bogusKey,
		},
		FS:           mfs,
		PollInterval: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = follower.Run(ctx) }()

	// Wait for halt.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if follower.Halted() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Errorf("follower never halted on bad key")
}
