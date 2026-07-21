package log

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"
	"golang.org/x/mod/sumdb/tlog"
)

func newTestLog(t *testing.T) (*Log, signer.Signer, storage.FS) {
	t.Helper()
	fs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x42}, signer.SeedSize)
	s, err := signer.FromSeed(signer.AlgMLDSA44, seed)
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(context.Background(), Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1"),
		Signer:      s,
		FS:          fs,
		FlushPeriod: 25 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	return l, s, fs
}

// TestLogStartsEmptyAndFirstEntryIsIndexZero pins draft-05 §5.2.1: a
// fresh log starts empty (no reserved index-0 null_entry), and the first
// appended entry is assigned index 0. (Regression for review finding 3.)
func TestLogStartsEmptyAndFirstEntryIsIndexZero(t *testing.T) {
	l, _, _ := newTestLog(t)
	if got := l.tw.Size(); got != 0 {
		t.Errorf("tw.Size = %d, want 0 (empty log, no reserved null entry)", got)
	}
	if cp := l.CurrentCheckpoint(); cp.Size != 0 {
		t.Errorf("Checkpoint.Size = %d, want 0", cp.Size)
	}
	tbs := []byte{0xCA, 0xFE}
	idx, err := l.Append(context.Background(), cert.EncodeTBSCertEntry(tbs), sha256.Sum256(tbs))
	if err != nil {
		t.Fatal(err)
	}
	if idx != 0 {
		t.Errorf("first entry index = %d, want 0", idx)
	}
}

func TestAppendAndWait(t *testing.T) {
	l, _, _ := newTestLog(t)

	// Submit a real entry.
	tbsContents := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	entry := cert.EncodeTBSCertEntry(tbsContents)
	idem := sha256.Sum256(tbsContents)
	idx, err := l.Append(context.Background(), entry, idem)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	iss, err := l.Wait(ctx, idx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if iss.Index != idx {
		t.Errorf("Issued.Index = %d, want %d", iss.Index, idx)
	}

	// Verify the inclusion proof against the subtree hash.
	leafHash := tlogx.HashLeaf(func(b []byte) tlogx.Hash {
		return tlogx.Hash(sha256.Sum256(b))
	}, entry)
	got, err := tlogx.EvaluateInclusionProof(
		func(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) },
		iss.Subtree.Start, iss.Subtree.End, idx, leafHash, iss.InclusionProof,
	)
	if err != nil {
		t.Fatalf("EvaluateInclusionProof: %v", err)
	}
	if got != iss.Subtree.Hash {
		t.Errorf("inclusion proof hash mismatch: got %x, want %x", got, iss.Subtree.Hash)
	}
}

func TestAppendIdempotency(t *testing.T) {
	l, _, _ := newTestLog(t)
	entry := cert.EncodeTBSCertEntry([]byte{1, 2, 3})
	idem := sha256.Sum256(entry)
	idx1, err := l.Append(context.Background(), entry, idem)
	if err != nil {
		t.Fatal(err)
	}
	idx2, err := l.Append(context.Background(), entry, idem)
	if err != nil {
		t.Fatal(err)
	}
	if idx1 != idx2 {
		t.Errorf("idempotency broken: %d vs %d", idx1, idx2)
	}
}

func TestParallelAppendEachVerified(t *testing.T) {
	l, _, _ := newTestLog(t)
	const n = 50
	var wg sync.WaitGroup
	results := make([]Issued, n)
	indices := make([]uint64, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			entry := cert.EncodeTBSCertEntry([]byte{byte(i), byte(i >> 8)})
			idem := sha256.Sum256(entry)
			idx, err := l.Append(context.Background(), entry, idem)
			if err != nil {
				t.Errorf("Append: %v", err)
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			iss, err := l.Wait(ctx, idx)
			if err != nil {
				t.Errorf("Wait(%d): %v", idx, err)
				return
			}
			results[i] = iss
			indices[i] = idx
		}(i)
	}
	wg.Wait()

	// Each result should verify against its subtree hash.
	for i, iss := range results {
		entry := cert.EncodeTBSCertEntry([]byte{byte(i), byte(i >> 8)})
		leafHash := tlogx.HashLeaf(
			func(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) },
			entry,
		)
		got, err := tlogx.EvaluateInclusionProof(
			func(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) },
			iss.Subtree.Start, iss.Subtree.End, indices[i], leafHash, iss.InclusionProof,
		)
		if err != nil {
			t.Errorf("entry %d: %v", i, err)
			continue
		}
		if got != iss.Subtree.Hash {
			t.Errorf("entry %d: hash mismatch", i)
		}
	}
}

func TestSignedNoteRoundTrip(t *testing.T) {
	root := tlogx.Hash{0xab, 0xcd, 0xef}
	nb, err := buildSignedNote(
		cert.TrustAnchorID("32473.1"),
		cert.TrustAnchorID("32473.1"),
		42, root, cert.AlgMLDSA44, make([]byte, 1312), []byte("signature"),
	)
	if err != nil {
		t.Fatal(err)
	}
	gotSize, gotRoot, err := parseSignedNote(nb, cert.TrustAnchorID("32473.1"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if gotSize != 42 {
		t.Errorf("size = %d", gotSize)
	}
	if gotRoot != root {
		t.Errorf("root mismatch")
	}
}

func TestLogReloadAfterRestart(t *testing.T) {
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x55}, signer.SeedSize)
	s, _ := signer.FromSeed(signer.AlgMLDSA44, seed)

	l1, err := New(context.Background(), Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1"),
		Signer:      s,
		FS:          fs,
		FlushPeriod: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		entry := cert.EncodeTBSCertEntry([]byte{byte(i)})
		idem := sha256.Sum256(entry)
		idx, _ := l1.Append(context.Background(), entry, idem)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := l1.Wait(ctx, idx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
	cp1 := l1.CurrentCheckpoint()
	l1.Stop()

	// Reopen.
	fs2, _ := storage.New(dir)
	l2, err := New(context.Background(), Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1"),
		Signer:      s,
		FS:          fs2,
		FlushPeriod: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Stop()
	cp2 := l2.CurrentCheckpoint()
	if cp1.Size != cp2.Size {
		t.Errorf("size after reload = %d, want %d", cp2.Size, cp1.Size)
	}
	if cp1.Root != cp2.Root {
		t.Errorf("root after reload differs")
	}
}

// TestEntriesAndTreeConsistencyProof covers the two read-path additions
// the tlog-mirror push client needs from the log: entry read-back, and
// the RFC 6962 *tree* consistency proof used by add-checkpoint — as
// distinct from ConsistencyProof, which is the MTC §4.4 *subtree* proof
// used by sign-subtree and by add-entries packages.
func TestEntriesAndTreeConsistencyProof(t *testing.T) {
	l, _, _ := newTestLog(t)
	ctx := context.Background()

	const n = 40
	want := make([][]byte, n)
	for i := range want {
		tbs := []byte{byte(i), 0xAA}
		want[i] = cert.EncodeTBSCertEntry(tbs)
		if _, err := l.Append(ctx, want[i], sha256.Sum256(tbs)); err != nil {
			t.Fatal(err)
		}
	}
	// Wait for the entries to be sequenced into a checkpoint.
	if _, err := l.Wait(ctx, n-1); err != nil {
		t.Fatal(err)
	}

	got, err := l.Entries(0, n)
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("Entries()[%d] = %x, want %x", i, got[i], want[i])
		}
	}
	// A sub-range must be the corresponding slice.
	mid, err := l.Entries(7, 19)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range mid {
		if !bytes.Equal(e, want[7+i]) {
			t.Fatalf("Entries(7,19)[%d] mismatch", i)
		}
	}

	// Tree consistency proofs must verify with the RFC 6962 checker.
	size := l.CurrentCheckpoint().Size
	newRoot, err := tlog.TreeHash(int64(size), hashesAsTlog(l.tw.SnapshotHashes()))
	if err != nil {
		t.Fatal(err)
	}
	for old := uint64(1); old < size; old++ {
		proof, err := l.TreeConsistencyProof(old, size)
		if err != nil {
			t.Fatalf("TreeConsistencyProof(%d,%d): %v", old, size, err)
		}
		oldRoot, err := tlog.TreeHash(int64(old), hashesAsTlog(l.tw.SnapshotHashes()))
		if err != nil {
			t.Fatal(err)
		}
		tp := make(tlog.TreeProof, len(proof))
		for i, h := range proof {
			tp[i] = tlog.Hash(h)
		}
		if err := tlog.CheckTree(tp, int64(size), newRoot, int64(old), oldRoot); err != nil {
			t.Fatalf("CheckTree(%d -> %d): %v", old, size, err)
		}
	}

	// An old size of zero has an empty proof: the empty tree is
	// consistent with every tree, and a witness rejects a non-empty
	// proof there with a 422.
	if proof, err := l.TreeConsistencyProof(0, size); err != nil || len(proof) != 0 {
		t.Errorf("TreeConsistencyProof(0,%d) = %v, %v; want empty proof and no error", size, proof, err)
	}
	if _, err := l.TreeConsistencyProof(size, 1); err == nil {
		t.Error("TreeConsistencyProof accepted oldSize > newSize")
	}
}

// TestMaxPoolSizeTriggersEarlyFlush verifies the pool_size knob: with a
// very long FlushPeriod, appending MaxPoolSize entries must flush (and so
// let Wait return) well before the ticker would fire.
func TestMaxPoolSizeTriggersEarlyFlush(t *testing.T) {
	fs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := signer.FromSeed(signer.AlgMLDSA44, bytes.Repeat([]byte{0x42}, signer.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(context.Background(), Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1"),
		Signer:      s,
		FS:          fs,
		FlushPeriod: time.Hour, // effectively never on its own
		MaxPoolSize: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)

	var lastIdx uint64
	for i := 0; i < 3; i++ {
		tbs := []byte{byte(i), 0x01}
		idx, err := l.Append(context.Background(), cert.EncodeTBSCertEntry(tbs), sha256.Sum256(tbs))
		if err != nil {
			t.Fatal(err)
		}
		lastIdx = idx
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := l.Wait(ctx, lastIdx); err != nil {
		t.Fatalf("Wait did not return before the hour-long flush period: %v", err)
	}
}

// failCheckpointFS wraps a storage.FS and fails the next Put to
// "log/checkpoint" once armed, to simulate a crash/failed flush after the
// tile writer (and its treeSize file) have advanced but before the
// checkpoint commits.
type failCheckpointFS struct {
	storage.FS
	armed bool
}

func (f *failCheckpointFS) Put(name string, data []byte, exclusive bool) error {
	if f.armed && name == "log/checkpoint" {
		f.armed = false
		return fmt.Errorf("injected checkpoint write failure")
	}
	return f.FS.Put(name, data, exclusive)
}

// TestFlushRecoversUncoveredGap reproduces the case where a flush advances
// the tile writer but fails before committing the checkpoint: the next
// flush must cover the gap entries with a signed subtree, not leave them
// committed-without-a-signature. Regression for the second-review HIGH
// finding.
func TestFlushRecoversUncoveredGap(t *testing.T) {
	inner, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fs := &failCheckpointFS{FS: inner}
	s, err := signer.FromSeed(signer.AlgMLDSA44, bytes.Repeat([]byte{0x42}, signer.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	// A long flush period so only our explicit l.flush() calls run.
	l, err := New(context.Background(), Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1"),
		Signer:      s,
		FS:          fs,
		FlushPeriod: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)

	// Queue three entries, then arm the checkpoint-write failure and flush:
	// tw advances to size 3 but the checkpoint never commits.
	for i := 0; i < 3; i++ {
		tbs := []byte{byte(i), 0x01}
		if _, err := l.Append(context.Background(), cert.EncodeTBSCertEntry(tbs), sha256.Sum256(tbs)); err != nil {
			t.Fatal(err)
		}
	}
	fs.armed = true
	if err := l.flush(); err == nil {
		t.Fatal("expected the armed flush to fail")
	}
	if got := uint64(l.tw.Size()); got != 3 {
		t.Fatalf("tile writer size = %d, want 3 (advanced despite failed checkpoint)", got)
	}
	if l.committed.size != 0 {
		t.Fatalf("committed size = %d, want 0 (checkpoint never committed)", l.committed.size)
	}

	// Recovery flush: must mint a covering subtree for [0,3).
	if err := l.flush(); err != nil {
		t.Fatalf("recovery flush: %v", err)
	}
	iss, err := l.buildIssued(2)
	if err != nil {
		t.Fatalf("buildIssued(2): %v", err)
	}
	if len(iss.Signatures) == 0 {
		t.Fatal("gap entry has no covering cosignature after recovery flush")
	}
	// The covering subtree must actually contain the entry (a real §4.5
	// covering subtree of [0,3), not the signature-less whole-tree
	// fallback).
	if !(iss.Subtree.Start <= 2 && 2 < iss.Subtree.End) {
		t.Fatalf("covering subtree [%d,%d) does not contain index 2", iss.Subtree.Start, iss.Subtree.End)
	}
}
