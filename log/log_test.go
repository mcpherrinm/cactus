package log

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"
)

func newTestLog(t *testing.T) (*Log, signer.Signer, storage.FS) {
	t.Helper()
	fs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x42}, signer.SeedSize)
	s, err := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	if err != nil {
		t.Fatal(err)
	}
	l, err := New(context.Background(), Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1.ca"),
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

func TestLogStartsWithNullEntry(t *testing.T) {
	l, _, _ := newTestLog(t)
	if got := l.tw.Size(); got != 1 {
		t.Errorf("tw.Size = %d, want 1 (null entry)", got)
	}
	cp := l.CurrentCheckpoint()
	if cp.Size != 1 {
		t.Errorf("Checkpoint.Size = %d, want 1", cp.Size)
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
		cert.TrustAnchorID("32473.1.ca"),
		42, root, []byte("signature"),
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
	s, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)

	l1, err := New(context.Background(), Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1.ca"),
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
		CosignerID:  cert.TrustAnchorID("32473.1.ca"),
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
