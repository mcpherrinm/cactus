package log

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync/atomic"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
)

// TestMirrorRequesterCalledAndSigsEmbedded confirms that when a
// MirrorRequester is configured, the log:
//  1. Invokes the callback for every covering subtree after the
//     CA's local sig.
//  2. Embeds the returned signatures in the Issued.Signatures slice
//     alongside the CA sig.
//  3. Tolerates a callback that returns an error (best-effort: the
//     flush completes and the CA-only sig still goes through).
func TestMirrorRequesterCalledAndSigsEmbedded(t *testing.T) {
	fs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x42}, signer.SeedSize)
	s, _ := signer.FromSeed(signer.AlgMLDSA44, seed)
	logID := cert.TrustAnchorID("32473.1")
	cosigID := cert.TrustAnchorID("32473.1")

	var calls int64
	fakeMirrorID := cert.TrustAnchorID("32473.24")
	requester := func(_ context.Context, st *cert.MTCSubtree, caSig cert.MTCSignature) ([]cert.MTCSignature, error) {
		atomic.AddInt64(&calls, 1)
		return []cert.MTCSignature{{
			CosignerID: fakeMirrorID,
			Signature:  []byte("synthetic-mirror-sig-" + string(rune('A'+atomic.LoadInt64(&calls)))),
		}}, nil
	}

	l, err := New(context.Background(), Config{
		LogID: logID, CosignerID: cosigID,
		Signer: s, FS: fs,
		FlushPeriod:      25 * time.Millisecond,
		MirrorRequester:  requester,
		WaitForCosigners: 2, // Wait until both CA and mirror sigs are in
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	// Submit one entry; this triggers a flush with a covering
	// subtree (since prevSize > 0 — the null entry was already
	// flushed by New).
	entry := cert.EncodeTBSCertEntry([]byte("entry-1"))
	idem := sha256.Sum256(entry)
	idx, err := l.Append(context.Background(), entry, idem)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	iss, err := l.Wait(ctx, idx)
	if err != nil {
		t.Fatal(err)
	}

	if atomic.LoadInt64(&calls) == 0 {
		t.Errorf("MirrorRequester never called")
	}
	// At least 2 sigs: CA + at least one mirror. (FindSubtrees may
	// produce 1 or 2 covering subtrees; each invocation appends one
	// fake sig.)
	if len(iss.Signatures) < 2 {
		t.Errorf("got %d sigs, want >= 2 (CA + mirror)", len(iss.Signatures))
	}
	caSeen, mirrorSeen := false, false
	for _, sig := range iss.Signatures {
		if string(sig.CosignerID) == string(cosigID) {
			caSeen = true
		}
		if string(sig.CosignerID) == string(fakeMirrorID) {
			mirrorSeen = true
		}
	}
	if !caSeen {
		t.Errorf("CA sig missing")
	}
	if !mirrorSeen {
		t.Errorf("synthetic mirror sig missing")
	}
}

// TestMirrorRequesterErrorIsNonFatal confirms the flush still
// completes (CA-only) when the requester returns an error.
func TestMirrorRequesterErrorIsNonFatal(t *testing.T) {
	fs, _ := storage.New(t.TempDir())
	seed := bytes.Repeat([]byte{0x55}, signer.SeedSize)
	s, _ := signer.FromSeed(signer.AlgMLDSA44, seed)
	cosigID := cert.TrustAnchorID("32473.1")

	requester := func(_ context.Context, _ *cert.MTCSubtree, _ cert.MTCSignature) ([]cert.MTCSignature, error) {
		return nil, &fakeErr{}
	}

	l, err := New(context.Background(), Config{
		LogID: cert.TrustAnchorID("32473.1"), CosignerID: cosigID,
		Signer: s, FS: fs,
		FlushPeriod:     25 * time.Millisecond,
		MirrorRequester: requester,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	entry := cert.EncodeTBSCertEntry([]byte("e"))
	idem := sha256.Sum256(entry)
	idx, _ := l.Append(context.Background(), entry, idem)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	iss, err := l.Wait(ctx, idx)
	if err != nil {
		t.Fatal(err)
	}
	// Should still have the CA sig.
	if len(iss.Signatures) != 1 {
		t.Errorf("got %d sigs, want exactly 1 (CA only on requester failure)", len(iss.Signatures))
	}
	if string(iss.Signatures[0].CosignerID) != string(cosigID) {
		t.Errorf("only sig should be CA's, got %q", iss.Signatures[0].CosignerID)
	}
}

// TestSlowMirrorSigSurvivesInterveningFlushes is a regression test for
// the issuance hang: an entry's covering subtree used to be evicted from
// l.committed by the very next flush, so a mirror cosignature that
// arrived after a later flush was dropped and Wait (WaitForCosigners=2)
// never saw the quorum — blocking until the finalize deadline.
//
// Here the mirror response for entry-0's subtree is stalled well past
// several subsequent flushes (driven by noise entries). Wait must still
// resolve once the late sig lands, because the subtree is now carried
// forward across flushes and the sig is matched by range, not by the
// (now-advanced) checkpoint size.
func TestSlowMirrorSigSurvivesInterveningFlushes(t *testing.T) {
	fs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{0x37}, signer.SeedSize)
	s, _ := signer.FromSeed(signer.AlgMLDSA44, seed)
	id := cert.TrustAnchorID("32473.1")
	mirrorID := cert.TrustAnchorID("32473.24")

	// targetIdx names entry-0 once it's appended; the requester stalls
	// only the subtree covering it, so unrelated (noise) subtrees keep
	// flowing and keep advancing the checkpoint.
	var targetIdx atomic.Int64
	targetIdx.Store(-1)
	requester := func(_ context.Context, st *cert.MTCSubtree, _ cert.MTCSignature) ([]cert.MTCSignature, error) {
		if ti := targetIdx.Load(); ti >= 0 && st.Start <= uint64(ti) && uint64(ti) < st.End {
			// Stall past several FlushPeriods so the covering subtree
			// is evicted by intervening flushes before this returns.
			time.Sleep(250 * time.Millisecond)
		}
		return []cert.MTCSignature{{
			CosignerID: mirrorID,
			Signature:  bytes.Repeat([]byte{0xAB}, 8),
		}}, nil
	}

	l, err := New(context.Background(), Config{
		LogID: id, CosignerID: id,
		Signer: s, FS: fs,
		FlushPeriod:      20 * time.Millisecond,
		MirrorRequester:  requester,
		WaitForCosigners: 2, // CA + mirror
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	entry0 := cert.EncodeTBSCertEntry([]byte("entry-0"))
	idx0, err := l.Append(context.Background(), entry0, sha256.Sum256(entry0))
	if err != nil {
		t.Fatal(err)
	}
	targetIdx.Store(int64(idx0))

	// Force several real flushes that advance the checkpoint past
	// entry-0's range while its mirror sig is still stalled.
	for i := 0; i < 5; i++ {
		e := cert.EncodeTBSCertEntry([]byte{byte('a' + i)})
		if _, err := l.Append(context.Background(), e, sha256.Sum256(e)); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Millisecond) // > FlushPeriod
	}

	// Bound generously but finitely: pre-fix this blocks until ctx and
	// returns an error; post-fix the late sig attaches and Wait returns.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	iss, err := l.Wait(ctx, idx0)
	if err != nil {
		t.Fatalf("Wait(idx0) did not resolve (the hang): %v", err)
	}
	if len(iss.Signatures) < 2 {
		t.Fatalf("got %d sigs, want >= 2 (CA + late mirror sig)", len(iss.Signatures))
	}
	mirrorSeen := false
	for _, sig := range iss.Signatures {
		if string(sig.CosignerID) == string(mirrorID) {
			mirrorSeen = true
		}
	}
	if !mirrorSeen {
		t.Errorf("late mirror sig was dropped; not present in Issued")
	}
}

type fakeErr struct{}

func (fakeErr) Error() string { return "synthetic requester failure" }
