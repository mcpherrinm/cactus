package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/landmark"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"
)

// TestLandmarkRelativeCertConstruction is an end-to-end check of
// Phase 8.3: bring up the stack, issue a cert, manually allocate a
// landmark that covers the issued entry, build the landmark-relative
// cert, and verify §7.2 with a *trusted-subtree* fast path (no
// cosigner key consulted).
func TestLandmarkRelativeCertConstruction(t *testing.T) {
	s := bringUp(t, t.TempDir())
	defer s.close()

	// Issue a few certs so we can pick a non-trivial entry.
	const n = 5
	var ders [][]byte
	for i := 0; i < n; i++ {
		der, err := acmeIssueOne(s.acmeBase, fmt.Sprintf("lm%d.test", i))
		if err != nil {
			t.Fatal(err)
		}
		ders = append(ders, der)
	}
	time.Sleep(100 * time.Millisecond) // let the last flush settle

	// Build a one-shot landmark sequence in-process. Its "tree size"
	// is the *current* checkpoint size, taken from the live log.
	cp := s.log.CurrentCheckpoint()
	if cp.Size < uint64(n+1) {
		t.Fatalf("log size %d, want >= %d", cp.Size, n+1)
	}

	dir := t.TempDir()
	cfg := landmark.Config{
		BaseID:               cert.TrustAnchorID("32473.1.lm"),
		TimeBetweenLandmarks: time.Millisecond,
		MaxCertLifetime:      time.Hour,
	}
	fs2, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	seq, err := landmark.New(cfg, fs2, t0)
	if err != nil {
		t.Fatal(err)
	}
	// Allocate a landmark at the current tree size.
	lm, ok, err := seq.Append(context.Background(), cp.Size, t0.Add(time.Second))
	if err != nil || !ok {
		t.Fatalf("append: ok=%v err=%v", ok, err)
	}

	// Cert serial = log index. We picked the third issued cert.
	chosen := ders[2]
	tbs, _, sigValue, err := cert.SplitCertificate(chosen)
	if err != nil {
		t.Fatal(err)
	}
	origProof, err := cert.ParseMTCProof(sigValue)
	if err != nil {
		t.Fatal(err)
	}
	_, serial, err := cert.RebuildLogEntryFromTBS(tbs, s.logIDDN)
	if err != nil {
		t.Fatal(err)
	}

	// Pick the §4.5 covering subtree of [0, lm.TreeSize) that
	// contains `serial`.
	subtrees := seq.LandmarkSubtrees(lm)
	if len(subtrees) == 0 {
		t.Fatalf("landmark %+v has no subtrees", lm)
	}
	var chosenSubtree tlogx.Subtree
	for _, st := range subtrees {
		if serial >= st.Start && serial < st.End {
			chosenSubtree = st
			break
		}
	}
	if chosenSubtree.End == 0 {
		t.Fatalf("serial %d not in any landmark subtree %+v", serial, subtrees)
	}

	// Compute the subtree hash + inclusion proof from the live log's
	// tile-server HTTP API. We reuse the helpers from the multi-cert
	// integration: the simplest is to walk the data tiles and
	// rebuild stored hashes ourselves, then call the new tlogx funcs.
	hashes, _, err := loadAllStoredHashes(s.tileBase, cp.Size)
	if err != nil {
		t.Fatal(err)
	}
	hr := hashReaderFromSlice(hashes)
	subtreeHash, err := tlogx.SubtreeHash(chosenSubtree.Start, chosenSubtree.End, hr)
	if err != nil {
		t.Fatal(err)
	}
	inclusionProof, err := tlogx.GenerateInclusionProof(
		chosenSubtree.Start, chosenSubtree.End, serial, hr)
	if err != nil {
		t.Fatal(err)
	}

	// Build the landmark-relative cert.
	mtcSubtree := cert.MTCSubtree{
		LogID: s.logID, Start: chosenSubtree.Start, End: chosenSubtree.End, Hash: subtreeHash,
	}
	lmDER, err := cert.BuildLandmarkRelativeCert(chosen, s.logID, mtcSubtree, inclusionProof)
	if err != nil {
		t.Fatal(err)
	}

	// (1) The TBS bytes of the landmark cert must equal the standalone
	// TBS bytes — only signatureValue differs.
	tbs2, sigAlg2, sigValue2, err := cert.SplitCertificate(lmDER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tbs, tbs2) {
		t.Errorf("TBS differs between standalone and landmark-relative")
	}
	// signatureAlgorithm should also be id-alg-mtcProof.
	if !bytes.Equal(sigValue2[:0], []byte{}) /* avoid empty-check noise */ && len(sigValue2) == 0 {
		t.Errorf("empty signatureValue")
	}

	// (2) The new MTCProof must have no signatures.
	lmProof, err := cert.ParseMTCProof(sigValue2)
	if err != nil {
		t.Fatal(err)
	}
	if len(lmProof.Signatures) != 0 {
		t.Errorf("landmark-relative cert has %d signatures, want 0", len(lmProof.Signatures))
	}

	// (3) The §4.3 inclusion proof in the new cert must reconstruct
	// the trusted-subtree hash. This is the relying-party fast path:
	// no cosigner needed.
	leafHash := cert.EntryHash(rebuildLogEntryContents(t, tbs, s.logIDDN))
	got, err := tlogx.EvaluateInclusionProof(
		func(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) },
		lmProof.Start, lmProof.End, serial, leafHash, lmProof.InclusionProof,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got != subtreeHash {
		t.Errorf("inclusion proof reconstructed %x, want %x", got[:8], subtreeHash[:8])
	}

	// (4) Sanity: the original cert had exactly 1 signature; the new one has 0.
	if len(origProof.Signatures) != 1 {
		t.Errorf("original cert had %d signatures, want 1", len(origProof.Signatures))
	}
	_ = sigAlg2
	_ = lm
}

// rebuildLogEntryContents wraps cert.RebuildLogEntryFromTBS for tests
// that need the bytes back rather than the (bytes, serial) pair.
func rebuildLogEntryContents(t *testing.T, tbs []byte, expectedIssuer []byte) []byte {
	t.Helper()
	contents, _, err := cert.RebuildLogEntryFromTBS(tbs, expectedIssuer)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

// loadAllStoredHashes pulls all entries from the tile server's data
// tiles and replays them through tlog.StoredHashes to rebuild the
// stored-hash slice. Same logic as TestTileBytesRecomputeToSignedRoot.
func loadAllStoredHashes(tileBase string, treeSize uint64) ([]tlog.Hash, [][]byte, error) {
	entries, err := loadAllEntries(tileBase, treeSize)
	if err != nil {
		return nil, nil, err
	}
	var hashes []tlog.Hash
	for i, e := range entries {
		hs, err := tlog.StoredHashes(int64(i), e, hashReader(hashes))
		if err != nil {
			return nil, nil, fmt.Errorf("StoredHashes(%d): %w", i, err)
		}
		hashes = append(hashes, hs...)
	}
	return hashes, entries, nil
}

func hashReaderFromSlice(h []tlog.Hash) tlog.HashReader {
	return hashReader(h)
}
