package tilewriter

import (
	"bytes"
	"testing"

	"github.com/letsencrypt/cactus/storage"
	"golang.org/x/mod/sumdb/tlog"
)

func newTestWriter(t *testing.T) (*TileWriter, storage.FS) {
	t.Helper()
	fs, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w, err := New(fs)
	if err != nil {
		t.Fatal(err)
	}
	return w, fs
}

func TestEmptyTreeRoot(t *testing.T) {
	w, _ := newTestWriter(t)
	if w.Size() != 0 {
		t.Errorf("Size = %d, want 0", w.Size())
	}
	root, err := w.RootHash()
	if err != nil {
		t.Fatal(err)
	}
	var zero tlog.Hash
	if root != zero {
		t.Errorf("RootHash = %x, want zero", root)
	}
}

func TestAppendAndProve(t *testing.T) {
	w, _ := newTestWriter(t)

	// Append 13 entries (the size used by the draft figures).
	entries := make([][]byte, 13)
	for i := range entries {
		entries[i] = []byte{byte(i)}
	}
	indices, err := w.Append(entries)
	if err != nil {
		t.Fatal(err)
	}
	if len(indices) != 13 || indices[0] != 0 || indices[12] != 12 {
		t.Errorf("indices = %v", indices)
	}
	if w.Size() != 13 {
		t.Errorf("Size = %d", w.Size())
	}

	// Compute root via TreeHash (already done by RootHash).
	root, err := w.RootHash()
	if err != nil {
		t.Fatal(err)
	}

	// Verify each entry has a valid inclusion proof against root.
	for i, entry := range entries {
		recordHash := tlog.RecordHash(entry)
		p, err := tlog.ProveRecord(int64(len(entries)), int64(i), w.HashReader())
		if err != nil {
			t.Fatalf("ProveRecord(%d): %v", i, err)
		}
		if err := tlog.CheckRecord(p, int64(len(entries)), root, int64(i), recordHash); err != nil {
			t.Errorf("CheckRecord(%d): %v", i, err)
		}
	}
}

func TestAppendIncrementalMatchesBatch(t *testing.T) {
	// Appending entries one at a time must yield the same root as
	// appending all at once.
	mkEntry := func(i int) []byte { return []byte{byte(i), byte(i ^ 0x55)} }

	wA, _ := newTestWriter(t)
	wB, _ := newTestWriter(t)

	all := make([][]byte, 31)
	for i := range all {
		all[i] = mkEntry(i)
	}
	if _, err := wA.Append(all); err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		if _, err := wB.Append([][]byte{e}); err != nil {
			t.Fatal(err)
		}
	}
	rA, _ := wA.RootHash()
	rB, _ := wB.RootHash()
	if rA != rB {
		t.Errorf("incremental root %x != batch %x", rB, rA)
	}
}

func TestReloadFromDisk(t *testing.T) {
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	w, err := New(fs)
	if err != nil {
		t.Fatal(err)
	}
	entries := [][]byte{
		[]byte("alpha"),
		[]byte("bravo"),
		[]byte("charlie"),
		[]byte("delta"),
		[]byte("echo"),
	}
	if _, err := w.Append(entries); err != nil {
		t.Fatal(err)
	}
	root, _ := w.RootHash()

	// Reopen.
	fs2, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	w2, err := New(fs2)
	if err != nil {
		t.Fatal(err)
	}
	if w2.Size() != w.Size() {
		t.Errorf("Size after reload = %d, want %d", w2.Size(), w.Size())
	}
	r2, _ := w2.RootHash()
	if r2 != root {
		t.Errorf("root after reload = %x, want %x", r2, root)
	}

	// New appends after reload should still be valid.
	if _, err := w2.Append([][]byte{[]byte("foxtrot")}); err != nil {
		t.Fatal(err)
	}
	if w2.Size() != 6 {
		t.Errorf("post-reload size = %d, want 6", w2.Size())
	}
	r3, _ := w2.RootHash()

	// Re-reload again.
	fs3, _ := storage.New(dir)
	w3, _ := New(fs3)
	r3b, _ := w3.RootHash()
	if r3b != r3 {
		t.Errorf("root after second reload = %x, want %x", r3b, r3)
	}
}

func TestDataTileRoundTrip(t *testing.T) {
	entries := [][]byte{
		[]byte("first"),
		[]byte(""),
		[]byte("third entry has more bytes"),
	}
	var buf []byte
	for _, e := range entries {
		buf = appendDataEntry(buf, e)
	}
	got, err := SplitDataTile(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(entries) {
		t.Fatalf("got %d entries, want %d", len(got), len(entries))
	}
	for i := range entries {
		if !bytes.Equal(got[i], entries[i]) {
			t.Errorf("entry %d mismatch: %q vs %q", i, got[i], entries[i])
		}
	}
}

func TestAppendAcrossDataTileBoundary(t *testing.T) {
	w, _ := newTestWriter(t)
	// Generate just over one data-tile worth of entries.
	n := EntriesPerDataTile + 5
	entries := make([][]byte, n)
	for i := range entries {
		entries[i] = []byte{byte(i)}
	}
	if _, err := w.Append(entries); err != nil {
		t.Fatal(err)
	}
	if w.Size() != int64(n) {
		t.Errorf("Size = %d, want %d", w.Size(), n)
	}
	// The first data tile (full width) should be retrievable from disk.
	full, err := w.fs.Get(dataTilePath(0, EntriesPerDataTile))
	if err != nil {
		t.Fatalf("read full data tile: %v", err)
	}
	parsed, err := SplitDataTile(full)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed) != EntriesPerDataTile {
		t.Errorf("first data tile has %d entries, want %d", len(parsed), EntriesPerDataTile)
	}
}
