// Package tilewriter maintains the on-disk Merkle tree for the cactus
// issuance log. It is a thin wrapper over golang.org/x/mod/sumdb/tlog
// that knows how to:
//
//   - Append a batch of entries, returning assigned indices.
//   - Persist new tiles (level >= 0 hash tiles, plus a level=-1 "data
//     tile" carrying full MerkleTreeCertEntry blobs).
//   - Serve as a tlog.HashReader so the rest of the log can build proofs.
//
// All state is owned by a single goroutine; the type is NOT
// goroutine-safe. The cactus sequencer is the sole writer per the
// single-writer invariant in PROJECT_PLAN §3.
package tilewriter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/letsencrypt/cactus/storage"
	"golang.org/x/mod/sumdb/tlog"
)

// TileHeight is the height of every published tile (hash and data).
// Matches tlog-tiles default and what sunlight uses; chosen so each
// tile holds at most 256 records.
const TileHeight = 8

// EntriesPerDataTile = 1 << TileHeight = 256.
const EntriesPerDataTile = 1 << TileHeight

// TileWriter is the cactus issuance-log tile writer.
type TileWriter struct {
	fs   storage.FS
	size int64

	// hashes is the in-memory mirror of every stored hash, indexed by
	// tlog.StoredHashIndex(level, n). It grows as entries are appended.
	// For a test server (single instance, modest tree) keeping all
	// hashes in memory is fine; it costs ~64 MiB per million entries.
	hashes []tlog.Hash

	// dataTiles holds the in-memory contents of partial level=-1 data
	// tiles, keyed by tile.N. Once a data tile reaches
	// EntriesPerDataTile records, it becomes immutable on disk and is
	// cleared from this map on the next reload.
	dataTiles map[int64][]byte
}

// New opens a tile writer rooted at fs. If a previous tree exists on
// disk under "log/", it is loaded; otherwise an empty tree is created.
func New(fs storage.FS) (*TileWriter, error) {
	w := &TileWriter{
		fs:        fs,
		dataTiles: map[int64][]byte{},
	}
	if err := w.loadFromDisk(); err != nil {
		return nil, err
	}
	return w, nil
}

// Size returns the current tree size (number of entries).
func (w *TileWriter) Size() int64 { return w.size }

// RootHash returns the Merkle tree hash at the current size, or the
// zero Hash if size==0.
func (w *TileWriter) RootHash() (tlog.Hash, error) {
	if w.size == 0 {
		return tlog.Hash{}, nil
	}
	return tlog.TreeHash(w.size, hashReader(w.hashes))
}

// HashReader returns a tlog.HashReader backed by this writer's in-memory
// hash array. Suitable for tlog.ProveRecord, tlog.ProveTree, etc. The
// returned reader shares state with the writer; do not retain across
// concurrent appends.
func (w *TileWriter) HashReader() tlog.HashReader {
	return hashReader(w.hashes)
}

// SnapshotHashes returns a copy of the writer's stored-hash slice for
// callers that need a stable HashReader after subsequent appends.
func (w *TileWriter) SnapshotHashes() []tlog.Hash {
	out := make([]tlog.Hash, len(w.hashes))
	copy(out, w.hashes)
	return out
}

// Append appends entries and returns the assigned indices [oldSize,
// oldSize+len(entries)). Storage is updated atomically: on error, the
// in-memory state is rolled back so a retry sees the original size.
func (w *TileWriter) Append(entries [][]byte) ([]int64, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	oldSize := w.size

	// Compute new stored hashes.
	prevCount := tlog.StoredHashCount(oldSize)
	newHashes := make([]tlog.Hash, 0, len(entries)*2)
	hr := hashReader(append([]tlog.Hash(nil), w.hashes...))
	curSize := oldSize
	for _, e := range entries {
		recordHash := tlog.RecordHash(e)
		hs, err := tlog.StoredHashes(curSize, e, hr)
		if err != nil {
			return nil, fmt.Errorf("tlog.StoredHashes(%d): %w", curSize, err)
		}
		newHashes = append(newHashes, hs...)
		hr = append(hr, hs...)
		_ = recordHash
		curSize++
	}
	if int64(len(newHashes)) != tlog.StoredHashCount(curSize)-prevCount {
		return nil, fmt.Errorf("internal: stored hash count mismatch (%d vs %d)",
			len(newHashes), tlog.StoredHashCount(curSize)-prevCount)
	}

	// Update in-memory state, then persist. If persistence fails, roll back.
	w.hashes = append(w.hashes, newHashes...)
	w.size = curSize
	indices := make([]int64, len(entries))
	for i := range entries {
		indices[i] = oldSize + int64(i)
	}

	if err := w.persistAfterAppend(oldSize, entries); err != nil {
		w.hashes = w.hashes[:prevCount]
		w.size = oldSize
		return nil, fmt.Errorf("persist tiles: %w", err)
	}
	return indices, nil
}

// persistAfterAppend writes:
//   - All hash tiles affected by the append (level >= 0).
//   - The data tiles covering the new entries (level = -1).
//
// The "treeSize" file is the source of truth for size on reload.
func (w *TileWriter) persistAfterAppend(oldSize int64, newEntries [][]byte) error {
	// 1) Hash tiles.
	tiles := tlog.NewTiles(TileHeight, oldSize, w.size)
	for _, t := range tiles {
		data, err := tlog.ReadTileData(t, w.HashReader())
		if err != nil {
			return fmt.Errorf("ReadTileData %s: %w", t.Path(), err)
		}
		if err := w.fs.Put(tilePath(t), data, false); err != nil {
			return fmt.Errorf("write %s: %w", tilePath(t), err)
		}
	}

	// 2) Data tiles.
	idx := oldSize
	for _, entry := range newEntries {
		tileN := idx / EntriesPerDataTile
		buf := w.dataTiles[tileN]
		if buf == nil {
			// First entry into this tile bucket. If the tile already
			// exists on disk (because we crashed between updating it
			// and writing the next), reload it.
			existing, err := w.readPartialDataTile(tileN, idx-tileN*EntriesPerDataTile)
			if err != nil {
				return err
			}
			buf = existing
		}
		buf = appendDataEntry(buf, entry)
		w.dataTiles[tileN] = buf
		// Persist the (possibly partial) tile.
		recordsInTile := int(idx-tileN*EntriesPerDataTile) + 1
		if err := w.fs.Put(dataTilePath(tileN, recordsInTile), buf, false); err != nil {
			return fmt.Errorf("write data tile: %w", err)
		}
		if recordsInTile == EntriesPerDataTile {
			delete(w.dataTiles, tileN)
		}
		idx++
	}

	// 3) treeSize source-of-truth file.
	var sz [8]byte
	binary.BigEndian.PutUint64(sz[:], uint64(w.size))
	if err := w.fs.Put("log/state/treeSize", sz[:], false); err != nil {
		return fmt.Errorf("write treeSize: %w", err)
	}
	return nil
}

// loadFromDisk restores treeSize and hashes by replaying all entries
// from the on-disk data tiles. Tile files at level >= 0 only store
// hashes at multiples of TileHeight; the intermediate stored hashes
// (which we keep in memory for tlog.HashReader) have to be reconstructed
// either from those tiles + recomputation or, more simply, by replaying
// records — that's what we do.
func (w *TileWriter) loadFromDisk() error {
	data, err := w.fs.Get("log/state/treeSize")
	if errors.Is(err, fs.ErrNotExist) {
		return nil // fresh log
	}
	if err != nil {
		return fmt.Errorf("read treeSize: %w", err)
	}
	if len(data) != 8 {
		return fmt.Errorf("treeSize file is %d bytes, want 8", len(data))
	}
	sz := int64(binary.BigEndian.Uint64(data))
	if sz == 0 {
		return nil
	}

	entries := make([][]byte, 0, sz)
	for tileN := int64(0); tileN*EntriesPerDataTile < sz; tileN++ {
		recordsInThisTile := EntriesPerDataTile
		if (tileN+1)*EntriesPerDataTile > sz {
			recordsInThisTile = int(sz - tileN*EntriesPerDataTile)
		}
		path := dataTilePath(tileN, recordsInThisTile)
		raw, err := w.fs.Get(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		es, err := SplitDataTile(raw)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if len(es) != recordsInThisTile {
			return fmt.Errorf("data tile %s has %d entries, expected %d", path, len(es), recordsInThisTile)
		}
		entries = append(entries, es...)
	}

	hr := hashReader{}
	for i, e := range entries {
		hs, err := tlog.StoredHashes(int64(i), e, hr)
		if err != nil {
			return fmt.Errorf("replay StoredHashes(%d): %w", i, err)
		}
		hr = append(hr, hs...)
	}
	w.hashes = []tlog.Hash(hr)
	w.size = sz
	return nil
}

// readPartialDataTile reads the most recent on-disk version of the
// data tile at index tileN. expectedRecords is the number already
// committed to it. We walk widths from expectedRecords down to 1
// looking for the most recently persisted file.
func (w *TileWriter) readPartialDataTile(tileN int64, expectedRecords int64) ([]byte, error) {
	if expectedRecords == 0 {
		return nil, nil
	}
	for ww := expectedRecords; ww >= 1; ww-- {
		d, err := w.fs.Get(dataTilePath(tileN, int(ww)))
		if err == nil {
			return d, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("partial data tile %d (expecting %d records) not found",
		tileN, expectedRecords)
}

// appendDataEntry encodes a length-prefixed entry into a data tile.
// Format: uint24 length (3 bytes, big-endian) || entry bytes.
func appendDataEntry(buf []byte, entry []byte) []byte {
	if len(entry) > 0xffffff {
		panic(fmt.Sprintf("tilewriter: entry too long (%d bytes)", len(entry)))
	}
	out := append(buf, byte(len(entry)>>16), byte(len(entry)>>8), byte(len(entry)))
	return append(out, entry...)
}

// SplitDataTile parses a data tile into its individual entry payloads.
func SplitDataTile(data []byte) ([][]byte, error) {
	var out [][]byte
	for len(data) > 0 {
		if len(data) < 3 {
			return nil, fmt.Errorf("tilewriter: short data tile (%d bytes)", len(data))
		}
		n := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
		if 3+n > len(data) {
			return nil, fmt.Errorf("tilewriter: truncated entry (%d > %d)", 3+n, len(data))
		}
		out = append(out, data[3:3+n])
		data = data[3+n:]
	}
	return out, nil
}

// hashReader is a tlog.HashReader backed by an in-memory slice of all
// stored hashes (indexed by StoredHashIndex).
type hashReader []tlog.Hash

func (h hashReader) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		if idx < 0 || idx >= int64(len(h)) {
			return nil, fmt.Errorf("tilewriter: hash index %d out of range [0,%d)", idx, len(h))
		}
		out[i] = h[idx]
	}
	return out, nil
}

// tilePath returns the on-disk path for a hash tile, rooted under
// "log/tile/...".
func tilePath(t tlog.Tile) string {
	// tlog.Tile.Path() returns "tile/H/L/NNN[.p/W]". Prepend "log/".
	return "log/" + t.Path()
}

// dataTilePath returns the on-disk path for a level=-1 data tile of
// width recordsInTile (1..EntriesPerDataTile).
func dataTilePath(tileN int64, recordsInTile int) string {
	t := tlog.Tile{H: TileHeight, L: -1, N: tileN, W: recordsInTile}
	// tlog.Tile.Path() uses "data" for level -1.
	p := t.Path()
	if !strings.HasPrefix(p, "tile/") {
		panic("unexpected tlog.Tile.Path: " + p)
	}
	return "log/" + p
}
