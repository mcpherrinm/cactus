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
// goroutine-safe. The cactus sequencer is the sole writer, per the
// single-writer invariant (see docs/threat-model.md).
package tilewriter

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"strconv"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/cactus/storage"
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

// RootHash returns the Merkle tree hash at the current size. For an
// empty tree it returns the RFC 6962 empty-tree hash SHA-256(""), as
// required by tlog-checkpoint / RFC 9162 §2.1 (not the zero hash).
func (w *TileWriter) RootHash() (tlog.Hash, error) {
	if w.size == 0 {
		return tlog.Hash(sha256.Sum256(nil)), nil
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

// ReadEntries returns the raw log entries with indices in [start, end),
// in order, read back out of the level=-1 data tiles.
//
// The read path exists for the c2sp.org/tlog-mirror push client, which
// has to re-transmit already-sequenced entries to a mirror and so needs
// the exact bytes that were hashed into the tree. It deliberately goes
// through the same data tiles a monitor would fetch, rather than keeping
// a second copy of every entry in memory.
//
// Entries are read from the in-memory copy of a still-growing partial
// tile when one is present, and otherwise from disk. Those two sources
// never disagree: persistAfterAppend rewrites the partial tile file on
// every single append, so the on-disk width always matches the tree
// size. The in-memory map is only consulted first to save a read, and
// it is empty after a restart (loadFromDisk replays entries without
// repopulating it), which is exactly why the disk path must handle
// partial tiles too.
func (w *TileWriter) ReadEntries(start, end uint64) ([][]byte, error) {
	if start > end {
		return nil, fmt.Errorf("tilewriter: ReadEntries start %d > end %d", start, end)
	}
	if end > uint64(w.size) {
		return nil, fmt.Errorf("tilewriter: ReadEntries end %d > tree size %d", end, w.size)
	}
	if start == end {
		return nil, nil
	}
	out := make([][]byte, 0, end-start)
	for tileN := int64(start / EntriesPerDataTile); tileN*EntriesPerDataTile < int64(end); tileN++ {
		base := uint64(tileN * EntriesPerDataTile)
		// The tile holds every entry the tree has in [base, base+256).
		width := min(uint64(w.size)-base, uint64(EntriesPerDataTile))
		raw, ok := w.dataTiles[tileN]
		if !ok {
			var err error
			raw, err = w.fs.Get(dataTilePath(tileN, int(width)))
			if err != nil {
				return nil, fmt.Errorf("tilewriter: read data tile %d (width %d): %w", tileN, width, err)
			}
		}
		es, err := SplitDataTile(raw)
		if err != nil {
			return nil, fmt.Errorf("tilewriter: parse data tile %d: %w", tileN, err)
		}
		if uint64(len(es)) != width {
			return nil, fmt.Errorf("tilewriter: data tile %d has %d entries, want %d", tileN, len(es), width)
		}
		// Clip the tile to the requested range.
		lo := max(start, base) - base
		hi := min(end, base+width) - base
		out = append(out, es[lo:hi]...)
	}
	if uint64(len(out)) != end-start {
		return nil, fmt.Errorf("tilewriter: read %d entries for [%d,%d)", len(out), start, end)
	}
	return out, nil
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
			return fmt.Errorf("ReadTileData %s: %w", tilePath(t), err)
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

// appendDataEntry encodes a length-prefixed entry into a data
// ("entries") tile. Per c2sp tlog-tiles, "entry bundles are sequences of
// big-endian uint16 length-prefixed log entries."
func appendDataEntry(buf []byte, entry []byte) []byte {
	if len(entry) > 0xffff {
		panic(fmt.Sprintf("tilewriter: entry too long for uint16 framing (%d bytes)", len(entry)))
	}
	out := append(buf, byte(len(entry)>>8), byte(len(entry)))
	return append(out, entry...)
}

// SplitDataTile parses a data ("entries") tile into its individual entry
// payloads, using the c2sp tlog-tiles uint16 length-prefixed framing.
func SplitDataTile(data []byte) ([][]byte, error) {
	var out [][]byte
	for len(data) > 0 {
		if len(data) < 2 {
			return nil, fmt.Errorf("tilewriter: short data tile (%d bytes)", len(data))
		}
		n := int(data[0])<<8 | int(data[1])
		if 2+n > len(data) {
			return nil, fmt.Errorf("tilewriter: truncated entry (%d > %d)", 2+n, len(data))
		}
		out = append(out, data[2:2+n])
		data = data[2+n:]
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

// TilePath returns the c2sp tlog-tiles relative path for a tile: hash
// tiles at "tile/<L>/<N>", entry (data, level -1) tiles at
// "tile/entries/<N>", with a ".p/<W>" suffix for partial tiles. Unlike
// golang.org/x/mod/sumdb/tlog's Tile.Path (which is the older Go checksum
// database layout "tile/<H>/<L>/<N>" with a height segment and "data" for
// level -1), this matches the convention the wider ecosystem and the
// IETF reference tooling use. It carries no "log/" storage prefix.
func TilePath(t tlog.Tile) string {
	var level string
	if t.L < 0 {
		level = "entries"
	} else {
		level = strconv.Itoa(t.L)
	}
	p := "tile/" + level + "/" + formatTileIndex(t.N)
	if t.W != 0 && t.W != 1<<uint(t.H) {
		p += ".p/" + strconv.Itoa(t.W)
	}
	return p
}

// DataTilePath returns the c2sp tlog-tiles relative path
// "tile/entries/<N>[.p/<W>]" for the data tile at index tileN holding
// recordsInTile entries (a full tile of EntriesPerDataTile omits the .p
// suffix).
func DataTilePath(tileN int64, recordsInTile int) string {
	return TilePath(tlog.Tile{H: TileHeight, L: -1, N: tileN, W: recordsInTile})
}

// formatTileIndex encodes a tile index N as c2sp tlog-tiles path
// segments: zero-padded 3-digit groups, all but the last prefixed "x"
// (e.g. 1234067 -> "x001/x234/067").
func formatTileIndex(n int64) string {
	s := fmt.Sprintf("%03d", n%1000)
	for n >= 1000 {
		n /= 1000
		s = fmt.Sprintf("x%03d/%s", n%1000, s)
	}
	return s
}

// tilePath returns the on-disk storage path for a hash tile, rooted under
// "log/".
func tilePath(t tlog.Tile) string {
	return "log/" + TilePath(t)
}

// dataTilePath returns the on-disk storage path for a level=-1 data tile
// of width recordsInTile (1..EntriesPerDataTile).
func dataTilePath(tileN int64, recordsInTile int) string {
	return "log/" + DataTilePath(tileN, recordsInTile)
}
