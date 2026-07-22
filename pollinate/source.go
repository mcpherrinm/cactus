package pollinate

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/letsencrypt/cactus/log/tilewriter"
	"github.com/letsencrypt/cactus/tlogx"

	"golang.org/x/mod/sumdb/tlog"
)

func sha256Hash(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) }

// snapshot is one log at one source at one checkpoint, as a
// mirrorpush.Source. Every hash it serves comes through a
// tlog.TileHashReader bound to the checkpoint's (size, root), so a
// source that serves bytes inconsistent with the checkpoint it
// advertised produces an error here rather than bad data downstream.
type snapshot struct {
	origin string
	size   uint64
	root   tlogx.Hash
	note   []byte
	f      *tileFetcher
	hr     tlog.HashReader
}

// newSnapshot binds a fetcher to the checkpoint it most recently
// served.
func newSnapshot(f *tileFetcher, n *Note) *snapshot {
	return &snapshot{
		origin: n.Origin,
		size:   n.Size,
		root:   n.Root,
		note:   n.Raw,
		f:      f,
		hr:     tlog.TileHashReader(tlog.Tree{N: int64(n.Size), Hash: tlog.Hash(n.Root)}, f),
	}
}

// Checkpoint implements mirrorpush.Source.
func (s *snapshot) Checkpoint() (uint64, tlogx.Hash, []byte) {
	return s.size, s.root, s.note
}

// Entries implements mirrorpush.Source: it fetches the entry bundles
// covering [start, end) and authenticates every entry's record hash
// against the checkpoint root before handing the bytes on.
func (s *snapshot) Entries(start, end uint64) ([][]byte, error) {
	if start > end || end > s.size {
		return nil, fmt.Errorf("pollinate: entries [%d,%d) out of range for tree size %d", start, end, s.size)
	}
	if start == end {
		return nil, nil
	}
	out := make([][]byte, 0, end-start)
	const per = uint64(tilewriter.EntriesPerDataTile)
	for tileN := start / per; tileN*per < end; tileN++ {
		base := tileN * per
		width := min(s.size-base, per)
		entries, err := s.f.entryBundle(int64(tileN), int(width))
		if err != nil {
			return nil, err
		}
		lo := max(start, base) - base
		hi := min(end, base+width) - base
		out = append(out, entries[lo:hi]...)
	}
	if uint64(len(out)) != end-start {
		return nil, fmt.Errorf("pollinate: read %d entries for [%d,%d)", len(out), start, end)
	}
	// Authenticate: each entry's record hash must be the stored leaf
	// hash, which the TileHashReader has verified against the root.
	indexes := make([]int64, end-start)
	for i := range indexes {
		indexes[i] = tlog.StoredHashIndex(0, int64(start)+int64(i))
	}
	want, err := s.hr.ReadHashes(indexes)
	if err != nil {
		return nil, fmt.Errorf("pollinate: read leaf hashes for [%d,%d): %w", start, end, err)
	}
	for i, e := range out {
		if tlog.RecordHash(e) != want[i] {
			return nil, fmt.Errorf("pollinate: entry %d from %s does not match the checkpoint root",
				start+uint64(i), s.f.base)
		}
	}
	return out, nil
}

// SubtreeConsistencyProof implements mirrorpush.Source with the MTC
// §4.4 proof, generated from O(log n) authenticated node hashes.
func (s *snapshot) SubtreeConsistencyProof(start, end, treeSize uint64) ([]tlogx.Hash, error) {
	return tlogx.GenerateConsistencyProofFromNodes(sha256Hash, start, end, treeSize,
		func(level int, index uint64) (tlogx.Hash, error) {
			hs, err := s.hr.ReadHashes([]int64{tlog.StoredHashIndex(level, int64(index))})
			if err != nil {
				return tlogx.Hash{}, err
			}
			return tlogx.Hash(hs[0]), nil
		})
}

// TreeConsistencyProof implements mirrorpush.Source with the RFC 6962
// §2.1.2 tree consistency proof.
func (s *snapshot) TreeConsistencyProof(oldSize, newSize uint64) ([]tlogx.Hash, error) {
	if oldSize > newSize {
		return nil, fmt.Errorf("pollinate: old size %d > new size %d", oldSize, newSize)
	}
	if oldSize == 0 {
		return nil, nil
	}
	proof, err := tlog.ProveTree(int64(newSize), int64(oldSize), s.hr)
	if err != nil {
		return nil, err
	}
	out := make([]tlogx.Hash, len(proof))
	for i, h := range proof {
		out[i] = tlogx.Hash(h)
	}
	return out, nil
}

// logSource is the long-lived mirrorpush.Source facade for one log.
// mirrorpush clients hold it for their lifetime; each sweep swaps in
// the snapshot for whichever source was chosen this round. With no
// snapshot set, Checkpoint reports an empty tree, which makes
// mirrorpush.Push a no-op.
type logSource struct {
	mu   sync.RWMutex
	snap *snapshot
}

func (l *logSource) set(s *snapshot) {
	l.mu.Lock()
	l.snap = s
	l.mu.Unlock()
}

func (l *logSource) current() *snapshot {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.snap
}

var errNoSnapshot = errors.New("pollinate: no source snapshot")

func (l *logSource) Checkpoint() (uint64, tlogx.Hash, []byte) {
	s := l.current()
	if s == nil {
		return 0, tlogx.Hash{}, nil
	}
	return s.Checkpoint()
}

func (l *logSource) Entries(start, end uint64) ([][]byte, error) {
	s := l.current()
	if s == nil {
		return nil, errNoSnapshot
	}
	return s.Entries(start, end)
}

func (l *logSource) SubtreeConsistencyProof(start, end, treeSize uint64) ([]tlogx.Hash, error) {
	s := l.current()
	if s == nil {
		return nil, errNoSnapshot
	}
	return s.SubtreeConsistencyProof(start, end, treeSize)
}

func (l *logSource) TreeConsistencyProof(oldSize, newSize uint64) ([]tlogx.Hash, error) {
	s := l.current()
	if s == nil {
		return nil, errNoSnapshot
	}
	return s.TreeConsistencyProof(oldSize, newSize)
}
