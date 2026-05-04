// Package landmark implements the landmark sequence from §6.3 of
// draft-ietf-plants-merkle-tree-certs-03.
//
// A landmark is a (number, treeSize, allocatedAt) triple. The
// sequence starts at landmark 0 with treeSize 0, and grows by one
// landmark each `time_between_landmarks` of wallclock time, taking the
// current checkpoint tree size as the new landmark's tree size.
//
// The sequence is append-only and persists to a JSONL file under the
// data directory; restart re-reads the file and resumes without
// double-allocating.
package landmark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"sync"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"
)

// Landmark identifies one landmark in the sequence.
type Landmark struct {
	Number      uint64    `json:"number"`
	TreeSize    uint64    `json:"tree_size"`
	AllocatedAt time.Time `json:"allocated_at"`
}

// TrustAnchorID returns the landmark's trust anchor ID per §6.3.1:
// base_id with the landmark number appended as a final OID component.
func (l Landmark) TrustAnchorID(base cert.TrustAnchorID) cert.TrustAnchorID {
	// In v1 the trust anchor ID is the ASCII representation of the OID
	// (per §5.2 "For initial experimentation"). Concatenate the number.
	return cert.TrustAnchorID(fmt.Sprintf("%s.%d", string(base), l.Number))
}

// Config configures the sequence allocator.
type Config struct {
	// BaseID is the OID arc for landmark trust anchor IDs (§6.3.1).
	BaseID cert.TrustAnchorID

	// TimeBetweenLandmarks is the §6.3.2 interval. A new landmark is
	// allocated at most once per such interval.
	TimeBetweenLandmarks time.Duration

	// MaxCertLifetime is the CA's maximum certificate lifetime; used
	// only to compute MaxActive() per §6.3.2.
	MaxCertLifetime time.Duration
}

// MaxActive returns max_active_landmarks per §6.3.2:
//
//	ceil(max_cert_lifetime / time_between_landmarks) + 1.
func (c Config) MaxActive() int {
	if c.TimeBetweenLandmarks <= 0 {
		return 1
	}
	ratio := float64(c.MaxCertLifetime) / float64(c.TimeBetweenLandmarks)
	return int(math.Ceil(ratio)) + 1
}

// Sequence is an append-only landmark sequence backed by storage.
type Sequence struct {
	cfg Config
	fs  storage.FS

	mu        sync.Mutex
	landmarks []Landmark // sorted by Number, always starts with [0, 0, …]
}

// SequenceFile is the path under storage.FS where the JSONL is kept.
const SequenceFile = "state/landmarks/sequence.jsonl"

// New constructs a Sequence and replays the on-disk JSONL if it
// exists. If the file is missing or empty, the sequence is initialized
// with landmark 0 at tree size 0 (§6.3.1).
func New(cfg Config, fs storage.FS, now time.Time) (*Sequence, error) {
	if cfg.TimeBetweenLandmarks <= 0 {
		return nil, errors.New("landmark: TimeBetweenLandmarks must be > 0")
	}
	s := &Sequence{cfg: cfg, fs: fs}
	if err := s.replay(now); err != nil {
		return nil, err
	}
	return s, nil
}

// replay reads SequenceFile and rebuilds in-memory state. If the file
// is missing, seed with landmark 0.
func (s *Sequence) replay(now time.Time) error {
	data, err := s.fs.Get(SequenceFile)
	if errors.Is(err, fs.ErrNotExist) {
		seed := Landmark{Number: 0, TreeSize: 0, AllocatedAt: now}
		s.landmarks = []Landmark{seed}
		return s.persistLineLocked(seed)
	}
	if err != nil {
		return fmt.Errorf("landmark: read sequence: %w", err)
	}
	for offset := 0; offset < len(data); {
		// Find next newline.
		end := offset
		for end < len(data) && data[end] != '\n' {
			end++
		}
		line := data[offset:end]
		offset = end + 1
		if len(line) == 0 {
			continue
		}
		var l Landmark
		if err := json.Unmarshal(line, &l); err != nil {
			return fmt.Errorf("landmark: decode %q: %w", line, err)
		}
		s.landmarks = append(s.landmarks, l)
	}
	if len(s.landmarks) == 0 {
		seed := Landmark{Number: 0, TreeSize: 0, AllocatedAt: now}
		s.landmarks = []Landmark{seed}
		return s.persistLineLocked(seed)
	}
	// Validate invariants.
	for i, l := range s.landmarks {
		if l.Number != uint64(i) {
			return fmt.Errorf("landmark: sequence not contiguous at index %d: number=%d", i, l.Number)
		}
	}
	if s.landmarks[0].TreeSize != 0 {
		return fmt.Errorf("landmark: landmark 0 must have tree_size 0, got %d", s.landmarks[0].TreeSize)
	}
	for i := 1; i < len(s.landmarks); i++ {
		if s.landmarks[i].TreeSize <= s.landmarks[i-1].TreeSize {
			return fmt.Errorf("landmark: tree sizes not strictly increasing: %d -> %d at index %d",
				s.landmarks[i-1].TreeSize, s.landmarks[i].TreeSize, i)
		}
	}
	return nil
}

// persistLineLocked appends a JSONL line for `l` to disk. The caller
// must hold s.mu. We re-write the whole file each time — landmarks are
// rare events (once per hour by default) and the file stays small
// (10s of KiB at most).
func (s *Sequence) persistLineLocked(_ Landmark) error {
	// Reserialize the entire sequence so we can use the existing
	// atomic-rename Put path. Pure-append would be marginally faster
	// but storage.Disk doesn't offer it.
	var buf []byte
	for _, lm := range s.landmarks {
		line, err := json.Marshal(lm)
		if err != nil {
			return err
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	return s.fs.Put(SequenceFile, buf, false)
}

// Append implements the §6.3.2 allocation procedure: at most once per
// TimeBetweenLandmarks, append the current treeSize if it strictly
// exceeds the last landmark's tree size.
//
// Returns (newLandmark, true, nil) if a landmark was appended,
// (zero, false, nil) if the conditions weren't met, or (zero, false, err)
// on persistence failure.
func (s *Sequence) Append(_ context.Context, treeSize uint64, now time.Time) (Landmark, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	last := s.landmarks[len(s.landmarks)-1]
	if treeSize <= last.TreeSize {
		return Landmark{}, false, nil
	}
	if now.Sub(last.AllocatedAt) < s.cfg.TimeBetweenLandmarks {
		return Landmark{}, false, nil
	}
	next := Landmark{
		Number:      last.Number + 1,
		TreeSize:    treeSize,
		AllocatedAt: now,
	}
	s.landmarks = append(s.landmarks, next)
	if err := s.persistLineLocked(next); err != nil {
		// Roll back the in-memory append on persistence failure.
		s.landmarks = s.landmarks[:len(s.landmarks)-1]
		return Landmark{}, false, err
	}
	return next, true, nil
}

// All returns a copy of every landmark in the sequence (ascending
// Number). Mostly for tests / monitoring.
func (s *Sequence) All() []Landmark {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Landmark, len(s.landmarks))
	copy(out, s.landmarks)
	return out
}

// Active returns the most recent MaxActive() landmarks, descending by
// Number. Per §6.3.1 these are the landmarks that may currently
// contain unexpired certs.
func (s *Sequence) Active() []Landmark {
	s.mu.Lock()
	defer s.mu.Unlock()
	maxN := s.cfg.MaxActive()
	if maxN <= 0 {
		return nil
	}
	start := 0
	if len(s.landmarks) > maxN {
		start = len(s.landmarks) - maxN
	}
	active := s.landmarks[start:]
	out := make([]Landmark, len(active))
	for i, l := range active {
		// Reverse so the newest is first.
		out[len(active)-1-i] = l
	}
	return out
}

// ContainingIndex returns the smallest landmark whose tree size is
// strictly greater than `index`. Returns false if no such landmark
// exists yet (i.e. all landmarks have treeSize <= index, meaning the
// entry is past the most recent landmark).
func (s *Sequence) ContainingIndex(index uint64) (Landmark, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Binary search would be faster, but landmarks are at most
	// max_active_landmarks (~169) so linear is fine.
	for _, l := range s.landmarks {
		if l.TreeSize > index {
			return l, true
		}
	}
	return Landmark{}, false
}

// LandmarkSubtrees returns the §4.5 covering subtrees of
// [prev_treeSize, l.TreeSize) — the ranges that, together, contain
// every entry assigned to landmark l. Landmark zero (treeSize 0) has
// no covering subtrees and returns nil.
func (s *Sequence) LandmarkSubtrees(l Landmark) []tlogx.Subtree {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l.Number == 0 {
		return nil
	}
	if int(l.Number) >= len(s.landmarks) || s.landmarks[l.Number] != l {
		return nil
	}
	prev := s.landmarks[l.Number-1].TreeSize
	if prev >= l.TreeSize {
		return nil
	}
	return tlogx.FindSubtrees(prev, l.TreeSize)
}

// LatestTreeSize returns the tree size of the most recent landmark.
// Useful for "is there a landmark covering this index yet?" checks.
func (s *Sequence) LatestTreeSize() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.landmarks[len(s.landmarks)-1].TreeSize
}

// MaxActive returns the §6.3.2 max_active_landmarks for this sequence.
// Convenience accessor for callers that need the number to populate
// CertificatePropertyList.additional_trust_anchor_ranges.
func (s *Sequence) MaxActive() int {
	return s.cfg.MaxActive()
}

// BaseID returns the configured base_id (§6.3.1).
func (s *Sequence) BaseID() interface{ String() string } {
	// Return a tiny shim because cert.TrustAnchorID is in another
	// package and embedding it here would create an import cycle for
	// callers. Realistic callers already know the type.
	return baseIDStringer(s.cfg.BaseID)
}

type baseIDStringer []byte

func (b baseIDStringer) String() string { return string(b) }
