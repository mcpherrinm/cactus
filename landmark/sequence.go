// Package landmark implements the landmark sequence from §6.4 of
// draft-ietf-plants-merkle-tree-certs-07.
//
// A landmark is a (number, tree size, expiry) triple (§6.4.1); cactus
// also records when each was allocated, to pace allocation. The
// sequence starts at landmark 0 with tree size 0 and expiry 0, and grows
// by at most one landmark each `time_between_landmarks` of wallclock
// time (§6.4.2), taking the current checkpoint tree size as the new
// landmark's tree size and now + max_cert_lifetime as its expiry. A
// landmark is active until it expires.
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
	"sync"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"
)

// Landmark identifies one landmark in the sequence.
type Landmark struct {
	Number   uint64 `json:"number"`
	TreeSize uint64 `json:"tree_size"`
	// Expiry is the §6.4.1 expiration time, in whole seconds. It is at
	// or after the notAfter of every entry below TreeSize; the landmark
	// is active until then. Landmark 0 expires at the Epoch, so it is
	// never active.
	Expiry time.Time `json:"expiry"`
	// AllocatedAt paces allocation (§6.4.2). It is not published.
	AllocatedAt time.Time `json:"allocated_at"`
}

// Active reports whether the landmark has not yet expired at now. The
// expiry is inclusive, like an X.509 notAfter.
func (l Landmark) Active(now time.Time) bool { return !l.Expiry.Before(now) }

// epoch is landmark 0's expiry (§6.4.1: zero seconds since the Epoch).
var epoch = time.Unix(0, 0).UTC()

// later returns the later of a and b.
func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// TrustAnchorID returns the landmark's trust anchor ID per §6.4.1/§8.2:
// CA-ID.1.logNumber.landmarkNumber.
func (l Landmark) TrustAnchorID(caID cert.TrustAnchorID, logNumber uint16) cert.TrustAnchorID {
	return cert.LandmarkID(caID, logNumber, l.Number)
}

// GroupID returns the single-log landmark group trust anchor ID per
// §8.2.1: CA-ID.2.logNumber.landmarkNumber. The group contains the CA
// ID plus landmarks 0 through this one of the log.
func (l Landmark) GroupID(caID cert.TrustAnchorID, logNumber uint16) cert.TrustAnchorID {
	return cert.LandmarkGroupID(caID, logNumber, l.Number)
}

// Config configures the sequence allocator.
type Config struct {
	// CAID is the CA's CA ID (§5.1); landmark trust anchor IDs are
	// derived from it and the log number (§6.4.1).
	CAID cert.TrustAnchorID

	// LogNumber is the issuance log's number (§5.2).
	LogNumber uint16

	// TimeBetweenLandmarks is the §6.4.2 interval. A new landmark is
	// allocated at most once per such interval.
	TimeBetweenLandmarks time.Duration

	// MaxCertLifetime is the CA's maximum certificate lifetime
	// (max_cert_lifetime, §6.4.2). Each landmark's expiry is its
	// allocation time plus this, so it MUST bound the validity period of
	// every certificate the CA issues.
	MaxCertLifetime time.Duration
}

// expiryFor returns the §6.4.2 expiry for a landmark allocated at now:
// now + MaxCertLifetime, rounded up to a whole second.
func (c Config) expiryFor(now time.Time) time.Time {
	e := now.Add(c.MaxCertLifetime)
	if t := e.Truncate(time.Second); !t.Equal(e) {
		e = t.Add(time.Second)
	}
	return e.UTC()
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
// with landmark 0 at tree size 0 and expiry 0 (§6.4.1).
func New(cfg Config, fs storage.FS, now time.Time) (*Sequence, error) {
	if cfg.TimeBetweenLandmarks <= 0 {
		return nil, errors.New("landmark: TimeBetweenLandmarks must be > 0")
	}
	if cfg.MaxCertLifetime <= 0 {
		return nil, errors.New("landmark: MaxCertLifetime must be > 0")
	}
	s := &Sequence{cfg: cfg, fs: fs}
	if err := s.replay(now); err != nil {
		return nil, err
	}
	return s, nil
}

// replay reads SequenceFile and rebuilds in-memory state. If the file
// is missing, seed with landmark 0.
//
// Files written before draft-07 support have no expiry. Each such
// landmark is given the expiry it would have had if allocated under the
// current config (landmark 0: the Epoch), raised as needed to keep
// expiries non-decreasing, and the migrated file is written back.
func (s *Sequence) replay(now time.Time) error {
	data, err := s.fs.Get(SequenceFile)
	if errors.Is(err, fs.ErrNotExist) {
		seed := Landmark{Number: 0, TreeSize: 0, Expiry: epoch, AllocatedAt: now}
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
		seed := Landmark{Number: 0, TreeSize: 0, Expiry: epoch, AllocatedAt: now}
		s.landmarks = []Landmark{seed}
		return s.persistLineLocked(seed)
	}
	migrated := false
	for i := range s.landmarks {
		l := &s.landmarks[i]
		if !l.Expiry.IsZero() {
			continue
		}
		migrated = true
		if i == 0 {
			l.Expiry = epoch
		} else {
			l.Expiry = later(s.cfg.expiryFor(l.AllocatedAt), s.landmarks[i-1].Expiry)
		}
	}
	// Validate invariants.
	for i, l := range s.landmarks {
		if l.Number != uint64(i) {
			return fmt.Errorf("landmark: sequence not contiguous at index %d: number=%d", i, l.Number)
		}
	}
	if s.landmarks[0].TreeSize != 0 || !s.landmarks[0].Expiry.Equal(epoch) {
		return fmt.Errorf("landmark: landmark 0 must have tree_size 0 and expiry 0, got %d, %v",
			s.landmarks[0].TreeSize, s.landmarks[0].Expiry)
	}
	for i := 1; i < len(s.landmarks); i++ {
		if s.landmarks[i].TreeSize <= s.landmarks[i-1].TreeSize {
			return fmt.Errorf("landmark: tree sizes not strictly increasing: %d -> %d at index %d",
				s.landmarks[i-1].TreeSize, s.landmarks[i].TreeSize, i)
		}
		if s.landmarks[i].Expiry.Before(s.landmarks[i-1].Expiry) {
			return fmt.Errorf("landmark: expiries decrease: %v -> %v at index %d",
				s.landmarks[i-1].Expiry, s.landmarks[i].Expiry, i)
		}
	}
	if migrated {
		return s.persistLineLocked(Landmark{})
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

// Append implements the §6.4.2 allocation procedure: at most once per
// TimeBetweenLandmarks, append the current treeSize if it strictly
// exceeds the last landmark's tree size, expiring at now +
// MaxCertLifetime. The expiry is never earlier than the previous
// landmark's (§6.4.1), even if MaxCertLifetime was lowered since.
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
		Expiry:      later(s.cfg.expiryFor(now), last.Expiry),
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

// Active returns the landmarks that have not expired at now, descending
// by Number (§6.4.1). Expiries are non-decreasing, so these are a suffix
// of the sequence; landmark 0 is never active.
func (s *Sequence) Active(now time.Time) []Landmark {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Landmark
	for i := len(s.landmarks) - 1; i > 0 && s.landmarks[i].Active(now); i-- {
		out = append(out, s.landmarks[i])
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
	// Binary search would be faster, but the sequence grows by one
	// landmark per interval (~9k a year at the hourly default), so
	// linear is fine.
	for _, l := range s.landmarks {
		if l.TreeSize > index {
			return l, true
		}
	}
	return Landmark{}, false
}

// LandmarkSubtrees returns landmark l's two landmark subtrees (§6.4.1):
// the §4.5.1 covering subtrees of [prev_treeSize, l.TreeSize), which
// together contain every entry assigned to l. Either may be empty, and
// landmark 0's are both [0, 0). It returns nil if l is not in the
// sequence.
func (s *Sequence) LandmarkSubtrees(l Landmark) []tlogx.Subtree {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l.Number >= uint64(len(s.landmarks)) || s.landmarks[l.Number] != l {
		return nil
	}
	if l.Number == 0 {
		return []tlogx.Subtree{{}, {}}
	}
	subs := tlogx.FindSubtrees(s.landmarks[l.Number-1].TreeSize, l.TreeSize)
	return subs[:]
}

// NextNumber returns the number the next landmark to be allocated will
// have. Numbers are contiguous starting at 0, so this is the current
// count of landmarks. Used to pin a not-yet-allocated landmark in the
// enhancement URL of a freshly-issued cert.
func (s *Sequence) NextNumber() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return uint64(len(s.landmarks))
}

// TimeUntilNextLandmark estimates how long until the next landmark is
// allocated — i.e. when a freshly-issued, not-yet-covered entry's
// landmark-relative cert becomes available. It is the remainder of the
// §6.4.2 interval since the most recent landmark, floored at zero. Used
// to set the Retry-After on the enhancement URL's 202 response.
func (s *Sequence) TimeUntilNextLandmark(now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	last := s.landmarks[len(s.landmarks)-1]
	return max(0, s.cfg.TimeBetweenLandmarks-now.Sub(last.AllocatedAt))
}

// LatestTreeSize returns the tree size of the most recent landmark.
// Useful for "is there a landmark covering this index yet?" checks.
func (s *Sequence) LatestTreeSize() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.landmarks[len(s.landmarks)-1].TreeSize
}

// CAID returns the CA ID the sequence's landmark trust anchor IDs are
// derived from (§5.1).
func (s *Sequence) CAID() cert.TrustAnchorID { return s.cfg.CAID }

// LogNumber returns the issuance log number (§5.2).
func (s *Sequence) LogNumber() uint16 { return s.cfg.LogNumber }
