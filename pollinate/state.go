package pollinate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/letsencrypt/cactus/storage"
)

// statePath is where the tracker state lives under the data dir. The
// mirrorpush clients keep their own resumable per-(log, mirror) state
// next to it, under "mirrorpush/".
const statePath = "pollinate/state.json"

// Carry states for a (log, mirror) pair.
const (
	// CarryUnknown: never successfully confirmed either way. The pair is
	// eligible for pushes; the mirror's submission API is what settles it.
	CarryUnknown = "unknown"
	// CarryYes: the mirror serves (or has accepted pushes for) this log.
	CarryYes = "yes"
	// CarryNo: the mirror answered "unknown origin" on the submission
	// API; it is not configured for this log. Rechecked on an interval
	// and when the cosigners file version changes.
	CarryNo = "no"
)

// State is the persisted tracker state: everything pollinate has
// learned about the world that is worth keeping across restarts.
type State struct {
	// CosignersVersion is the version of the last cosigners file loaded;
	// a change resets not-carried verdicts, since a new file version is
	// exactly when a mirror may have picked up new logs.
	CosignersVersion string               `json:"cosigners_version,omitempty"`
	Logs             map[string]*LogState `json:"logs"` // keyed by checkpoint origin
}

// LogState is one discovered issuance log.
type LogState struct {
	Origin   string `json:"origin"`
	IssuerID string `json:"issuer_id"`
	// URL is the log's tlog-tiles prefix on the issuer (the CA prefix
	// URL plus log number, or the bare CA URL for single-log CAs).
	URL string `json:"url"`
	// HeadHistory records when the log head was first seen at each size,
	// newest last. It is what turns "the mirror is smaller than the log"
	// into "the mirror is N minutes behind": a mirror is only pushed to
	// when it is missing entries the log head already had a full delay
	// window ago.
	HeadHistory []HeadObservation          `json:"head_history,omitempty"`
	Mirrors     map[string]*MirrorLogState `json:"mirrors,omitempty"` // keyed by mirror base_id
}

// HeadObservation is one (time, size) sample of the log head.
type HeadObservation struct {
	Time time.Time `json:"time"`
	Size uint64    `json:"size"`
}

// MirrorLogState is what we know about one mirror's copy of one log.
type MirrorLogState struct {
	Carries      string    `json:"carries"`
	Size         uint64    `json:"size"`
	LastSeen     time.Time `json:"last_seen,omitzero"`
	LastChecked  time.Time `json:"last_checked,omitzero"`
	LastPush     time.Time `json:"last_push,omitzero"`
	LastPushSize uint64    `json:"last_push_size,omitempty"`
	LastError    string    `json:"last_error,omitempty"`
}

func newState() *State {
	return &State{Logs: make(map[string]*LogState)}
}

// logState returns (creating if needed) the state record for origin.
func (st *State) logState(origin string) *LogState {
	ls, ok := st.Logs[origin]
	if !ok {
		ls = &LogState{Origin: origin, Mirrors: make(map[string]*MirrorLogState)}
		st.Logs[origin] = ls
	}
	if ls.Mirrors == nil {
		ls.Mirrors = make(map[string]*MirrorLogState)
	}
	return ls
}

// mirrorState returns (creating if needed) the record for one mirror's
// copy of this log.
func (ls *LogState) mirrorState(mirrorID string) *MirrorLogState {
	ms, ok := ls.Mirrors[mirrorID]
	if !ok {
		ms = &MirrorLogState{Carries: CarryUnknown}
		ls.Mirrors[mirrorID] = ms
	}
	return ms
}

// recordHead notes that the log head was observed at size at time now,
// and prunes history the delay window no longer needs. Only growth is
// recorded; observing an unchanged (or smaller — e.g. from a lagging
// secondary source) size adds nothing the history doesn't already say.
func (ls *LogState) recordHead(now time.Time, size uint64, delay time.Duration) {
	n := len(ls.HeadHistory)
	if n == 0 || size > ls.HeadHistory[n-1].Size {
		ls.HeadHistory = append(ls.HeadHistory, HeadObservation{Time: now, Size: size})
	}
	// Keep every observation inside the window plus the newest one at or
	// beyond its edge: that one defines headAt(now - delay).
	cutoff := now.Add(-delay)
	firstKept := 0
	for i, o := range ls.HeadHistory {
		if !o.Time.After(cutoff) {
			firstKept = i
		}
	}
	ls.HeadHistory = ls.HeadHistory[firstKept:]
}

// headAt returns the largest log head size observed at or before t. ok
// is false when no observation is that old — right after startup or
// discovery, when we cannot yet distinguish "behind for a while" from
// "the CA's own push just hasn't landed yet".
func (ls *LogState) headAt(t time.Time) (uint64, bool) {
	var size uint64
	ok := false
	for _, o := range ls.HeadHistory {
		if o.Time.After(t) {
			break
		}
		size, ok = o.Size, true
	}
	return size, ok
}

// loadState reads the persisted state, returning a fresh one if none
// exists yet.
func loadState(fsys storage.FS) (*State, error) {
	data, err := fsys.Get(statePath)
	if errors.Is(err, fs.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return nil, fmt.Errorf("pollinate: read state: %w", err)
	}
	st := newState()
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("pollinate: parse state %s: %w", statePath, err)
	}
	if st.Logs == nil {
		st.Logs = make(map[string]*LogState)
	}
	return st, nil
}

// saveState persists the state atomically.
func saveState(fsys storage.FS, st *State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("pollinate: marshal state: %w", err)
	}
	if err := fsys.Put(statePath, data, false); err != nil {
		return fmt.Errorf("pollinate: persist state: %w", err)
	}
	return nil
}
