package mirror

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/log/tilewriter"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"
)

// Upstream describes the log being mirrored.
type Upstream struct {
	// TileURL is the tlog-tiles base URL (no trailing slash).
	TileURL string
	// LogID is the upstream's trust anchor ID, used to validate the
	// signed-note origin line ("oid/<LogID>").
	LogID cert.TrustAnchorID
	// CACosignerID identifies the upstream CA cosigner; used as the
	// signed-note key name ("oid/<CACosignerID>").
	CACosignerID cert.TrustAnchorID
	// CACosignerKey is the SPKI of the upstream CA cosigner key.
	// ECDSA-P256-SHA256 only in the v3 milestone.
	CACosignerKey []byte
}

// FollowerConfig configures a Follower.
type FollowerConfig struct {
	Upstream     Upstream
	FS           storage.FS
	PollInterval time.Duration
	Logger       *slog.Logger
	// Metrics are optional; nil-safe.
	Metrics FollowerMetrics
}

// FollowerMetrics are the optional Prometheus instruments the
// Follower updates. Each one has the same nil-safe contract as in
// the log package.
type FollowerMetrics struct {
	UpstreamSize        Gauge
	ConsistencyFailures Counter
}

// Gauge / Counter mirror the metrics.* interfaces, declared locally
// so this package doesn't have to import metrics.
type Gauge interface{ Set(float64) }
type Counter interface{ Add(float64) }

// Follower follows an upstream log and maintains a verified local
// copy. It is goroutine-safe: Run owns mutation; the read-only
// accessors (Current, SubtreeHash, Halted) take a snapshot lock.
type Follower struct {
	cfg        FollowerConfig
	httpClient *http.Client

	mu         sync.Mutex
	size       uint64
	root       tlogx.Hash
	signedNote []byte
	hashes     []tlog.Hash // stored hashes, indexed by tlog.StoredHashIndex
	halted     bool
}

// State paths under the configured storage.FS.
const (
	stateRoot       = "state/mirror/upstream/"
	stateCheckpoint = stateRoot + "checkpoint"
	stateSize       = stateRoot + "size"
	stateHaltedFile = stateRoot + "halted"
)

// NewFollower constructs a Follower and replays any persisted state
// from disk. If state/mirror/upstream/halted exists, the follower
// starts in halted mode and refuses to advance until manually cleared.
func NewFollower(cfg FollowerConfig) (*Follower, error) {
	if cfg.PollInterval <= 0 {
		return nil, errors.New("mirror: PollInterval must be > 0")
	}
	if len(cfg.Upstream.CACosignerKey) == 0 {
		return nil, errors.New("mirror: Upstream.CACosignerKey is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	f := &Follower{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
	if err := f.loadFromDisk(); err != nil {
		return nil, err
	}
	return f, nil
}

// Run blocks until ctx is cancelled. It polls the upstream every
// PollInterval and advances local state on a verified checkpoint.
func (f *Follower) Run(ctx context.Context) error {
	t := time.NewTicker(f.cfg.PollInterval)
	defer t.Stop()
	// Try once immediately on Run() entry rather than waiting a tick.
	f.poll(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			f.poll(ctx)
		}
	}
}

// poll executes one upstream poll. Errors are logged and counted but
// do not return up — Run must keep ticking.
func (f *Follower) poll(ctx context.Context) {
	if f.Halted() {
		return
	}
	if err := f.advance(ctx); err != nil {
		f.cfg.Logger.Error("mirror: advance failed", "err", err)
	}
}

// advance is the per-tick state machine: fetch upstream checkpoint,
// verify, fetch new entries, recompute root, persist.
func (f *Follower) advance(ctx context.Context) error {
	// 1) Fetch upstream /checkpoint.
	checkpoint, err := f.httpGet(ctx, f.cfg.Upstream.TileURL+"/checkpoint")
	if err != nil {
		return fmt.Errorf("fetch checkpoint: %w", err)
	}
	keyName := "oid/" + string(f.cfg.Upstream.CACosignerID)
	upstreamSize, upstreamRoot, sigBytes, err := parseSignedNote(checkpoint, keyName)
	if err != nil {
		return fmt.Errorf("parse checkpoint: %w", err)
	}

	// 2) Verify the CA cosignature against MTCSubtreeSignatureInput
	// for [0, upstreamSize). If this fails, halt.
	subtree := &cert.MTCSubtree{
		LogID: f.cfg.Upstream.LogID,
		Start: 0, End: upstreamSize, Hash: upstreamRoot,
	}
	sigInput, err := cert.MarshalSignatureInput(f.cfg.Upstream.CACosignerID, subtree)
	if err != nil {
		return err
	}
	verifyErr := cert.VerifyMTCSignature(cert.CosignerKey{
		ID:        f.cfg.Upstream.CACosignerID,
		Algorithm: cert.AlgECDSAP256SHA256,
		PublicKey: f.cfg.Upstream.CACosignerKey,
	}, cert.MTCSignature{
		CosignerID: f.cfg.Upstream.CACosignerID,
		Signature:  sigBytes,
	}, sigInput)
	if verifyErr != nil {
		return f.haltf("CA cosignature verify: %v", verifyErr)
	}

	// 3) Compare against current local size. If equal, no advance; if
	// less, the upstream is going backwards (consistency violation).
	f.mu.Lock()
	currentSize := f.size
	f.mu.Unlock()
	if upstreamSize == currentSize {
		// Already caught up. Refresh signedNote in case sigs changed.
		f.mu.Lock()
		f.signedNote = checkpoint
		f.mu.Unlock()
		return f.fs().Put(stateCheckpoint, checkpoint, false)
	}
	if upstreamSize < currentSize {
		return f.haltf("upstream size %d < local %d (rollback)", upstreamSize, currentSize)
	}

	// 4) Fetch the [currentSize, upstreamSize) data-tile slice and
	// replay through tlog.StoredHashes.
	newHashes, err := f.replayNewEntries(ctx, currentSize, upstreamSize)
	if err != nil {
		return fmt.Errorf("replay new entries: %w", err)
	}

	// 5) Recompute root and verify.
	f.mu.Lock()
	combined := make([]tlog.Hash, len(f.hashes)+len(newHashes))
	copy(combined, f.hashes)
	copy(combined[len(f.hashes):], newHashes)
	root, err := tlog.TreeHash(int64(upstreamSize), hashReader(combined))
	f.mu.Unlock()
	if err != nil {
		return fmt.Errorf("TreeHash: %w", err)
	}
	if tlogx.Hash(root) != upstreamRoot {
		return f.haltf("recomputed root %x != upstream root %x", root[:8], upstreamRoot[:8])
	}

	// 6) Commit state.
	f.mu.Lock()
	f.hashes = combined
	f.size = upstreamSize
	f.root = upstreamRoot
	f.signedNote = checkpoint
	f.mu.Unlock()

	if err := f.fs().Put(stateCheckpoint, checkpoint, false); err != nil {
		return err
	}
	var sb [8]byte
	binary.BigEndian.PutUint64(sb[:], upstreamSize)
	if err := f.fs().Put(stateSize, sb[:], false); err != nil {
		return err
	}
	if f.cfg.Metrics.UpstreamSize != nil {
		f.cfg.Metrics.UpstreamSize.Set(float64(upstreamSize))
	}
	f.cfg.Logger.Info("mirror: advanced", "size", upstreamSize)
	return nil
}

// replayNewEntries fetches data tiles covering [from, to), splits them
// into entry blobs, and runs tlog.StoredHashes to produce the new
// stored-hash slice.
func (f *Follower) replayNewEntries(ctx context.Context, from, to uint64) ([]tlog.Hash, error) {
	entries, err := f.fetchEntries(ctx, from, to)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	current := f.hashes
	f.mu.Unlock()
	hr := hashReader(append([]tlog.Hash(nil), current...))
	var added []tlog.Hash
	for i, e := range entries {
		hs, err := tlog.StoredHashes(int64(from)+int64(i), e, hr)
		if err != nil {
			return nil, fmt.Errorf("StoredHashes(%d): %w", from+uint64(i), err)
		}
		hr = append(hr, hs...)
		added = append(added, hs...)
	}
	return added, nil
}

func (f *Follower) fetchEntries(ctx context.Context, from, to uint64) ([][]byte, error) {
	const ents = uint64(tilewriter.EntriesPerDataTile)
	out := make([][]byte, 0, to-from)
	for tileN := from / ents; tileN*ents < to; tileN++ {
		recordsInTile := int(ents)
		if (tileN+1)*ents > to {
			recordsInTile = int(to - tileN*ents)
		}
		raw, err := f.httpGet(ctx, f.cfg.Upstream.TileURL+"/"+dataTilePath(int64(tileN), recordsInTile))
		if err != nil {
			return nil, err
		}
		es, err := tilewriter.SplitDataTile(raw)
		if err != nil {
			return nil, err
		}
		// Trim leading entries we already have (when from > tileN*ents).
		startInTile := int(0)
		if from > tileN*ents {
			startInTile = int(from - tileN*ents)
		}
		for i := startInTile; i < len(es); i++ {
			out = append(out, es[i])
			if uint64(len(out))+from >= to {
				return out, nil
			}
		}
	}
	return out, nil
}

// dataTilePath mirrors tile/server's path computation. Duplicated here
// to avoid an import cycle into the tile package.
func dataTilePath(tileN int64, recordsInTile int) string {
	prefix := "tile/" + strconv.Itoa(tilewriter.TileHeight) + "/data/"
	if recordsInTile == tilewriter.EntriesPerDataTile {
		return prefix + nnnPath(tileN)
	}
	return prefix + nnnPath(tileN) + ".p/" + strconv.Itoa(recordsInTile)
}

func nnnPath(n int64) string {
	if n == 0 {
		return "000"
	}
	var parts []string
	for n > 0 {
		parts = append([]string{padDigit(int(n % 1000))}, parts...)
		n /= 1000
	}
	for i := 0; i < len(parts)-1; i++ {
		parts[i] = "x" + parts[i]
	}
	return strings.Join(parts, "/")
}

func padDigit(n int) string {
	s := strconv.Itoa(n)
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}

// haltf marks the follower halted, persists the marker, and returns an
// error with the message. Use %v (not %w) when including a wrapped
// error — both Sprintf and the persisted marker need a string-shaped
// rendering.
func (f *Follower) haltf(format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	f.mu.Lock()
	f.halted = true
	f.mu.Unlock()
	_ = f.fs().Put(stateHaltedFile, []byte(msg+"\n"), false)
	if f.cfg.Metrics.ConsistencyFailures != nil {
		f.cfg.Metrics.ConsistencyFailures.Add(1)
	}
	return errors.New("mirror halted: " + msg)
}

// Current returns the latest verified checkpoint.
func (f *Follower) Current() (size uint64, root tlogx.Hash, signedNote []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.size, f.root, append([]byte(nil), f.signedNote...)
}

// SubtreeHash returns the §4 Merkle subtree hash for [start, end)
// based on the local mirror's verified state. Used by the
// sign-subtree handler.
func (f *Follower) SubtreeHash(start, end uint64) (tlogx.Hash, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if end > f.size {
		return tlogx.Hash{}, fmt.Errorf("mirror: end %d > local size %d", end, f.size)
	}
	return tlogx.SubtreeHash(start, end, hashReader(f.hashes))
}

// Halted reports whether the follower has stopped advancing due to a
// detected consistency failure.
func (f *Follower) Halted() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.halted
}

// fs returns the storage FS, asserting it's non-nil.
func (f *Follower) fs() storage.FS { return f.cfg.FS }

// loadFromDisk replays state/mirror/upstream/* into memory.
func (f *Follower) loadFromDisk() error {
	if f.cfg.FS == nil {
		return errors.New("mirror: FS required")
	}
	// Halted marker?
	if ok, _ := f.cfg.FS.Exists(stateHaltedFile); ok {
		f.halted = true
		return nil
	}
	sizeBytes, err := f.cfg.FS.Get(stateSize)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // fresh
	}
	if err != nil {
		return err
	}
	if len(sizeBytes) != 8 {
		return errors.New("mirror: bad size file")
	}
	size := binary.BigEndian.Uint64(sizeBytes)
	cp, err := f.cfg.FS.Get(stateCheckpoint)
	if err != nil {
		return err
	}
	keyName := "oid/" + string(f.cfg.Upstream.CACosignerID)
	_, root, _, err := parseSignedNote(cp, keyName)
	if err != nil {
		return err
	}
	// We don't persist the full hash array on disk; on restart the
	// follower has to refetch entries to rebuild it. Since the
	// upstream still serves them this is fine.
	f.size = 0
	f.root = root // overwritten on first advance
	f.signedNote = cp
	_ = size // we'll re-derive size from the upstream
	_ = root // ditto
	return nil
}

// hashReader wraps a slice as tlog.HashReader.
type hashReader []tlog.Hash

func (h hashReader) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		if idx < 0 || idx >= int64(len(h)) {
			return nil, fmt.Errorf("mirror: hash index %d out of range [0,%d)", idx, len(h))
		}
		out[i] = h[idx]
	}
	return out, nil
}

// httpGet fetches url and returns the body.
func (f *Follower) httpGet(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// Bound the response so a hostile or buggy upstream can't OOM the
	// mirror with a multi-GiB body. Tile and checkpoint payloads are
	// always small (a checkpoint is ~hundreds of bytes; a SHA-256 tile
	// at H=8 is at most 256·32 = 8 KiB, with subtree padding a small
	// constant; data tiles cap at EntriesPerDataTile entries with a
	// per-entry size that ACME bounds well below 256 KiB). 8 MiB is a
	// generous ceiling.
	const MaxFetchBytes = 8 << 20
	return io.ReadAll(io.LimitReader(resp.Body, MaxFetchBytes))
}

// keep these imports used
var (
	_ = sha256.Sum256
)
