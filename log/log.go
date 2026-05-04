// Package log is the cactus issuance log: a tiled, single-writer
// append-only log of MerkleTreeCertEntry blobs (per §5.3 of the draft)
// that periodically signs checkpoints and covering subtrees (§4.5,
// §5.4.1) using a CA cosigner.
//
// The public surface is the Log type, which exposes Append + Wait per
// PROJECT_PLAN §6. Append assigns an index immediately; Wait blocks
// until the entry has been included in a published checkpoint and a
// covering signed subtree exists.
package log

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"sync"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/log/tilewriter"
	cactusmetrics "github.com/letsencrypt/cactus/metrics"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"
	"golang.org/x/mod/sumdb/tlog"
)

// Issued is the result of Wait: everything the CA needs to assemble a
// standalone certificate (§6.2) for this entry.
type Issued struct {
	Index          uint64
	Subtree        cert.MTCSubtree
	InclusionProof []tlogx.Hash
	Signatures     []cert.MTCSignature
}

// Checkpoint summarises the current head of the log.
type Checkpoint struct {
	Size uint64
	Root tlogx.Hash
	// SignedNote is the c2sp signed-note bytes (origin + size + base64
	// root + cosigner signatures).
	SignedNote []byte
}

// Config carries the parameters needed to bring up a Log.
type Config struct {
	LogID       cert.TrustAnchorID
	CosignerID  cert.TrustAnchorID
	Signer      signer.Signer
	FS          storage.FS
	FlushPeriod time.Duration
	NowFunc     func() time.Time // optional, defaults to time.Now
	Metrics     Metrics          // optional; nil-safe

	// OnFlush, if set, is invoked after each successful flush with
	// the *new* tree size. Used by the landmark allocator to call
	// `seq.Append(treeSize, now)` per §6.3.2. Runs in its own
	// goroutine so a slow callback can't stall the sequencer.
	OnFlush func(treeSize uint64)

	// MirrorRequester, if set, is invoked once per signed covering
	// subtree after the checkpoint has been published. Runs in a
	// background goroutine — by the time it fires, /checkpoint
	// already serves the new (size, root), so mirrors polling
	// upstream can verify and respond. Sigs returned here are
	// appended to the matching subtree's `sigs` slice in
	// l.committed (still at this checkpoint). Late arrivals against
	// a superseded checkpoint are dropped silently.
	MirrorRequester func(
		ctx context.Context,
		subtree *cert.MTCSubtree,
		caSig cert.MTCSignature,
	) ([]cert.MTCSignature, error)

	// WaitForCosigners, if > 0, makes Wait block until the entry's
	// covering subtree has accumulated at least this many signatures
	// (CA + mirrors), or until ctx fires. With the default of 0,
	// Wait returns as soon as the entry is committed regardless of
	// how many sigs are present.
	WaitForCosigners int

	// Logger is used to surface flush errors and other operational
	// messages from the sequencer goroutine. Defaults to slog.Default().
	Logger *slog.Logger
}

// Metrics is the small subset of prometheus instruments the Log uses.
// All fields are nil-safe.
type Metrics struct {
	Entries           cactusmetrics.Counter
	Checkpoints       cactusmetrics.Counter
	PoolFlushSize     cactusmetrics.Observer
	SignatureDuration cactusmetrics.ObserverVec // labels: alg
}

// Log is the issuance log. It owns one writer goroutine per instance.
type Log struct {
	cfg Config
	tw  *tilewriter.TileWriter

	mu sync.Mutex // protects pool and checkpoint
	// pool is the queue of pending submissions.
	pool []poolItem
	// dedup maps idempotency key -> already-assigned index.
	dedup map[[32]byte]uint64
	// committed is the latest checkpoint that has been signed and
	// persisted with covering subtrees.
	committed *committedCheckpoint
	// notify is closed and re-created each flush; waiters re-check.
	notify chan struct{}

	stop    chan struct{}
	stopped chan struct{}
}

type poolItem struct {
	entry   []byte
	idemKey [32]byte
}

type committedCheckpoint struct {
	size uint64
	root tlogx.Hash
	// covering subtrees from the last flush. Only meaningful after at
	// least one flush has produced new entries.
	subtrees    []signedSubtree
	signedNote  []byte
	hashesAtCkp []tlog.Hash // snapshot for proof generation
}

type signedSubtree struct {
	subtree cert.MTCSubtree
	// sigs are the cosigner signatures attached to this subtree.
	// sigs[0] is always the CA cosigner; mirror cosigner signatures
	// (Phase 9.4) are appended afterwards.
	sigs []cert.MTCSignature
}

// New constructs a Log and starts its sequencing goroutine. The first
// entry of a fresh log is reserved as a null_entry (§5.3) and is
// written before this returns.
func New(ctx context.Context, cfg Config) (*Log, error) {
	if cfg.Signer == nil {
		return nil, errors.New("log: cfg.Signer required")
	}
	if cfg.FS == nil {
		return nil, errors.New("log: cfg.FS required")
	}
	if cfg.FlushPeriod <= 0 {
		return nil, errors.New("log: cfg.FlushPeriod must be > 0")
	}
	if cfg.NowFunc == nil {
		cfg.NowFunc = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	tw, err := tilewriter.New(cfg.FS)
	if err != nil {
		return nil, fmt.Errorf("log: tilewriter.New: %w", err)
	}
	l := &Log{
		cfg:     cfg,
		tw:      tw,
		dedup:   make(map[[32]byte]uint64),
		notify:  make(chan struct{}),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}

	// Index 0 must be a null_entry (§5.3). If the log is empty, write it.
	if tw.Size() == 0 {
		_, err := tw.Append([][]byte{cert.EncodeNullEntry()})
		if err != nil {
			return nil, fmt.Errorf("log: write null entry: %w", err)
		}
	}

	// Seed the committed checkpoint and dedup index from disk if present.
	if err := l.loadCheckpoint(); err != nil {
		return nil, err
	}
	if l.committed == nil {
		// No prior signed checkpoint — sign the current state synchronously
		// so Append/Wait have something to wait on after the null entry.
		if err := l.flush(); err != nil {
			return nil, fmt.Errorf("log: initial flush: %w", err)
		}
	}

	go l.run()
	return l, nil
}

// Stop signals the sequencer to drain and return.
func (l *Log) Stop() {
	close(l.stop)
	<-l.stopped
}

// Append submits an entry and returns its assigned index. If an entry
// with the same idempotency key was already appended, the existing
// index is returned without re-appending.
func (l *Log) Append(_ context.Context, entry []byte, idemKey [32]byte) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if idx, ok := l.dedup[idemKey]; ok {
		return idx, nil
	}
	// Index assignment: current committed size + len(pool) + 1 (null_entry baseline absorbed).
	// Actually: the next-assigned index is current treeSize (post-null) + queued.
	// But we don't know treeSize here without calling tw which is single-writer.
	// We assign indices when the sequencer flushes; for now we just queue
	// and return a "tentative" index based on queue position. That's fine
	// because callers compare via the idempotency key; the *real* index
	// is returned by Wait.
	//
	// Simpler: do bookkeeping based on the tilewriter's current size,
	// which is owned by the writer goroutine but only mutated under our
	// lock during flush. We CAN read it here as long as flush holds
	// l.mu while updating tw.
	//
	// We keep that invariant: l.mu must be held during flush's
	// tw.Append. See flush().
	pendingIdx := uint64(l.tw.Size()) + uint64(len(l.pool))
	l.pool = append(l.pool, poolItem{entry: entry, idemKey: idemKey})
	l.dedup[idemKey] = pendingIdx
	return pendingIdx, nil
}

// Wait blocks until the given index has been included in a signed
// checkpoint and the covering subtree has been signed, then returns
// the proof material. If WaitForCosigners > 0, also waits for the
// covering subtree to accumulate that many signatures (or for ctx).
func (l *Log) Wait(ctx context.Context, index uint64) (Issued, error) {
	for {
		l.mu.Lock()
		ch := l.notify
		var iss Issued
		ok := false
		if l.committed != nil && index < l.committed.size {
			var err error
			iss, err = l.buildIssued(index)
			if err != nil {
				l.mu.Unlock()
				return Issued{}, err
			}
			// Honour WaitForCosigners: only consider the issuance
			// "ready" when the covering subtree has enough sigs.
			if l.cfg.WaitForCosigners > 0 && len(iss.Signatures) < l.cfg.WaitForCosigners {
				ok = false
			} else {
				ok = true
			}
		}
		l.mu.Unlock()
		if ok {
			return iss, nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return Issued{}, ctx.Err()
		case <-l.stop:
			return Issued{}, errors.New("log: stopped")
		}
	}
}

// SubtreeProof returns the §4.3 inclusion proof for entry `index` within
// subtree [start, end), plus the subtree's Merkle hash. The returned
// proof + hash are computed against the latest committed tile state,
// so callers must hold a consistent view of the tree (e.g. a tree
// size from CurrentCheckpoint or a landmark.Sequence entry).
//
// Used by the ACME alternate-URL handler (Phase 8.4) to assemble
// landmark-relative certs.
func (l *Log) SubtreeProof(start, end, index uint64) (tlogx.Hash, []tlogx.Hash, error) {
	l.mu.Lock()
	hashes := l.tw.SnapshotHashes()
	l.mu.Unlock()
	hr := hashesAsTlog(hashes)
	hash, err := tlogx.SubtreeHash(start, end, hr)
	if err != nil {
		return tlogx.Hash{}, nil, err
	}
	proof, err := tlogx.GenerateInclusionProof(start, end, index, hr)
	if err != nil {
		return tlogx.Hash{}, nil, err
	}
	return hash, proof, nil
}

// ConsistencyProof returns the §4.4 subtree consistency proof from
// (start, end) up to a tree of size treeSize, against a snapshot of
// the current tile state. Used by the multi-mirror requester to
// construct the §C.2 sign-subtree request body.
func (l *Log) ConsistencyProof(start, end, treeSize uint64) ([]tlogx.Hash, error) {
	l.mu.Lock()
	hashes := l.tw.SnapshotHashes()
	l.mu.Unlock()
	hr := hashesAsTlog(hashes)
	return tlogx.GenerateConsistencyProof(
		sha256Hash, start, end, treeSize,
		func(i uint64) (tlogx.Hash, error) {
			hs, err := hr.ReadHashes([]int64{tlog.StoredHashIndex(0, int64(i))})
			if err != nil {
				return tlogx.Hash{}, err
			}
			return tlogx.Hash(hs[0]), nil
		},
	)
}

// CurrentCheckpoint returns the latest signed checkpoint, or zero-value
// if none has been published yet.
func (l *Log) CurrentCheckpoint() Checkpoint {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.committed == nil {
		return Checkpoint{}
	}
	return Checkpoint{
		Size:       l.committed.size,
		Root:       l.committed.root,
		SignedNote: append([]byte(nil), l.committed.signedNote...),
	}
}

// run is the single-writer goroutine. It ticks every FlushPeriod and
// flushes pending entries into a new checkpoint.
func (l *Log) run() {
	defer close(l.stopped)
	t := time.NewTicker(l.cfg.FlushPeriod)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			// Drain anything left.
			if err := l.flush(); err != nil {
				l.cfg.Logger.Error("log: drain flush failed", "err", err)
			}
			return
		case <-t.C:
			if err := l.flush(); err != nil {
				// Sequencer-internal errors mostly indicate disk
				// problems; surface them so operators see the
				// failure mode instead of issuance silently
				// hanging. The sequencer keeps running and will
				// retry on the next tick.
				l.cfg.Logger.Error("log: flush failed", "err", err)
			}
		}
	}
}

// flush is called from run() (and once from New for the initial
// checkpoint). It:
//  1. Acquires l.mu and snapshots the pending pool.
//  2. Appends those entries via the tile writer.
//  3. Signs the new checkpoint and the up-to-two covering subtrees.
//  4. Persists the signed note and signed subtrees.
//  5. Updates l.committed and signals waiters.
func (l *Log) flush() error {
	// Hold l.mu for the entire flush. Append() reads tw.Size() under
	// the same lock, so we must not mutate tw without it. (Earlier
	// versions tried to release l.mu around tile-writer I/O for
	// concurrency, but that races with API readers; the test server
	// can tolerate disk I/O under the lock.)
	l.mu.Lock()
	defer l.mu.Unlock()

	prevSize := uint64(l.tw.Size())
	pool := l.pool
	l.pool = nil

	if len(pool) == 0 && l.committed != nil && l.committed.size == prevSize {
		return nil // nothing to do
	}

	var entries [][]byte
	for _, p := range pool {
		entries = append(entries, p.entry)
	}
	if len(entries) > 0 {
		if _, err := l.tw.Append(entries); err != nil {
			l.pool = append(pool, l.pool...)
			return fmt.Errorf("flush append: %w", err)
		}
		if l.cfg.Metrics.Entries != nil {
			l.cfg.Metrics.Entries.Add(float64(len(entries)))
		}
	}
	if l.cfg.Metrics.PoolFlushSize != nil {
		l.cfg.Metrics.PoolFlushSize.Observe(float64(len(entries)))
	}

	newSize := uint64(l.tw.Size())
	root, err := l.tw.RootHash()
	if err != nil {
		return fmt.Errorf("flush root: %w", err)
	}
	var rootCp tlogx.Hash
	copy(rootCp[:], root[:])

	// Sign checkpoint.
	checkpointSubtree := cert.MTCSubtree{
		LogID: l.cfg.LogID,
		Start: 0,
		End:   newSize,
		Hash:  rootCp,
	}
	checkpointSig, err := l.signSubtree(&checkpointSubtree)
	if err != nil {
		return fmt.Errorf("flush sign checkpoint: %w", err)
	}
	signedNote, err := buildSignedNote(l.cfg.LogID, l.cfg.CosignerID,
		newSize, rootCp, checkpointSig.Signature)
	if err != nil {
		return fmt.Errorf("flush build note: %w", err)
	}

	// Sign covering subtrees for the just-added range, if any.
	// Phase 9.4: subtrees start with just the CA's sig; mirror sigs
	// are collected *after* the checkpoint is committed so that
	// mirrors polling our /checkpoint can see and verify the new
	// state before we ask them to sign.
	var subs []signedSubtree
	if newSize > prevSize && prevSize > 0 {
		covers := tlogx.FindSubtrees(prevSize, newSize)
		for _, s := range covers {
			h, err := subtreeHashFromTW(l.tw, s.Start, s.End)
			if err != nil {
				return fmt.Errorf("flush subtree hash [%d,%d): %w", s.Start, s.End, err)
			}
			st := cert.MTCSubtree{
				LogID: l.cfg.LogID,
				Start: s.Start,
				End:   s.End,
				Hash:  h,
			}
			caSig, err := l.signSubtree(&st)
			if err != nil {
				return fmt.Errorf("flush sign subtree: %w", err)
			}
			subs = append(subs, signedSubtree{subtree: st, sigs: []cert.MTCSignature{caSig}})
		}
	}

	if err := l.persistCheckpoint(newSize, rootCp, signedNote, subs); err != nil {
		return fmt.Errorf("flush persist: %w", err)
	}

	l.committed = &committedCheckpoint{
		size:        newSize,
		root:        rootCp,
		signedNote:  signedNote,
		subtrees:    subs,
		hashesAtCkp: l.tw.SnapshotHashes(),
	}
	close(l.notify)
	l.notify = make(chan struct{})
	if l.cfg.Metrics.Checkpoints != nil {
		l.cfg.Metrics.Checkpoints.Add(1)
	}
	if l.cfg.OnFlush != nil {
		// Don't block the sequencer if the callback wants to do
		// disk I/O (e.g. the landmark allocator).
		go l.cfg.OnFlush(newSize)
	}

	// Phase 9.4: kick off mirror cosignature collection for each
	// subtree we just committed. Runs in a goroutine so it doesn't
	// block subsequent flushes; on success it appends to
	// subtree.sigs in l.committed (still keyed to *this* checkpoint
	// — older checkpoints are dropped from l.committed).
	if l.cfg.MirrorRequester != nil && len(subs) > 0 {
		// Capture by value so a subsequent flush replacing
		// l.committed doesn't perturb the request.
		toRequest := append([]signedSubtree(nil), subs...)
		capturedNote := append([]byte(nil), signedNote...)
		capturedSize := newSize
		go l.collectMirrorSigs(toRequest, capturedNote, capturedSize)
	}
	return nil
}

// collectMirrorSigs invokes MirrorRequester for each just-committed
// subtree and appends the returned signatures to the matching subtree
// in l.committed (if it's still the current checkpoint). Late arrivals
// against a superseded checkpoint are dropped.
func (l *Log) collectMirrorSigs(subs []signedSubtree, signedNote []byte, atSize uint64) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for i := range subs {
		st := subs[i].subtree
		caSig := subs[i].sigs[0]
		mirrorSigs, err := l.cfg.MirrorRequester(ctx, &st, caSig)
		if err != nil {
			// Best-effort: skip this subtree.
			continue
		}
		if len(mirrorSigs) == 0 {
			continue
		}

		// Mutate l.committed under l.mu, but only if it still
		// matches the checkpoint we collected sigs for. A newer
		// flush in-between superseded our state; drop the result.
		l.mu.Lock()
		if l.committed != nil && l.committed.size == atSize {
			for j := range l.committed.subtrees {
				cs := &l.committed.subtrees[j]
				if cs.subtree.Start == st.Start && cs.subtree.End == st.End {
					cs.sigs = append(cs.sigs, mirrorSigs...)
					_ = l.persistOneSubtree(*cs)
					close(l.notify)
					l.notify = make(chan struct{})
					break
				}
			}
		}
		l.mu.Unlock()
	}
	_ = signedNote
}

func (l *Log) signSubtree(st *cert.MTCSubtree) (cert.MTCSignature, error) {
	msg, err := cert.MarshalSignatureInput(l.cfg.CosignerID, st)
	if err != nil {
		return cert.MTCSignature{}, err
	}
	start := time.Now()
	sig, err := l.cfg.Signer.Sign(rand.Reader, msg)
	if err != nil {
		return cert.MTCSignature{}, err
	}
	if l.cfg.Metrics.SignatureDuration != nil {
		l.cfg.Metrics.SignatureDuration.WithLabelValues(l.cfg.Signer.Algorithm().String()).
			Observe(time.Since(start).Seconds())
	}
	return cert.MTCSignature{
		CosignerID: append([]byte(nil), l.cfg.CosignerID...),
		Signature:  sig,
	}, nil
}

func (l *Log) persistCheckpoint(size uint64, root tlogx.Hash,
	signedNote []byte, subs []signedSubtree) error {
	// Signed note: latest checkpoint, mutable, atomic rename.
	if err := l.cfg.FS.Put("log/checkpoint", signedNote, false); err != nil {
		return err
	}
	// Per-subtree files in log/subtrees/<start>-<end>.
	for _, s := range subs {
		if err := l.persistOneSubtree(s); err != nil {
			return err
		}
	}
	return nil
}

// persistOneSubtree writes one subtree-signature file using the
// `uint8 count` || repeated `(uint8 id_len, id, uint16 sig_len, sig)`
// layout.
func (l *Log) persistOneSubtree(s signedSubtree) error {
	var buf []byte
	buf = append(buf, byte(len(s.sigs)))
	for _, sig := range s.sigs {
		buf = append(buf, byte(len(sig.CosignerID)))
		buf = append(buf, sig.CosignerID...)
		var sl [2]byte
		binary.BigEndian.PutUint16(sl[:], uint16(len(sig.Signature)))
		buf = append(buf, sl[:]...)
		buf = append(buf, sig.Signature...)
	}
	path := fmt.Sprintf("log/subtrees/%d-%d", s.subtree.Start, s.subtree.End)
	return l.cfg.FS.Put(path, buf, false)
}

// loadCheckpoint reads any previously-written checkpoint to seed
// l.committed on startup. The checkpoint's cosigner signature is
// verified against the configured Signer's public key so on-disk bit
// rot or tampering is caught before we trust the seeded state.
func (l *Log) loadCheckpoint() error {
	data, err := l.cfg.FS.Get("log/checkpoint")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	size, root, sigs, err := parseSignedNoteFull(data, l.cfg.LogID)
	if err != nil {
		return fmt.Errorf("parse stored checkpoint: %w", err)
	}
	if uint64(l.tw.Size()) < size {
		// On-disk checkpoint claims more entries than the tile writer
		// has — should not happen in single-writer mode, but signal
		// the inconsistency rather than silently masking it.
		return fmt.Errorf("checkpoint size %d > tilewriter size %d", size, l.tw.Size())
	}
	if err := l.verifyLoadedCheckpointSig(size, root, sigs); err != nil {
		return fmt.Errorf("verify stored checkpoint: %w", err)
	}
	l.committed = &committedCheckpoint{
		size:        size,
		root:        root,
		signedNote:  data,
		hashesAtCkp: l.tw.SnapshotHashes(),
	}
	return nil
}

// verifyLoadedCheckpointSig confirms that one of the signatures on the
// loaded signed-note is from our configured CA cosigner over the
// reconstructed §5.4.1 MTCSubtreeSignatureInput for [0, size). Any
// other sigs (mirrors) are not checked here.
func (l *Log) verifyLoadedCheckpointSig(size uint64, root tlogx.Hash, sigs []parsedNoteSig) error {
	cosignerKeyName := "oid/" + string(l.cfg.CosignerID)
	wantKeyID := mtcCheckpointKeyID(cosignerKeyName)
	var sig parsedNoteSig
	found := false
	for _, s := range sigs {
		if s.keyName == cosignerKeyName && s.keyID == wantKeyID {
			sig = s
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("no signature from cosigner %q found", cosignerKeyName)
	}
	subtree := cert.MTCSubtree{
		LogID: l.cfg.LogID,
		Start: 0, End: size, Hash: root,
	}
	msg, err := cert.MarshalSignatureInput(l.cfg.CosignerID, &subtree)
	if err != nil {
		return fmt.Errorf("build signature input: %w", err)
	}
	key := cert.CosignerKey{
		ID:        l.cfg.CosignerID,
		Algorithm: cert.SignatureAlgorithm(l.cfg.Signer.Algorithm()),
		PublicKey: l.cfg.Signer.PublicKey(),
	}
	mtcSig := cert.MTCSignature{CosignerID: l.cfg.CosignerID, Signature: sig.sig}
	return cert.VerifyMTCSignature(key, mtcSig, msg)
}

func (l *Log) buildIssued(index uint64) (Issued, error) {
	if l.committed == nil || index >= l.committed.size {
		return Issued{}, fmt.Errorf("log: index %d not yet committed (size %d)", index, sizeOrZero(l.committed))
	}
	// Find the covering subtree(s) for the last flush's range. The
	// inclusion proof we need is from `index` to the subtree that
	// contains it — chosen from the available signed subtrees, or the
	// whole tree if none exist (initial null-entry-only state).
	for _, s := range l.committed.subtrees {
		if index >= s.subtree.Start && index < s.subtree.End {
			proof, err := subtreeInclusionProof(s.subtree.Start, s.subtree.End, index, l.committed.hashesAtCkp)
			if err != nil {
				return Issued{}, fmt.Errorf("inclusion proof: %w", err)
			}
			return Issued{
				Index:          index,
				Subtree:        s.subtree,
				InclusionProof: proof,
				Signatures:     append([]cert.MTCSignature(nil), s.sigs...),
			}, nil
		}
	}
	// Fall back: cover via the whole-tree (start=0). The checkpoint
	// signature itself covers [0, size).
	root := l.committed.root
	st := cert.MTCSubtree{LogID: l.cfg.LogID, Start: 0, End: l.committed.size, Hash: root}
	proof, err := subtreeInclusionProof(0, l.committed.size, index, l.committed.hashesAtCkp)
	if err != nil {
		return Issued{}, fmt.Errorf("whole-tree inclusion proof: %w", err)
	}
	// We don't have a separate stored signature for the whole-tree
	// subtree (the signed note covers it implicitly), so we sign on
	// demand from the cached state. We can't re-sign cheaply without
	// the signer here; fortunately at startup we have nothing in
	// covering subtrees and there are no real entries to issue
	// against. Return the proof and an empty signatures slice; callers
	// for the null entry won't ever ask for an Issued.
	return Issued{
		Index:          index,
		Subtree:        st,
		InclusionProof: proof,
	}, nil
}

func sizeOrZero(c *committedCheckpoint) uint64 {
	if c == nil {
		return 0
	}
	return c.size
}

// subtreeInclusionProof builds an inclusion proof for index of subtree
// [start, end). It mirrors the §4.3 procedure: treat the subtree as a
// Merkle tree of size end-start and use tlog.ProveRecord on the
// effective sub-log.
//
// We delegate to tlog.ProveRecord by translating: for a full subtree
// directly contained in the global tree, its hash equals
// tlog.TreeHash(end) when start==0; otherwise we have to recursively
// compute. To keep this simple and correct we use the recursion below
// rather than tlog.
func subtreeInclusionProof(start, end, index uint64, h []tlog.Hash) ([]tlogx.Hash, error) {
	hr := hashesAsTlog(h)
	// Build proof against a virtual subtree by walking down the
	// Merkle structure for [start, end).
	return walkInclusionProof(start, end, index, hr)
}

// walkInclusionProof is a direct recursive implementation of the
// inclusion proof for a subtree whose hashes share the storage layout
// of the underlying tlog tree.
//
// Because [start, end) is a valid subtree (start is a multiple of
// bit_ceil(end-start)), there's a unique path from index up to the
// subtree root. At each level we descend into the half containing
// index and emit the sibling hash.
func walkInclusionProof(start, end, index uint64, hr tlog.HashReader) ([]tlogx.Hash, error) {
	if !tlogx.IsValid(start, end) {
		return nil, fmt.Errorf("invalid subtree [%d,%d)", start, end)
	}
	if index < start || index >= end {
		return nil, fmt.Errorf("index %d outside [%d,%d)", index, start, end)
	}
	var proof []tlogx.Hash
	for end-start > 1 {
		// Largest power of 2 strictly less than (end-start).
		k := largestPowerOfTwoLT(end - start)
		mid := start + k
		if index < mid {
			// Sibling = subtreeHash([mid, end)).
			sib, err := subtreeHashFromHR(mid, end, hr)
			if err != nil {
				return nil, err
			}
			proof = append(proof, sib)
			end = mid
		} else {
			sib, err := subtreeHashFromHR(start, mid, hr)
			if err != nil {
				return nil, err
			}
			proof = append(proof, sib)
			start = mid
		}
	}
	// Reverse: above we emit from root toward leaf, but EvaluateInclusionProof
	// expects leaf-up.
	for i, j := 0, len(proof)-1; i < j; i, j = i+1, j-1 {
		proof[i], proof[j] = proof[j], proof[i]
	}
	return proof, nil
}

func largestPowerOfTwoLT(n uint64) uint64 {
	if n <= 1 {
		return 0
	}
	k := uint64(1)
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// subtreeHashFromHR returns the Merkle subtree hash for [start, end)
// using a tlog.HashReader. For subtrees that are valid per §4.1, we
// can compute this recursively from stored hashes.
func subtreeHashFromHR(start, end uint64, hr tlog.HashReader) (tlogx.Hash, error) {
	if start >= end {
		return tlogx.Hash{}, fmt.Errorf("empty subtree [%d,%d)", start, end)
	}
	// If [start, end) is a complete power-of-two-aligned subtree, it
	// lives directly at a stored level. The stored level is
	// log2(end-start), and the offset within that level is
	// start / (end-start).
	width := end - start
	if width&(width-1) == 0 && start%width == 0 {
		level := bitsLen(width) - 1
		n := start / width
		idx := tlog.StoredHashIndex(level, int64(n))
		hs, err := hr.ReadHashes([]int64{idx})
		if err != nil {
			return tlogx.Hash{}, err
		}
		return tlogx.Hash(hs[0]), nil
	}
	// Otherwise split using the largest power-of-two less than width.
	k := largestPowerOfTwoLT(width)
	mid := start + k
	left, err := subtreeHashFromHR(start, mid, hr)
	if err != nil {
		return tlogx.Hash{}, err
	}
	right, err := subtreeHashFromHR(mid, end, hr)
	if err != nil {
		return tlogx.Hash{}, err
	}
	return tlogx.HashChildren(sha256Hash, left, right), nil
}

func sha256Hash(b []byte) tlogx.Hash {
	return tlogx.Hash(sha256.Sum256(b))
}

func bitsLen(x uint64) int {
	n := 0
	for x > 0 {
		n++
		x >>= 1
	}
	return n
}

func subtreeHashFromTW(tw *tilewriter.TileWriter, start, end uint64) (tlogx.Hash, error) {
	return subtreeHashFromHR(start, end, tw.HashReader())
}

// hashesAsTlog wraps a snapshot slice as a tlog.HashReader.
type hashesAsTlog []tlog.Hash

func (h hashesAsTlog) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		if idx < 0 || idx >= int64(len(h)) {
			return nil, fmt.Errorf("hash index %d out of range [0,%d)", idx, len(h))
		}
		out[i] = h[idx]
	}
	return out, nil
}
