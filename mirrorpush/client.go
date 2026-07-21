// Package mirrorpush is a client for c2sp.org/tlog-mirror: it pushes
// the cactus issuance log to mirrors that expect to be written to,
// rather than to poll.
//
// The direction matters. A c2sp.org/tlog-mirror mirror never fetches
// from the origin log; the log (or something acting for it) drives every
// update over three write endpoints under the mirror's submission
// prefix — add-checkpoint, add-entries, and optionally sign-subtree.
// cactus is therefore the client on all three.
//
// The reason cactus cares about more than durability is sign-subtree.
// MTC §5.3.1 CosignedMessage and a c2sp.org/tlog-cosignature
// cosigned_message are byte-identical under SHA-256 + ML-DSA-44, so a
// mirror's sign-subtree response drops straight into an MTCProof with
// no translation. But a mirror will only sign a subtree against a
// reference checkpoint that already carries its own cosignature, and
// the only place that cosignature is ever produced is the add-entries
// 200 response. Pushing entries is thus a precondition for collecting
// the mirror cosignatures that go into issued certificates, which is
// why this package retains the cosigned checkpoint and hands it back
// out via Pool.CheckpointWithCosignatures.
//
// Update flow per mirror, per log flush:
//
//	discover  — learn the mirror's checkpoint size (monitoring prefix)
//	            and the size it will accept as `old` (add-checkpoint 409)
//	add-checkpoint — move the mirror's *pending* checkpoint to ours,
//	            with an RFC 6962 tree consistency proof
//	add-entries    — upload [next_entry, upload_end) as 256-aligned
//	            packages, each with an MTC §4.4 subtree consistency
//	            proof; loop on 202 until a 200 arrives
//	200 → retain the mirror's checkpoint cosignature
package mirrorpush

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"
)

// maxResponseBytes bounds every mirror response we read. Cosignature
// bodies are a few kilobytes (an ML-DSA-44 line is ~3.3 KiB of base64)
// and mirror-info bodies are three short lines, so this is generous.
const maxResponseBytes = 256 << 10

// maxUploadRounds bounds the 202/409 loop. Each round must strictly
// advance the mirror's next entry, so the loop terminates on its own;
// this is a belt-and-braces cap against a mirror that reports progress
// it did not make.
const maxUploadRounds = 64

// Source is the read side of the log, as the push client needs it. It
// is an interface so the state machine can be tested without a real
// tree; *log.Log satisfies it modulo the small adapter in cmd/cactus.
type Source interface {
	// Checkpoint returns the current signed checkpoint: its tree size,
	// root hash, and the signed-note bytes.
	Checkpoint() (size uint64, root tlogx.Hash, note []byte)
	// Entries returns the raw log entries with indices in [start, end).
	Entries(start, end uint64) ([][]byte, error)
	// SubtreeConsistencyProof returns the MTC §4.4 subtree consistency
	// proof from the subtree [start, end) to a tree of size treeSize.
	SubtreeConsistencyProof(start, end, treeSize uint64) ([]tlogx.Hash, error)
	// TreeConsistencyProof returns the RFC 6962 §2.1.2 tree consistency
	// proof from a tree of size oldSize to one of size newSize.
	TreeConsistencyProof(oldSize, newSize uint64) ([]tlogx.Hash, error)
}

// Target is one mirror to push to.
type Target struct {
	// SubmissionPrefix is the base URL of the write APIs; the client
	// appends "/add-checkpoint", "/add-entries".
	SubmissionPrefix string
	// MonitoringPrefix is the base URL of the read APIs, under which
	// the mirror serves "<origin hash>/checkpoint".
	MonitoringPrefix string
	// Key is the mirror's cosigner identity and public key, used to
	// pick its cosignature lines out of an add-entries 200 response and
	// verify them.
	Key cert.CosignerKey
	// HTTPClient is optional; http.DefaultClient is used if nil.
	HTTPClient *http.Client
	// Timeout bounds each individual HTTP request. Zero means no
	// per-request bound beyond the caller's context.
	Timeout time.Duration
	// DisableGzip turns off Content-Encoding: gzip on add-entries
	// bodies. tlog-mirror says clients SHOULD compress and mirrors MUST
	// support gzip, so compression is on by default; the switch exists
	// for packet-level debugging against a new peer.
	DisableGzip bool
}

// errFatal marks a failure that must not be retried by re-pushing the
// same data. See Client.Push for the classification.
type errFatal struct{ err error }

func (e errFatal) Error() string { return e.err.Error() }
func (e errFatal) Unwrap() error { return e.err }

// IsFatal reports whether err is a mirror failure that retrying cannot
// fix, and that an operator needs to look at.
//
// The important member of this class is a 422 from add-entries. A 422
// means the mirror could not verify a subtree consistency proof against
// its pending checkpoint — either our proofs are wrong, or the mirror
// is locked onto a checkpoint inconsistent with ours. Neither is
// transient, and the second is an integrity signal about the log
// itself, so retrying would at best paper over it and at worst hammer
// the mirror. 400 (framing) and 404 (unknown origin) are likewise our
// bug or a misconfiguration, not something time fixes.
func IsFatal(err error) bool {
	var f errFatal
	return errors.As(err, &f)
}

// Client pushes one log to one mirror. It is safe for concurrent use;
// at most one add-entries exchange with a given mirror is in flight at
// a time, per the "one in-flight upload per mirror" rule.
type Client struct {
	target Target
	src    Source
	logID  cert.TrustAnchorID
	origin string
	fsys   storage.FS // optional; state is kept in memory only if nil
	logger *slog.Logger

	// push serialises whole Push calls so a slow upload cannot overlap
	// with the next flush's.
	push sync.Mutex

	mu sync.Mutex
	st state
}

// state is everything the client remembers about a mirror between
// pushes.
type state struct {
	// nextEntry is the mirror's next entry: the first index it is
	// missing. It is only ever moved forward by a value the mirror
	// itself advertised, or by a completed upload confirmed with a 200.
	// Guessing it forward would make us skip entries the mirror needs
	// and stall the upload permanently.
	nextEntry uint64
	// pendingSize is a tree size the mirror will accept as upload_end,
	// and ticket is the opaque token that lets it recover that pending
	// checkpoint. They are stored, persisted, and invalidated as a
	// matched pair: a ticket is only meaningful for the size it was
	// issued alongside, so replaying one against a different upload_end
	// is at best useless and at worst confusing to the mirror.
	pendingSize uint64
	ticket      []byte
	// known distinguishes "we have never talked to this mirror" from
	// "the mirror told us it is at zero".
	known bool

	// cosignedSize and cosigLines hold the mirror's cosignature over a
	// checkpoint of that size, harvested from an add-entries 200. This
	// is the payload the whole exercise is for: it is what makes a
	// reference checkpoint acceptable to sign-subtree.
	cosignedSize uint64
	cosigLines   []string
}

// persistedState is the on-disk form of the resumable parts of state.
type persistedState struct {
	NextEntry   uint64 `json:"next_entry"`
	PendingSize uint64 `json:"pending_size"`
	Ticket      string `json:"ticket,omitempty"` // base64
}

// New builds a push client for one (log, mirror) pair. fsys may be nil,
// in which case state lives only in memory and is rediscovered from the
// mirror after a restart.
func New(logID cert.TrustAnchorID, t Target, src Source, fsys storage.FS, logger *slog.Logger) (*Client, error) {
	if t.SubmissionPrefix == "" {
		return nil, errors.New("mirrorpush: submission prefix required")
	}
	if src == nil {
		return nil, errors.New("mirrorpush: source required")
	}
	if t.Key.Algorithm != cert.AlgMLDSA44 {
		return nil, fmt.Errorf("mirrorpush: mirror %q must be ML-DSA-44, got 0x%04x",
			t.Key.ID, uint16(t.Key.Algorithm))
	}
	if logger == nil {
		logger = slog.Default()
	}
	c := &Client{
		target: t,
		src:    src,
		logID:  logID,
		origin: cert.OIDName(logID),
		fsys:   fsys,
		logger: logger.With("mirror", string(t.Key.ID), "submission_prefix", t.SubmissionPrefix),
	}
	if err := c.loadState(); err != nil {
		return nil, err
	}
	return c, nil
}

// Name is the mirror's signed-note key name.
func (c *Client) Name() string { return cert.OIDName(c.target.Key.ID) }

// Push brings the mirror up to the log's current checkpoint: it moves
// the mirror's pending checkpoint forward, uploads the entries the
// mirror is missing, and retains the resulting checkpoint cosignature.
//
// It is intended to be called after every log flush. Calls serialise;
// a call that arrives while another is in flight waits for it, and then
// sees the newer checkpoint, so no work is lost.
func (c *Client) Push(ctx context.Context) error {
	c.push.Lock()
	defer c.push.Unlock()

	size, root, note := c.src.Checkpoint()
	if size == 0 || len(note) == 0 {
		// Nothing has been sequenced yet. A mirror has no use for an
		// empty tree and add-entries would have an empty canonical
		// sequence with nothing to cosign.
		return nil
	}

	if err := c.discover(ctx, size); err != nil {
		return err
	}
	if err := c.pushCheckpoint(ctx, size, note); err != nil {
		return err
	}
	return c.pushEntries(ctx, size, root, note)
}

// CosignedCheckpoint returns the checkpoint note the client last
// obtained a mirror cosignature for, together with its tree size, or
// (nil, 0) if none.
func (c *Client) CosignedCheckpoint() (uint64, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st.cosignedSize, append([]string(nil), c.st.cosigLines...)
}

// discover establishes an initial next-entry guess for a mirror we have
// no state for, by reading the checkpoint the mirror publishes.
//
// tlog-mirror sanctions exactly this bootstrap: a client without
// information on the mirror "MAY initially make an add-checkpoint
// request to obtain a pending checkpoint size and fetch a checkpoint
// from the monitoring prefix". Both can be stale by the time
// add-entries runs, which is fine — they are a starting point, and any
// error is corrected by the 202/409 loop, which is the only thing we
// actually trust to set next entry.
func (c *Client) discover(ctx context.Context, ourSize uint64) error {
	c.mu.Lock()
	known := c.st.known
	c.mu.Unlock()
	if known {
		return nil
	}
	size, err := c.fetchMirrorCheckpointSize(ctx)
	if err != nil {
		// A mirror that has never cosigned this log answers 404, which
		// fetchMirrorCheckpointSize reports as size 0, so a real error
		// here is a transport or configuration problem. Fall back to
		// zero rather than refusing to push: add-entries will tell us
		// the truth via a 409.
		c.logger.Debug("mirrorpush: could not read mirror checkpoint, starting from 0", "err", err)
		size = 0
	}
	// The discovered size comes from an unauthenticated GET of the
	// mirror's checkpoint (no signature is verified). Never let it seed a
	// next-entry beyond our own checkpoint: a forged or buggy oversized
	// value would make every pushEntries take the "mirror is ahead"
	// bail-out and silently wedge this mirror out of cosignature
	// collection for the process lifetime. Clamp to our size; a mirror
	// that is genuinely ahead is corrected by the authenticated
	// add-entries loop.
	if size > ourSize {
		c.logger.Warn("mirrorpush: mirror advertises a larger checkpoint than ours; clamping discovery seed",
			"mirror_size", size, "our_size", ourSize)
		size = ourSize
	}
	c.mu.Lock()
	c.st.nextEntry = size
	c.st.known = true
	c.mu.Unlock()
	return nil
}

// fetchMirrorCheckpointSize GETs <monitoring prefix>/<origin hash>/
// checkpoint and returns its tree size, or 0 if the mirror has never
// cosigned this log (404).
func (c *Client) fetchMirrorCheckpointSize(ctx context.Context) (uint64, error) {
	if c.target.MonitoringPrefix == "" {
		return 0, errors.New("mirrorpush: no monitoring prefix configured")
	}
	// The origin hash is the SHA-256 of the log's origin, hex encoded,
	// in lowercase.
	sum := sha256.Sum256([]byte(c.origin))
	url := strings.TrimSuffix(c.target.MonitoringPrefix, "/") + "/" + hex.EncodeToString(sum[:]) + "/checkpoint"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	status, body, err := c.do(ctx, req)
	if err != nil {
		return 0, err
	}
	if status == http.StatusNotFound {
		return 0, nil
	}
	if status != http.StatusOK {
		return 0, fmt.Errorf("mirrorpush: GET checkpoint: HTTP %d", status)
	}
	// A checkpoint body is "<origin>\n<size>\n<base64 root>\n" followed
	// by a blank line and signature lines. We only want the size.
	lines := strings.Split(string(body), "\n")
	if len(lines) < 3 {
		return 0, errors.New("mirrorpush: malformed mirror checkpoint")
	}
	if lines[0] != c.origin {
		return 0, fmt.Errorf("mirrorpush: mirror checkpoint origin %q != %q", lines[0], c.origin)
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("mirrorpush: mirror checkpoint size: %w", err)
	}
	return size, nil
}

// pushCheckpoint moves the mirror's pending checkpoint to ours via the
// witness add-checkpoint endpoint.
//
// The consistency proof here is an RFC 6962 *tree* consistency proof
// from the mirror's last accepted size to ours — not the MTC §4.4
// subtree proof that add-entries packages and sign-subtree use. The two
// endpoints genuinely want different proof systems and a proof of the
// wrong kind verifies against neither.
func (c *Client) pushCheckpoint(ctx context.Context, size uint64, note []byte) error {
	oldSize := c.checkpointOldSize()
	// At most two attempts: the first with our belief about the
	// mirror's size, the second with the size a 409 told us. A second
	// 409 means the mirror is moving under us, which the next flush
	// will pick up.
	for attempt := 0; attempt < 2; attempt++ {
		if oldSize > size {
			// The mirror is ahead of us. That is legitimate — another
			// client may have pushed, or we may have lost state — and
			// there is nothing to add-checkpoint. add-entries will
			// still run and reconcile against the mirror's view.
			c.logger.Debug("mirrorpush: mirror is ahead of us", "mirror_size", oldSize, "our_size", size)
			return nil
		}
		body, err := c.buildAddCheckpointBody(oldSize, size, note)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			strings.TrimSuffix(c.target.SubmissionPrefix, "/")+"/add-checkpoint", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "text/plain; charset=utf-8")
		status, respBody, err := c.do(ctx, req)
		if err != nil {
			return err
		}
		switch status {
		case http.StatusOK:
			// A mirror MAY answer with an empty body, and MUST NOT sign
			// the checkpoint here — any cosignature present would be
			// from a separate witness identity, so there is nothing for
			// us to harvest. The pending checkpoint is now at `size`.
			c.mu.Lock()
			c.st.pendingSize = size
			c.mu.Unlock()
			return nil
		case http.StatusConflict:
			advertised, perr := ParseSize(respBody)
			if perr != nil {
				return fmt.Errorf("mirrorpush: add-checkpoint 409: %w", perr)
			}
			if advertised == oldSize {
				return fmt.Errorf("mirrorpush: add-checkpoint 409 re-advertised size %d", advertised)
			}
			oldSize = advertised
		case http.StatusNotFound:
			return errFatal{fmt.Errorf("mirrorpush: add-checkpoint: mirror does not know origin %q", c.origin)}
		case http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusForbidden:
			return errFatal{fmt.Errorf("mirrorpush: add-checkpoint: HTTP %d: %s", status, truncate(respBody))}
		default:
			return fmt.Errorf("mirrorpush: add-checkpoint: HTTP %d: %s", status, truncate(respBody))
		}
	}
	return errors.New("mirrorpush: add-checkpoint kept conflicting")
}

// checkpointOldSize is our current belief about the size of the last
// checkpoint the mirror accepted, i.e. the `old` value add-checkpoint
// wants. Zero for a mirror we have never pushed to, which is the
// sanctioned way to ask: the mirror answers 409 with the real size.
func (c *Client) checkpointOldSize() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st.pendingSize
}

// buildAddCheckpointBody assembles the tlog-witness add-checkpoint body:
//
//	old <size>
//	<base64 tree consistency proof hash>   (0..63 lines)
//	...
//	<empty line>
//	<checkpoint>
func (c *Client) buildAddCheckpointBody(oldSize, newSize uint64, note []byte) ([]byte, error) {
	proof, err := c.src.TreeConsistencyProof(oldSize, newSize)
	if err != nil {
		return nil, fmt.Errorf("mirrorpush: tree consistency proof %d->%d: %w", oldSize, newSize, err)
	}
	if oldSize == 0 && len(proof) != 0 {
		// The empty tree is consistent with every tree, so a witness
		// rejects a non-empty proof here with a 422.
		return nil, errors.New("mirrorpush: non-empty consistency proof for old size 0")
	}
	if len(proof) > MaxProofHashes {
		return nil, fmt.Errorf("mirrorpush: consistency proof has %d hashes, max %d", len(proof), MaxProofHashes)
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "old %d\n", oldSize)
	for _, h := range proof {
		b.WriteString(base64.StdEncoding.EncodeToString(h[:]) + "\n")
	}
	b.WriteString("\n")
	b.Write(note)
	if !bytes.HasSuffix(note, []byte("\n")) {
		b.WriteString("\n")
	}
	return b.Bytes(), nil
}

// pushEntries uploads [next entry, size) to the mirror and retains the
// checkpoint cosignature from the final 200.
func (c *Client) pushEntries(ctx context.Context, uploadEnd uint64, root tlogx.Hash, note []byte) error {
	for round := 0; round < maxUploadRounds; round++ {
		c.mu.Lock()
		uploadStart := c.st.nextEntry
		// The ticket is only replayable against the size it was issued
		// with. Sending it with a different upload_end tells the mirror
		// to recover a pending checkpoint that has nothing to do with
		// the one we are claiming, so drop it instead.
		var ticket []byte
		if c.st.pendingSize == uploadEnd {
			ticket = append([]byte(nil), c.st.ticket...)
		}
		c.mu.Unlock()

		if uploadStart > uploadEnd {
			// The mirror is ahead of our checkpoint. Nothing to upload
			// against this checkpoint; a later flush will catch up. Log
			// it: after discovery clamps to our size this should only
			// happen for a genuinely-ahead mirror, so a persistent
			// message here points at a real divergence worth noticing.
			c.logger.Warn("mirrorpush: mirror ahead of our checkpoint, skipping upload",
				"next_entry", uploadStart, "our_size", uploadEnd)
			return nil
		}

		body, err := c.buildUpload(uploadStart, uploadEnd, ticket)
		if err != nil {
			return err
		}
		status, respBody, err := c.postAddEntries(ctx, body)
		if err != nil {
			return err
		}

		switch status {
		case http.StatusOK:
			// The mirror committed everything through uploadEnd and
			// cosigned the checkpoint at that size. Verify before we
			// believe any of it.
			subtree := &cert.MTCSubtree{
				LogID: c.logID,
				// A checkpoint cosignature covers the whole tree:
				// start MUST be zero, end is the tree size.
				Start: 0,
				End:   uploadEnd,
				Hash:  root,
			}
			cosigs, err := VerifyCosignatures(respBody, c.target.Key, subtree, TimestampNonZero)
			if err != nil {
				// A bad cosignature on an otherwise successful upload
				// is a serious mirror fault, not a retryable blip.
				return errFatal{err}
			}
			lines := make([]string, 0, len(cosigs))
			for _, cs := range cosigs {
				lines = append(lines, cs.Line)
			}
			c.mu.Lock()
			c.st.nextEntry = uploadEnd
			c.st.pendingSize = uploadEnd
			c.st.cosignedSize = uploadEnd
			c.st.cosigLines = lines
			c.mu.Unlock()
			c.saveState()
			c.logger.Debug("mirrorpush: upload complete", "size", uploadEnd, "cosignatures", len(lines))
			return nil

		case http.StatusAccepted, http.StatusConflict:
			mi, perr := ParseMirrorInfo(respBody)
			if perr != nil {
				return fmt.Errorf("mirrorpush: add-entries HTTP %d: %w", status, perr)
			}
			advanced, aerr := c.applyMirrorInfo(status, uploadStart, mi)
			if aerr != nil {
				return aerr
			}
			if !advanced && status == http.StatusAccepted {
				// A 202 means "I committed a prefix and want more", so
				// the next entry must have moved. If it hasn't, looping
				// would spin forever against an unchanging mirror.
				return fmt.Errorf("mirrorpush: add-entries 202 did not advance next entry past %d", uploadStart)
			}
			if mi.PendingSize != uploadEnd {
				// The mirror no longer recognises the checkpoint we are
				// uploading against, so every proof we would build is
				// against the wrong tree size. Bail out and let the
				// next flush re-run add-checkpoint; that is cheaper and
				// clearer than trying to pivot mid-upload.
				c.logger.Debug("mirrorpush: mirror pending size moved",
					"ours", uploadEnd, "theirs", mi.PendingSize)
				return nil
			}
			continue

		case http.StatusUnprocessableEntity:
			return errFatal{fmt.Errorf(
				"mirrorpush: add-entries 422: mirror could not verify a subtree consistency proof "+
					"against its pending checkpoint for [%d,%d) — this is an integrity signal, not a "+
					"transient error: %s", uploadStart, uploadEnd, truncate(respBody))}
		case http.StatusBadRequest:
			return errFatal{fmt.Errorf("mirrorpush: add-entries 400 (malformed request framing): %s", truncate(respBody))}
		case http.StatusNotFound:
			return errFatal{fmt.Errorf("mirrorpush: add-entries: mirror does not know origin %q", c.origin)}
		case http.StatusUnsupportedMediaType:
			return errFatal{errors.New("mirrorpush: add-entries 415: mirror rejected the request content type")}
		default:
			return fmt.Errorf("mirrorpush: add-entries: HTTP %d: %s", status, truncate(respBody))
		}
	}
	return fmt.Errorf("mirrorpush: upload did not finish in %d rounds", maxUploadRounds)
}

// applyMirrorInfo folds a 202/409 body into our state and reports
// whether the mirror's next entry moved past what we just tried to
// upload from.
//
// Next entry is never set from anything but a value the mirror
// advertised, and never moved backwards past a position we already know
// it reached — a stale or reordered response must not rewind us into
// re-uploading entries we have confirmation for.
func (c *Client) applyMirrorInfo(status int, uploadStart uint64, mi MirrorInfo) (bool, error) {
	c.mu.Lock()
	advanced := mi.NextEntry > uploadStart
	if mi.NextEntry > c.st.nextEntry || status == http.StatusConflict {
		// A 409 can legitimately move us *backwards*: it is how a
		// mirror says "you started past my next entry". Honour it —
		// unlike a 202, that is not progress, it is a correction.
		c.st.nextEntry = mi.NextEntry
	}
	// Ticket and pending size are stored together; a ticket without the
	// size it was issued for is unusable.
	c.st.pendingSize = mi.PendingSize
	c.st.ticket = mi.Ticket
	c.st.known = true
	c.mu.Unlock()
	c.saveState()
	return advanced, nil
}

// buildUpload assembles one add-entries request body covering at most
// MaxPackagesPerRequest packages of the canonical sequence for
// [uploadStart, uploadEnd).
func (c *Client) buildUpload(uploadStart, uploadEnd uint64, ticket []byte) ([]byte, error) {
	seq, err := CanonicalSequence(uploadStart, uploadEnd)
	if err != nil {
		return nil, err
	}
	// Send at most 32 packages; the mirror answers 202 with an advanced
	// next entry and we come back for the rest.
	if len(seq) > MaxPackagesPerRequest {
		seq = seq[:MaxPackagesPerRequest]
	}
	data := make([]PackageData, 0, len(seq))
	for _, p := range seq {
		entries, err := c.src.Entries(p.Start, p.End)
		if err != nil {
			return nil, fmt.Errorf("mirrorpush: read entries [%d,%d): %w", p.Start, p.End, err)
		}
		// The proof covers [ProofStart, End), the whole 256-aligned
		// bundle, even when we only transmit [Start, End). See the
		// Package doc comment.
		proof, err := c.src.SubtreeConsistencyProof(p.ProofStart, p.End, uploadEnd)
		if err != nil {
			return nil, fmt.Errorf("mirrorpush: subtree consistency proof [%d,%d) to %d: %w",
				p.ProofStart, p.End, uploadEnd, err)
		}
		data = append(data, PackageData{Entries: entries, Proof: proof})
	}
	return BuildAddEntries(Header{
		Origin:      c.origin,
		UploadStart: uploadStart,
		UploadEnd:   uploadEnd,
		Ticket:      ticket,
	}, data)
}

// postAddEntries sends an add-entries request, optionally gzipped.
func (c *Client) postAddEntries(ctx context.Context, body []byte) (int, []byte, error) {
	payload := body
	encoding := ""
	if !c.target.DisableGzip {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(body); err != nil {
			return 0, nil, err
		}
		if err := zw.Close(); err != nil {
			return 0, nil, err
		}
		payload = buf.Bytes()
		encoding = "gzip"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(c.target.SubmissionPrefix, "/")+"/add-entries", bytes.NewReader(payload))
	if err != nil {
		return 0, nil, err
	}
	// Mandatory: a mirror answers 415 for anything else.
	req.Header.Set("Content-Type", "application/octet-stream")
	if encoding != "" {
		req.Header.Set("Content-Encoding", encoding)
	}
	return c.do(ctx, req)
}

// do performs a request and reads a bounded response body.
//
// A mirror is explicitly allowed to answer before it has read our
// request body — it SHOULD send 409/422 early rather than draining a
// large upload it is going to reject, and clients SHOULD be prepared
// for it. When that happens the request write can fail concurrently
// with the response arriving, and net/http may surface either one; if
// the write error wins the race, a perfectly good status code is lost.
//
// Two things keep that from doing damage. The body is fully buffered
// before the request starts (rather than streamed from the tree), so
// the write window is as short as we can make it and Request.GetBody
// lets the transport replay it. And a transport error is reported as an
// ordinary, non-fatal error: it never advances next-entry state and is
// never mistaken for a 422, so the worst case is that the next flush
// repeats the exchange and reads the status properly. Never inferring a
// status from a write error is the whole point — inferring the wrong
// one is how a client silently skips entries.
func (c *Client) do(ctx context.Context, req *http.Request) (int, []byte, error) {
	hc := c.target.HTTPClient
	if hc == nil {
		hc = http.DefaultClient
	}
	if c.target.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.target.Timeout)
		defer cancel()
		req = req.WithContext(ctx)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("mirrorpush: %s %s: %w", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, fmt.Errorf("mirrorpush: read response: %w", err)
	}
	return resp.StatusCode, body, nil
}

// statePath is where this (log, mirror) pair's resumable state lives.
// The mirror is identified by a hash of its cosigner ID and submission
// prefix so the path is filesystem-safe whatever the operator
// configures.
func (c *Client) statePath() string {
	sum := sha256.Sum256([]byte(string(c.target.Key.ID) + "\n" + c.target.SubmissionPrefix + "\n" + c.origin))
	return "mirrorpush/" + hex.EncodeToString(sum[:8]) + ".json"
}

func (c *Client) loadState() error {
	if c.fsys == nil {
		return nil
	}
	data, err := c.fsys.Get(c.statePath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("mirrorpush: read state: %w", err)
	}
	var ps persistedState
	if err := json.Unmarshal(data, &ps); err != nil {
		return fmt.Errorf("mirrorpush: parse state: %w", err)
	}
	ticket, err := base64.StdEncoding.DecodeString(ps.Ticket)
	if err != nil {
		return fmt.Errorf("mirrorpush: parse state ticket: %w", err)
	}
	c.st.nextEntry = ps.NextEntry
	c.st.pendingSize = ps.PendingSize
	c.st.ticket = ticket
	c.st.known = true
	return nil
}

// saveState persists the resumable state. Failures are logged, not
// returned: losing the state costs a rediscovery round trip on the next
// start, which is not worth failing a push over.
func (c *Client) saveState() {
	if c.fsys == nil {
		return
	}
	c.mu.Lock()
	ps := persistedState{
		NextEntry:   c.st.nextEntry,
		PendingSize: c.st.pendingSize,
		Ticket:      base64.StdEncoding.EncodeToString(c.st.ticket),
	}
	c.mu.Unlock()
	data, err := json.Marshal(ps)
	if err != nil {
		c.logger.Warn("mirrorpush: marshal state", "err", err)
		return
	}
	if err := c.fsys.Put(c.statePath(), data, false); err != nil {
		c.logger.Warn("mirrorpush: persist state", "err", err)
	}
}

func truncate(b []byte) string {
	const limit = 256
	if len(b) > limit {
		return string(b[:limit]) + "…"
	}
	return string(b)
}

// Pool is a set of push clients, one per configured mirror, driven
// together after each log flush.
//
// A nil *Pool is usable and inert: every method is a no-op or a
// pass-through, so a deployment with no push targets behaves exactly as
// it did before this package existed.
type Pool struct {
	clients []*Client
	logger  *slog.Logger
}

// NewPool groups clients into a pool.
func NewPool(clients []*Client, logger *slog.Logger) *Pool {
	if len(clients) == 0 {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Pool{clients: clients, logger: logger}
}

// Push runs every client concurrently, best effort. One mirror being
// down or misbehaving must not hold up the others, so per-client
// failures are logged and swallowed; a fatal error is logged loudly
// because it needs an operator.
func (p *Pool) Push(ctx context.Context) {
	if p == nil {
		return
	}
	var wg sync.WaitGroup
	for _, c := range p.clients {
		wg.Add(1)
		go func(c *Client) {
			defer wg.Done()
			if err := c.Push(ctx); err != nil {
				if IsFatal(err) {
					p.logger.Error("mirrorpush: fatal push failure, not retrying",
						"mirror", c.Name(), "err", err)
					return
				}
				p.logger.Warn("mirrorpush: push failed", "mirror", c.Name(), "err", err)
			}
		}(c)
	}
	wg.Wait()
}

// CheckpointWithCosignatures returns note with every mirror
// cosignature we hold for a checkpoint of exactly this size appended as
// additional signed-note signature lines.
//
// This is how the push path feeds sign-subtree. c2sp.org/tlog-witness
// requires the reference checkpoint of a sign-subtree request to carry
// a cosignature from the responding key, or the mirror answers 403.
// Because a signed note may carry many signature lines and each
// cosigner ignores the lines that are not its own, one note with every
// mirror's cosignature appended satisfies all of them, and the CA can
// keep fanning a single request body out to the whole quorum.
//
// Cosignatures are matched on exact tree size: a cosignature is a
// statement about one (size, root) pair and means nothing attached to
// another.
func (p *Pool) CheckpointWithCosignatures(note []byte, size uint64) []byte {
	if p == nil || len(note) == 0 {
		return note
	}
	out := note
	if !bytes.HasSuffix(out, []byte("\n")) {
		out = append(append([]byte(nil), out...), '\n')
	}
	existing := string(out)
	for _, c := range p.clients {
		cosignedSize, lines := c.CosignedCheckpoint()
		if cosignedSize != size {
			continue
		}
		for _, line := range lines {
			if strings.Contains(existing, line+"\n") {
				continue // already present; don't duplicate
			}
			out = append(out, (line + "\n")...)
			existing += line + "\n"
		}
	}
	return out
}
