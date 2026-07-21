package mirrorpush

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tlogx"
)

var testLogID = cert.TrustAnchorID("32473.1.0.1")

func sha256Hash(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) }

// logSource adapts *log.Log to Source, mirroring the adapter in
// cmd/cactus. Using the real log means the proofs the client builds are
// real proofs, which the stub mirror below actually verifies.
type logSource struct{ l *cactuslog.Log }

func (s logSource) Checkpoint() (uint64, tlogx.Hash, []byte) {
	cp := s.l.CurrentCheckpoint()
	return cp.Size, cp.Root, cp.SignedNote
}
func (s logSource) Entries(start, end uint64) ([][]byte, error) { return s.l.Entries(start, end) }
func (s logSource) SubtreeConsistencyProof(start, end, treeSize uint64) ([]tlogx.Hash, error) {
	return s.l.ConsistencyProof(start, end, treeSize)
}
func (s logSource) TreeConsistencyProof(oldSize, newSize uint64) ([]tlogx.Hash, error) {
	return s.l.TreeConsistencyProof(oldSize, newSize)
}

// newTestLog returns a log holding n entries, flushed into a signed
// checkpoint.
func newTestLog(t *testing.T, n int) *cactuslog.Log {
	t.Helper()
	fsys, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := signer.FromSeed(signer.AlgMLDSA44, bytes.Repeat([]byte{0x42}, signer.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	l, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID:       testLogID,
		CosignerID:  cert.TrustAnchorID("32473.1"),
		Signer:      s,
		FS:          fsys,
		FlushPeriod: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)

	for i := range n {
		entry := cert.EncodeTBSCertEntry(fmt.Appendf(nil, "test entry %d", i))
		if _, err := l.Append(context.Background(), entry, sha256.Sum256(fmt.Appendf(nil, "idem %d", i))); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for uint64(n) > l.CurrentCheckpoint().Size {
		if time.Now().After(deadline) {
			t.Fatalf("log did not reach size %d (stuck at %d)", n, l.CurrentCheckpoint().Size)
		}
		time.Sleep(2 * time.Millisecond)
	}
	return l
}

// subtreeHashOfEntries computes the MTC §4.2 Merkle subtree hash of a
// contiguous run of entries, the way a mirror reconstructs a package's
// subtree from its own storage plus what the client sent.
func subtreeHashOfEntries(entries [][]byte) tlogx.Hash {
	if len(entries) == 1 {
		return tlogx.HashLeaf(sha256Hash, entries[0])
	}
	k := 1
	for k<<1 < len(entries) {
		k <<= 1
	}
	return tlogx.HashChildren(sha256Hash,
		subtreeHashOfEntries(entries[:k]), subtreeHashOfEntries(entries[k:]))
}

// stubMirror is a c2sp.org/tlog-mirror server that implements enough of
// the protocol to hold the push client to it. Unlike a bare fixture it
// verifies the per-package subtree consistency proofs for real,
// reconstructing each package's subtree hash from its own stored entries
// plus the ones just received. That is precisely the check that catches
// a client which proves [start, end) rather than the aligned
// [rounded_start + i*256, end).
type stubMirror struct {
	t      *testing.T
	id     cert.TrustAnchorID
	signer signer.Signer
	key    cert.CosignerKey
	logID  cert.TrustAnchorID

	mu sync.Mutex
	// entries the mirror holds, by log index.
	entries map[uint64][]byte
	// nextEntry is the first index the mirror is missing.
	nextEntry uint64
	// acceptedSize/pendingRoot describe the pending checkpoint.
	acceptedSize uint64
	pendingRoot  tlogx.Hash
	// maxPackagesPerCall caps how much of an upload the mirror commits
	// per request, so a prefix upload (202) can be forced without
	// generating 8192 entries.
	maxPackagesPerCall int
	// ticket is handed out in mirror-info bodies and asserted on the
	// next add-entries request.
	ticket []byte
	// fail422, if set, makes the next add-entries answer 422.
	fail422 bool

	// observed state, for assertions.
	addEntriesCalls  int
	addCheckpoints   int
	seenProofStarts  []uint64
	seenTickets      [][]byte
	seenUploadRanges [][2]uint64
}

func newStubMirror(t *testing.T, logID cert.TrustAnchorID, seedByte byte) *stubMirror {
	t.Helper()
	s, key := testCosigner(t, cert.TrustAnchorID("32473.77"), seedByte)
	return &stubMirror{
		t: t, id: key.ID, signer: s, key: key, logID: logID,
		entries:            map[uint64][]byte{},
		maxPackagesPerCall: MaxPackagesPerRequest,
	}
}

// seed pre-loads the mirror with entries [0, n) so tests can start the
// client from a non-zero, possibly unaligned, next entry.
func (m *stubMirror) seed(entries [][]byte) {
	for i, e := range entries {
		m.entries[uint64(i)] = e
	}
	m.nextEntry = uint64(len(entries))
}

func (m *stubMirror) mirrorInfo() []byte {
	return fmt.Appendf(nil, "%d\n%d\n%s\n",
		m.acceptedSize, m.nextEntry, base64.StdEncoding.EncodeToString(m.ticket))
}

func (m *stubMirror) writeMirrorInfo(w http.ResponseWriter, status int) {
	// Any mirror-info response is an opportunity to hand out a resume
	// ticket, and the client must send it back raw on the next request.
	m.ticket = []byte{0xDE, 0xAD, 0xBE, 0xEF}
	w.Header().Set("Content-Type", MirrorInfoContentType)
	w.WriteHeader(status)
	_, _ = w.Write(m.mirrorInfo())
}

func (m *stubMirror) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /add-checkpoint", m.addCheckpoint)
	mux.HandleFunc("POST /add-entries", m.addEntries)
	return mux
}

func (m *stubMirror) addCheckpoint(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addCheckpoints++
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(string(body), "\n\n", 2)
	if len(parts) != 2 {
		http.Error(w, "no blank line", http.StatusBadRequest)
		return
	}
	head := strings.Split(parts[0], "\n")
	var old uint64
	if _, err := fmt.Sscanf(head[0], "old %d", &old); err != nil {
		http.Error(w, "bad old line", http.StatusBadRequest)
		return
	}
	if old != m.acceptedSize {
		w.Header().Set("Content-Type", SizeContentType)
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, "%d\n", m.acceptedSize)
		return
	}
	// Record the new pending checkpoint's size and root.
	lines := strings.Split(parts[1], "\n")
	if len(lines) < 3 {
		http.Error(w, "short checkpoint", http.StatusBadRequest)
		return
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		http.Error(w, "bad size", http.StatusBadRequest)
		return
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(root) != tlogx.HashSize {
		http.Error(w, "bad root", http.StatusBadRequest)
		return
	}
	m.acceptedSize = size
	m.pendingRoot = tlogx.Hash(root)
	// A mirror MUST NOT cosign here; an empty body is explicitly allowed.
	w.WriteHeader(http.StatusOK)
}

func (m *stubMirror) addEntries(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addEntriesCalls++

	if ct := r.Header.Get("Content-Type"); ct != "application/octet-stream" {
		http.Error(w, "bad content type", http.StatusUnsupportedMediaType)
		return
	}
	var body []byte
	var err error
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, zerr := gzip.NewReader(r.Body)
		if zerr != nil {
			http.Error(w, "gunzip", http.StatusBadRequest)
			return
		}
		body, err = io.ReadAll(zr)
	} else {
		body, err = io.ReadAll(r.Body)
	}
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}

	h, pkgs, data, err := ParseAddEntries(body)
	if err != nil {
		http.Error(w, "framing: "+err.Error(), http.StatusBadRequest)
		return
	}
	if h.Origin != cert.OIDName(m.logID) {
		http.Error(w, "unknown origin", http.StatusNotFound)
		return
	}
	m.seenTickets = append(m.seenTickets, h.Ticket)
	m.seenUploadRanges = append(m.seenUploadRanges, [2]uint64{h.UploadStart, h.UploadEnd})

	if m.fail422 {
		m.fail422 = false
		http.Error(w, "proof did not verify", http.StatusUnprocessableEntity)
		return
	}
	if h.UploadEnd != m.acceptedSize {
		m.writeMirrorInfo(w, http.StatusConflict)
		return
	}
	if h.UploadStart > m.nextEntry {
		m.writeMirrorInfo(w, http.StatusConflict)
		return
	}

	limit := min(len(pkgs), m.maxPackagesPerCall)
	for i := range limit {
		p, pd := pkgs[i], data[i]
		m.seenProofStarts = append(m.seenProofStarts, p.ProofStart)

		// Reconstruct the package's subtree from our own storage plus
		// the received entries, then verify the consistency proof
		// against the pending checkpoint. This is the check a client
		// fails if it proves the transmitted range instead of the
		// aligned bundle.
		var subtree [][]byte
		for j := p.ProofStart; j < p.Start; j++ {
			e, ok := m.entries[j]
			if !ok {
				m.t.Errorf("mirror lacks entry %d needed to reconstruct subtree [%d,%d)",
					j, p.ProofStart, p.End)
				http.Error(w, "missing entry", http.StatusUnprocessableEntity)
				return
			}
			subtree = append(subtree, e)
		}
		subtree = append(subtree, pd.Entries...)
		nodeHash := subtreeHashOfEntries(subtree)
		if err := tlogx.VerifyConsistencyProof(sha256Hash,
			p.ProofStart, p.End, h.UploadEnd, pd.Proof, nodeHash, m.pendingRoot); err != nil {
			http.Error(w, "consistency proof: "+err.Error(), http.StatusUnprocessableEntity)
			return
		}

		for j, e := range pd.Entries {
			m.entries[p.Start+uint64(j)] = e
		}
		if p.End > m.nextEntry {
			m.nextEntry = p.End
		}
	}

	if m.nextEntry < h.UploadEnd {
		// A committed prefix: ask for the rest.
		m.writeMirrorInfo(w, http.StatusAccepted)
		return
	}

	// Everything through upload_end is committed: update the mirror
	// checkpoint and cosign it. The cosignature covers the whole tree,
	// so start is zero, and carries a non-zero timestamp.
	st := &cert.MTCSubtree{LogID: m.logID, Start: 0, End: h.UploadEnd, Hash: m.pendingRoot}
	ts := uint64(time.Now().Unix())
	msg, err := cert.MarshalSignatureInputAt(m.id, st, ts)
	if err != nil {
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}
	sig, err := m.signer.Sign(nil, msg)
	if err != nil {
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}
	name := cert.OIDName(m.id)
	keyID, err := cert.CosignatureKeyID(name, cert.AlgMLDSA44, m.signer.PublicKey())
	if err != nil {
		http.Error(w, "key id", http.StatusInternalServerError)
		return
	}
	blob := append(append([]byte(nil), keyID[:]...), cert.MarshalTimestampedSignature(ts, sig)...)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "— %s %s\n", name, base64.StdEncoding.EncodeToString(blob))
}

// newTestClient wires a push client to a stub mirror over httptest.
func newTestClient(t *testing.T, l *cactuslog.Log, m *stubMirror) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	fsys, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(testLogID, Target{
		SubmissionPrefix: srv.URL,
		MonitoringPrefix: srv.URL, // no /checkpoint route: discovery 404s, as for a new mirror
		Key:              m.key,
	}, logSource{l}, fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

// assertMirrorHasLog checks the mirror ended up with exactly the log's
// entries, byte for byte.
func assertMirrorHasLog(t *testing.T, m *stubMirror, l *cactuslog.Log) {
	t.Helper()
	size := l.CurrentCheckpoint().Size
	want, err := l.Entries(0, size)
	if err != nil {
		t.Fatal(err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if uint64(len(m.entries)) != size {
		t.Fatalf("mirror holds %d entries, log has %d", len(m.entries), size)
	}
	for i, w := range want {
		if got := m.entries[uint64(i)]; !bytes.Equal(got, w) {
			t.Fatalf("mirror entry %d = %x, want %x", i, got, w)
		}
	}
}

// TestPushSuccess is the straightforward path: a fresh mirror, a small
// log, one add-checkpoint and one add-entries answered 200.
func TestPushSuccess(t *testing.T) {
	l := newTestLog(t, 5)
	m := newStubMirror(t, testLogID, 0x55)
	c, _ := newTestClient(t, l, m)

	if err := c.Push(context.Background()); err != nil {
		t.Fatalf("Push: %v", err)
	}
	assertMirrorHasLog(t, m, l)

	if m.addEntriesCalls != 1 {
		t.Errorf("add-entries calls = %d, want 1", m.addEntriesCalls)
	}
	size, lines := c.CosignedCheckpoint()
	if size != l.CurrentCheckpoint().Size {
		t.Errorf("cosigned size = %d, want %d", size, l.CurrentCheckpoint().Size)
	}
	if len(lines) != 1 {
		t.Fatalf("got %d cosignature lines, want 1", len(lines))
	}

	// The retained cosignature must land in the checkpoint note the CA
	// presents to sign-subtree — that is the entire point of keeping it.
	pool := NewPool([]*Client{c}, nil)
	cp := l.CurrentCheckpoint()
	note := pool.CheckpointWithCosignatures(cp.SignedNote, cp.Size)
	if !strings.Contains(string(note), lines[0]) {
		t.Error("CheckpointWithCosignatures did not append the mirror cosignature")
	}
	// A size mismatch must not attach the cosignature to the wrong tree.
	if got := pool.CheckpointWithCosignatures(cp.SignedNote, cp.Size+1); strings.Contains(string(got), lines[0]) {
		t.Error("CheckpointWithCosignatures attached a cosignature to a different tree size")
	}
	// Calling twice must not duplicate lines.
	twice := pool.CheckpointWithCosignatures(note, cp.Size)
	if strings.Count(string(twice), lines[0]) != 1 {
		t.Error("CheckpointWithCosignatures duplicated a cosignature line")
	}
}

// TestPush202ThenOK drives the prefix-upload loop: the mirror commits
// one package per request and answers 202 until the upload completes.
func TestPush202ThenOK(t *testing.T) {
	l := newTestLog(t, 600) // three packages: [0,256) [256,512) [512,600)
	m := newStubMirror(t, testLogID, 0x56)
	m.maxPackagesPerCall = 1
	c, _ := newTestClient(t, l, m)

	if err := c.Push(context.Background()); err != nil {
		t.Fatalf("Push: %v", err)
	}
	assertMirrorHasLog(t, m, l)
	if m.addEntriesCalls != 3 {
		t.Errorf("add-entries calls = %d, want 3 (one per package)", m.addEntriesCalls)
	}
	// Every request after the first must carry the ticket the mirror
	// handed out — as RAW bytes, not the base64 it travelled in.
	for i, tk := range m.seenTickets[1:] {
		if !bytes.Equal(tk, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
			t.Errorf("add-entries %d ticket = %x, want the raw 4-byte ticket (base64 is response-only)", i+1, tk)
		}
	}
	if len(m.seenTickets) > 0 && len(m.seenTickets[0]) != 0 {
		t.Errorf("first add-entries carried a ticket %x, want none", m.seenTickets[0])
	}
	if _, lines := c.CosignedCheckpoint(); len(lines) != 1 {
		t.Errorf("got %d cosignature lines, want 1", len(lines))
	}
}

// TestPush409ThenRetry covers stale client state: the mirror is further
// along than we believe, answers 409 with its real next entry, and the
// client restarts the upload from there.
func TestPush409ThenRetry(t *testing.T) {
	l := newTestLog(t, 300)
	m := newStubMirror(t, testLogID, 0x57)
	// The mirror already holds [0,120): a next entry inside the first
	// 256-entry bundle, so package 0 transmits [120,256) while proving
	// the aligned [0,256).
	all, err := l.Entries(0, 300)
	if err != nil {
		t.Fatal(err)
	}
	m.seed(all[:120])
	c, _ := newTestClient(t, l, m)

	// Give the client a deliberately stale belief: it thinks the mirror
	// wants entries from 0, which is behind the mirror's next entry.
	// (Below its next entry is accepted by a mirror as re-upload, so
	// force the 409 by starting *past* it.)
	c.mu.Lock()
	c.st.known = true
	c.st.nextEntry = 200
	c.mu.Unlock()

	if err := c.Push(context.Background()); err != nil {
		t.Fatalf("Push: %v", err)
	}
	assertMirrorHasLog(t, m, l)
	if m.addEntriesCalls < 2 {
		t.Errorf("add-entries calls = %d, want at least 2 (409 then retry)", m.addEntriesCalls)
	}
	// The first attempt started past the mirror's next entry and was
	// rejected; the retry must have restarted from the advertised 120.
	if got := m.seenUploadRanges[0][0]; got != 200 {
		t.Errorf("first upload_start = %d, want the stale 200", got)
	}
	if got := m.seenUploadRanges[1][0]; got != 120 {
		t.Errorf("retry upload_start = %d, want the mirror-advertised 120", got)
	}
	// Package 0 of the retry proves the aligned bundle boundary, not
	// the unaligned transmit start.
	if got := m.seenProofStarts[0]; got != 0 {
		t.Errorf("first package ProofStart = %d, want 0 (rounded_start), not 120", got)
	}
	// The 409's ticket must come back raw on the retry.
	if !bytes.Equal(m.seenTickets[1], []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("retry ticket = %x, want the raw ticket bytes", m.seenTickets[1])
	}
}

// TestPushUnalignedStartProvesAlignedBundle is the second half of the
// aligned-proof trap, and the nastier one.
//
// TestPush409ThenRetry starts at 120, where the transmitted range
// [120,256) is not a valid subtree at all, so a client that proved the
// transmitted range would fail loudly while generating the proof. Here
// the mirror's next entry is 128, and [128,256) *is* a valid subtree:
// such a client would happily produce a well-formed proof of the wrong
// thing, and only the mirror's reconstruction — over the full aligned
// bundle from index 0 — rejects it, with a 422 that looks for all the
// world like a Merkle bug.
func TestPushUnalignedStartProvesAlignedBundle(t *testing.T) {
	l := newTestLog(t, 400)
	m := newStubMirror(t, testLogID, 0x5b)
	all, err := l.Entries(0, 400)
	if err != nil {
		t.Fatal(err)
	}
	m.seed(all[:128])
	c, _ := newTestClient(t, l, m)
	// Start the client where the mirror actually is, as a persisted or
	// mirror-advertised next entry would.
	c.mu.Lock()
	c.st.known = true
	c.st.nextEntry = 128
	c.mu.Unlock()

	if err := c.Push(context.Background()); err != nil {
		t.Fatalf("Push: %v", err)
	}
	assertMirrorHasLog(t, m, l)
	if got := m.seenProofStarts[0]; got != 0 {
		t.Errorf("first package ProofStart = %d, want 0 (the aligned bundle), not the transmit start 128", got)
	}
	if got := m.seenUploadRanges[0][0]; got != 128 {
		t.Errorf("upload_start = %d, want 128", got)
	}
}

// TestPush422IsFatal pins the integrity signal: a 422 must be reported
// as fatal so the caller stops rather than re-uploading, and it must
// not move next-entry state.
func TestPush422IsFatal(t *testing.T) {
	l := newTestLog(t, 5)
	m := newStubMirror(t, testLogID, 0x58)
	m.fail422 = true
	c, _ := newTestClient(t, l, m)

	err := c.Push(context.Background())
	if err == nil {
		t.Fatal("Push succeeded, want a 422 failure")
	}
	if !IsFatal(err) {
		t.Errorf("IsFatal(%v) = false, want true: a 422 must not be retried", err)
	}
	c.mu.Lock()
	next := c.st.nextEntry
	c.mu.Unlock()
	if next != 0 {
		t.Errorf("next entry advanced to %d on a 422, want 0", next)
	}
	if m.addEntriesCalls != 1 {
		t.Errorf("add-entries calls = %d, want 1 (no retry after 422)", m.addEntriesCalls)
	}
}

// TestPushIsIdempotent checks that a second push against an unchanged
// log is cheap and harmless: nothing to upload, nothing to break.
func TestPushIsIdempotent(t *testing.T) {
	l := newTestLog(t, 300)
	m := newStubMirror(t, testLogID, 0x59)
	c, _ := newTestClient(t, l, m)

	for i := range 3 {
		if err := c.Push(context.Background()); err != nil {
			t.Fatalf("Push %d: %v", i, err)
		}
	}
	assertMirrorHasLog(t, m, l)
	if _, lines := c.CosignedCheckpoint(); len(lines) != 1 {
		t.Errorf("got %d cosignature lines, want 1", len(lines))
	}
}

// TestPushStatePersistence checks the ticket and pending size survive a
// restart together, as the matched pair they are.
func TestPushStatePersistence(t *testing.T) {
	l := newTestLog(t, 600)
	m := newStubMirror(t, testLogID, 0x5a)
	m.maxPackagesPerCall = 1
	srv := httptest.NewServer(m.handler())
	t.Cleanup(srv.Close)
	fsys, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := Target{SubmissionPrefix: srv.URL, MonitoringPrefix: srv.URL, Key: m.key}

	c1, err := New(testLogID, target, logSource{l}, fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c1.Push(context.Background()); err != nil {
		t.Fatalf("Push: %v", err)
	}

	// A second client over the same storage must come up already
	// knowing where the mirror is, without re-discovering.
	c2, err := New(testLogID, target, logSource{l}, fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	c2.mu.Lock()
	next, pending, known := c2.st.nextEntry, c2.st.pendingSize, c2.st.known
	c2.mu.Unlock()
	if !known {
		t.Error("restarted client did not load persisted state")
	}
	if next != 600 {
		t.Errorf("restored next entry = %d, want 600", next)
	}
	if pending != 600 {
		t.Errorf("restored pending size = %d, want 600", pending)
	}
}

// TestNilPoolIsInert pins the "no targets configured behaves exactly as
// before" requirement.
func TestNilPoolIsInert(t *testing.T) {
	var p *Pool
	if got := NewPool(nil, nil); got != nil {
		t.Errorf("NewPool(nil) = %v, want nil", got)
	}
	p.Push(context.Background()) // must not panic
	note := []byte("origin\n5\nAAA=\n\n— sig line\n")
	if got := p.CheckpointWithCosignatures(note, 5); !bytes.Equal(got, note) {
		t.Errorf("nil Pool rewrote the checkpoint: %q", got)
	}
}

// TestDiscoverClampsOversizedCheckpoint guards the fix for an
// unauthenticated discovery size wedging pushes: a mirror that advertises
// a checkpoint larger than ours must not seed next-entry beyond our size.
func TestDiscoverClampsOversizedCheckpoint(t *testing.T) {
	origin := cert.OIDName(testLogID)
	sum := sha256.Sum256([]byte(origin))
	wantPath := "/" + hex.EncodeToString(sum[:]) + "/checkpoint"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != wantPath {
			http.NotFound(w, r)
			return
		}
		// Advertise a wildly oversized (unauthenticated) checkpoint.
		fmt.Fprintf(w, "%s\n%d\n%s\n\n", origin, uint64(1)<<40,
			base64.StdEncoding.EncodeToString(make([]byte, 32)))
	}))
	t.Cleanup(srv.Close)

	l := newTestLog(t, 5)
	m := newStubMirror(t, testLogID, 0x42)
	fsys, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(testLogID, Target{
		SubmissionPrefix: srv.URL,
		MonitoringPrefix: srv.URL,
		Key:              m.key,
	}, logSource{l}, fsys, nil)
	if err != nil {
		t.Fatal(err)
	}
	const ourSize = 5
	if err := c.discover(context.Background(), ourSize); err != nil {
		t.Fatal(err)
	}
	if c.st.nextEntry > ourSize {
		t.Fatalf("discover seeded next-entry %d beyond our size %d; wedge not closed",
			c.st.nextEntry, ourSize)
	}
}
