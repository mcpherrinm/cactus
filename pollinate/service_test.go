package pollinate

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/letsencrypt/cactus/cert"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/log/tilewriter"
	"github.com/letsencrypt/cactus/mirrorpush"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tile"
	"github.com/letsencrypt/cactus/tlogx"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/mod/sumdb/tlog"
)

var (
	testCAID    = cert.TrustAnchorID("32473.1")
	testLogID   = cert.TrustAnchorID("32473.1.0.1")
	testOrigin  = cert.OIDName(testLogID) // oid/1.3.6.1.4.1.32473.1.0.1
	testMirror1 = cert.TrustAnchorID("32473.77")
	testMirror2 = cert.TrustAnchorID("32473.78")
)

// testCA is a real cactus log served over HTTP the way cactus serves
// it: tlog-tiles under <base>/1/.
type testCA struct {
	log *cactuslog.Log
	sgn signer.Signer
	srv *httptest.Server
}

func newTestCA(t *testing.T, n int) *testCA {
	t.Helper()
	fsys, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sgn, err := signer.FromSeed(signer.AlgMLDSA44, bytes.Repeat([]byte{0x42}, signer.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	l, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID:       testLogID,
		CosignerID:  testCAID,
		Signer:      sgn,
		FS:          fsys,
		FlushPeriod: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Stop)
	ca := &testCA{log: l, sgn: sgn}
	ca.append(t, 0, n)

	mux := http.NewServeMux()
	mux.Handle("/1/", http.StripPrefix("/1", tile.New(l, fsys).Handler()))
	ca.srv = httptest.NewServer(mux)
	t.Cleanup(ca.srv.Close)
	return ca
}

// append adds entries [from, to) and waits for them to be sequenced.
func (ca *testCA) append(t *testing.T, from, to int) {
	t.Helper()
	for i := from; i < to; i++ {
		entry := cert.EncodeTBSCertEntry(fmt.Appendf(nil, "test entry %d", i))
		if _, err := ca.log.Append(context.Background(), entry, sha256.Sum256(fmt.Appendf(nil, "idem %d", i))); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for uint64(to) > ca.log.CurrentCheckpoint().Size {
		if time.Now().After(deadline) {
			t.Fatalf("log stuck at %d, want %d", ca.log.CurrentCheckpoint().Size, to)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func testHash(b []byte) tlogx.Hash { return tlogx.Hash(sha256.Sum256(b)) }

// subtreeHashOfEntries computes the MTC §4.2 subtree hash of a
// contiguous run of entries, as a mirror reconstructs a package.
func subtreeHashOfEntries(entries [][]byte) tlogx.Hash {
	if len(entries) == 1 {
		return tlogx.HashLeaf(testHash, entries[0])
	}
	k := 1
	for k<<1 < len(entries) {
		k <<= 1
	}
	return tlogx.HashChildren(testHash,
		subtreeHashOfEntries(entries[:k]), subtreeHashOfEntries(entries[k:]))
}

// stubMirror is a c2sp.org/tlog-mirror server that verifies pushed
// subtree consistency proofs for real (against the pending checkpoint)
// and serves its committed copy back out over the monitoring interface,
// so it can be both a push target and a read source in tests.
type stubMirror struct {
	t      *testing.T
	id     cert.TrustAnchorID
	signer signer.Signer
	key    cert.CosignerKey
	// knownOrigin=false makes the submission API answer 404, modelling a
	// mirror not configured for this log.
	knownOrigin bool
	srv         *httptest.Server

	mu           sync.Mutex
	entries      map[uint64][]byte
	nextEntry    uint64
	acceptedSize uint64
	pendingRoot  tlogx.Hash
	pendingNote  []byte
	servedNote   []byte // the mirror checkpoint, once one is committed
	servedSize   uint64

	addCheckpointCalls int
	addEntriesCalls    int
	// seenUA records the User-Agent of the last request, submission or
	// monitoring, to pin down the tlog-tiles contact-header requirement.
	seenUA string
}

func newStubMirror(t *testing.T, id cert.TrustAnchorID, seedByte byte) *stubMirror {
	t.Helper()
	sgn, err := signer.FromSeed(signer.AlgMLDSA44, bytes.Repeat([]byte{seedByte}, signer.SeedSize))
	if err != nil {
		t.Fatal(err)
	}
	m := &stubMirror{
		t: t, id: id, signer: sgn,
		key: cert.CosignerKey{
			ID:        id,
			Algorithm: cert.AlgMLDSA44,
			PublicKey: sgn.PublicKey(),
		},
		knownOrigin: true,
		entries:     map[uint64][]byte{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /add-checkpoint", m.addCheckpoint)
	mux.HandleFunc("POST /add-entries", m.addEntries)
	mux.HandleFunc("GET /{ohash}/checkpoint", m.monCheckpoint)
	mux.HandleFunc("GET /{ohash}/tile/{rest...}", m.monTile)
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.seenUA = r.Header.Get("User-Agent")
		m.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *stubMirror) addCheckpoint(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addCheckpointCalls++
	if !m.knownOrigin {
		http.Error(w, "unknown origin", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	head, note, ok := strings.Cut(string(body), "\n\n")
	if !ok {
		http.Error(w, "no blank line", http.StatusBadRequest)
		return
	}
	var old uint64
	if _, err := fmt.Sscanf(strings.Split(head, "\n")[0], "old %d", &old); err != nil {
		http.Error(w, "bad old line", http.StatusBadRequest)
		return
	}
	if old != m.acceptedSize {
		w.Header().Set("Content-Type", mirrorpush.SizeContentType)
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, "%d\n", m.acceptedSize)
		return
	}
	lines := strings.Split(note, "\n")
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
	m.pendingNote = []byte(note)
	w.WriteHeader(http.StatusOK)
}

func (m *stubMirror) addEntries(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addEntriesCalls++
	if !m.knownOrigin {
		http.Error(w, "unknown origin", http.StatusNotFound)
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
	h, pkgs, data, err := mirrorpush.ParseAddEntries(body)
	if err != nil {
		http.Error(w, "framing: "+err.Error(), http.StatusBadRequest)
		return
	}
	if h.Origin != testOrigin {
		http.Error(w, "unknown origin", http.StatusNotFound)
		return
	}
	if h.UploadEnd != m.acceptedSize || h.UploadStart > m.nextEntry {
		w.Header().Set("Content-Type", mirrorpush.MirrorInfoContentType)
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, "%d\n%d\n\n", m.acceptedSize, m.nextEntry)
		return
	}
	for i, p := range pkgs {
		var subtree [][]byte
		for j := p.ProofStart; j < p.Start; j++ {
			e, ok := m.entries[j]
			if !ok {
				http.Error(w, "missing entry", http.StatusUnprocessableEntity)
				return
			}
			subtree = append(subtree, e)
		}
		subtree = append(subtree, data[i].Entries...)
		if err := tlogx.VerifyConsistencyProof(testHash,
			p.ProofStart, p.End, h.UploadEnd, data[i].Proof,
			subtreeHashOfEntries(subtree), m.pendingRoot); err != nil {
			http.Error(w, "consistency proof: "+err.Error(), http.StatusUnprocessableEntity)
			return
		}
		for j, e := range data[i].Entries {
			m.entries[p.Start+uint64(j)] = e
		}
		if p.End > m.nextEntry {
			m.nextEntry = p.End
		}
	}
	if m.nextEntry < h.UploadEnd {
		w.Header().Set("Content-Type", mirrorpush.MirrorInfoContentType)
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprintf(w, "%d\n%d\n\n", m.acceptedSize, m.nextEntry)
		return
	}

	// Committed: publish the mirror checkpoint and cosign it.
	m.servedNote = m.pendingNote
	m.servedSize = h.UploadEnd
	ts := uint64(time.Now().Unix())
	name := cert.OIDName(m.id)
	msg, err := cert.MarshalCosignedMessage(name, testOrigin, ts, 0, h.UploadEnd, m.pendingRoot)
	if err != nil {
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}
	sig, err := m.signer.Sign(nil, msg)
	if err != nil {
		http.Error(w, "sign", http.StatusInternalServerError)
		return
	}
	keyID, err := cert.CosignatureKeyID(name, cert.AlgMLDSA44, m.signer.PublicKey())
	if err != nil {
		http.Error(w, "key id", http.StatusInternalServerError)
		return
	}
	blob := append(append([]byte(nil), keyID[:]...), cert.MarshalTimestampedSignature(ts, sig)...)
	fmt.Fprintf(w, "— %s %s\n", name, base64.StdEncoding.EncodeToString(blob))
}

func (m *stubMirror) monCheckpoint(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.PathValue("ohash") != originHash(testOrigin) || m.servedNote == nil {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(m.servedNote)
}

// monTile serves hash tiles and entry bundles recomputed from the
// mirror's committed entries. Tile indexes stay below 1000 in tests, so
// the x-group path encoding never appears.
func (m *stubMirror) monTile(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.PathValue("ohash") != originHash(testOrigin) || m.servedNote == nil {
		http.NotFound(w, r)
		return
	}
	rest := r.PathValue("rest") // "<level>/<N>[.p/<W>]" or "entries/<N>[.p/<W>]"
	level, idx, ok := strings.Cut(rest, "/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	width := 0
	if base, wstr, found := strings.Cut(idx, ".p/"); found {
		n, err := strconv.Atoi(wstr)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		idx, width = base, n
	}
	n, err := strconv.ParseInt(idx, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if width == 0 {
		width = tilewriter.EntriesPerDataTile
	}

	if level == "entries" {
		var buf []byte
		for i := range width {
			e, ok := m.entries[uint64(n)*uint64(tilewriter.EntriesPerDataTile)+uint64(i)]
			if !ok {
				http.NotFound(w, r)
				return
			}
			buf = append(buf, byte(len(e)>>8), byte(len(e)))
			buf = append(buf, e...)
		}
		_, _ = w.Write(buf)
		return
	}

	l, err := strconv.Atoi(level)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Replay committed entries into stored hashes and cut the tile.
	var hashes []tlog.Hash
	for i := uint64(0); i < m.servedSize; i++ {
		e, ok := m.entries[i]
		if !ok {
			http.NotFound(w, r)
			return
		}
		hs, err := tlog.StoredHashes(int64(i), e, testHashReader(hashes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		hashes = append(hashes, hs...)
	}
	data, err := tlog.ReadTileData(tlog.Tile{H: tilewriter.TileHeight, L: l, N: n, W: width}, testHashReader(hashes))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write(data)
}

type testHashReader []tlog.Hash

func (h testHashReader) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, idx := range indexes {
		if idx < 0 || idx >= int64(len(h)) {
			return nil, fmt.Errorf("hash index %d out of range", idx)
		}
		out[i] = h[idx]
	}
	return out, nil
}

// spkiPEM marshals a signer's public key as the SPKI PEM block the
// cosigners key bundle carries.
func spkiPEM(t *testing.T, sgn signer.Signer) ([]byte, string) {
	t.Helper()
	spki, err := cert.MarshalCosignerSPKI(cert.AlgMLDSA44, sgn.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), fmt.Sprintf("%x", sum)
}

// testEnv wires a CA, mirrors, cosigners files, and a Service.
type testEnv struct {
	t       *testing.T
	ca      *testCA
	mirrors []*stubMirror
	dir     string // holds cosigners.json / cosigners.pem
	version string
	svc     *Service
	m       *Metrics
}

func newTestEnv(t *testing.T, ca *testCA, mirrors ...*stubMirror) *testEnv {
	t.Helper()
	env := &testEnv{t: t, ca: ca, mirrors: mirrors, dir: t.TempDir(), version: "1.0.0"}
	env.writeCosigners()

	cfg := DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Cosigners.List = filepath.Join(env.dir, "cosigners.json")
	cfg.Cosigners.Keys = filepath.Join(env.dir, "cosigners.pem")
	cfg.Discovery.MaxLogNumber = 2
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	env.m = NewMetrics()
	svc, err := New(cfg, testLogger(t), env.m)
	if err != nil {
		t.Fatal(err)
	}
	env.svc = svc
	return env
}

func (env *testEnv) writeCosigners() {
	env.t.Helper()
	var pemOut []byte
	caPEM, caHash := spkiPEM(env.t, env.ca.sgn)
	pemOut = append(pemOut, caPEM...)
	list := map[string]any{
		"version":   env.version,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"operators": []map[string]any{{"name": "test"}},
		"issuers": []map[string]any{{
			"friendly_name": "testca",
			"base_id":       string(testCAID),
			"base_url":      env.ca.srv.URL,
			"type":          "ISSUER",
			"key_sha256":    caHash,
		}},
	}
	var ms []map[string]any
	for _, m := range env.mirrors {
		mPEM, mHash := spkiPEM(env.t, m.signer)
		pemOut = append(pemOut, mPEM...)
		ms = append(ms, map[string]any{
			"friendly_name": "mirror-" + string(m.id),
			"base_id":       string(m.id),
			"base_url":      m.srv.URL,
			"type":          "MIRROR",
			"key_sha256":    mHash,
			"state_history": []map[string]any{{"state": "USABLE", "state_start": "2026-01-01T00:00:00Z"}},
		})
	}
	list["mirrors"] = ms
	data, err := json.Marshal(list)
	if err != nil {
		env.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.dir, "cosigners.json"), data, 0o644); err != nil {
		env.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.dir, "cosigners.pem"), pemOut, 0o644); err != nil {
		env.t.Fatal(err)
	}
}

func testLogger(t *testing.T) *slog.Logger {
	return slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

// assertMirrorMatchesLog checks the mirror holds exactly the log's
// entries, byte for byte.
func assertMirrorMatchesLog(t *testing.T, m *stubMirror, l *cactuslog.Log) {
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

// TestSweepSyncsLaggingMirror is the end-to-end path: discovery finds
// the log, the delay window gates the first push, and the push brings
// an empty mirror to the full tree — with every proof the client sends
// verified for real by the stub mirror.
func TestSweepSyncsLaggingMirror(t *testing.T) {
	ca := newTestCA(t, 300) // spans a full and a partial entry bundle
	mirror := newStubMirror(t, testMirror1, 0x55)
	env := newTestEnv(t, ca, mirror)
	ctx := context.Background()
	delay := env.svc.cfg.PushDelay()

	// Sweep 1: discovers the log, sees the lagging (absent) mirror, but
	// pushes nothing — no head observation is a full delay old yet.
	t0 := time.Now()
	env.svc.sweep(ctx, t0)
	if mirror.addEntriesCalls != 0 {
		t.Fatalf("pushed during the grace period (%d add-entries calls)", mirror.addEntriesCalls)
	}
	ls := env.svc.state.Logs[testOrigin]
	if ls == nil {
		t.Fatalf("log not discovered; state has %d logs", len(env.svc.state.Logs))
	}
	if ls.URL != ca.srv.URL+"/1" {
		t.Fatalf("discovered URL = %q", ls.URL)
	}

	// Sweep 2, one delay later: the mirror has provably been behind for
	// the whole window, so it gets pushed to and catches up fully.
	t1 := t0.Add(delay + time.Minute)
	env.svc.sweep(ctx, t1)
	assertMirrorMatchesLog(t, mirror, ca.log)
	ms := ls.Mirrors[string(testMirror1)]
	if ms.Carries != CarryYes || ms.Size != 300 {
		t.Fatalf("mirror state = %+v", ms)
	}
	if got := testutil.ToFloat64(env.m.Pushes.WithLabelValues(string(testMirror1), "ok")); got != 1 {
		t.Errorf("pushes ok = %v, want 1", got)
	}
	// tlog-tiles: clients SHOULD identify themselves with a contact in
	// the User-Agent, and operators MAY rate-limit anonymous clients.
	if !strings.Contains(mirror.seenUA, "+https://github.com/mcpherrinm/cactus/cmd/pollinate") {
		t.Errorf("mirror saw User-Agent %q, want the pollinate contact UA", mirror.seenUA)
	}

	// Sweep 3: in sync, nothing to do.
	calls := mirror.addEntriesCalls
	env.svc.sweep(ctx, t1.Add(time.Minute))
	if mirror.addEntriesCalls != calls {
		t.Fatal("pushed to an in-sync mirror")
	}

	// The log grows. Within the delay window the CA is left to do its
	// own pushing; after it, pollinate steps in.
	ca.append(t, 300, 350)
	t2 := t1.Add(2 * time.Minute)
	env.svc.sweep(ctx, t2)
	if mirror.addEntriesCalls != calls {
		t.Fatal("pushed fresh entries before the delay elapsed")
	}
	t3 := t2.Add(delay + time.Minute)
	env.svc.sweep(ctx, t3)
	assertMirrorMatchesLog(t, mirror, ca.log)
	if ms.Size != 350 {
		t.Fatalf("mirror size = %d, want 350", ms.Size)
	}
}

// TestUnknownOriginMirror: a mirror that answers 404 on its submission
// API is recorded as not carrying the log and left alone until the
// recheck interval.
func TestUnknownOriginMirror(t *testing.T) {
	ca := newTestCA(t, 10)
	mirror := newStubMirror(t, testMirror1, 0x66)
	mirror.knownOrigin = false
	env := newTestEnv(t, ca, mirror)
	ctx := context.Background()
	delay := env.svc.cfg.PushDelay()

	t0 := time.Now()
	env.svc.sweep(ctx, t0)
	env.svc.sweep(ctx, t0.Add(delay+time.Minute))

	ms := env.svc.state.Logs[testOrigin].Mirrors[string(testMirror1)]
	if ms.Carries != CarryNo {
		t.Fatalf("carries = %q, want no", ms.Carries)
	}
	if got := testutil.ToFloat64(env.m.Pushes.WithLabelValues(string(testMirror1), "unknown_origin")); got != 1 {
		t.Errorf("unknown_origin pushes = %v, want 1", got)
	}

	// Further sweeps inside the recheck interval leave the mirror alone.
	calls := mirror.addCheckpointCalls
	env.svc.sweep(ctx, t0.Add(delay+2*time.Minute))
	if mirror.addCheckpointCalls != calls {
		t.Fatal("re-probed a mirror inside the not-carried window")
	}

	// After the recheck interval (and with the mirror now configured),
	// the verdict expires and the push succeeds.
	mirror.knownOrigin = true
	env.svc.sweep(ctx, t0.Add(delay+env.svc.cfg.NotCarriedRecheck()+3*time.Minute))
	assertMirrorMatchesLog(t, mirror, ca.log)
}

// TestMirrorAsSource: with the CA unreachable, a lagging mirror is
// synced from another mirror's monitoring interface.
func TestMirrorAsSource(t *testing.T) {
	ca := newTestCA(t, 300)
	m1 := newStubMirror(t, testMirror1, 0x55)
	env := newTestEnv(t, ca, m1)
	ctx := context.Background()
	delay := env.svc.cfg.PushDelay()

	// Get m1 in sync while the CA is up.
	t0 := time.Now()
	env.svc.sweep(ctx, t0)
	t1 := t0.Add(delay + time.Minute)
	env.svc.sweep(ctx, t1)
	assertMirrorMatchesLog(t, m1, ca.log)

	// Add a second, empty mirror to the roster and kill the CA.
	m2 := newStubMirror(t, testMirror2, 0x77)
	env.mirrors = append(env.mirrors, m2)
	env.version = "1.0.1"
	env.writeCosigners()
	ca.srv.Close()

	// Advance past the cosigners refresh so the new roster loads, and
	// past the delay so m2's lag is actionable. m2 must be filled from
	// m1, the only reachable source.
	t2 := t1.Add(env.svc.cfg.Cosigners.Refresh() + time.Minute)
	env.svc.sweep(ctx, t2)
	t3 := t2.Add(delay + time.Minute)
	env.svc.sweep(ctx, t3)
	assertMirrorMatchesLog(t, m2, ca.log)
	if reads := testutil.ToFloat64(env.m.SourceReads.WithLabelValues("mirror:" + string(testMirror1))); reads == 0 {
		t.Error("no reads recorded against the source mirror")
	}
}
