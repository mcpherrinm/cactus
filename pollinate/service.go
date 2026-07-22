package pollinate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/mirrorpush"
	"github.com/letsencrypt/cactus/storage"
)

// maxCosignersBytes caps a cosigners list or key bundle fetch.
const maxCosignersBytes = 8 << 20

// userAgent identifies pollinate to log and mirror operators.
// c2sp.org/tlog-tiles: clients SHOULD include a way for the operator to
// contact them in the User-Agent, as an email and/or a +https:// URL,
// and logs MAY rate-limit anonymous or unreachable clients.
const userAgent = "cactus-pollinate (+https://github.com/mcpherrinm/cactus/cmd/pollinate)"

// uaTransport stamps the contact User-Agent onto every outgoing
// request that doesn't already carry one. It wraps the single
// http.Client the service uses everywhere — tile and checkpoint reads,
// cosigners fetches, and the mirrorpush submission requests.
type uaTransport struct{ base http.RoundTripper }

func (t uaTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("User-Agent", userAgent)
	}
	return t.base.RoundTrip(req)
}

// cachedTiles bounds the shared verified-tile cache: 4096 full hash
// tiles is 32 MiB, enough to keep the hot upper levels of even a very
// large tree resident.
const cachedTiles = 4096

// issuer is one CA from the cosigners file, with its key resolved.
type issuer struct {
	id       string
	friendly string
	baseURL  string
	// key is the raw ML-DSA-44 checkpoint verification key, or nil when
	// the issuer's key is missing from the bundle or uses an algorithm
	// cactus does not implement (e.g. Ed25519). Checkpoints from such
	// issuers are used unverified: every hash and entry pollinate
	// forwards is still authenticated against the checkpoint root, and
	// the receiving mirror independently verifies the log's signature.
	key []byte
}

// mirrorTarget is one mirror from the cosigners file, with its key
// resolved and overrides applied.
type mirrorTarget struct {
	id       string
	friendly string
	baseURL  string // monitoring prefix
	subURL   string // submission prefix
	key      cert.CosignerKey
}

// logHandle is the per-log push machinery that outlives sweeps: the
// mirrorpush clients (which carry resumable upload state) and the
// source facade they read through.
type logHandle struct {
	src     *logSource
	clients map[string]*mirrorpush.Client // keyed by mirror id + submission prefix
}

// Service is the pollinate daemon.
type Service struct {
	cfg    Config
	logger *slog.Logger
	m      *Metrics
	fsys   storage.FS
	hc     *http.Client
	cache  *tileCache

	state *State

	issuers           []*issuer
	mirrors           []*mirrorTarget
	lastCosignersLoad time.Time
	lastDiscovery     time.Time

	logs map[string]*logHandle
}

// New builds a Service from a validated config.
func New(cfg Config, logger *slog.Logger, m *Metrics) (*Service, error) {
	fsys, err := storage.New(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("open data dir: %w", err)
	}
	state, err := loadState(fsys)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	if m == nil {
		m = NewMetrics()
	}
	return &Service{
		cfg:    cfg,
		logger: logger,
		m:      m,
		fsys:   fsys,
		hc: &http.Client{
			Timeout:   cfg.RequestTimeout(),
			Transport: uaTransport{http.DefaultTransport},
		},
		cache: newTileCache(cachedTiles),
		state: state,
		logs:  make(map[string]*logHandle),
	}, nil
}

// Run sweeps once immediately and then on every poll interval until ctx
// is done. Sweeps never overlap; a tick that fires while a sweep is
// still running is simply dropped.
func (s *Service) Run(ctx context.Context) {
	s.sweep(ctx, time.Now())
	ticker := time.NewTicker(s.cfg.PollInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sweep(ctx, time.Now())
		}
	}
}

// sweep is one full pass: refresh the cosigners roster, discover logs,
// poll every log head and mirror copy, and push to mirrors that have
// been lagging for longer than the configured delay. now is injected so
// tests can drive the delay window without sleeping.
func (s *Service) sweep(ctx context.Context, now time.Time) {
	started := time.Now()
	defer func() {
		s.m.Sweeps.Add(1)
		s.m.SweepDuration.Observe(time.Since(started).Seconds())
	}()

	if s.issuers == nil || now.Sub(s.lastCosignersLoad) >= s.cfg.Cosigners.Refresh() {
		if err := s.loadCosigners(ctx); err != nil {
			s.m.PollErrors.WithLabelValues("cosigners").Add(1)
			s.logger.Error("cosigners load failed", "err", err)
		} else {
			s.lastCosignersLoad = now
		}
	}
	if s.issuers == nil {
		return // never had a roster; nothing to follow yet
	}

	if now.Sub(s.lastDiscovery) >= s.cfg.Discovery.Interval() {
		s.discover(ctx, now)
		s.lastDiscovery = now
	}

	jobs := s.poll(ctx, now)
	s.push(ctx, now, jobs)

	if err := saveState(s.fsys, s.state); err != nil {
		s.m.PollErrors.WithLabelValues("state").Add(1)
		s.logger.Error("state save failed", "err", err)
	}
}

// fetchResource loads an http(s) URL or a local file path.
func (s *Service) fetchResource(ctx context.Context, ref string) ([]byte, error) {
	if !strings.HasPrefix(ref, "http://") && !strings.HasPrefix(ref, "https://") {
		return os.ReadFile(ref)
	}
	f := &tileFetcher{ctx: ctx, hc: s.hc}
	return f.get(ref, maxCosignersBytes)
}

// loadCosigners fetches and applies the cosigners list and key bundle.
func (s *Service) loadCosigners(ctx context.Context) error {
	listData, err := s.fetchResource(ctx, s.cfg.Cosigners.List)
	if err != nil {
		return fmt.Errorf("fetch cosigners list: %w", err)
	}
	keysData, err := s.fetchResource(ctx, s.cfg.Cosigners.Keys)
	if err != nil {
		return fmt.Errorf("fetch cosigners keys: %w", err)
	}
	list, err := ParseCosigners(listData)
	if err != nil {
		return err
	}
	keys, err := ParseKeys(keysData)
	if err != nil {
		return err
	}

	overrides := make(map[string]MirrorOverride, len(s.cfg.Mirrors))
	for _, o := range s.cfg.Mirrors {
		overrides[o.ID] = o
	}

	var issuers []*issuer
	for _, sg := range list.Issuers {
		if sg.CurrentState() == "REMOVED" {
			continue
		}
		is := &issuer{
			id:       sg.BaseID,
			friendly: sg.FriendlyName,
			baseURL:  trimSlash(sg.BaseURL),
		}
		if spki, ok := keys[sg.KeySHA256]; !ok {
			s.logger.Warn("issuer key missing from bundle; checkpoints will not be signature-verified",
				"issuer", sg.BaseID, "key_sha256", sg.KeySHA256)
		} else if raw, ok := mldsa44KeyFromSPKI(spki); !ok {
			s.logger.Warn("issuer key is not ML-DSA-44; checkpoints will not be signature-verified",
				"issuer", sg.BaseID)
		} else {
			is.key = raw
		}
		issuers = append(issuers, is)
	}

	var mirrors []*mirrorTarget
	for _, sg := range list.Mirrors {
		if sg.CurrentState() == "REMOVED" {
			continue
		}
		o := overrides[sg.BaseID]
		if o.Disable {
			s.logger.Info("mirror disabled by config", "mirror", sg.BaseID)
			continue
		}
		spki, ok := keys[sg.KeySHA256]
		if !ok {
			s.logger.Warn("mirror key missing from bundle; skipping mirror", "mirror", sg.BaseID)
			continue
		}
		raw, ok := mldsa44KeyFromSPKI(spki)
		if !ok {
			// The mtc-tlog profile requires ML-DSA-44 cosigners, and
			// without the key we could not verify the cosignatures that
			// confirm a push landed.
			s.logger.Warn("mirror key is not ML-DSA-44; skipping mirror", "mirror", sg.BaseID)
			continue
		}
		sub := trimSlash(sg.BaseURL)
		if o.SubmissionPrefix != "" {
			sub = trimSlash(o.SubmissionPrefix)
		}
		mirrors = append(mirrors, &mirrorTarget{
			id:       sg.BaseID,
			friendly: sg.FriendlyName,
			baseURL:  trimSlash(sg.BaseURL),
			subURL:   sub,
			key: cert.CosignerKey{
				ID:        cert.TrustAnchorID(sg.BaseID),
				Algorithm: cert.AlgMLDSA44,
				PublicKey: raw,
			},
		})
	}

	// A new list version is exactly when a mirror may have been
	// configured for logs it previously rejected: forget old verdicts.
	if list.Version != s.state.CosignersVersion {
		for _, ls := range s.state.Logs {
			for _, ms := range ls.Mirrors {
				if ms.Carries == CarryNo {
					ms.Carries = CarryUnknown
				}
			}
		}
		s.state.CosignersVersion = list.Version
	}

	s.issuers = issuers
	s.mirrors = mirrors
	if !list.Timestamp.IsZero() {
		s.m.CosignersTimestamp.Set(float64(list.Timestamp.Unix()))
	}
	s.m.CosignersSigners.WithLabelValues("issuer").Set(float64(len(issuers)))
	s.m.CosignersSigners.WithLabelValues("mirror").Set(float64(len(mirrors)))
	s.logger.Info("cosigners loaded", "version", list.Version,
		"issuers", len(issuers), "mirrors", len(mirrors))
	return nil
}

// originHash is the tlog-mirror monitoring path element for a log: the
// lowercase hex SHA-256 of its checkpoint origin.
func originHash(origin string) string {
	sum := sha256.Sum256([]byte(origin))
	return hex.EncodeToString(sum[:])
}

// fetcher builds a tileFetcher for one log prefix URL, counting reads
// against the given source label.
func (s *Service) fetcher(ctx context.Context, base, origin, sourceLabel string) *tileFetcher {
	return &tileFetcher{
		ctx:    ctx,
		base:   trimSlash(base),
		origin: origin,
		hc:     s.hc,
		cache:  s.cache,
		reads:  s.m.SourceReads.WithLabelValues(sourceLabel),
	}
}

// discover probes every issuer for the logs it serves. Both observed
// layouts are probed: a single log at the bare base URL (Cloudflare's
// bootstrap CA) and mtc-tlog-profile logs at <CA prefix>/<log number>.
// A log is identified by the origin its checkpoint declares, so a URL
// that turns out to serve an already-known log is ignored.
func (s *Service) discover(ctx context.Context, now time.Time) {
	for _, is := range s.issuers {
		candidates := []string{is.baseURL}
		for n := 0; n <= s.cfg.Discovery.MaxLogNumber; n++ {
			candidates = append(candidates, is.baseURL+"/"+strconv.Itoa(n))
		}
		for _, url := range candidates {
			if ctx.Err() != nil {
				return
			}
			f := s.fetcher(ctx, url, "", "issuer:"+is.id)
			note, err := f.checkpoint()
			if err != nil {
				continue // most probes miss; that is what probing is
			}
			if _, known := s.state.Logs[note.Origin]; known {
				continue
			}
			if is.key != nil {
				if err := note.VerifySignature(cert.TrustAnchorID(is.id), is.key); err != nil {
					s.logger.Warn("discovered checkpoint fails issuer signature; ignoring log",
						"issuer", is.id, "url", url, "err", err)
					continue
				}
			}
			ls := s.state.logState(note.Origin)
			ls.IssuerID = is.id
			ls.URL = url
			ls.recordHead(now, note.Size, s.cfg.PushDelay())
			s.logger.Info("discovered log", "issuer", is.id, "origin", note.Origin,
				"url", url, "size", note.Size)
		}
	}
}

// pushJob is one lagging (log, mirror) pair the sweep decided to push.
type pushJob struct {
	origin string
	mirror *mirrorTarget
	// prevSize is the mirror's size before the push, for the
	// pushed-entries metric.
	prevSize uint64
}

// poll refreshes every log head and every mirror copy, records head
// history, updates gauges, and returns the pairs that have been lagging
// beyond the delay window, grouped by origin.
func (s *Service) poll(ctx context.Context, now time.Time) map[string][]pushJob {
	issuerByID := make(map[string]*issuer, len(s.issuers))
	for _, is := range s.issuers {
		issuerByID[is.id] = is
	}

	origins := make([]string, 0, len(s.state.Logs))
	for origin := range s.state.Logs {
		origins = append(origins, origin)
	}
	sort.Strings(origins)

	jobs := make(map[string][]pushJob)
	for _, origin := range origins {
		if ctx.Err() != nil {
			return jobs
		}
		ls := s.state.logState(origin)
		logger := s.logger.With("origin", origin)

		head := uint64(0)
		seenAny := false

		// The issuer's own view of the log head.
		if is := issuerByID[ls.IssuerID]; is != nil {
			f := s.fetcher(ctx, ls.URL, origin, "issuer:"+is.id)
			note, err := f.checkpoint()
			if err == nil && note.Origin != origin {
				err = fmt.Errorf("pollinate: checkpoint origin %q, want %q", note.Origin, origin)
			}
			if err == nil && is.key != nil {
				err = note.VerifySignature(cert.TrustAnchorID(is.id), is.key)
			}
			if err != nil {
				s.m.PollErrors.WithLabelValues("log_head").Add(1)
				logger.Warn("log head poll failed", "url", ls.URL, "err", err)
			} else {
				head = note.Size
				seenAny = true
			}
		}

		// Every mirror's copy. failed marks pairs we could not read this
		// sweep for a reason other than 404 — no push decisions for those.
		failed := make(map[string]bool)
		for _, mt := range s.mirrors {
			ms := ls.mirrorState(mt.id)
			if ms.Carries == CarryNo {
				if now.Sub(ms.LastChecked) < s.cfg.NotCarriedRecheck() {
					continue
				}
				ms.Carries = CarryUnknown // verdict expired; re-probe below
			}
			ms.LastChecked = now
			f := s.fetcher(ctx, mt.baseURL+"/"+originHash(origin), origin, "mirror:"+mt.id)
			note, err := f.checkpoint()
			switch {
			case err == nil && note.Origin != origin:
				failed[mt.id] = true
				s.m.PollErrors.WithLabelValues("mirror_checkpoint").Add(1)
				logger.Warn("mirror serves wrong origin", "mirror", mt.id, "got", note.Origin)
			case err == nil:
				if is := issuerByID[ls.IssuerID]; is != nil && is.key != nil {
					// tlog-mirror requires the mirror to retain the log's
					// signature; a copy that fails it is not this log.
					if verr := note.VerifySignature(cert.TrustAnchorID(is.id), is.key); verr != nil {
						failed[mt.id] = true
						s.m.PollErrors.WithLabelValues("mirror_checkpoint").Add(1)
						logger.Warn("mirror checkpoint fails log signature", "mirror", mt.id, "err", verr)
						continue
					}
				}
				ms.Size = note.Size
				ms.LastSeen = now
				ms.Carries = CarryYes
				head = max(head, note.Size)
				seenAny = true
			case errors.Is(err, errNotFound):
				// The mirror does not serve this log (yet). Either it has
				// never been pushed to — a push will bootstrap it — or it
				// is not configured for this origin, which its submission
				// API will tell us via ErrUnknownOrigin.
				ms.Size = 0
			default:
				failed[mt.id] = true
				s.m.PollErrors.WithLabelValues("mirror_checkpoint").Add(1)
				logger.Warn("mirror poll failed", "mirror", mt.id, "err", err)
			}
		}

		if seenAny {
			ls.recordHead(now, head, s.cfg.PushDelay())
		}
		s.m.LogHeadSize.WithLabelValues(origin).Set(float64(head))

		// Lag decisions. threshold is the head as of one delay window
		// ago: entries newer than that are still the CA's to deliver.
		threshold, thresholdOK := ls.headAt(now.Add(-s.cfg.PushDelay()))
		for _, mt := range s.mirrors {
			ms := ls.mirrorState(mt.id)
			if ms.Carries == CarryNo {
				continue
			}
			s.m.MirrorSize.WithLabelValues(origin, mt.id).Set(float64(ms.Size))
			s.m.MirrorLag.WithLabelValues(origin, mt.id).Set(float64(max(head, ms.Size) - ms.Size))
			s.m.MirrorCarries.WithLabelValues(origin, mt.id).Set(carryGauge(ms.Carries))
			if !thresholdOK || failed[mt.id] || ms.Size >= threshold {
				continue
			}
			jobs[origin] = append(jobs[origin], pushJob{origin: origin, mirror: mt, prevSize: ms.Size})
		}
	}
	return jobs
}

func carryGauge(carries string) float64 {
	switch carries {
	case CarryYes:
		return 1
	case CarryNo:
		return 0
	default:
		return 0.5
	}
}

// push prepares a source snapshot per lagging log and runs the pushes,
// bounded by MaxConcurrentPushes across all pairs.
func (s *Service) push(ctx context.Context, now time.Time, jobs map[string][]pushJob) {
	type result struct {
		job      pushJob
		snapSize uint64
		err      error
	}
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []result
	)
	sem := make(chan struct{}, s.cfg.MaxConcurrentPushes)

	origins := make([]string, 0, len(jobs))
	for origin := range jobs {
		origins = append(origins, origin)
	}
	sort.Strings(origins)

	for _, origin := range origins {
		snap := s.snapshotFor(ctx, now, origin)
		if snap == nil {
			continue
		}
		handle := s.handle(origin)
		handle.src.set(snap)
		for _, job := range jobs[origin] {
			if job.prevSize >= snap.size {
				continue // the best source has nothing this mirror lacks
			}
			client, err := s.pushClient(handle, origin, job.mirror)
			if err != nil {
				s.logger.Error("push client", "origin", origin, "mirror", job.mirror.id, "err", err)
				continue
			}
			wg.Add(1)
			go func(job pushJob) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				pctx, cancel := context.WithTimeout(ctx, s.cfg.PushTimeout())
				err := client.Push(pctx)
				cancel()
				mu.Lock()
				results = append(results, result{job: job, snapSize: snap.size, err: err})
				mu.Unlock()
			}(job)
		}
	}
	wg.Wait()

	for _, r := range results {
		ms := s.state.logState(r.job.origin).mirrorState(r.job.mirror.id)
		logger := s.logger.With("origin", r.job.origin, "mirror", r.job.mirror.id)
		switch {
		case r.err == nil:
			ms.Carries = CarryYes
			ms.Size = r.snapSize
			ms.LastSeen = now
			ms.LastPush = now
			ms.LastPushSize = r.snapSize
			ms.LastError = ""
			s.m.Pushes.WithLabelValues(r.job.mirror.id, "ok").Add(1)
			s.m.PushedEntries.WithLabelValues(r.job.mirror.id).Add(float64(r.snapSize - r.job.prevSize))
			logger.Info("pushed", "size", r.snapSize, "entries", r.snapSize-r.job.prevSize)
		case errors.Is(r.err, mirrorpush.ErrUnknownOrigin):
			ms.Carries = CarryNo
			ms.LastChecked = now
			ms.LastError = r.err.Error()
			s.m.Pushes.WithLabelValues(r.job.mirror.id, "unknown_origin").Add(1)
			logger.Info("mirror does not carry log", "recheck_in", s.cfg.NotCarriedRecheck())
		case mirrorpush.IsFatal(r.err):
			ms.LastError = r.err.Error()
			s.m.Pushes.WithLabelValues(r.job.mirror.id, "fatal").Add(1)
			logger.Error("push failed fatally", "err", r.err)
		default:
			ms.LastError = r.err.Error()
			s.m.Pushes.WithLabelValues(r.job.mirror.id, "error").Add(1)
			logger.Warn("push failed", "err", r.err)
		}
	}
}

// snapshotFor picks a read source for a log and binds a snapshot to its
// current checkpoint. Candidates are the issuer's log URL and every
// mirror currently serving the log; the freshest (largest) views win,
// with ties broken randomly so repeated syncs spread their reads across
// sources instead of hammering one.
func (s *Service) snapshotFor(ctx context.Context, now time.Time, origin string) *snapshot {
	ls := s.state.logState(origin)

	type candidate struct {
		base  string
		label string
		size  uint64
	}
	var cands []candidate
	for _, is := range s.issuers {
		if is.id == ls.IssuerID {
			size, _ := ls.headAt(now)
			cands = append(cands, candidate{base: ls.URL, label: "issuer:" + is.id, size: size})
		}
	}
	for _, mt := range s.mirrors {
		ms := ls.Mirrors[mt.id]
		if ms == nil || ms.Carries != CarryYes || ms.Size == 0 {
			continue
		}
		cands = append(cands, candidate{
			base:  mt.baseURL + "/" + originHash(origin),
			label: "mirror:" + mt.id,
			size:  ms.Size,
		})
	}
	// Sort by size descending with random tie-breaks, then take the
	// first candidate that serves a usable checkpoint.
	rand.Shuffle(len(cands), func(i, j int) { cands[i], cands[j] = cands[j], cands[i] })
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].size > cands[j].size })

	issuerKey := s.issuerKey(ls.IssuerID)
	for _, c := range cands {
		f := s.fetcher(ctx, c.base, origin, c.label)
		note, err := f.checkpoint()
		if err != nil {
			s.logger.Warn("source checkpoint fetch failed", "origin", origin, "source", c.label, "err", err)
			continue
		}
		if note.Origin != origin || note.Size == 0 {
			s.logger.Warn("source served unusable checkpoint", "origin", origin,
				"source", c.label, "got_origin", note.Origin, "size", note.Size)
			continue
		}
		if issuerKey != nil {
			if err := note.VerifySignature(cert.TrustAnchorID(ls.IssuerID), issuerKey); err != nil {
				s.logger.Warn("source checkpoint fails log signature", "origin", origin, "source", c.label, "err", err)
				continue
			}
		}
		s.logger.Debug("source chosen", "origin", origin, "source", c.label, "size", note.Size)
		return newSnapshot(f, note)
	}
	s.logger.Warn("no usable source for lagging log", "origin", origin)
	return nil
}

func (s *Service) issuerKey(issuerID string) []byte {
	for _, is := range s.issuers {
		if is.id == issuerID {
			return is.key
		}
	}
	return nil
}

// handle returns (creating if needed) the per-log push machinery.
func (s *Service) handle(origin string) *logHandle {
	h, ok := s.logs[origin]
	if !ok {
		h = &logHandle{src: &logSource{}, clients: make(map[string]*mirrorpush.Client)}
		s.logs[origin] = h
	}
	return h
}

// pushClient returns (creating if needed) the mirrorpush client for one
// (log, mirror) pair. Clients persist their resumable upload state
// under the data dir, so a restart resumes instead of rediscovering.
func (s *Service) pushClient(h *logHandle, origin string, mt *mirrorTarget) (*mirrorpush.Client, error) {
	key := mt.id + "|" + mt.subURL
	if c, ok := h.clients[key]; ok {
		return c, nil
	}
	c, err := mirrorpush.New(nil, mirrorpush.Target{
		Origin:           origin,
		SubmissionPrefix: mt.subURL,
		MonitoringPrefix: mt.baseURL,
		Key:              mt.key,
		HTTPClient:       s.hc,
		Timeout:          s.cfg.RequestTimeout(),
	}, h.src, s.fsys, s.logger.With("origin", origin))
	if err != nil {
		return nil, err
	}
	h.clients[key] = c
	return c, nil
}
