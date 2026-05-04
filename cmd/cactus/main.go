// cactus is the main ACME + issuance log server.
//
// Usage:
//
//	cactus -config /path/to/config.json
//
// See PROJECT_PLAN.md for the design and §1 (Goals & Non-Goals): this
// is a *test* server; do not use it for anything that matters.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"encoding/pem"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/cactus/acme"
	"github.com/letsencrypt/cactus/ca"
	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/config"
	"github.com/letsencrypt/cactus/landmark"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/logging"
	"github.com/letsencrypt/cactus/metrics"
	"github.com/letsencrypt/cactus/mirror"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tile"
)

// pemDecode is just pem.Decode kept here so the file can keep the
// "all stdlib imports first" Go convention without splitting groups.
func pemDecode(s string) (*pem.Block, []byte) {
	return pem.Decode([]byte(s))
}

// mirrorCounterVecAdapter adapts a *prometheus.CounterVec to the
// mirror.CounterVec interface (whose WithLabelValues returns
// mirror.Counter rather than prometheus.Counter).
type mirrorCounterVecAdapter struct {
	cv *prometheus.CounterVec
}

func (a mirrorCounterVecAdapter) WithLabelValues(lvs ...string) mirror.Counter {
	return a.cv.WithLabelValues(lvs...)
}

// caMirrorRequestsAdapter adapts a *prometheus.CounterVec to the
// cert.CounterVec interface.
type caMirrorRequestsAdapter struct {
	cv *prometheus.CounterVec
}

func (a caMirrorRequestsAdapter) WithLabelValues(lvs ...string) cert.Counter {
	return a.cv.WithLabelValues(lvs...)
}

// buildMirrorEndpoints converts the per-mirror config slice into the
// cert.MirrorEndpoint shape, parsing each public key from PEM.
func buildMirrorEndpoints(mirrors []config.MirrorEndpointConfig) ([]cert.MirrorEndpoint, error) {
	out := make([]cert.MirrorEndpoint, 0, len(mirrors))
	for i, m := range mirrors {
		alg, err := signer.ParseAlgorithm(m.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("mirrors[%d]: %w", i, err)
		}
		key, err := parsePEMSPKI(m.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("mirrors[%d] public_key_pem: %w", i, err)
		}
		out = append(out, cert.MirrorEndpoint{
			URL: m.URL,
			Key: cert.CosignerKey{
				ID:        cert.TrustAnchorID(m.ID),
				Algorithm: signerAlgToCertAlg(alg),
				PublicKey: key,
			},
		})
	}
	return out, nil
}

// signerAlgToCertAlg maps a signer.Algorithm code to the cert
// package's parallel SignatureAlgorithm enum. Both use the same
// numeric values (TLS SignatureScheme codepoints), but the type
// systems are distinct.
func signerAlgToCertAlg(a signer.Algorithm) cert.SignatureAlgorithm {
	switch a {
	case signer.AlgECDSAP256SHA256:
		return cert.AlgECDSAP256SHA256
	case signer.AlgECDSAP384SHA384:
		return cert.AlgECDSAP384SHA384
	case signer.AlgEd25519:
		return cert.AlgEd25519
	case signer.AlgMLDSA44:
		return cert.AlgMLDSA44
	case signer.AlgMLDSA65:
		return cert.AlgMLDSA65
	default:
		return cert.AlgUnknown
	}
}

var version = "dev"

func main() {
	configPath := flag.String("config", "config.json", "path to JSON config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("cactus", version)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		die("load config: %v", err)
	}

	logger := logging.New(os.Stdout, cfg.LogLevel)
	slog.SetDefault(logger)
	logger.Info("starting", "version", version, "config", *configPath, "data_dir", cfg.DataDir)

	if err := run(cfg, logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(cfg config.Config, logger *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fsRoot, err := storage.New(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("open data dir: %w", err)
	}

	// Load (or create) the cosigner seed.
	seedPath := filepath.Join(cfg.DataDir, cfg.CACosigner.SeedPath)
	if err := os.MkdirAll(filepath.Dir(seedPath), 0o755); err != nil {
		return fmt.Errorf("mkdir keys: %w", err)
	}
	seed, err := loadOrInitSeed(seedPath)
	if err != nil {
		return fmt.Errorf("seed: %w", err)
	}
	alg, err := signer.ParseAlgorithm(cfg.CACosigner.Algorithm)
	if err != nil {
		return err
	}
	sgn, err := signer.FromSeed(alg, seed)
	if err != nil {
		return fmt.Errorf("signer: %w", err)
	}
	logger.Info("cosigner ready",
		"alg", sgn.Algorithm().String(),
		"id", cfg.CACosigner.ID)

	// Metrics first so the log and ACME server can register.
	m := metrics.New()

	// Optional landmark sequence (Phase 8). Built before the log so we
	// can pass the OnFlush hook to log.Config.
	var landmarkSeq *landmark.Sequence
	if cfg.Landmarks.Enabled {
		landmarkSeq, err = landmark.New(landmark.Config{
			BaseID:               cert.TrustAnchorID(cfg.Landmarks.BaseID),
			TimeBetweenLandmarks: cfg.Landmarks.TimeBetweenLandmarks(),
			MaxCertLifetime:      cfg.Landmarks.MaxCertLifetime(),
		}, fsRoot, time.Now())
		if err != nil {
			return fmt.Errorf("landmark sequence: %w", err)
		}
		logger.Info("landmarks enabled",
			"base_id", cfg.Landmarks.BaseID,
			"interval", cfg.Landmarks.TimeBetweenLandmarks(),
			"max_active", landmarkSeq.MaxActive())
	}

	// Issuance log. The MirrorRequester closure (Phase 9 CA-mode
	// quorum) needs `l` to compute consistency proofs, so we
	// forward-declare via a pointer the closure captures.
	var l *cactuslog.Log
	logCfg := cactuslog.Config{
		LogID:       cert.TrustAnchorID(cfg.Log.ID),
		CosignerID:  cert.TrustAnchorID(cfg.CACosigner.ID),
		Signer:      sgn,
		FS:          fsRoot,
		FlushPeriod: cfg.Log.CheckpointPeriod(),
		Logger:      logger,
		Metrics: cactuslog.Metrics{
			Entries:           m.LogEntries,
			Checkpoints:       m.LogCheckpoints,
			PoolFlushSize:     m.PoolFlushSize,
			SignatureDuration: m.SignatureDurationVec(),
		},
	}
	if landmarkSeq != nil {
		logCfg.OnFlush = func(treeSize uint64) {
			lm, ok, err := landmarkSeq.Append(ctx, treeSize, time.Now())
			if err != nil {
				logger.Error("landmark append", "err", err)
				return
			}
			if ok {
				logger.Info("landmark allocated",
					"number", lm.Number, "tree_size", lm.TreeSize)
			}
		}
	}
	if len(cfg.CACosignerQuorum.Mirrors) > 0 {
		endpoints, err := buildMirrorEndpoints(cfg.CACosignerQuorum.Mirrors)
		if err != nil {
			return fmt.Errorf("ca_cosigner_quorum: %w", err)
		}
		logCfg.WaitForCosigners = 1 + cfg.CACosignerQuorum.MinSignatures
		logCfg.MirrorRequester = func(ctx context.Context, st *cert.MTCSubtree, caSig cert.MTCSignature) ([]cert.MTCSignature, error) {
			deadline := time.Now().Add(cfg.CACosignerQuorum.RetryDeadline())
			sleep := func(d time.Duration) error {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(d):
					return nil
				}
			}
			for time.Now().Before(deadline) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				cp := l.CurrentCheckpoint()
				if cp.Size == 0 {
					if err := sleep(50 * time.Millisecond); err != nil {
						return nil, err
					}
					continue
				}
				proof, err := l.ConsistencyProof(st.Start, st.End, cp.Size)
				if err != nil {
					return nil, err
				}
				req := &cert.SubtreeRequest{
					Subtree:          st,
					CACheckpointBody: cp.SignedNote,
					ConsistencyProof: proof,
				}
				subCtx, cancel := context.WithTimeout(ctx, cfg.CACosignerQuorum.RequestTimeout())
				sigs, err := cert.RequestCosignaturesWithMetrics(
					subCtx, req, endpoints,
					cfg.CACosignerQuorum.MinSignatures,
					cfg.CACosignerQuorum.RequestTimeout(),
					cfg.CACosignerQuorum.BestEffortAfterMinimum,
					cert.CosignerRequestMetrics{
						Requests:       caMirrorRequestsAdapter{m.CAMirrorRequests},
						QuorumFailures: m.CAQuorumFailures,
					},
				)
				cancel()
				if err == nil && len(sigs) >= cfg.CACosignerQuorum.MinSignatures {
					return sigs, nil
				}
				if err := sleep(100 * time.Millisecond); err != nil {
					return nil, err
				}
			}
			return nil, fmt.Errorf("multi-mirror quorum not met within %s", cfg.CACosignerQuorum.RetryDeadline())
		}
		logger.Info("multi-mirror CA mode enabled",
			"mirrors", len(endpoints),
			"min_signatures", cfg.CACosignerQuorum.MinSignatures,
			"request_timeout", cfg.CACosignerQuorum.RequestTimeout())
	}
	l, err = cactuslog.New(ctx, logCfg)
	if err != nil {
		return fmt.Errorf("open log: %w", err)
	}
	defer l.Stop()
	logger.Info("log ready", "size", l.CurrentCheckpoint().Size)

	// CA issuer.
	issuer, err := ca.New(l, cfg.Log.ID)
	if err != nil {
		return fmt.Errorf("issuer: %w", err)
	}

	// ACME server.
	acmeCfg := acme.Config{
		ExternalURL:    cfg.ACME.ExternalURL,
		Issuer:         issuer,
		ChallengeMode:  acme.ChallengeMode(cfg.ACME.ChallengeMode),
		Logger:         logger,
		OrdersByStatus: m.ACMEOrdersVec(),
		LogID:          cert.TrustAnchorID(cfg.Log.ID),
	}
	if landmarkSeq != nil {
		acmeCfg.Landmarks = landmarkSeq
		acmeCfg.SubtreeProof = l.SubtreeProof
		acmeCfg.LandmarkBaseID = cert.TrustAnchorID(cfg.Landmarks.BaseID)
	}
	acmeSrv, err := acme.New(acmeCfg)
	if err != nil {
		return fmt.Errorf("acme: %w", err)
	}
	if err := acmeSrv.AttachStorage(fsRoot); err != nil {
		return fmt.Errorf("acme storage: %w", err)
	}

	// Server timeouts. ACME requests are tiny (CSR + JWS); a slow
	// client trickling bytes for minutes is just DoS.  pprof endpoints
	// like /debug/pprof/profile?seconds=N legitimately stream for a
	// while, so the metrics listener gets a more generous WriteTimeout.
	const (
		readHeaderTimeout = 5 * time.Second
		readTimeout       = 30 * time.Second
		writeTimeout      = 30 * time.Second
		idleTimeout       = 120 * time.Second
	)
	acmeHTTP := &http.Server{
		Addr:              cfg.ACME.Listen,
		Handler:           logging.Middleware(logger)(acmeSrv.Handler()),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    16 * 1024,
	}
	tileSrv := tile.New(l, fsRoot)
	if landmarkSeq != nil {
		tileSrv = tileSrv.WithLandmarks(landmarkSeq)
	}
	monitoringHTTP := &http.Server{
		Addr:              cfg.Monitoring.Listen,
		Handler:           logging.Middleware(logger)(tileSrv.Handler()),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    16 * 1024,
	}

	// Metrics + pprof. pprof endpoints expose heap/goroutine/CPU
	// profiles that can leak in-memory secrets and provide a DoS
	// amplifier (an unauthenticated /debug/pprof/profile?seconds=300
	// call burns 5 minutes of CPU). They're only enabled when the
	// metrics listener address is localhost — i.e. we trust whoever
	// can connect. If the operator changes Metrics.Listen to a
	// non-loopback address, /debug/pprof is refused.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", m.Handler())
	if metricsListenIsLoopback(cfg.Metrics.Listen) {
		metricsMux.HandleFunc("/debug/pprof/", pprof.Index)
		metricsMux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		metricsMux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		metricsMux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		metricsMux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	} else {
		logger.Warn("metrics listener is not loopback; /debug/pprof disabled",
			"listen", cfg.Metrics.Listen)
	}
	metricsHTTP := &http.Server{
		Addr:              cfg.Metrics.Listen,
		Handler:           metricsMux,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		// 5 minutes: covers /debug/pprof/profile?seconds=30 (default)
		// and CPU profiles up to a few minutes.
		WriteTimeout:   5 * time.Minute,
		IdleTimeout:    idleTimeout,
		MaxHeaderBytes: 16 * 1024,
	}

	// Optional mirror operating mode (Phase 9).
	var mirrorHTTP *http.Server
	if cfg.Mirror.Enabled {
		mirrorHTTP, err = startMirror(ctx, cfg, fsRoot, logger, m, readHeaderTimeout, readTimeout, writeTimeout, idleTimeout)
		if err != nil {
			return fmt.Errorf("mirror: %w", err)
		}
	}

	// Start listeners.
	startServer(logger, acmeHTTP, "acme", cfg.ACME.TLSCert, cfg.ACME.TLSKey)
	startServer(logger, monitoringHTTP, "monitoring", "", "")
	startServer(logger, metricsHTTP, "metrics", "", "")
	if mirrorHTTP != nil {
		startServer(logger, mirrorHTTP, "mirror", "", "")
	}

	// Wait for SIGTERM/SIGINT.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	logger.Info("shutting down", "signal", sig.String())

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = acmeHTTP.Shutdown(shutdownCtx)
	_ = monitoringHTTP.Shutdown(shutdownCtx)
	_ = metricsHTTP.Shutdown(shutdownCtx)
	if mirrorHTTP != nil {
		_ = mirrorHTTP.Shutdown(shutdownCtx)
	}
	return nil
}

// startMirror brings up the mirror operating mode: loads the mirror's
// own seed, parses the upstream CA cosigner public key, builds a
// Follower goroutine, and returns the configured sign-subtree HTTP
// server (not yet started — caller does that).
func startMirror(
	ctx context.Context,
	cfg config.Config,
	fsRoot *storage.Disk,
	logger *slog.Logger,
	m *metrics.Metrics,
	readHeaderTimeout, readTimeout, writeTimeout, idleTimeout time.Duration,
) (*http.Server, error) {
	mSeedPath := filepath.Join(cfg.DataDir, cfg.Mirror.SeedPath)
	if err := os.MkdirAll(filepath.Dir(mSeedPath), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir mirror keys: %w", err)
	}
	mSeed, err := loadOrInitSeed(mSeedPath)
	if err != nil {
		return nil, fmt.Errorf("mirror seed: %w", err)
	}
	mAlg, err := signer.ParseAlgorithm(cfg.Mirror.Algorithm)
	if err != nil {
		return nil, err
	}
	mSigner, err := signer.FromSeed(mAlg, mSeed)
	if err != nil {
		return nil, fmt.Errorf("mirror signer: %w", err)
	}

	upstreamKey, err := parsePEMSPKI(cfg.Mirror.Upstream.CACosignerKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("upstream ca_cosigner_key_pem: %w", err)
	}

	follower, err := mirror.NewFollower(mirror.FollowerConfig{
		Upstream: mirror.Upstream{
			TileURL:       cfg.Mirror.Upstream.TileURL,
			LogID:         cert.TrustAnchorID(cfg.Mirror.Upstream.LogID),
			CACosignerID:  cert.TrustAnchorID(cfg.Mirror.Upstream.CACosignerID),
			CACosignerKey: upstreamKey,
		},
		FS:           fsRoot,
		PollInterval: cfg.Mirror.Upstream.PollInterval(),
		Logger:       logger,
		Metrics: mirror.FollowerMetrics{
			UpstreamSize:        m.MirrorUpstreamSize,
			ConsistencyFailures: m.MirrorConsistencyFailures,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("follower: %w", err)
	}
	go func() { _ = follower.Run(ctx) }()
	logger.Info("mirror follower started",
		"upstream", cfg.Mirror.Upstream.TileURL,
		"poll_interval", cfg.Mirror.Upstream.PollInterval())

	mServerCfg := mirror.ServerConfig{
		Follower:                    follower,
		Signer:                      mSigner,
		CosignerID:                  cert.TrustAnchorID(cfg.Mirror.CosignerID),
		RequireCASignatureOnSubtree: cfg.Mirror.RequireCASignatureOnSubtree,
		Metrics: mirror.ServerMetrics{
			Requests:        mirrorCounterVecAdapter{m.MirrorSignSubtreeRequests},
			RequestDuration: m.MirrorSignSubtreeDuration,
		},
	}
	if cfg.Mirror.RequireCASignatureOnSubtree {
		mServerCfg.UpstreamCAKey = &cert.CosignerKey{
			ID:        cert.TrustAnchorID(cfg.Mirror.Upstream.CACosignerID),
			Algorithm: cert.AlgECDSAP256SHA256,
			PublicKey: upstreamKey,
		}
	}
	mSrv, err := mirror.NewServer(mServerCfg)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle(cfg.Mirror.SignSubtreePath, mSrv.Handler())
	return &http.Server{
		Addr:              cfg.Mirror.SignSubtreeListen,
		Handler:           logging.Middleware(logger)(mux),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    16 * 1024,
	}, nil
}

// parsePEMSPKI accepts a PEM SubjectPublicKeyInfo block and returns
// the inner DER bytes that mirror.Upstream.CACosignerKey expects.
func parsePEMSPKI(pemStr string) ([]byte, error) {
	block, _ := pemDecode(pemStr)
	if block == nil {
		return nil, errors.New("not a PEM block")
	}
	if !strings.Contains(block.Type, "PUBLIC KEY") {
		return nil, fmt.Errorf("PEM type %q is not a PUBLIC KEY", block.Type)
	}
	return block.Bytes, nil
}

func startServer(logger *slog.Logger, srv *http.Server, name, certFile, keyFile string) {
	go func() {
		var err error
		if certFile != "" && keyFile != "" {
			logger.Info("listening (TLS)", "name", name, "addr", srv.Addr)
			err = srv.ListenAndServeTLS(certFile, keyFile)
		} else {
			logger.Info("listening", "name", name, "addr", srv.Addr)
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "name", name, "err", err)
		}
	}()
}

func loadOrInitSeed(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		// Create a fresh seed.
		var seed [signer.SeedSize]byte
		if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, seed[:], 0o600); err != nil {
			return nil, err
		}
		return seed[:], nil
	}
	if err != nil {
		return nil, err
	}
	if len(data) != signer.SeedSize {
		return nil, fmt.Errorf("seed file %q is %d bytes, want %d", path, len(data), signer.SeedSize)
	}
	return data, nil
}

// metricsListenIsLoopback returns true if the given listen address is
// bound to a loopback (or otherwise local-only) host. Bare ":<port>"
// and "0.0.0.0:<port>" are NOT considered loopback. Used to gate
// pprof exposure: we only register the heap/CPU profile handlers when
// callers must already be on the local machine.
func metricsListenIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "" {
		// Bare ":port" listens on all interfaces.
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func die(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cactus: "+format+"\n", args...)
	os.Exit(1)
}
