// cactus is the main ACME + issuance log server.
//
// Usage:
//
//	cactus -config /path/to/config.json
//
// This is a *test* server; do not use it for anything that matters.
// See docs/threat-model.md for what it deliberately does not protect
// against.
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
	"math"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"encoding/json"
	"encoding/pem"
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/letsencrypt/cactus/acme"
	"github.com/letsencrypt/cactus/ca"
	"github.com/letsencrypt/cactus/cert"
	"github.com/letsencrypt/cactus/config"
	"github.com/letsencrypt/cactus/cors"
	"github.com/letsencrypt/cactus/landmark"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/logging"
	"github.com/letsencrypt/cactus/metrics"
	"github.com/letsencrypt/cactus/mirrorpush"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
	"github.com/letsencrypt/cactus/tile"
	"github.com/letsencrypt/cactus/tlogx"
)

// pemDecode is just pem.Decode kept here so the file can keep the
// "all stdlib imports first" Go convention without splitting groups.
func pemDecode(s string) (*pem.Block, []byte) {
	return pem.Decode([]byte(s))
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
// cert.MirrorEndpoint shape, loading each public key from its PEM file
// (resolved relative to dataDir).
func buildMirrorEndpoints(mirrors []config.MirrorEndpointConfig, dataDir string) ([]cert.MirrorEndpoint, error) {
	out := make([]cert.MirrorEndpoint, 0, len(mirrors))
	for i, m := range mirrors {
		alg, err := signer.ParseAlgorithm(m.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("mirrors[%d]: %w", i, err)
		}
		key, err := loadPEMSPKI(filepath.Join(dataDir, m.PublicKeyPath))
		if err != nil {
			return nil, fmt.Errorf("mirrors[%d] public_key_path: %w", i, err)
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

// logSource adapts *cactuslog.Log to the mirrorpush.Source interface.
// The names differ deliberately: mirrorpush needs both proof systems
// side by side and spells out which is which, whereas the log's own
// ConsistencyProof has always meant the MTC §4.4 subtree proof.
type logSource struct{ l *cactuslog.Log }

func (s logSource) Checkpoint() (uint64, tlogx.Hash, []byte) {
	cp := s.l.CurrentCheckpoint()
	return cp.Size, cp.Root, cp.SignedNote
}

func (s logSource) Entries(start, end uint64) ([][]byte, error) {
	return s.l.Entries(start, end)
}

func (s logSource) SubtreeConsistencyProof(start, end, treeSize uint64) ([]tlogx.Hash, error) {
	return s.l.ConsistencyProof(start, end, treeSize)
}

func (s logSource) TreeConsistencyProof(oldSize, newSize uint64) ([]tlogx.Hash, error) {
	return s.l.TreeConsistencyProof(oldSize, newSize)
}

// buildPushClients converts the mirror_push target list into
// mirrorpush.Client values, loading each mirror's public key from its
// PEM file (resolved relative to dataDir).
func buildPushClients(
	cfg config.Config,
	logID cert.TrustAnchorID,
	src mirrorpush.Source,
	fsys storage.FS,
	logger *slog.Logger,
) ([]*mirrorpush.Client, error) {
	httpClient := &http.Client{Timeout: cfg.MirrorPush.RequestTimeout()}
	out := make([]*mirrorpush.Client, 0, len(cfg.MirrorPush.Targets))
	for i, t := range cfg.MirrorPush.Targets {
		alg, err := signer.ParseAlgorithm(t.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("mirror_push.targets[%d]: %w", i, err)
		}
		key, err := loadPEMSPKI(filepath.Join(cfg.DataDir, t.PublicKeyPath))
		if err != nil {
			return nil, fmt.Errorf("mirror_push.targets[%d] public_key_path: %w", i, err)
		}
		c, err := mirrorpush.New(logID, mirrorpush.Target{
			SubmissionPrefix: t.SubmissionPrefix,
			MonitoringPrefix: t.MonitoringPrefix,
			Key: cert.CosignerKey{
				ID:        cert.TrustAnchorID(t.ID),
				Algorithm: signerAlgToCertAlg(alg),
				PublicKey: key,
			},
			HTTPClient:  httpClient,
			Timeout:     cfg.MirrorPush.RequestTimeout(),
			DisableGzip: cfg.MirrorPush.DisableGzip,
		}, src, fsys, logger)
		if err != nil {
			return nil, fmt.Errorf("mirror_push.targets[%d]: %w", i, err)
		}
		out = append(out, c)
	}
	return out, nil
}

// signerAlgToCertAlg maps a signer.Algorithm code to the cert
// package's parallel SignatureAlgorithm enum. Both use the same
// numeric values (TLS SignatureScheme codepoints), but the type
// systems are distinct.
func signerAlgToCertAlg(a signer.Algorithm) cert.SignatureAlgorithm {
	switch a {
	case signer.AlgMLDSA44:
		return cert.AlgMLDSA44
	case signer.AlgMLDSA65:
		return cert.AlgMLDSA65
	case signer.AlgMLDSA87:
		return cert.AlgMLDSA87
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

	// draft-04 identity model: the CA cosigner ID is the CA ID (§5.4),
	// and the issuance log ID is derived as CA-ID.0.<log.number> (§5.2).
	caID := cert.TrustAnchorID(cfg.CACosigner.ID)
	logID, err := cert.LogID(caID, cfg.Log.Number)
	if err != nil {
		return fmt.Errorf("derive log ID: %w", err)
	}

	// §5.5 CA certificate: the artifact a relying party configures from
	// (§7.1). Built once at startup and served at /ca-certificate on the
	// monitoring listener so peers can derive trust via
	// cert.ConfigFromCACertificate.
	caCertPEM, err := buildCACertPEM(caID, sgn)
	if err != nil {
		return fmt.Errorf("build CA certificate: %w", err)
	}

	// Landmark sequence. Built before the log so we can pass the
	// OnFlush hook to log.Config. Landmarks are mandatory.
	landmarkSeq, err := landmark.New(landmark.Config{
		CAID:                 caID,
		LogNumber:            cfg.Log.Number,
		TimeBetweenLandmarks: cfg.Landmarks.TimeBetweenLandmarks(),
		MaxCertLifetime:      cfg.Landmarks.MaxCertLifetime(),
	}, fsRoot, time.Now())
	if err != nil {
		return fmt.Errorf("landmark sequence: %w", err)
	}
	logger.Info("landmarks ready",
		"ca_id", string(caID),
		"log_number", cfg.Log.Number,
		"interval", cfg.Landmarks.TimeBetweenLandmarks(),
		"max_active", landmarkSeq.MaxActive())

	// Issuance log. The MirrorRequester closure (CA-mode quorum)
	// needs `l` to compute consistency proofs, so we forward-declare
	// via a pointer the closure captures.
	var l *cactuslog.Log
	// pushPool is the c2sp.org/tlog-mirror push client set. It is
	// likewise assigned after the log exists (its clients read from
	// it), and the closures below capture the variable. A nil *Pool is
	// inert, so the initial flush that log.New performs — which fires
	// OnFlush before this is set — and any deployment with no
	// mirror_push targets both behave exactly as before.
	var pushPool *mirrorpush.Pool
	logCfg := cactuslog.Config{
		LogID:       logID,
		CosignerID:  caID,
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
	logCfg.OnFlush = func(treeSize uint64) {
		// Push before allocating a landmark: a landmark is only useful
		// once mirrors can serve the range it names, and a push failure
		// must not stop the landmark from being allocated either way.
		if pushPool != nil {
			pushCtx, cancel := context.WithTimeout(ctx, cfg.MirrorPush.PushTimeout())
			pushPool.Push(pushCtx)
			cancel()
		}
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
	if len(cfg.CACosignerQuorum.Mirrors) > 0 {
		endpoints, err := buildMirrorEndpoints(cfg.CACosignerQuorum.Mirrors, cfg.DataDir)
		if err != nil {
			return fmt.Errorf("ca_cosigner_quorum: %w", err)
		}
		logCfg.WaitForCosigners = 1 + cfg.CACosignerQuorum.MinSignatures
		logCfg.MirrorRequester = func(ctx context.Context, st *cert.MTCSubtree, _ cert.MTCSignature) ([]cert.MTCSignature, error) {
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
					Subtree: st,
					// The reference checkpoint must carry the responding
					// mirror's own cosignature or it answers 403, and the
					// only source of one is an add-entries 200. Fold in
					// whatever the push pool has collected for this exact
					// size; with no push targets this returns the CA-signed
					// note unchanged.
					CACheckpointBody: pushPool.CheckpointWithCosignatures(cp.SignedNote, cp.Size),
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

	// c2sp.org/tlog-mirror push clients. Built after the log because
	// they read entries and proofs from it.
	if len(cfg.MirrorPush.Targets) > 0 {
		clients, err := buildPushClients(cfg, logID, logSource{l}, fsRoot, logger)
		if err != nil {
			return fmt.Errorf("mirror_push: %w", err)
		}
		pushPool = mirrorpush.NewPool(clients, logger)
		logger.Info("mirror push enabled",
			"targets", len(clients),
			"request_timeout", cfg.MirrorPush.RequestTimeout(),
			"push_timeout", cfg.MirrorPush.PushTimeout())
	}

	// CA issuer.
	issuer, err := ca.New(l, cfg.CACosigner.ID, cfg.Log.Number)
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
		LogID:          logID,
		CAID:           caID,
	}
	acmeCfg.Landmarks = landmarkSeq
	acmeCfg.SubtreeProof = l.SubtreeProof
	acmeCfg.LogNumber = cfg.Log.Number
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
		Handler:           logging.Middleware(logger)(cors.Middleware(acmeSrv.Handler())),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    16 * 1024,
	}
	tileSrv := tile.New(l, fsRoot).WithLandmarks(landmarkSeq)
	// Expose a redacted (no paths, no secrets) export of the running config
	// on the log's browser UI. Marshal failures are non-fatal: just skip it.
	if cfgJSON, err := json.MarshalIndent(cfg.Redacted(), "", "  "); err != nil {
		logger.Warn("could not marshal redacted config for /config endpoint", "err", err)
	} else {
		tileSrv = tileSrv.WithConfigJSON(cfgJSON)
	}
	monMux := http.NewServeMux()
	monMux.HandleFunc("/ca-certificate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(caCertPEM)
	})
	// Per the MTC-with-tlog profile, each issuance log is served as a
	// tiled transparency log at <prefix>/<log number>, where the
	// monitoring listener's base URL is the CA prefix. So mount the log's
	// tile/checkpoint/landmark routes under "/<log number>/".
	logPrefix := "/" + strconv.Itoa(int(cfg.Log.Number))
	monMux.Handle(logPrefix+"/", http.StripPrefix(logPrefix, tileSrv.Handler()))
	// The monitoring base is the CA prefix; redirect it to the (single)
	// log's browser UI so the bare root lands somewhere useful.
	monMux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, logPrefix+"/", http.StatusFound)
	})
	monitoringHTTP := &http.Server{
		Addr:              cfg.Monitoring.Listen,
		Handler:           logging.Middleware(logger)(cors.Middleware(monMux)),
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

	// Start listeners.
	startServer(logger, acmeHTTP, "acme", cfg.ACME.TLSCert, cfg.ACME.TLSKey)
	startServer(logger, monitoringHTTP, "monitoring", "", "")
	startServer(logger, metricsHTTP, "metrics", "", "")

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
	return nil
}

// loadPEMSPKI reads a PEM SubjectPublicKeyInfo file from path and
// returns the inner DER bytes of the public key.
func loadPEMSPKI(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key %q: %w", path, err)
	}
	return parsePEMSPKI(string(data))
}

// parsePEMSPKI accepts a PEM SubjectPublicKeyInfo block and returns
// the inner DER bytes of the public key.
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

// buildCACertPEM builds the §5.5 CA certificate (an unsigned cert,
// RFC 9925) representing this CA, as a PEM CERTIFICATE block. A relying
// party derives its configuration from it via cert.ConfigFromCACertificate
// (§7.1). minSerial is 0 because cactus does not prune, and maxSerial is
// 2^64-1 because cactus does not bound its log numbers, so no serials are
// initially revoked. An operator wanting to bound a relying party's
// monitoring scope would lower maxSerial (§7.5).
func buildCACertPEM(caID cert.TrustAnchorID, sgn signer.Signer) ([]byte, error) {
	alg := cert.SignatureAlgorithm(sgn.Algorithm())
	sigAlg, err := cert.SigAlgOID(alg)
	if err != nil {
		return nil, err
	}
	cosignerSPKI, err := cert.MarshalCosignerSPKI(alg, sgn.PublicKey())
	if err != nil {
		return nil, err
	}
	now := time.Now()
	der, err := cert.BuildCACertificate(cert.CACertificateInput{
		CAID:         caID,
		CosignerSPKI: cosignerSPKI,
		LogHash:      cert.OIDDigestSHA256,
		SigAlg:       sigAlg,
		MinSerial:    0,
		MaxSerial:    math.MaxUint64,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(10, 0, 0),
	})
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
