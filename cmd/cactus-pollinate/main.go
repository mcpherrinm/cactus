// cactus-pollinate keeps MTC mirrors in sync with the issuance logs
// they carry.
//
// Usage:
//
//	cactus-pollinate -config /path/to/pollinate.json
//
// It follows the Chrome MTC cosigners list, polls every issuer's logs
// and every mirror's copy of them, and pushes missing entries (via the
// c2sp.org/tlog-mirror write API) to any mirror that has been lagging
// the log head for longer than the configured delay. CAs are expected
// to push on their own; pollinate is the backstop for mirrors they are
// failing to reach.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/letsencrypt/cactus/logging"
	"github.com/letsencrypt/cactus/pollinate"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "pollinate.json", "path to JSON config file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("cactus-pollinate", version)
		return
	}

	cfg, err := pollinate.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cactus-pollinate: load config: %v\n", err)
		os.Exit(1)
	}

	logger := logging.New(os.Stdout, cfg.LogLevel)
	slog.SetDefault(logger)
	logger.Info("starting", "version", version, "config", *configPath,
		"data_dir", cfg.DataDir, "cosigners", cfg.Cosigners.List,
		"push_delay", cfg.PushDelay())

	if err := run(cfg, logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(cfg pollinate.Config, logger *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := pollinate.NewMetrics()
	svc, err := pollinate.New(cfg, logger, m)
	if err != nil {
		return err
	}

	// Metrics + pprof, gated to loopback listeners exactly as in cactus:
	// profiles can leak memory contents and burn CPU on demand.
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", m.Handler())
	if listenIsLoopback(cfg.Metrics.Listen) {
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
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute, // pprof profiles stream for a while
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 * 1024,
	}
	srvErr := make(chan error, 1)
	go func() {
		logger.Info("listening", "name", "metrics", "addr", metricsHTTP.Addr)
		if err := metricsHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srvErr <- fmt.Errorf("metrics listener: %w", err)
		}
	}()

	go svc.Run(ctx)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	var runErr error
	select {
	case sig := <-sigCh:
		logger.Info("shutting down", "signal", sig.String())
	case err := <-srvErr:
		logger.Error("listener failed, shutting down", "err", err)
		runErr = err
	}
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = metricsHTTP.Shutdown(shutdownCtx)
	return runErr
}

// listenIsLoopback reports whether addr is bound to a loopback host.
// Bare ":<port>" and "0.0.0.0:<port>" are NOT loopback.
func listenIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
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
