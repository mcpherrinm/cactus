package integration

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/letsencrypt/cactus/acme"
	"github.com/letsencrypt/cactus/ca"
	"github.com/letsencrypt/cactus/cert"
	cactuslog "github.com/letsencrypt/cactus/log"
	"github.com/letsencrypt/cactus/metrics"
	"github.com/letsencrypt/cactus/signer"
	"github.com/letsencrypt/cactus/storage"
)

// TestMetricsCountersMove issues a few certs and verifies the relevant
// Prometheus counters all advance.
func TestMetricsCountersMove(t *testing.T) {
	dir := t.TempDir()
	fs, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, signer.SeedSize)
	for i := range seed {
		seed[i] = 0x77
	}
	s, _ := signer.FromSeed(signer.AlgECDSAP256SHA256, seed)
	m := metrics.New()
	l, err := cactuslog.New(context.Background(), cactuslog.Config{
		LogID:       cert.TrustAnchorID("32473.1"),
		CosignerID:  cert.TrustAnchorID("32473.1.ca"),
		Signer:      s,
		FS:          fs,
		FlushPeriod: 25 * time.Millisecond,
		Metrics: cactuslog.Metrics{
			Entries:           m.LogEntries,
			Checkpoints:       m.LogCheckpoints,
			PoolFlushSize:     m.PoolFlushSize,
			SignatureDuration: m.SignatureDurationVec(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Stop()
	issuer, _ := ca.New(l, "32473.1")
	srv, _ := acme.New(acme.Config{
		Issuer:         issuer,
		ChallengeMode:  acme.ChallengeAutoPass,
		OrdersByStatus: m.ACMEOrdersVec(),
	})
	hsrv := httptest.NewServer(srv.Handler())
	defer hsrv.Close()
	srv.SetExternalURL(hsrv.URL)

	for i := 0; i < 3; i++ {
		if _, err := acmeIssueOne(hsrv.URL, "x.test"); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}

	// We expect at least 3 entries appended and at least one checkpoint
	// (the New() call publishes the initial null-entry checkpoint, plus
	// at least one per flush window).
	if got := testutil.ToFloat64(m.LogEntries); got < 3 {
		t.Errorf("LogEntries = %v, want >= 3", got)
	}
	if got := testutil.ToFloat64(m.LogCheckpoints); got < 2 {
		t.Errorf("LogCheckpoints = %v, want >= 2", got)
	}
	if got := testutil.ToFloat64(m.ACMEOrders.WithLabelValues("valid")); got != 3 {
		t.Errorf("acme_orders_total{valid} = %v, want 3", got)
	}

	// Sanity: /metrics endpoint actually serves something with our counters.
	mhsrv := httptest.NewServer(m.Handler())
	defer mhsrv.Close()
	body := httpGetBody(t, mhsrv.URL)
	for _, name := range []string{
		"cactus_log_entries_total",
		"cactus_log_checkpoints_total",
		"cactus_acme_orders_total",
		"cactus_signature_duration_seconds",
	} {
		if !strings.Contains(body, name) {
			t.Errorf("metrics output missing %s", name)
		}
	}
}
