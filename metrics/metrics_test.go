package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerExposesMetrics(t *testing.T) {
	m := New()
	m.LogEntries.Inc()
	m.ACMEOrders.WithLabelValues("valid").Inc()

	srv := httptest.NewServer(m.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "cactus_log_entries_total 1") {
		t.Errorf("missing log entries metric: %q", s)
	}
	if !strings.Contains(s, `cactus_acme_orders_total{status="valid"} 1`) {
		t.Errorf("missing acme orders metric: %q", s)
	}
}
