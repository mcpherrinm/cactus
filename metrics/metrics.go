// Package metrics owns the Prometheus registry used across cactus and
// exposes the /metrics handler.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics is the cactus-wide metric registry plus instruments.
type Metrics struct {
	Registry *prometheus.Registry

	ACMEOrders        *prometheus.CounterVec // labels: status
	LogEntries        prometheus.Counter
	LogCheckpoints    prometheus.Counter
	SignatureDuration *prometheus.HistogramVec // labels: alg
	PoolFlushSize     prometheus.Histogram

	// Phase 9 — mirror operating mode.
	MirrorUpstreamSize        prometheus.Gauge
	MirrorConsistencyFailures prometheus.Counter
	MirrorSignSubtreeRequests *prometheus.CounterVec // labels: result
	MirrorSignSubtreeDuration prometheus.Histogram

	// Phase 9 — CA-mode multi-mirror.
	CAMirrorRequests *prometheus.CounterVec // labels: mirror_id, result
	CAQuorumFailures prometheus.Counter
}

// New constructs a Metrics with a fresh registry pre-loaded with stdlib
// runtime collectors.
func New() *Metrics {
	r := prometheus.NewRegistry()
	r.MustRegister(collectors.NewGoCollector())
	r.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	m := &Metrics{
		Registry: r,
		ACMEOrders: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cactus_acme_orders_total",
			Help: "ACME orders processed, by terminal status.",
		}, []string{"status"}),
		LogEntries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cactus_log_entries_total",
			Help: "Entries appended to the issuance log.",
		}),
		LogCheckpoints: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cactus_log_checkpoints_total",
			Help: "Signed checkpoints published.",
		}),
		SignatureDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "cactus_signature_duration_seconds",
			Help:    "Time spent producing a cosigner signature.",
			Buckets: prometheus.DefBuckets,
		}, []string{"alg"}),
		PoolFlushSize: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "cactus_pool_flush_size",
			Help:    "Entries written per checkpoint flush.",
			Buckets: []float64{0, 1, 4, 16, 64, 256, 1024, 4096, 16384},
		}),

		MirrorUpstreamSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cactus_mirror_upstream_checkpoint_size",
			Help: "Tree size of the latest verified upstream checkpoint.",
		}),
		MirrorConsistencyFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cactus_mirror_consistency_failures_total",
			Help: "Times the mirror refused to advance because a consistency check failed.",
		}),
		MirrorSignSubtreeRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cactus_mirror_signsubtree_requests_total",
			Help: "sign-subtree requests served by the mirror, by result.",
		}, []string{"result"}),
		MirrorSignSubtreeDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "cactus_mirror_signsubtree_duration_seconds",
			Help:    "Time to serve a sign-subtree request.",
			Buckets: prometheus.DefBuckets,
		}),

		CAMirrorRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cactus_ca_mirror_request_total",
			Help: "Outbound CA→mirror sign-subtree requests, by mirror_id and result.",
		}, []string{"mirror_id", "result"}),
		CAQuorumFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cactus_ca_quorum_failures_total",
			Help: "Times the CA failed to reach mirror cosignature quorum.",
		}),
	}
	r.MustRegister(m.ACMEOrders, m.LogEntries, m.LogCheckpoints,
		m.SignatureDuration, m.PoolFlushSize,
		m.MirrorUpstreamSize, m.MirrorConsistencyFailures,
		m.MirrorSignSubtreeRequests, m.MirrorSignSubtreeDuration,
		m.CAMirrorRequests, m.CAQuorumFailures)
	return m
}

// Handler returns the /metrics http.Handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{Registry: m.Registry})
}

// Counter / Observer / ObserverVec / CounterVec mirror the small
// Prometheus subset downstream packages use, so those packages don't
// have to import prometheus directly.
type Counter interface{ Add(float64) }
type Observer interface{ Observe(float64) }
type ObserverVec interface {
	WithLabelValues(...string) Observer
}
type CounterVec interface {
	WithLabelValues(...string) Counter
}

// histogramVecAdapter wraps a *prometheus.HistogramVec so its
// WithLabelValues returns metrics.Observer (not prometheus.Observer).
type histogramVecAdapter struct {
	hv *prometheus.HistogramVec
}

func (h *histogramVecAdapter) WithLabelValues(lvs ...string) Observer {
	return scalarObserver{h.hv.WithLabelValues(lvs...)}
}

type scalarObserver struct{ inner prometheus.Observer }

func (s scalarObserver) Observe(v float64) { s.inner.Observe(v) }

// SignatureDurationVec returns the metrics.ObserverVec adapter for the
// signature_duration_seconds histogram.
func (m *Metrics) SignatureDurationVec() ObserverVec {
	return &histogramVecAdapter{hv: m.SignatureDuration}
}

// counterVecAdapter wraps a *prometheus.CounterVec.
type counterVecAdapter struct {
	cv *prometheus.CounterVec
}

func (c *counterVecAdapter) WithLabelValues(lvs ...string) Counter {
	return c.cv.WithLabelValues(lvs...)
}

// ACMEOrdersVec returns the metrics.CounterVec adapter for the
// cactus_acme_orders_total counter.
func (m *Metrics) ACMEOrdersVec() CounterVec {
	return &counterVecAdapter{cv: m.ACMEOrders}
}

// MirrorSignSubtreeRequestsVec returns the CounterVec adapter for
// cactus_mirror_signsubtree_requests_total.
func (m *Metrics) MirrorSignSubtreeRequestsVec() CounterVec {
	return &counterVecAdapter{cv: m.MirrorSignSubtreeRequests}
}

// CAMirrorRequestsVec returns the CounterVec adapter for
// cactus_ca_mirror_request_total.
func (m *Metrics) CAMirrorRequestsVec() CounterVec {
	return &counterVecAdapter{cv: m.CAMirrorRequests}
}
