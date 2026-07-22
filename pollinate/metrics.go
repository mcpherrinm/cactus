package pollinate

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics is the cactus-pollinate metric registry plus instruments.
type Metrics struct {
	Registry *prometheus.Registry

	LogHeadSize   *prometheus.GaugeVec // labels: origin
	MirrorSize    *prometheus.GaugeVec // labels: origin, mirror
	MirrorLag     *prometheus.GaugeVec // labels: origin, mirror
	MirrorCarries *prometheus.GaugeVec // labels: origin, mirror

	Sweeps        prometheus.Counter
	SweepDuration prometheus.Histogram
	PollErrors    *prometheus.CounterVec // labels: kind
	Pushes        *prometheus.CounterVec // labels: mirror, result
	PushedEntries *prometheus.CounterVec // labels: mirror
	SourceReads   *prometheus.CounterVec // labels: source

	CosignersTimestamp prometheus.Gauge
	CosignersSigners   *prometheus.GaugeVec // labels: kind
}

// NewMetrics constructs a Metrics with a fresh registry pre-loaded with
// stdlib runtime collectors.
func NewMetrics() *Metrics {
	r := prometheus.NewRegistry()
	r.MustRegister(collectors.NewGoCollector())
	r.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	m := &Metrics{
		Registry: r,
		LogHeadSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cactus_pollinate_log_head_size",
			Help: "Largest observed tree size of each followed log.",
		}, []string{"origin"}),
		MirrorSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cactus_pollinate_mirror_size",
			Help: "Tree size of each mirror's copy of each log.",
		}, []string{"origin", "mirror"}),
		MirrorLag: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cactus_pollinate_mirror_lag_entries",
			Help: "Entries the mirror's copy is behind the log head.",
		}, []string{"origin", "mirror"}),
		MirrorCarries: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cactus_pollinate_mirror_carries",
			Help: "Whether the mirror carries the log (1), does not (0), or is undetermined (0.5).",
		}, []string{"origin", "mirror"}),
		Sweeps: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "cactus_pollinate_sweeps_total",
			Help: "Poll/push sweeps completed.",
		}),
		SweepDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "cactus_pollinate_sweep_duration_seconds",
			Help:    "Wall time per sweep.",
			Buckets: prometheus.ExponentialBuckets(0.05, 2, 12),
		}),
		PollErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cactus_pollinate_poll_errors_total",
			Help: "Failed polls, by kind (cosigners, log_head, mirror_checkpoint, state).",
		}, []string{"kind"}),
		Pushes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cactus_pollinate_pushes_total",
			Help: "Push attempts to lagging mirrors, by mirror and result (ok, error, fatal, unknown_origin).",
		}, []string{"mirror", "result"}),
		PushedEntries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cactus_pollinate_pushed_entries_total",
			Help: "Entries delivered to mirrors by successful pushes.",
		}, []string{"mirror"}),
		SourceReads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "cactus_pollinate_source_reads_total",
			Help: "HTTP reads per source, for watching read load balancing.",
		}, []string{"source"}),
		CosignersTimestamp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "cactus_pollinate_cosigners_timestamp_seconds",
			Help: "Freshness timestamp of the loaded cosigners file.",
		}),
		CosignersSigners: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "cactus_pollinate_cosigners_signers",
			Help: "Signers in the loaded cosigners file, by kind (issuer, mirror).",
		}, []string{"kind"}),
	}
	r.MustRegister(m.LogHeadSize, m.MirrorSize, m.MirrorLag, m.MirrorCarries,
		m.Sweeps, m.SweepDuration, m.PollErrors, m.Pushes, m.PushedEntries,
		m.SourceReads, m.CosignersTimestamp, m.CosignersSigners)
	return m
}

// Handler returns the /metrics http.Handler.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{Registry: m.Registry})
}
