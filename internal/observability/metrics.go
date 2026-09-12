// Prometheus counters / histograms for the adapter.
package observability

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

type Metrics struct {
	DecisionsReceived prometheus.Counter
	AttestationsOK    prometheus.Counter
	AttestationsErr   *prometheus.CounterVec
	HeartbeatsOK      prometheus.Counter
	HeartbeatsErr     prometheus.Counter
	RetryAfters       prometheus.Counter
	registry          *prometheus.Registry
}

func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		registry: reg,
		DecisionsReceived: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "opa_adapter_decisions_received_total",
			Help: "Total OPA decision-log records received.",
		}),
		AttestationsOK: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "opa_adapter_attestations_submitted_total",
			Help: "Total attestations successfully submitted to Overturo.",
		}),
		AttestationsErr: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "opa_adapter_attestation_errors_total",
			Help: "Attestation submission failures by reason_code.",
		}, []string{"reason_code"}),
		HeartbeatsOK: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "opa_adapter_heartbeats_ok_total",
			Help: "Heartbeat ticks accepted by Overturo.",
		}),
		HeartbeatsErr: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "opa_adapter_heartbeats_err_total",
			Help: "Heartbeat tick failures.",
		}),
		RetryAfters: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "opa_adapter_retry_after_observed_total",
			Help: "429/5xx responses where the adapter backed off per Retry-After.",
		}),
	}
	reg.MustRegister(
		m.DecisionsReceived, m.AttestationsOK, m.AttestationsErr,
		m.HeartbeatsOK, m.HeartbeatsErr, m.RetryAfters,
	)
	return m
}

// Serve binds the Prometheus /metrics endpoint on the given address.
// Returns the *http.Server so the caller can graceful-shutdown.
// Address `""` disables metrics entirely.
func (m *Metrics) Serve(addr string, logger zerolog.Logger) *http.Server {
	if addr == "" {
		logger.Info().Msg("metrics endpoint disabled (observability.metrics_listen is empty)")
		return nil
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		logger.Info().Str("addr", addr).Msg("metrics endpoint listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error().Err(err).Msg("metrics endpoint exited unexpectedly")
		}
	}()
	return srv
}

// Shutdown gracefully stops the metrics HTTP server, if running.
func (m *Metrics) Shutdown(ctx context.Context, srv *http.Server) error {
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}
