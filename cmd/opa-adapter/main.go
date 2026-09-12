// overturo-opa-adapter entrypoint.
//
// Flow:
//
//  1. Load YAML config (env-var interpolation supported)
//  2. Discover OAP endpoints (`/.well-known/openid-configuration`)
//  3. Start the configured decision-log consumer (HTTP or file tail)
//  4. For each decision: map → submit attestation → persist sequence
//  5. Heartbeat in a separate goroutine
//  6. Graceful shutdown on SIGINT/SIGTERM
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/overturo/opa-adapter/internal/config"
	"github.com/overturo/opa-adapter/internal/mapping"
	"github.com/overturo/opa-adapter/internal/observability"
	"github.com/overturo/opa-adapter/internal/opa"
	"github.com/overturo/opa-adapter/internal/overturo"
)

// version is set from the release tag at build time
// (-ldflags "-X main.version=<tag>"); "dev" for a plain `go build`.
var version = "dev"

func main() {
	configPath := flag.String("config", "/etc/opa-adapter.yaml", "path to YAML config")
	versionFlag := flag.Bool("version", false, "print version + exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println("overturo-opa-adapter " + version)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config load failed: %v\n", err)
		os.Exit(2)
	}

	logger := observability.NewLogger(cfg.Observability.LogLevel)
	logger.Info().
		Str("base_url", observability.SafeURL(cfg.Overturo.BaseURL)).
		Str("touchpoint_id", cfg.Overturo.TouchpointID).
		Str("opa_mode", cfg.OPA.Mode).
		Msg("opa-adapter starting")

	metrics := observability.NewMetrics()
	metricsServer := metrics.Serve(cfg.Observability.MetricsListen, logger)

	rootCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := run(rootCtx, cfg, logger, metrics); err != nil {
		logger.Error().Err(err).Msg("adapter exited with error")
		os.Exit(1)
	}

	if metricsServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = metrics.Shutdown(shutdownCtx, metricsServer)
	}
}

func run(ctx context.Context, cfg *config.Config, logger zerolog.Logger, metrics *observability.Metrics) error {
	// Install signal handler.
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Discovery.
	httpClient := &http.Client{Timeout: time.Duration(cfg.Overturo.TimeoutSeconds) * time.Second}
	disc, err := overturo.FetchDiscovery(sigCtx, cfg.Overturo.BaseURL, cfg.Overturo.RequiredOAPVersion, httpClient)
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	logger.Info().
		Str("attestation_endpoint", disc.Endpoints.Attestation).
		Str("heartbeat_endpoint", disc.Endpoints.Heartbeat).
		Msg("discovery resolved")

	// Token + sequence + client.
	tokens := overturo.NewTokenManager(cfg.Overturo.Token, cfg.Overturo.TokenEnv)
	seq, err := overturo.NewSequenceManager(cfg.Overturo.StateFile)
	if err != nil {
		return fmt.Errorf("sequence state: %w", err)
	}
	logger.Info().Int64("next_sequence", seq.Peek()).Msg("sequence state loaded")

	clientLogger := &zerologClientLogger{logger: logger.With().Str("component", "oap-client").Logger()}
	client := overturo.NewClient(overturo.ClientConfig{
		HTTPClient:   httpClient,
		Tokens:       tokens,
		Endpoints:    disc.Endpoints,
		MaxRetries:   cfg.Overturo.MaxRetries,
		TouchpointID: cfg.Overturo.TouchpointID,
		Logger:       clientLogger,
		Timeout:      time.Duration(cfg.Overturo.TimeoutSeconds) * time.Second,
	})

	// Mapping engine.
	mapper, err := mapping.Compile(
		cfg.Mapping.AgentClass,
		cfg.Mapping.ActionClass,
		cfg.Mapping.LegalBasis,
		cfg.Mapping.PolicyRef,
		cfg.Mapping.PolicyVersion,
	)
	if err != nil {
		return fmt.Errorf("compile mapping templates: %w", err)
	}

	// Decision-log consumer.
	var consumer opa.Consumer
	switch cfg.OPA.Mode {
	case "http":
		consumer = &opa.HTTPConsumer{Addr: cfg.OPA.HTTPListen, Logger: logger}
	case "file":
		consumer = &opa.FileConsumer{Path: cfg.OPA.FilePath, Logger: logger}
	default:
		return fmt.Errorf("unsupported opa.mode: %s", cfg.OPA.Mode)
	}

	// Buffered channel so a brief Overturo outage doesn't block OPA.
	decisions := make(chan opa.DecisionLog, 256)

	var wg sync.WaitGroup

	// Consumer goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// B4 — defer the channel-close so a panic in Consumer.Run
		// (e.g., bad-state panic in a future consumer impl) still
		// unblocks the submission goroutine. Without `defer`, a panic
		// skipped the close and deadlocked wg.Wait().
		defer close(decisions)
		if err := consumer.Run(sigCtx, decisions); err != nil && err != context.Canceled {
			logger.Error().Err(err).Msg("decision-log consumer exited")
		}
	}()

	// Heartbeat goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		runHeartbeats(sigCtx, client, time.Duration(cfg.Overturo.HeartbeatCadenceSeconds)*time.Second, logger, metrics)
	}()

	// Submission goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		runSubmissions(sigCtx, decisions, mapper, client, seq, cfg.Overturo.TouchpointID, logger, metrics)
	}()

	wg.Wait()
	logger.Info().Msg("opa-adapter exited cleanly")
	return nil
}

func runHeartbeats(ctx context.Context, client *overturo.Client, cadence time.Duration, logger zerolog.Logger, metrics *observability.Metrics) {
	if cadence <= 0 {
		return
	}
	ticker := time.NewTicker(cadence)
	defer ticker.Stop()
	logger.Info().Dur("cadence", cadence).Msg("heartbeat started")
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := client.Heartbeat(ctx); err != nil {
				logger.Warn().Err(err).Msg("heartbeat failed")
				metrics.HeartbeatsErr.Inc()
				continue
			}
			metrics.HeartbeatsOK.Inc()
		}
	}
}

func runSubmissions(
	ctx context.Context,
	decisions <-chan opa.DecisionLog,
	mapper *mapping.Mapping,
	client *overturo.Client,
	seq *overturo.SequenceManager,
	touchpointID string,
	logger zerolog.Logger,
	metrics *observability.Metrics,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case decision, ok := <-decisions:
			if !ok {
				return
			}
			metrics.DecisionsReceived.Inc()
			handleDecision(ctx, decision, mapper, client, seq, touchpointID, logger, metrics)
		}
	}
}

func handleDecision(
	ctx context.Context,
	decision opa.DecisionLog,
	mapper *mapping.Mapping,
	client *overturo.Client,
	seq *overturo.SequenceManager,
	touchpointID string,
	logger zerolog.Logger,
	metrics *observability.Metrics,
) {
	payload, err := mapper.Apply(decision)
	if err != nil {
		logger.Error().Err(err).Str("decision_id", decision.DecisionID).Msg("mapping failed")
		metrics.AttestationsErr.WithLabelValues("mapping_failed").Inc()
		return
	}

	payload.TouchpointID = touchpointID
	payload.AttestationID = "att-opa-adapter-" + uuid.NewString()
	payload.SequenceNumber = seq.Next()

	resp, err := client.Attest(ctx, payload)
	if err != nil {
		reasonCode := "unknown"
		if apiErr, ok := err.(*overturo.APIError); ok && apiErr.ReasonCode != "" {
			reasonCode = apiErr.ReasonCode
		}
		metrics.AttestationsErr.WithLabelValues(reasonCode).Inc()
		// B5 — roll back the sequence number when the attempt failed
		// AND the counter hasn't moved on. Without this, a failed
		// attest silently consumes a sequence number; the next
		// successful submission lands at N+1 instead of N, and the
		// server emits `attestation.gap_detected` on every following
		// submission until restart.
		if !seq.Rewind(payload.SequenceNumber) {
			logger.Warn().
				Int64("sequence_number", payload.SequenceNumber).
				Msg("sequence rewind skipped (concurrent submission moved the counter); " +
					"server will see attestation.gap_detected on next success")
		}
		logger.Error().
			Err(err).
			Str("decision_id", decision.DecisionID).
			Str("reason_code", reasonCode).
			Int64("sequence_number", payload.SequenceNumber).
			Msg("attestation submission failed")
		return
	}

	metrics.AttestationsOK.Inc()
	if err := seq.Persist(payload.SequenceNumber); err != nil {
		logger.Warn().Err(err).Int64("sequence_number", payload.SequenceNumber).
			Msg("sequence persist failed — state may diverge on next restart")
	}
	logger.Debug().
		Str("decision_id", decision.DecisionID).
		Str("attestation_id", resp.Attestation.ID).
		Int64("sequence_number", payload.SequenceNumber).
		Str("decision", payload.Decision).
		Msg("attestation submitted")
}

// zerologClientLogger adapts a zerolog.Logger to the ClientLogger
// interface the overturo client expects.
type zerologClientLogger struct {
	logger zerolog.Logger
}

func (z *zerologClientLogger) Warnf(format string, args ...any) {
	z.logger.Warn().Msgf(format, args...)
}

func (z *zerologClientLogger) Infof(format string, args ...any) {
	z.logger.Info().Msgf(format, args...)
}
