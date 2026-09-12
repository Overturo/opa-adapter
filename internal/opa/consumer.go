// Consumer is the interface a decision-log source implements.
//
// Two implementations ship: HTTPConsumer (receives POSTs from OPA's
// decision-log channel) and FileConsumer (tails newline-delimited
// JSON). Both push records into the provided channel.
package opa

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"
)

// Consumer pushes decision-log records to `ch` until ctx is canceled.
type Consumer interface {
	Run(ctx context.Context, ch chan<- DecisionLog) error
}

// ── HTTPConsumer ──────────────────────────────────────────────────

type HTTPConsumer struct {
	Addr   string
	Logger zerolog.Logger
}

// Run starts the HTTP server. Returns when ctx is canceled or the
// server fails to bind.
func (c *HTTPConsumer) Run(ctx context.Context, ch chan<- DecisionLog) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", c.handle(ch))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              c.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		c.Logger.Info().Str("addr", c.Addr).Msg("HTTP decision-log consumer listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (c *HTTPConsumer) handle(ch chan<- DecisionLog) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// OPA may POST either a single record OR an array.
		body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10 MiB cap
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}

		var single map[string]any
		var batch []map[string]any
		if err := json.Unmarshal(body, &batch); err != nil {
			if err := json.Unmarshal(body, &single); err != nil {
				c.Logger.Warn().Err(err).Msg("invalid decision-log JSON")
				http.Error(w, "invalid JSON", http.StatusBadRequest)
				return
			}
			batch = []map[string]any{single}
		}

		for _, raw := range batch {
			record := decodeRecord(raw)
			select {
			case ch <- record:
			case <-r.Context().Done():
				http.Error(w, "shutting down", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}
}

// ── FileConsumer ──────────────────────────────────────────────────

type FileConsumer struct {
	Path   string
	Logger zerolog.Logger
}

func (c *FileConsumer) Run(ctx context.Context, ch chan<- DecisionLog) error {
	file, err := os.Open(c.Path)
	if err != nil {
		return fmt.Errorf("open %s: %w", c.Path, err)
	}
	defer file.Close()

	// Seek to end — process new appends only. Operators wanting
	// backfill should manually replay via curl/jq into HTTP mode.
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek %s: %w", c.Path, err)
	}

	reader := bufio.NewReader(file)
	c.Logger.Info().Str("path", c.Path).Msg("file decision-log consumer tailing")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := reader.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if err != nil {
			return fmt.Errorf("read %s: %w", c.Path, err)
		}
		if len(line) <= 1 {
			continue
		}

		var raw map[string]any
		if err := json.Unmarshal(line, &raw); err != nil {
			c.Logger.Warn().Err(err).Msg("skipping malformed JSON line")
			continue
		}
		select {
		case ch <- decodeRecord(raw):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// ── shared decoder ────────────────────────────────────────────────

func decodeRecord(raw map[string]any) DecisionLog {
	d := DecisionLog{Raw: raw}
	if v, ok := raw["path"].(string); ok {
		d.Path = v
	}
	if v, ok := raw["decision_id"].(string); ok {
		d.DecisionID = v
	}
	if v, ok := raw["input"].(map[string]any); ok {
		d.Input = v
	}
	if v, ok := raw["result"].(map[string]any); ok {
		d.Result = v
	}
	if v, ok := raw["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			d.Timestamp = t
		}
	}
	if v, ok := raw["bundles"].(map[string]any); ok {
		bundles := map[string]BundleRevision{}
		for k, b := range v {
			if bMap, ok := b.(map[string]any); ok {
				if rev, ok := bMap["revision"].(string); ok {
					bundles[k] = BundleRevision{Revision: rev}
				}
			}
		}
		d.Bundles = bundles
	}
	return d
}
