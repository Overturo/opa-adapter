// Package overturo speaks the OAP wire.
//
// Client wraps an `*http.Client` with:
//   - Bearer auth (sourced from TokenManager)
//   - Exponential backoff on 429 / 5xx (honors `Retry-After` header)
//   - One-shot 401 token-rotation retry
//   - Per-request context propagation
//   - SDK-style error returns (HTTP status + reason_code + detail)
package overturo

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Client struct {
	httpClient *http.Client
	tokens     *TokenManager
	endpoints  Endpoints
	maxRetries int
	touchpoint string
	logger     ClientLogger
}

// ClientLogger is the thin logging interface the client needs.
// Implementations (e.g., zerolog) inject their own — keeps this
// package free of a hard zerolog dependency.
type ClientLogger interface {
	Warnf(format string, args ...any)
	Infof(format string, args ...any)
}

type ClientConfig struct {
	HTTPClient   *http.Client
	Tokens       *TokenManager
	Endpoints    Endpoints
	MaxRetries   int
	TouchpointID string
	Logger       ClientLogger
	Timeout      time.Duration
}

// NewClient constructs a client; sensible defaults applied for unset fields.
func NewClient(cfg ClientConfig) *Client {
	if cfg.HTTPClient == nil {
		timeout := cfg.Timeout
		if timeout == 0 {
			timeout = 30 * time.Second
		}
		cfg.HTTPClient = &http.Client{Timeout: timeout}
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	if cfg.Logger == nil {
		cfg.Logger = nopLogger{}
	}
	return &Client{
		httpClient: cfg.HTTPClient,
		tokens:     cfg.Tokens,
		endpoints:  cfg.Endpoints,
		maxRetries: cfg.MaxRetries,
		touchpoint: cfg.TouchpointID,
		logger:     cfg.Logger,
	}
}

// AttestPayload mirrors the attestation ingest body shape.
type AttestPayload struct {
	AttestationID  string         `json:"attestation_id"`
	TouchpointID   string         `json:"touchpoint_id"`
	AgentClass     string         `json:"agent_class"`
	ActionClass    string         `json:"action_class"`
	Decision       string         `json:"decision"`
	DecidedAt      string         `json:"decided_at"`
	SequenceNumber int64          `json:"sequence_number"`
	LegalBasis     string         `json:"legal_basis"`
	EvidenceDigest string         `json:"evidence_digest"`
	Context        map[string]any `json:"context"`
}

// AttestResponse is the parsed attestation ingest envelope.
type AttestResponse struct {
	Attestation struct {
		ID               string `json:"id"`
		ReceivedAt       string `json:"received_at"`
		SequenceNumber   int64  `json:"sequence_number"`
		Decision         string `json:"decision"`
		IdempotentReplay bool   `json:"idempotent_replay"`
	} `json:"attestation"`
	Receipt *string `json:"receipt"`
}

// APIError carries the structured server-side error envelope.
type APIError struct {
	HTTPStatus int
	ReasonCode string
	Message    string
	Detail     any
	RequestID  string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Overturo API error: HTTP %d reason_code=%s: %s",
		e.HTTPStatus, e.ReasonCode, e.Message)
}

// Attest submits a single attestation. Sets `attestation_id` and
// `decided_at` if empty.
func (c *Client) Attest(ctx context.Context, body AttestPayload) (*AttestResponse, error) {
	if body.AttestationID == "" {
		body.AttestationID = "att-opa-adapter-" + uuid.NewString()
	}
	if body.DecidedAt == "" {
		body.DecidedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if body.TouchpointID == "" {
		body.TouchpointID = c.touchpoint
	}

	var resp AttestResponse
	if err := c.postJSON(ctx, c.endpoints.Attestation, body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Heartbeat fires a single heartbeat ping.
func (c *Client) Heartbeat(ctx context.Context) error {
	return c.postJSON(ctx, c.endpoints.Heartbeat, map[string]string{
		"touchpoint_id": c.touchpoint,
	}, nil)
}

// EvidenceDigest returns the SHA-256 hex digest of
// `canonical(input) | canonical(output)`. Matches the server's `/\A[a-f0-9]{64}\z/`
// validator AND matches the TS / Python SDK implementations
// byte-for-byte — partners can compute the digest in any of the three
// SDKs and get the same value.
//
// Algorithm: JCS-trimmed RFC 8785:
//   - object keys sorted lexicographically
//   - no whitespace
//   - strings as UTF-8 (NOT escaped to \uXXXX)
//
// We can't use `encoding/json` directly: Go's `json.Encoder` escapes
// non-ASCII to `\uXXXX`, diverging from TS `JSON.stringify` and Python
// `json.dumps(ensure_ascii=False)`. The custom canonicalizer below
// keeps the three SDKs byte-identical for the same input.
func EvidenceDigest(input, output any) (string, error) {
	var buf bytes.Buffer
	if err := canonicalize(&buf, input); err != nil {
		return "", fmt.Errorf("canonicalize input: %w", err)
	}
	buf.WriteByte('|')
	if err := canonicalize(&buf, output); err != nil {
		return "", fmt.Errorf("canonicalize output: %w", err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// canonicalize emits JCS-style canonical JSON to `buf`. UTF-8
// preserved; map keys sorted; no whitespace.
func canonicalize(buf *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeJSONString(buf, v)
	case json.Number:
		buf.WriteString(string(v))
	case float64:
		if v != v || v > 1.7976931348623157e308 || v < -1.7976931348623157e308 {
			return fmt.Errorf("canonicalize: non-finite number %v is not representable in JCS", v)
		}
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(b)
	case int:
		buf.WriteString(strconv.FormatInt(int64(v), 10))
	case int64:
		buf.WriteString(strconv.FormatInt(v, 10))
	case []any:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonicalize(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJSONString(buf, k)
			buf.WriteByte(':')
			if err := canonicalize(buf, v[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		// Fallback for types OPA decision logs shouldn't produce
		// (timestamps as time.Time, structs, etc.). json.Marshal here
		// MAY escape unicode — but the OPA pipeline turns all values
		// into map[string]any / []any / scalars before reaching us.
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}

// writeJSONString emits a JSON-quoted string preserving UTF-8 (mirrors
// TS `JSON.stringify` / Python `json.dumps(s, ensure_ascii=False)`).
// Escapes the JSON-required set; emits raw bytes for any rune ≥ 0x20.
func writeJSONString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// ── internals ─────────────────────────────────────────────────────

func (c *Client) postJSON(ctx context.Context, url string, body any, dst any) error {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal body: %w", err)
	}

	attempt := 0
	tokenRetried := false

	for {
		attempt++
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+c.tokens.Current())
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if attempt > c.maxRetries {
				return fmt.Errorf("HTTP transport error: %w", err)
			}
			c.logger.Warnf("HTTP transport error on %s (attempt %d/%d): %v", url, attempt, c.maxRetries, err)
			sleepCtx(ctx, ExponentialBackoff(attempt))
			// B3 — bail immediately if ctx cancelled during backoff;
			// avoids issuing one more attest after SIGTERM.
			if err := ctx.Err(); err != nil {
				return err
			}
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			defer resp.Body.Close()
			if dst == nil || resp.StatusCode == 204 {
				_, _ = io.Copy(io.Discard, resp.Body)
				return nil
			}
			return json.NewDecoder(resp.Body).Decode(dst)
		}

		if resp.StatusCode == 401 && !tokenRetried {
			resp.Body.Close()
			if c.tokens.Refresh() {
				c.logger.Infof("Token rotated after 401; retrying %s once", url)
				tokenRetried = true
				attempt = 0
				continue
			}
		}

		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			if attempt > c.maxRetries {
				return parseAPIError(resp)
			}
			wait := ParseRetryAfter(resp.Header)
			if wait == 0 {
				wait = ExponentialBackoff(attempt)
			}
			c.logger.Warnf("HTTP %d on %s; backing off %s (attempt %d/%d)",
				resp.StatusCode, url, wait, attempt, c.maxRetries)
			resp.Body.Close()
			sleepCtx(ctx, wait)
			// B3 — bail immediately if ctx cancelled during backoff;
			// avoids issuing one more attest after SIGTERM.
			if err := ctx.Err(); err != nil {
				return err
			}
			continue
		}

		return parseAPIError(resp)
	}
}

func parseAPIError(resp *http.Response) error {
	defer resp.Body.Close()
	requestID := resp.Header.Get("X-Request-Id")

	var envelope struct {
		Error struct {
			ReasonCode string `json:"reason_code"`
			Message    string `json:"message"`
			Detail     any    `json:"detail"`
		} `json:"error"`
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if len(body) > 0 {
		_ = json.Unmarshal(body, &envelope)
	}

	msg := envelope.Error.Message
	if msg == "" {
		msg = strings.TrimSpace(string(body))
	}
	if msg == "" {
		msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	return &APIError{
		HTTPStatus: resp.StatusCode,
		ReasonCode: envelope.Error.ReasonCode,
		Message:    msg,
		Detail:     envelope.Error.Detail,
		RequestID:  requestID,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

type nopLogger struct{}

func (nopLogger) Warnf(string, ...any) {}
func (nopLogger) Infof(string, ...any) {}
