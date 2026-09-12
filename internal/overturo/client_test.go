package overturo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func newTestClient(t *testing.T, srv *httptest.Server, tokens *TokenManager) *Client {
	t.Helper()
	disc := Endpoints{
		Attestation: srv.URL + "/api/v1/oap/attestations",
		Heartbeat:   srv.URL + "/api/v1/oap/attestations/heartbeat",
		Escalation:  srv.URL + "/api/v1/oap/escalations",
		Revocation:  srv.URL + "/api/v1/oap/revocations",
	}
	return NewClient(ClientConfig{
		HTTPClient:   srv.Client(),
		Tokens:       tokens,
		Endpoints:    disc,
		MaxRetries:   2,
		TouchpointID: "tp_dev_yyy",
		Timeout:      5 * time.Second,
	})
}

func TestAttestHappyPath(t *testing.T) {
	var lastAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"attestation": map[string]any{
				"id": "att_dev_xyz", "received_at": "2026-06-01T12:00:00Z",
				"sequence_number": 1, "decision": "allow",
			},
			"receipt": "eyJhbGc.eyJjbGFpbXM.signature",
		})
	}))
	defer srv.Close()

	tokens := NewTokenManager("tat_dev_xxx", "")
	client := newTestClient(t, srv, tokens)
	resp, err := client.Attest(context.Background(), AttestPayload{
		AgentClass: "data_export_agent", ActionClass: "tool_call",
		Decision: "allow", LegalBasis: "consent", SequenceNumber: 1,
		EvidenceDigest: "a", Context: map[string]any{},
	})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if resp.Attestation.ID != "att_dev_xyz" {
		t.Errorf("attestation.id = %q", resp.Attestation.ID)
	}
	if lastAuth != "Bearer tat_dev_xxx" {
		t.Errorf("Authorization header = %q", lastAuth)
	}
}

func Test422MapsToValidationError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"reason_code": "validation_failed",
				"message":     "bad scope",
			},
		})
	}))
	defer srv.Close()

	client := newTestClient(t, srv, NewTokenManager("tat_dev_xxx", ""))
	_, err := client.Attest(context.Background(), AttestPayload{})
	if err == nil {
		t.Fatal("expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError; got %T", err)
	}
	if apiErr.HTTPStatus != 422 {
		t.Errorf("status: %d", apiErr.HTTPStatus)
	}
	if apiErr.ReasonCode != "validation_failed" {
		t.Errorf("reason_code: %q", apiErr.ReasonCode)
	}
}

func TestRetryAfter429ThenSucceeds(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{"reason_code": "rate_limited"},
			})
			return
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"attestation": map[string]any{
				"id": "att_x", "received_at": "t",
				"sequence_number": 1, "decision": "allow",
			},
			"receipt": nil,
		})
	}))
	defer srv.Close()

	client := newTestClient(t, srv, NewTokenManager("tat_dev_xxx", ""))
	_, err := client.Attest(context.Background(), AttestPayload{})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if attempts.Load() != 2 {
		t.Errorf("attempts = %d; want 2", attempts.Load())
	}
}

func Test401TriggersTokenRotation(t *testing.T) {
	t.Setenv("OAP_TEST_TOKEN", "tat_dev_rotated")

	var attempts atomic.Int32
	var seenAuth atomic.Pointer[string]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{"reason_code": "trusted_attester_unauthenticated"},
			})
			return
		}
		seenAuth.Store(&auth)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"attestation": map[string]any{
				"id": "att_x", "received_at": "t",
				"sequence_number": 1, "decision": "allow",
			},
			"receipt": nil,
		})
	}))
	defer srv.Close()

	tokens := NewTokenManager("tat_dev_initial", "OAP_TEST_TOKEN")
	client := newTestClient(t, srv, tokens)
	if _, err := client.Attest(context.Background(), AttestPayload{}); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if attempts.Load() != 2 {
		t.Errorf("attempts = %d; want 2", attempts.Load())
	}
	if got := seenAuth.Load(); got == nil || *got != "Bearer tat_dev_rotated" {
		t.Errorf("second call auth = %v; want Bearer tat_dev_rotated", got)
	}
}

func TestEvidenceDigest(t *testing.T) {
	digest, err := EvidenceDigest(
		map[string]any{"a": 1, "b": 2},
		map[string]any{"x": 10},
	)
	if err != nil {
		t.Fatalf("EvidenceDigest: %v", err)
	}
	if len(digest) != 64 {
		t.Errorf("digest length = %d; want 64 (hex)", len(digest))
	}

	// Stable across key order.
	digest2, _ := EvidenceDigest(
		map[string]any{"b": 2, "a": 1},
		map[string]any{"x": 10},
	)
	if digest != digest2 {
		t.Errorf("digest not stable across key order: %s != %s", digest, digest2)
	}
}

// B1 regression — the Go canonicalizer MUST preserve UTF-8 (not
// escape to \uXXXX) so all three SDKs (TS / Python / Go) produce
// identical digests for the same input. the cross-SDK conformance harness
// will assert this against fixtures.
func TestEvidenceDigestPreservesUTF8(t *testing.T) {
	// `café` exercises the UTF-8 path:
	//   TS `JSON.stringify("café")` = `"café"` (raw UTF-8)
	//   Py `json.dumps("café", ensure_ascii=False)` = `"café"`
	//   Old Go (bug): json.Encoder escaped to `"café"`
	//   New Go (fixed): writes raw UTF-8 `"café"`
	got, err := EvidenceDigest(
		map[string]any{"city": "café"},
		map[string]any{"ok": true},
	)
	if err != nil {
		t.Fatalf("EvidenceDigest: %v", err)
	}

	// Hand-compute the expected SHA-256 hex via the same canonical
	// form the TS/Python implementations produce.
	expectedCanonical := `{"city":"café"}|{"ok":true}`
	sum := sha256.Sum256([]byte(expectedCanonical))
	want := hex.EncodeToString(sum[:])

	if got != want {
		t.Errorf("UTF-8 canonicalization drift — Go diverges from TS/Python:\n  got:  %s\n  want: %s",
			got, want)
	}
}

func TestEvidenceDigestRejectsNaN(t *testing.T) {
	z := 0.0
	nan := z / z
	_, err := EvidenceDigest(map[string]any{"v": nan}, map[string]any{})
	if err == nil {
		t.Fatal("expected error for non-finite number")
	}
}

func TestHeartbeat(t *testing.T) {
	var called atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := newTestClient(t, srv, NewTokenManager("tat_dev_xxx", ""))
	if err := client.Heartbeat(context.Background()); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if !called.Load() {
		t.Error("server did not receive heartbeat")
	}
}
