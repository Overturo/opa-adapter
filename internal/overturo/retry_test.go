package overturo

import (
	"net/http"
	"testing"
	"time"
)

func TestParseRetryAfterSeconds(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "15")
	got := ParseRetryAfter(h)
	if got != 15*time.Second {
		t.Errorf("ParseRetryAfter(15) = %v; want 15s", got)
	}
}

func TestParseRetryAfterZero(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "0")
	if got := ParseRetryAfter(h); got != 0 {
		t.Errorf("ParseRetryAfter(0) = %v; want 0", got)
	}
}

func TestParseRetryAfterAbsent(t *testing.T) {
	if got := ParseRetryAfter(http.Header{}); got != 0 {
		t.Errorf("ParseRetryAfter(absent) = %v; want 0", got)
	}
}

func TestParseRetryAfterUnparseable(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "garbage")
	if got := ParseRetryAfter(h); got != 0 {
		t.Errorf("ParseRetryAfter(garbage) = %v; want 0", got)
	}
}

func TestParseRetryAfterHTTPDate(t *testing.T) {
	h := http.Header{}
	future := time.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	h.Set("Retry-After", future)
	got := ParseRetryAfter(h)
	// Allow some slop — we expect ~30s, but parsing + computation
	// have second-level granularity.
	if got < 25*time.Second || got > 35*time.Second {
		t.Errorf("ParseRetryAfter(http-date+30s) = %v; want ~30s", got)
	}
}

func TestExponentialBackoffMonotonic(t *testing.T) {
	prev := time.Duration(0)
	for attempt := 1; attempt <= 5; attempt++ {
		got := ExponentialBackoff(attempt)
		if got <= prev {
			t.Errorf("backoff not monotonic: attempt=%d prev=%v got=%v", attempt, prev, got)
		}
		prev = got
	}
}

func TestExponentialBackoffCap(t *testing.T) {
	// Attempt=10 → 2^9 * 1s = 512s, capped at 30s.
	got := ExponentialBackoff(10)
	if got > 31*time.Second {
		t.Errorf("backoff cap missed: %v", got)
	}
}
