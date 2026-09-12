// Retry / backoff helpers for the OAP HTTP client.
package overturo

import (
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ParseRetryAfter parses a `Retry-After` header value (either "N
// seconds" integer form or RFC 7231 HTTP-date form). Returns 0 when
// the header is absent or unparseable.
func ParseRetryAfter(h http.Header) time.Duration {
	val := strings.TrimSpace(h.Get("Retry-After"))
	if val == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(val); err == nil && seconds >= 0 {
		return time.Duration(seconds) * time.Second
	}
	if t, err := http.ParseTime(val); err == nil {
		delta := time.Until(t)
		if delta < 0 {
			return 0
		}
		return delta
	}
	return 0
}

// ExponentialBackoff returns the next backoff delay for `attempt`.
//
//	attempt=1 → ~1s, attempt=2 → ~2s, attempt=3 → ~4s ... capped at 30s.
//
// ±250ms jitter.
func ExponentialBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base := time.Duration(math.Min(float64(time.Second)*math.Pow(2, float64(attempt-1)), float64(30*time.Second)))
	jitter := time.Duration(rand.Int63n(int64(250 * time.Millisecond)))
	return base + jitter
}
