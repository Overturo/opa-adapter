// token-rotation manager.
//
// On 401, the HTTP client calls `Refresh()` to re-read the bearer
// token from the same env var the config pointed at. If the value
// changed, the failed request is retried once. The server's two-slot
// rotation (24h overlap) makes the gap invisible if env updates land
// within the overlap window.
package overturo

import (
	"os"
	"sync"
)

type TokenManager struct {
	mu      sync.RWMutex
	current string
	envName string
}

// NewTokenManager constructs a manager rooted at `initial`. When
// `envName` is non-empty, `Refresh()` re-reads that env var; when
// empty, `Refresh()` is always a no-op (returns false).
func NewTokenManager(initial, envName string) *TokenManager {
	return &TokenManager{current: initial, envName: envName}
}

// Current returns the active bearer token.
func (t *TokenManager) Current() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.current
}

// Refresh re-reads the env var (when configured). Returns true when
// the token changed (caller should retry once).
func (t *TokenManager) Refresh() bool {
	if t.envName == "" {
		return false
	}
	next := os.Getenv(t.envName)
	if next == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if next == t.current {
		return false
	}
	t.current = next
	return true
}
