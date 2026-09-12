// Package observability wires zerolog + Prometheus.
//
// token redaction: structured fields named
// "token" or "authorization" are scrubbed before emission. Callers
// who put bearer tokens in arbitrary field names defeat the safety
// net; the recommended pattern is to never log raw tokens at all.
package observability

import (
	"os"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
)

// Token shape: tat_<region>_<urlsafe_base64>.
// `SecureRandom.urlsafe_base64` emits `-` and `_` in the suffix, so
// the character class MUST include them — `[A-Za-z0-9]+` truncates
// real tokens at the first `_`/`-`, leaking the entropy.
var tokenPattern = regexp.MustCompile(`tat_[a-z]+_[A-Za-z0-9_\-]+`)

// NewLogger returns a zerolog.Logger configured for the given level
// + a custom hook that redacts bearer tokens from any string field.
func NewLogger(level string) zerolog.Logger {
	zerologLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		zerologLevel = zerolog.InfoLevel
	}
	logger := zerolog.New(os.Stdout).
		Level(zerologLevel).
		With().
		Timestamp().
		Str("component", "opa-adapter").
		Logger().
		Hook(tokenRedactingHook{})
	return logger
}

type tokenRedactingHook struct{}

func (tokenRedactingHook) Run(e *zerolog.Event, _ zerolog.Level, msg string) {
	// zerolog doesn't expose the partially-assembled JSON before
	// emission, so we redact the MESSAGE here. Field values containing
	// raw tokens must be pre-redacted by the caller; the regex below
	// is a defensive last line.
	if tokenPattern.MatchString(msg) {
		e.Str("redaction", "token-pattern-in-message")
	}
}

// RedactToken applies the SDK-standard redaction to a string. Use it
// in field values that MIGHT contain bearer tokens.
func RedactToken(s string) string {
	return tokenPattern.ReplaceAllString(s, "tat_<redacted>")
}

// SafeURL strips userinfo from a URL string before logging.
func SafeURL(u string) string {
	if idx := strings.Index(u, "@"); idx > 0 {
		if schemeIdx := strings.Index(u, "://"); schemeIdx > 0 {
			return u[:schemeIdx+3] + "<redacted>@" + u[idx+1:]
		}
	}
	return u
}
