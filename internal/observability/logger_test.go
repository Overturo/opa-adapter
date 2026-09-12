package observability

import (
	"strings"
	"testing"
)

func TestRedactToken(t *testing.T) {
	tests := []struct {
		name string
		in   string
		bad  string // substring that must NOT appear after redaction
	}{
		{
			"simple alphanumeric token",
			"sent tat_us_abc123XYZ done",
			"abc123XYZ",
		},
		{
			"urlsafe_base64 token with _ (B2 regression)",
			"sent tat_us_LX3c5_Fik5jV2OQbCxYnXBe9 done",
			"Fik5jV2OQbCxYnXBe9",
		},
		{
			"urlsafe_base64 token with - (B2 regression)",
			"sent tat_us_LX3c5-Fik5jV-OQbCxYnXBe9 done",
			"Fik5jV-OQbCxYnXBe9",
		},
		{
			"two tokens in one string",
			"first tat_us_AAAA and tat_eu_BBBB",
			"BBBB",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := RedactToken(tt.in)
			if strings.Contains(out, tt.bad) {
				t.Errorf("token suffix %q leaked into redacted output: %q", tt.bad, out)
			}
			if !strings.Contains(out, "tat_<redacted>") {
				t.Errorf("redaction marker missing in: %q", out)
			}
		})
	}
}

func TestSafeURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://user:pass@example.com/path", "https://<redacted>@example.com/path"},
		{"https://example.com/path", "https://example.com/path"},
		{"no-userinfo-no-scheme@nothing", "no-userinfo-no-scheme@nothing"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := SafeURL(tt.in); got != tt.want {
				t.Errorf("SafeURL(%q) = %q; want %q", tt.in, got, tt.want)
			}
		})
	}
}
