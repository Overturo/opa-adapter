package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadHappyPath(t *testing.T) {
	cfg, err := Load(writeFile(t, `
overturo:
  base_url: https://api.overturo.us
  token: tat_dev_xxx
  touchpoint_id: tp_dev_yyy
opa:
  mode: http
  http_listen: :8181
mapping:
  agent_class: "data_export_agent"
  action_class: "tool_call"
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Overturo.BaseURL != "https://api.overturo.us" {
		t.Errorf("base_url: %s", cfg.Overturo.BaseURL)
	}
	if cfg.Overturo.HeartbeatCadenceSeconds != 60 {
		t.Errorf("default heartbeat cadence: %d", cfg.Overturo.HeartbeatCadenceSeconds)
	}
	if cfg.Overturo.RequiredOAPVersion != "1.0" {
		t.Errorf("default oap version: %s", cfg.Overturo.RequiredOAPVersion)
	}
}

func TestLoadInterpolatesEnvVars(t *testing.T) {
	t.Setenv("MY_TOUCHPOINT", "tp_dev_from_env")
	cfg, err := Load(writeFile(t, `
overturo:
  base_url: https://api.overturo.us
  token: tat_dev_xxx
  touchpoint_id: ${MY_TOUCHPOINT}
opa:
  mode: http
mapping:
  agent_class: x
  action_class: y
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Overturo.TouchpointID != "tp_dev_from_env" {
		t.Errorf("env interp: %s", cfg.Overturo.TouchpointID)
	}
}

func TestTokenEnvFallback(t *testing.T) {
	t.Setenv("MY_TOKEN_VAR", "tat_dev_from_env")
	cfg, err := Load(writeFile(t, `
overturo:
  base_url: https://api.overturo.us
  token_env: MY_TOKEN_VAR
  touchpoint_id: tp_dev_yyy
opa:
  mode: http
mapping:
  agent_class: x
  action_class: y
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Overturo.Token != "tat_dev_from_env" {
		t.Errorf("token_env: %s", cfg.Overturo.Token)
	}
}

func TestRejectsMissingRequiredFields(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantWord string
	}{
		{
			"missing base_url",
			`overturo: { token: t, touchpoint_id: tp }
opa: { mode: http }
mapping: { agent_class: x, action_class: y }`,
			"base_url",
		},
		{
			"missing touchpoint_id",
			`overturo: { base_url: https://x.test, token: t }
opa: { mode: http }
mapping: { agent_class: x, action_class: y }`,
			"touchpoint_id",
		},
		{
			"missing token",
			`overturo: { base_url: https://x.test, touchpoint_id: tp }
opa: { mode: http }
mapping: { agent_class: x, action_class: y }`,
			"token",
		},
		{
			"opa mode invalid",
			`overturo: { base_url: https://x.test, token: t, touchpoint_id: tp }
opa: { mode: rogue }
mapping: { agent_class: x, action_class: y }`,
			"opa.mode",
		},
		{
			"file mode missing path",
			`overturo: { base_url: https://x.test, token: t, touchpoint_id: tp }
opa: { mode: file }
mapping: { agent_class: x, action_class: y }`,
			"file_path",
		},
		{
			"missing mapping",
			`overturo: { base_url: https://x.test, token: t, touchpoint_id: tp }
opa: { mode: http }
mapping: { agent_class: x }`,
			"action_class",
		},
		{
			"invalid log_level",
			`overturo: { base_url: https://x.test, token: t, touchpoint_id: tp }
opa: { mode: http }
mapping: { agent_class: x, action_class: y }
observability: { log_level: noisy }`,
			"log_level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeFile(t, tt.yaml))
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantWord)
			}
			if !strings.Contains(err.Error(), tt.wantWord) {
				t.Errorf("expected error containing %q; got %v", tt.wantWord, err)
			}
		})
	}
}

func TestDefaultsApplyWhenAbsent(t *testing.T) {
	cfg, err := Load(writeFile(t, `
overturo:
  base_url: https://api.overturo.us
  token: tat_dev_xxx
  touchpoint_id: tp_dev_yyy
opa:
  mode: http
mapping:
  agent_class: x
  action_class: y
`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.OPA.HTTPListen != ":8181" {
		t.Errorf("default http_listen: %s", cfg.OPA.HTTPListen)
	}
	if cfg.Observability.LogLevel != "info" {
		t.Errorf("default log_level: %s", cfg.Observability.LogLevel)
	}
	if cfg.Mapping.LegalBasis != "legitimate_interests" {
		t.Errorf("default legal_basis: %s", cfg.Mapping.LegalBasis)
	}
}
