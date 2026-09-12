// Package config loads + validates the YAML configuration for the
// overturo-opa-adapter.
//
// Env-var interpolation: any `${VAR_NAME}` in a string field is
// substituted with the corresponding environment variable at load
// time. Missing env vars produce an empty string (NOT an error) so
// optional fields (e.g., touchpoint_id when seeded via env) behave
// intuitively; required-field validation runs after substitution.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Overturo      OverturoConfig      `yaml:"overturo"`
	OPA           OPAConfig           `yaml:"opa"`
	Mapping       MappingConfig       `yaml:"mapping"`
	Observability ObservabilityConfig `yaml:"observability"`
}

type OverturoConfig struct {
	BaseURL                 string `yaml:"base_url"`
	Token                   string `yaml:"token"`
	TokenEnv                string `yaml:"token_env"`
	TouchpointID            string `yaml:"touchpoint_id"`
	HeartbeatCadenceSeconds int    `yaml:"heartbeat_cadence_seconds"`
	MaxRetries              int    `yaml:"max_retries"`
	TimeoutSeconds          int    `yaml:"timeout_seconds"`
	StateFile               string `yaml:"state_file"`
	RequiredOAPVersion      string `yaml:"required_oap_version"`
}

type OPAConfig struct {
	// "http" or "file"
	Mode       string `yaml:"mode"`
	HTTPListen string `yaml:"http_listen"`
	FilePath   string `yaml:"file_path"`
}

type MappingConfig struct {
	AgentClass    string `yaml:"agent_class"`
	ActionClass   string `yaml:"action_class"`
	LegalBasis    string `yaml:"legal_basis"`
	PolicyRef     string `yaml:"policy_ref"`
	PolicyVersion string `yaml:"policy_version"`
}

type ObservabilityConfig struct {
	LogLevel      string `yaml:"log_level"`
	MetricsListen string `yaml:"metrics_listen"`
}

// Load reads + parses + interpolates + validates the config file.
func Load(path string) (*Config, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	interpolated := interpolateEnv(string(bytes))

	var cfg Config
	if err := yaml.Unmarshal([]byte(interpolated), &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	applyDefaults(&cfg)

	if cfg.Overturo.TokenEnv != "" && cfg.Overturo.Token == "" {
		cfg.Overturo.Token = os.Getenv(cfg.Overturo.TokenEnv)
	}

	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return &cfg, nil
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func interpolateEnv(s string) string {
	return envRef.ReplaceAllStringFunc(s, func(match string) string {
		name := match[2 : len(match)-1]
		return os.Getenv(name)
	})
}

func applyDefaults(cfg *Config) {
	if cfg.Overturo.HeartbeatCadenceSeconds == 0 {
		cfg.Overturo.HeartbeatCadenceSeconds = 60
	}
	if cfg.Overturo.MaxRetries == 0 {
		cfg.Overturo.MaxRetries = 3
	}
	if cfg.Overturo.TimeoutSeconds == 0 {
		cfg.Overturo.TimeoutSeconds = 30
	}
	if cfg.Overturo.RequiredOAPVersion == "" {
		cfg.Overturo.RequiredOAPVersion = "1.0"
	}
	if cfg.OPA.Mode == "" {
		cfg.OPA.Mode = "http"
	}
	if cfg.OPA.Mode == "http" && cfg.OPA.HTTPListen == "" {
		cfg.OPA.HTTPListen = ":8181"
	}
	if cfg.Observability.LogLevel == "" {
		cfg.Observability.LogLevel = "info"
	}
	if cfg.Mapping.LegalBasis == "" {
		cfg.Mapping.LegalBasis = "legitimate_interests"
	}
}

func validate(cfg *Config) error {
	var errs []string

	if cfg.Overturo.BaseURL == "" {
		errs = append(errs, "overturo.base_url is required")
	} else if !strings.HasPrefix(cfg.Overturo.BaseURL, "http") {
		errs = append(errs, "overturo.base_url must start with http(s)://")
	}
	if cfg.Overturo.Token == "" {
		errs = append(errs, "overturo.token (or token_env-resolved value) is required")
	}
	if cfg.Overturo.TouchpointID == "" {
		errs = append(errs, "overturo.touchpoint_id is required")
	}
	if cfg.Overturo.HeartbeatCadenceSeconds < 10 {
		errs = append(errs, "overturo.heartbeat_cadence_seconds must be >= 10")
	}

	switch cfg.OPA.Mode {
	case "http":
		if cfg.OPA.HTTPListen == "" {
			errs = append(errs, "opa.http_listen required when opa.mode=http")
		}
	case "file":
		if cfg.OPA.FilePath == "" {
			errs = append(errs, "opa.file_path required when opa.mode=file")
		}
	default:
		errs = append(errs, fmt.Sprintf("opa.mode must be one of: http, file (got %q)", cfg.OPA.Mode))
	}

	if cfg.Mapping.AgentClass == "" {
		errs = append(errs, "mapping.agent_class is required (Go text/template)")
	}
	if cfg.Mapping.ActionClass == "" {
		errs = append(errs, "mapping.action_class is required (Go text/template)")
	}

	allowedLevels := map[string]bool{"trace": true, "debug": true, "info": true, "warn": true, "error": true}
	if !allowedLevels[cfg.Observability.LogLevel] {
		errs = append(errs, fmt.Sprintf("observability.log_level must be trace/debug/info/warn/error (got %q)", cfg.Observability.LogLevel))
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}
