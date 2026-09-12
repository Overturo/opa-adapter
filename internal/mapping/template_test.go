package mapping

import (
	"testing"

	"github.com/overturo/opa-adapter/internal/opa"
)

func TestCompileHappyPath(t *testing.T) {
	m, err := Compile(
		`{{ if .input.agent_class }}{{ .input.agent_class }}{{ else }}default_agent{{ end }}`,
		`{{ index .path (sub (len .path) 1) }}`,
		"consent",
		`opa://{{ .path_string }}`,
		`{{ range $k, $v := .bundles }}{{ $v.Revision }}{{ end }}`,
	)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if m.LegalBasis != "consent" {
		t.Errorf("legal_basis: %s", m.LegalBasis)
	}
}

func TestApplyExtractsFields(t *testing.T) {
	m, err := Compile(
		`{{ .input.agent_class }}`,
		`{{ .input.action }}`,
		"legitimate_interests",
		"",
		"",
	)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	decision := opa.DecisionLog{
		Path: "authz/allow",
		Input: map[string]any{
			"agent_class": "data_export_agent",
			"action":      "tool_call",
		},
		Result:     map[string]any{"allow": true},
		DecisionID: "uuid-1",
		Bundles: map[string]opa.BundleRevision{
			"data": {Revision: "rev-123"},
		},
	}

	payload, err := m.Apply(decision)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if payload.AgentClass != "data_export_agent" {
		t.Errorf("agent_class: %q", payload.AgentClass)
	}
	if payload.ActionClass != "tool_call" {
		t.Errorf("action_class: %q", payload.ActionClass)
	}
	if payload.Decision != "allow" {
		t.Errorf("decision: %q", payload.Decision)
	}
	if payload.LegalBasis != "legitimate_interests" {
		t.Errorf("legal_basis: %q", payload.LegalBasis)
	}
	if len(payload.EvidenceDigest) != 64 {
		t.Errorf("evidence_digest length: %d", len(payload.EvidenceDigest))
	}
	if payload.Context["policy_ref"] != "opa://authz/allow" {
		t.Errorf("default policy_ref: %v", payload.Context["policy_ref"])
	}
	if payload.Context["policy_version"] != "rev-123" {
		t.Errorf("default policy_version (bundle revision): %v", payload.Context["policy_version"])
	}
	if payload.Context["decision_id"] != "uuid-1" {
		t.Errorf("decision_id: %v", payload.Context["decision_id"])
	}
}

func TestApplyEscalateDecision(t *testing.T) {
	m, _ := Compile("agent", "action", "consent", "", "")
	decision := opa.DecisionLog{
		Result: map[string]any{"escalate": true},
		Input:  map[string]any{"x": 1},
	}
	payload, err := m.Apply(decision)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if payload.Decision != "escalate" {
		t.Errorf("decision: %q; want escalate", payload.Decision)
	}
}

func TestApplyDeniedDecision(t *testing.T) {
	m, _ := Compile("agent", "action", "consent", "", "")
	decision := opa.DecisionLog{
		Result: map[string]any{"allow": false},
		Input:  map[string]any{},
	}
	payload, err := m.Apply(decision)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if payload.Decision != "deny" {
		t.Errorf("decision: %q; want deny", payload.Decision)
	}
}

func TestCompileInvalidTemplate(t *testing.T) {
	_, err := Compile("{{ unclosed", "x", "consent", "", "")
	if err == nil {
		t.Fatal("expected parse error")
	}
}
