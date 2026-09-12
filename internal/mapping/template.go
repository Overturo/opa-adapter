// Package mapping translates OPA decision-log records into OAP
// attestation payloads via Go text/template expressions.
//
// Template context per record:
//
//	{{ .path }}          string
//	{{ .input.<x> }}     OPA policy input
//	{{ .result.<x> }}    OPA policy result
//	{{ .decision_id }}   OPA decision UUID
//	{{ .timestamp }}     time.Time as RFC3339Nano
//	{{ .bundles.<k>.revision }}  bundle revisions
//	{{ .raw.<x> }}       unstructured raw fields (forward-compat)
package mapping

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/overturo/opa-adapter/internal/opa"
	"github.com/overturo/opa-adapter/internal/overturo"
)

// Mapping captures the templated field expressions from config.
type Mapping struct {
	AgentClass    *template.Template
	ActionClass   *template.Template
	LegalBasis    string // not templated — closed-enum
	PolicyRef     *template.Template
	PolicyVersion *template.Template
}

// Compile parses the templated expressions from raw strings.
func Compile(agentClass, actionClass, legalBasis, policyRef, policyVersion string) (*Mapping, error) {
	if legalBasis == "" {
		legalBasis = "legitimate_interests"
	}
	agentTmpl, err := parseTemplate("agent_class", agentClass)
	if err != nil {
		return nil, err
	}
	actionTmpl, err := parseTemplate("action_class", actionClass)
	if err != nil {
		return nil, err
	}
	refTmpl, err := parseTemplate("policy_ref", policyRef)
	if err != nil {
		return nil, err
	}
	verTmpl, err := parseTemplate("policy_version", policyVersion)
	if err != nil {
		return nil, err
	}
	return &Mapping{
		AgentClass:    agentTmpl,
		ActionClass:   actionTmpl,
		LegalBasis:    legalBasis,
		PolicyRef:     refTmpl,
		PolicyVersion: verTmpl,
	}, nil
}

// Apply translates a decision-log record into an OAP attestation payload.
// Returns a partial payload — the caller is responsible for setting
// `SequenceNumber`, `TouchpointID`, and `AttestationID`.
func (m *Mapping) Apply(decision opa.DecisionLog) (overturo.AttestPayload, error) {
	agentClass, err := renderTemplate(m.AgentClass, decision)
	if err != nil {
		return overturo.AttestPayload{}, fmt.Errorf("render agent_class: %w", err)
	}
	actionClass, err := renderTemplate(m.ActionClass, decision)
	if err != nil {
		return overturo.AttestPayload{}, fmt.Errorf("render action_class: %w", err)
	}

	policyRef, _ := renderTemplate(m.PolicyRef, decision)
	policyVersion, _ := renderTemplate(m.PolicyVersion, decision)

	if policyVersion == "" {
		policyVersion = extractBundleRevision(decision)
	}
	if policyRef == "" {
		policyRef = "opa://" + decision.Path
	}

	digest, err := overturo.EvidenceDigest(decision.Input, decision.Result)
	if err != nil {
		return overturo.AttestPayload{}, fmt.Errorf("evidence_digest: %w", err)
	}

	context := map[string]any{
		"policy_ref":     policyRef,
		"policy_version": policyVersion,
		"decision_id":    decision.DecisionID,
		"path":           decision.Path,
		"input":          decision.Input,
		"result":         decision.Result,
	}
	if !decision.Timestamp.IsZero() {
		context["opa_timestamp"] = decision.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z07:00")
	}

	return overturo.AttestPayload{
		AgentClass:     agentClass,
		ActionClass:    actionClass,
		Decision:       decision.DecideDecision(),
		LegalBasis:     m.LegalBasis,
		EvidenceDigest: digest,
		Context:        context,
	}, nil
}

// ── internals ─────────────────────────────────────────────────────

func parseTemplate(name, expr string) (*template.Template, error) {
	if expr == "" {
		return nil, nil
	}
	tmpl, err := template.New(name).Funcs(funcMap()).Parse(expr)
	if err != nil {
		return nil, fmt.Errorf("parse template %s (%q): %w", name, expr, err)
	}
	return tmpl, nil
}

func renderTemplate(tmpl *template.Template, decision opa.DecisionLog) (string, error) {
	if tmpl == nil {
		return "", nil
	}
	var buf bytes.Buffer
	ctx := map[string]any{
		"path":        decision.PathSegments(),
		"path_string": decision.Path,
		"input":       decision.Input,
		"result":      decision.Result,
		"decision_id": decision.DecisionID,
		"timestamp":   decision.Timestamp,
		"bundles":     decision.Bundles,
		"raw":         decision.Raw,
	}
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

func extractBundleRevision(decision opa.DecisionLog) string {
	for _, b := range decision.Bundles {
		if b.Revision != "" {
			return b.Revision
		}
	}
	return ""
}

// funcMap exposes a small set of helpers to templates.
func funcMap() template.FuncMap {
	return template.FuncMap{
		"sub": func(a, b int) int { return a - b },
		"add": func(a, b int) int { return a + b },
		"len": func(v any) int {
			switch x := v.(type) {
			case []string:
				return len(x)
			case []any:
				return len(x)
			case string:
				return len(x)
			case map[string]any:
				return len(x)
			}
			return 0
		},
	}
}
