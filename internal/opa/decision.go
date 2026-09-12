// Package opa models OPA decision-log records + provides consumer
// implementations (HTTP receive + file tail).
//
// Decision-log format reference (OPA ≥ 0.50):
//
//	https://www.openpolicyagent.org/docs/latest/management-decision-logs/
package opa

import (
	"time"
)

// DecisionLog is the subset of OPA's decision-log record the
// adapter consumes. Unknown fields parse harmlessly and are
// available via the Raw map for mapping templates.
type DecisionLog struct {
	// `path` is the rule path (e.g., "authz/allow").
	Path string `json:"path"`

	// `input` is the policy input document.
	Input map[string]any `json:"input"`

	// `result` is the policy result. Conventionally contains
	// `allow` (bool) and may contain `escalate` (bool).
	Result map[string]any `json:"result"`

	// `decision_id` is OPA's UUID for the decision.
	DecisionID string `json:"decision_id"`

	// `timestamp` is when OPA evaluated the policy.
	Timestamp time.Time `json:"timestamp"`

	// Bundle revision information (when OPA's bundles feature is on).
	Bundles map[string]BundleRevision `json:"bundles,omitempty"`

	// Raw captures the full unstructured JSON for template mapping.
	Raw map[string]any `json:"-"`
}

// BundleRevision captures OPA's bundle versioning info.
type BundleRevision struct {
	Revision string `json:"revision,omitempty"`
}

// DecideDecision returns the OAP-side `decision` value for the
// record. Conventional mapping:
//
//	result.escalate == true  → "escalate"
//	result.allow    == true  → "allow"
//	otherwise                → "deny"
func (d *DecisionLog) DecideDecision() string {
	if d.Result == nil {
		return "deny"
	}
	if escalate, ok := d.Result["escalate"].(bool); ok && escalate {
		return "escalate"
	}
	if allow, ok := d.Result["allow"].(bool); ok && allow {
		return "allow"
	}
	return "deny"
}

// PathSegments returns the dotted path as a slice for template use:
// `{{ index .path (sub (len .path) 1) }}` extracts the last segment.
func (d *DecisionLog) PathSegments() []string {
	if d.Path == "" {
		return nil
	}
	out := []string{}
	current := ""
	for _, c := range d.Path {
		if c == '.' || c == '/' {
			if current != "" {
				out = append(out, current)
				current = ""
			}
			continue
		}
		current += string(c)
	}
	if current != "" {
		out = append(out, current)
	}
	return out
}
