package opa

import (
	"reflect"
	"testing"
)

func TestDecideDecision(t *testing.T) {
	tests := []struct {
		name   string
		result map[string]any
		want   string
	}{
		{"escalate wins over allow", map[string]any{"allow": true, "escalate": true}, "escalate"},
		{"explicit allow", map[string]any{"allow": true}, "allow"},
		{"explicit deny", map[string]any{"allow": false}, "deny"},
		{"missing keys default to deny", map[string]any{}, "deny"},
		{"nil result", nil, "deny"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := DecisionLog{Result: tt.result}
			if got := d.DecideDecision(); got != tt.want {
				t.Errorf("DecideDecision() = %q; want %q", got, tt.want)
			}
		})
	}
}

func TestPathSegments(t *testing.T) {
	tests := []struct {
		name string
		path string
		want []string
	}{
		{"dotted", "authz.allow", []string{"authz", "allow"}},
		{"slashed", "authz/allow", []string{"authz", "allow"}},
		{"single segment", "allow", []string{"allow"}},
		{"empty", "", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := DecisionLog{Path: tt.path}
			got := d.PathSegments()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PathSegments() = %v; want %v", got, tt.want)
			}
		})
	}
}
