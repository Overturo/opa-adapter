// discovery-document fetch.
package overturo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Endpoints struct {
	Attestation string
	Heartbeat   string
	Escalation  string
	Revocation  string
}

type Discovery struct {
	Endpoints                  Endpoints
	SupportedDecisions         []string
	SupportedLegalBases        []string
	SupportedOAPVersions       []string
	SupportedRevocationScopes  []string
	SupportedRevocationReasons []string
}

type discoveryDoc struct {
	OAPProtocolVersionsSupported          []string `json:"oap_protocol_versions_supported"`
	OversightAttestationEndpoint          string   `json:"oversight_attestation_endpoint"`
	OversightAttestationHeartbeatEndpoint string   `json:"oversight_attestation_heartbeat_endpoint"`
	OversightEscalationEndpoint           string   `json:"oversight_escalation_endpoint"`
	OversightRevocationEndpoint           string   `json:"oversight_revocation_endpoint"`
	OversightAttestationDecisions         []string `json:"oversight_attestation_decisions_supported"`
	OversightAttestationLegalBases        []string `json:"oversight_attestation_legal_bases_supported"`
	OversightRevocationScopes             []string `json:"oversight_revocation_scopes_supported"`
	OversightRevocationReasons            []string `json:"oversight_revocation_reasons_supported"`
}

// FetchDiscovery reads `/.well-known/openid-configuration` and
// validates `oap_protocol_versions_supported`.
func FetchDiscovery(ctx context.Context, baseURL, requiredOAPVersion string, httpClient *http.Client) (*Discovery, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	url := strings.TrimRight(baseURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return nil, fmt.Errorf("discovery fetch %s: HTTP %d: %s", url, resp.StatusCode, body)
	}

	var doc discoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode discovery %s: %w", url, err)
	}

	if !contains(doc.OAPProtocolVersionsSupported, requiredOAPVersion) {
		return nil, fmt.Errorf(
			"server does NOT support OAP version %s; advertised: %v",
			requiredOAPVersion, doc.OAPProtocolVersionsSupported,
		)
	}

	if doc.OversightAttestationEndpoint == "" {
		return nil, fmt.Errorf("discovery missing required field: oversight_attestation_endpoint")
	}
	if doc.OversightAttestationHeartbeatEndpoint == "" {
		return nil, fmt.Errorf("discovery missing required field: oversight_attestation_heartbeat_endpoint")
	}

	return &Discovery{
		Endpoints: Endpoints{
			Attestation: doc.OversightAttestationEndpoint,
			Heartbeat:   doc.OversightAttestationHeartbeatEndpoint,
			Escalation:  doc.OversightEscalationEndpoint,
			Revocation:  doc.OversightRevocationEndpoint,
		},
		SupportedDecisions:         defaultDecisions(doc.OversightAttestationDecisions),
		SupportedLegalBases:        defaultLegalBases(doc.OversightAttestationLegalBases),
		SupportedOAPVersions:       doc.OAPProtocolVersionsSupported,
		SupportedRevocationScopes:  doc.OversightRevocationScopes,
		SupportedRevocationReasons: doc.OversightRevocationReasons,
	}, nil
}

func defaultDecisions(advertised []string) []string {
	if len(advertised) > 0 {
		return advertised
	}
	return []string{"allow", "deny", "escalate"}
}

func defaultLegalBases(advertised []string) []string {
	if len(advertised) > 0 {
		return advertised
	}
	return []string{
		"consent", "contract", "legal_obligation",
		"vital_interests", "public_task", "legitimate_interests",
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
