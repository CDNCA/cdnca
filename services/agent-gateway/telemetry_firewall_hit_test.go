package gateway

import (
	"testing"
	"time"
)

// testTelemetryScopeID is a configuration scope (access_scopes.id): the
// tenant the global firewall command names. It differs from the tenant
// (tenants.id) the node authorization carries.
const testTelemetryScopeID = "018f47a2-5b9c-7d31-8a60-104c9c0b7190"

// A global firewall hit as the Agent publishes it (security.v2, network
// class; agents/edge-agent firewall/hitlog.go and telemetry_sources.go
// bindFirewallHits) is accepted only under the site's tenant and published
// config version. The scope ID and the firewall runtime version the command
// carries are rejected, and a rejection fails the whole batch.
func TestTelemetryAcceptsGlobalFirewallHitOnlyUnderTheSitesTelemetryIdentity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	firewallHit := func(tenantID, configVersionID string) func(map[string]any, map[string]any) {
		return func(envelope, event map[string]any) {
			envelope["tenant_id"] = tenantID
			event["tenant_id"], event["config_version_id"] = tenantID, configVersionID
			event["host"], event["path"], event["method"] = "-", "/", "NETWORK"
			event["listen_port"], event["destination_port"], event["protocol"] = 443, 443, "tcp"
			event["request_class"], event["event_type"], event["action"], event["severity"] = "network", "global_firewall", "block", "medium"
			event["rule_id"] = "018f47a2-5b9c-7d31-8a60-104c9c0b7191"
			for _, key := range []string{"status_code", "request_headers", "response_headers", "request_body", "response_body",
				"origin_connect_us", "origin_first_byte_us", "origin_total_us"} {
				delete(event, key)
			}
		}
	}
	tests := []struct {
		name, tenantID, configVersionID string
		accepted                        bool
	}{
		{"site telemetry identity", testTelemetryTenantID, testTelemetryConfigVersionID, true},
		{"command scope as tenant", testTelemetryScopeID, testTelemetryConfigVersionID, false},
		{"firewall runtime version", testTelemetryTenantID, "runtime-018f47a2-5b9c-7d31-8a60-104c9c0b7192", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batch := telemetryV2Batch(t, telemetryKindSecurityV2, now)
			mutateTelemetryV2Payload(t, batch.Records[0], firewallHit(test.tenantID, test.configVersionID))
			batch.BatchId = telemetryBatchID(batch.Records)
			_, err := validateTelemetryBatch(
				batch, 1, nodeIdentity{NodeID: testNodeID}, telemetryTestAuthorization(), DefaultTelemetryConfig(), now,
			)
			if test.accepted && err != nil {
				t.Fatalf("global firewall hit rejected: %v; payload=%s", err, batch.Records[0].Payload)
			}
			if !test.accepted && err == nil {
				t.Fatalf("global firewall hit accepted: %s", batch.Records[0].Payload)
			}
		})
	}
}
