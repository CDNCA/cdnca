package gateway

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// FX60 access records carry "blocked":true for block pages the node answered
// (WAF / CC). The strict gateway decode refused the whole batch for the
// unknown field; it must accept it and keep it through the authority binding.
func TestTelemetryAccessAcceptsAndKeepsBlocked(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	payload := fmt.Sprintf(`{"schema_version":1,"type":"access.v1","message_id":"m1","produced_at":%q,"tenant_id":%q,"node_id":%q,"events":[{"metric_version":1,"event_id":"e1","occurred_at":%q,"tenant_id":%q,"site_id":%q,"node_id":%q,"config_version_id":%q,"host":"a.test","path":"/","client_ip":"192.0.2.1","method":"GET","protocol":"HTTP/1.1","cache_status":"MISS","status_code":403,"request_bytes":1,"response_bytes":1,"duration_us":1,"blocked":true}]}`,
		now.Format(time.RFC3339), testTelemetryTenantID, testNodeID, now.Format(time.RFC3339), testTelemetryTenantID, testTelemetrySiteID,
		testNodeID, testTelemetryConfigVersionID)
	record := &agentv1.TelemetryRecord{Kind: agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_V1, MessageId: "m1", FirstSequence: 1,
		LastSequence: 1, EventCount: 1, LastEventId: "e1", Payload: []byte(payload)}
	key := telemetryScopeKey{siteID: testTelemetrySiteID, configVersionID: testTelemetryConfigVersionID}
	authority := telemetryAuthorization{tenantID: testTelemetryTenantID, installationID: testConnectionsInstallationID,
		configBySite: map[telemetryScopeKey]string{key: testTelemetryTenantID}, subscriptionBySite: map[telemetryScopeKey]string{key: ""}}
	if _, _, _, err := validateTelemetryPayload(record, testNodeID, authority, now); err != nil {
		t.Fatalf("blocked access record refused: %v", err)
	}
	if err := bindTelemetryPackageSubscription(record, "", authority.installationID); err != nil {
		t.Fatal(err)
	}
	var bound struct {
		Events []struct {
			Blocked bool `json:"blocked"`
		} `json:"events"`
	}
	if err := json.Unmarshal(record.Payload, &bound); err != nil || len(bound.Events) != 1 || !bound.Events[0].Blocked {
		t.Fatalf("blocked lost in binding: %s", record.Payload)
	}
}
