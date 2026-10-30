package gateway

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBuildCCCoordinationMessageFiltersAndBindsVerifiedAuthority(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	publication := TelemetryPublication{
		NodeID: "30000000-0000-4000-8000-000000000001", TenantID: "10000000-0000-4000-8000-000000000001",
		SiteID: "20000000-0000-4000-8000-000000000001", ConfigVersionID: "40000000-0000-4000-8000-000000000001",
		InstallationID: "installation-a", MessageID: "security-batch-1",
		Payload: []byte(`{"schema_version":1,"type":"security.v1","message_id":"security-batch-1","produced_at":"2026-08-07T10:00:00Z","tenant_id":"10000000-0000-4000-8000-000000000001","node_id":"30000000-0000-4000-8000-000000000001","events":[{"metric_version":1,"event_id":"cc-hit-1","occurred_at":"2026-08-07T09:59:59Z","tenant_id":"10000000-0000-4000-8000-000000000001","site_id":"20000000-0000-4000-8000-000000000001","node_id":"30000000-0000-4000-8000-000000000001","config_version_id":"40000000-0000-4000-8000-000000000001","host":"edge.example.test","path":"/login","client_ip":"198.51.100.8","method":"POST","listen_port":443,"protocol":"https","request_class":"standard","event_type":"cc","action":"block","severity":"high","rule_id":"50000000-0000-4000-8000-000000000001","status_code":429,"request_bytes":10,"response_bytes":20},{"metric_version":1,"event_id":"cc-acme-1","occurred_at":"2026-08-07T09:59:59Z","tenant_id":"10000000-0000-4000-8000-000000000001","site_id":"20000000-0000-4000-8000-000000000001","node_id":"30000000-0000-4000-8000-000000000001","config_version_id":"40000000-0000-4000-8000-000000000001","host":"edge.example.test","path":"/.well-known/acme-challenge/token","client_ip":"198.51.100.8","method":"GET","listen_port":80,"protocol":"http","request_class":"acme","event_type":"cc","action":"block","severity":"high","rule_id":"50000000-0000-4000-8000-000000000001","status_code":429,"request_bytes":10,"response_bytes":20},{"metric_version":1,"event_id":"waf-hit-1","occurred_at":"2026-08-07T09:59:59Z","tenant_id":"10000000-0000-4000-8000-000000000001","site_id":"20000000-0000-4000-8000-000000000001","node_id":"30000000-0000-4000-8000-000000000001","config_version_id":"40000000-0000-4000-8000-000000000001","host":"edge.example.test","path":"/login","client_ip":"198.51.100.9","method":"POST","listen_port":443,"protocol":"https","request_class":"standard","event_type":"waf","action":"block","severity":"high","rule_id":"60000000-0000-4000-8000-000000000001","status_code":403,"request_bytes":11,"response_bytes":21}]}`),
	}

	message, ok, err := buildCCCoordinationMessage(publication, now)
	if err != nil || !ok {
		t.Fatalf("buildCCCoordinationMessage() = (%v, %v)", ok, err)
	}
	if message.Subject != CCCoordinationSubjectPrefix+"."+publication.TenantID+"."+publication.SiteID ||
		message.Header.Get(telemetryNodeHeader) != publication.NodeID ||
		message.Header.Get(telemetryTenantHeader) != publication.TenantID ||
		message.Header.Get(telemetrySiteHeader) != publication.SiteID ||
		message.Header.Get(telemetryConfigHeader) != publication.ConfigVersionID ||
		message.Header.Get(telemetryInstallationHeader) != publication.InstallationID ||
		message.Header.Get("Nats-Msg-Id") != publication.MessageID {
		t.Fatalf("coordination message authority drifted: subject=%q headers=%v", message.Subject, message.Header)
	}
	var envelope ccCoordinationEnvelopeV1
	if err := json.Unmarshal(message.Data, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.SchemaVersion != 1 || envelope.Type != "security.cccoord.v1" ||
		envelope.MessageID != publication.MessageID || envelope.ProducedAt != now ||
		envelope.TenantID != publication.TenantID || envelope.SiteID != publication.SiteID ||
		envelope.NodeID != publication.NodeID || envelope.ConfigVersionID != publication.ConfigVersionID ||
		len(envelope.Events) != 1 || envelope.Events[0].EventID != "cc-hit-1" ||
		envelope.Events[0].ClientIP != "198.51.100.8" || envelope.Events[0].RuleID != "50000000-0000-4000-8000-000000000001" ||
		envelope.Events[0].Host != "edge.example.test" || envelope.Events[0].Path != "/login" ||
		envelope.Events[0].Method != "POST" || envelope.Events[0].ListenPort != 443 ||
		envelope.Events[0].Protocol != "https" || envelope.Events[0].RequestClass != "standard" {
		t.Fatalf("coordination envelope = %+v", envelope)
	}
	if !json.Valid(message.Data) {
		t.Fatalf("coordination bytes are not JSON: %s", message.Data)
	}
}

func TestBuildCCCoordinationMessageSkipsNonSecurityAndNonCC(t *testing.T) {
	publication := TelemetryPublication{
		NodeID: "30000000-0000-4000-8000-000000000001", TenantID: "10000000-0000-4000-8000-000000000001",
		SiteID: "20000000-0000-4000-8000-000000000001", ConfigVersionID: "40000000-0000-4000-8000-000000000001",
		InstallationID: "installation-a", MessageID: "access-batch-1",
		Payload: []byte(`{"schema_version":1,"type":"access.v1","message_id":"access-batch-1"}`),
	}
	if message, ok, err := buildCCCoordinationMessage(publication, time.Now().UTC()); err != nil || ok || message != nil {
		t.Fatalf("access payload produced coordination message: message=%v ok=%v err=%v", message, ok, err)
	}
	publication.MessageID = "security-batch-2"
	publication.Payload = []byte(`{"schema_version":1,"type":"security.v1","message_id":"security-batch-2","produced_at":"2026-08-07T10:00:00Z","tenant_id":"10000000-0000-4000-8000-000000000001","node_id":"30000000-0000-4000-8000-000000000001","events":[]}`)
	if message, ok, err := buildCCCoordinationMessage(publication, time.Now().UTC()); err != nil || ok || message != nil {
		t.Fatalf("empty security payload produced coordination message: message=%v ok=%v err=%v", message, ok, err)
	}
}
