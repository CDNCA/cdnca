package gateway

import (
	"encoding/json"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"strings"
	"testing"
	"time"
)

func TestAccessWindowGatewayBindsAuthenticatedInstallationAndRejectsDrift(t *testing.T) {
	end := time.Now().UTC().Truncate(time.Hour)
	event := edgeconfig.AccessWindowEvent{MetricVersion: 1, WindowStart: end.Add(-time.Hour), WindowEnd: end, FinalizedThrough: end,
		TenantID: testTelemetryTenantID, NodeID: testNodeID, SiteID: testTelemetrySiteID, ConfigVersionID: testTelemetryConfigVersionID,
		Host: "example.test", ListenPort: 443, SourceWatermark: 12, DependencyState: "ready", EvidenceSHA256: strings.Repeat("ab", 32)}
	event.EventID = edgeconfig.AccessWindowEventID(event)
	envelope := edgeconfig.AccessWindowEnvelope{SchemaVersion: 1, Type: edgeconfig.AccessWindowType, TenantID: event.TenantID, NodeID: event.NodeID, ProducedAt: end, Events: []edgeconfig.AccessWindowEvent{event}}
	envelope.MessageID = edgeconfig.AccessWindowMessageID(envelope)
	payload, _ := json.Marshal(envelope)
	record := &agentv1.TelemetryRecord{Kind: agentv1.TelemetryKind_TELEMETRY_KIND_ACCESS_WINDOW_V1, MessageId: envelope.MessageID, FirstSequence: 1, LastSequence: 1, EventCount: 1, LastEventId: event.EventID, Payload: payload}
	key := telemetryScopeKey{siteID: event.SiteID, configVersionID: event.ConfigVersionID}
	authority := telemetryAuthorization{tenantID: event.TenantID, installationID: testConnectionsInstallationID, configBySite: map[telemetryScopeKey]string{key: event.TenantID}, subscriptionBySite: map[telemetryScopeKey]string{key: ""}}
	if _, _, _, err := validateTelemetryPayload(record, testNodeID, authority, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := bindTelemetryPackageSubscription(record, "", authority.installationID); err != nil {
		t.Fatal(err)
	}
	var bound edgeconfig.AccessWindowEnvelope
	if err := json.Unmarshal(record.Payload, &bound); err != nil {
		t.Fatal(err)
	}
	if bound.InstallationID != authority.installationID || bound.Events[0].InstallationID != authority.installationID || edgeconfig.AccessWindowMessageID(bound) != envelope.MessageID {
		t.Fatal("authority binding changed identity")
	}
	if _, _, _, err := validateTelemetryPayload(record, testNodeID, authority, time.Now()); err == nil {
		t.Fatal("Agent-supplied installation identity accepted")
	}
}
