package gateway

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

const testMinuteSubscriptionID = "40000000-0000-4000-8000-000000000001"

func subscriptionMinuteRecord(t *testing.T, subscriptionID string) (*agentv1.TelemetryRecord, edgeconfig.SubscriptionMinuteEnvelope) {
	t.Helper()
	minute := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	event := edgeconfig.SubscriptionMinuteEvent{MetricVersion: 1, Minute: minute, TenantID: testTelemetryTenantID,
		SubscriptionID: subscriptionID, SiteID: testTelemetrySiteID, NodeID: testNodeID, ConfigVersionID: testTelemetryConfigVersionID,
		SubscriptionMinuteCounters: edgeconfig.SubscriptionMinuteCounters{MaxRequests: 4, MaxConnections: 2, MaxQPS: 9, BytesOut: 100, PeakBPS: 800}}
	event.EventID = edgeconfig.SubscriptionMinuteEventID(testNodeID, subscriptionID, minute)
	envelope := edgeconfig.SubscriptionMinuteEnvelope{SchemaVersion: 1, Type: edgeconfig.SubscriptionMinuteType, TenantID: event.TenantID,
		NodeID: event.NodeID, ProducedAt: minute, Events: []edgeconfig.SubscriptionMinuteEvent{event}}
	envelope.MessageID = edgeconfig.SubscriptionMinuteMessageID(envelope)
	payload, _ := json.Marshal(envelope)
	return &agentv1.TelemetryRecord{Kind: agentv1.TelemetryKind_TELEMETRY_KIND_SUBSCRIPTION_MINUTE_V1, MessageId: envelope.MessageID,
		FirstSequence: 1, LastSequence: 1, EventCount: 1, LastEventId: event.EventID, Payload: payload}, envelope
}

func TestSubscriptionMinuteGatewayChecksSubscriptionAndBinds(t *testing.T) {
	key := telemetryScopeKey{siteID: testTelemetrySiteID, configVersionID: testTelemetryConfigVersionID}
	authority := telemetryAuthorization{tenantID: testTelemetryTenantID, installationID: testConnectionsInstallationID,
		configBySite: map[telemetryScopeKey]string{key: testTelemetryTenantID}, subscriptionBySite: map[telemetryScopeKey]string{key: testMinuteSubscriptionID}}
	record, envelope := subscriptionMinuteRecord(t, testMinuteSubscriptionID)
	if _, siteID, _, err := validateTelemetryPayload(record, testNodeID, authority, time.Now()); err != nil || siteID != testTelemetrySiteID {
		t.Fatal(siteID, err)
	}
	if err := bindTelemetryPackageSubscription(record, testMinuteSubscriptionID, authority.installationID); err != nil {
		t.Fatal(err)
	}
	var bound edgeconfig.SubscriptionMinuteEnvelope
	if err := json.Unmarshal(record.Payload, &bound); err != nil {
		t.Fatal(err)
	}
	if bound.PackageSubscriptionID != testMinuteSubscriptionID || bound.Events[0].InstallationID != authority.installationID ||
		edgeconfig.SubscriptionMinuteMessageID(bound) != envelope.MessageID {
		t.Fatal("binding changed identity")
	}
	if _, _, _, err := validateTelemetryPayload(record, testNodeID, authority, time.Now()); err == nil {
		t.Fatal("bound (agent-supplied) installation accepted")
	}
	// A subscription the site is not sold under is refused.
	other, _ := subscriptionMinuteRecord(t, "40000000-0000-4000-8000-000000000002")
	if _, _, _, err := validateTelemetryPayload(other, testNodeID, authority, time.Now()); err == nil {
		t.Fatal("subscription of another site accepted")
	}
	// Binding never invents a subscription.
	record, _ = subscriptionMinuteRecord(t, testMinuteSubscriptionID)
	if err := bindTelemetryPackageSubscription(record, "", authority.installationID); err == nil {
		t.Fatal("unbound subscription accepted")
	}
}
