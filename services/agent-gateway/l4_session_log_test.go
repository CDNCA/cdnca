package gateway

import (
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// An L4 event's session_log (tcp/udp v7) is accepted when well formed and
// refuses the batch otherwise.
func TestL4TelemetryValidatesTheSessionLog(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 10, 0, time.UTC)
	connect := uint32(12)
	validate := func(log *agentv1.L4SessionLogV1) error {
		eventID := "l4evt_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		event := &agentv1.L4SessionEventV1{
			Event:    &commonv1.EventMetadata{EventId: eventID, OccurredTime: timestamppb.New(now)},
			TenantId: testTelemetryTenantID, SiteId: testTelemetrySiteID, NodeId: testNodeID,
			StreamId: "018f47a2-5b9c-7d31-8a60-104c9c0b7190", ListenerId: "018f47a2-5b9c-7d31-8a60-104c9c0b7190",
			ConfigVersionId: testTelemetryConfigVersionID, ConfigRevision: 9, Protocol: "tcp", ListenPort: 18080,
			SessionId: "42", StartedAt: timestamppb.New(now.Add(-time.Second)), FinalizedAt: timestamppb.New(now),
			StatusCode: 200, CanonicalEventSha256: bytesOf(1), EvidenceSha256: bytesOf(2), SessionLog: log,
		}
		envelope := &agentv1.L4SessionEnvelopeV1{
			SchemaVersion: 1, ProducedAt: timestamppb.New(now), TenantId: testTelemetryTenantID,
			NodeId: testNodeID, SiteId: testTelemetrySiteID, ConfigVersionId: testTelemetryConfigVersionID,
			SourceWatermark: 1, FinalizedThrough: timestamppb.New(now), EvidenceSha256: bytesOf(3), Events: []*agentv1.L4SessionEventV1{event},
		}
		envelope.MessageId = l4TelemetryMessageID(envelope)
		payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		record := &agentv1.TelemetryRecord{Kind: agentv1.TelemetryKind_TELEMETRY_KIND_L4_SESSION_V1, MessageId: envelope.MessageId,
			FirstSequence: 1, LastSequence: 1, LastEventId: eventID, EventCount: 1, Payload: payload}
		batch := &agentv1.TelemetryBatch{FirstSequence: 1, LastSequence: 1, Records: []*agentv1.TelemetryRecord{record}}
		batch.BatchId = telemetryBatchID(batch.Records)
		authorization := telemetryAuthorization{installationID: "installation-1", tenantID: testTelemetryTenantID,
			configBySite:       map[telemetryScopeKey]string{{siteID: testTelemetrySiteID, configVersionID: testTelemetryConfigVersionID}: testTelemetryTenantID},
			subscriptionBySite: map[telemetryScopeKey]string{}}
		_, err = validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, authorization, DefaultTelemetryConfig(), now)
		return err
	}
	for name, log := range map[string]*agentv1.L4SessionLogV1{
		"none":  nil,
		"plain": {ClientIp: "198.51.100.7", ClientPort: 40001, UpstreamAddr: "10.0.0.9:443", UpstreamConnectMs: &connect, EndReason: "closed"},
		"proxy": {ClientIp: "2001:db8::5", ClientPort: 1, PeerIp: "192.0.2.9", EndReason: "rate_limited"},
		"guard": {ClientIp: "198.51.100.8", ClientPort: 2, EndReason: "guard_blocked"},
	} {
		if err := validate(log); err != nil {
			t.Fatalf("%s refused: %v", name, err)
		}
	}
	for name, log := range map[string]*agentv1.L4SessionLogV1{
		"bad client":    {ClientIp: "nope", EndReason: "closed"},
		"bad reason":    {ClientIp: "198.51.100.7", EndReason: "whatever"},
		"peer = client": {ClientIp: "198.51.100.7", PeerIp: "198.51.100.7", EndReason: "closed"},
		"bad upstream":  {ClientIp: "198.51.100.7", UpstreamAddr: "origin", EndReason: "closed"},
		"bad port":      {ClientIp: "198.51.100.7", ClientPort: 70000, EndReason: "closed"},
	} {
		if err := validate(log); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
