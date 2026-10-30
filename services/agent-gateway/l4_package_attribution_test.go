package gateway

import (
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// 四层事实上的套餐必须等于授权快照给这个（转发, 配置版本）绑定的套餐；
// 无套餐的转发必须为空。节点不能自报别的套餐。
func TestL4TelemetryPackageMustMatchTheAuthorizationBinding(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 10, 0, time.UTC)
	const bound = "66666666-6666-4666-8666-666666666666"
	validate := func(bindingSubscription, eventSubscription string) error {
		eventID := "l4evt_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		event := &agentv1.L4SessionEventV1{
			Event:    &commonv1.EventMetadata{EventId: eventID, OccurredTime: timestamppb.New(now)},
			TenantId: testTelemetryTenantID, SiteId: testTelemetrySiteID, NodeId: testNodeID,
			StreamId: testTelemetrySiteID, ListenerId: testTelemetrySiteID,
			ConfigVersionId: testTelemetryConfigVersionID, ConfigRevision: 9, Protocol: "tcp", ListenPort: 18080,
			SessionId: "43", StartedAt: timestamppb.New(now.Add(-time.Second)), FinalizedAt: timestamppb.New(now),
			StatusCode: 200, CanonicalEventSha256: bytesOf(1), EvidenceSha256: bytesOf(2), PackageSubscriptionId: eventSubscription,
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
		key := telemetryScopeKey{siteID: testTelemetrySiteID, configVersionID: testTelemetryConfigVersionID}
		authorization := telemetryAuthorization{installationID: "installation-1", tenantID: testTelemetryTenantID,
			configBySite:       map[telemetryScopeKey]string{key: testTelemetryTenantID},
			subscriptionBySite: map[telemetryScopeKey]string{key: bindingSubscription}}
		_, err = validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, authorization, DefaultTelemetryConfig(), now)
		return err
	}
	if err := validate(bound, bound); err != nil {
		t.Fatalf("bound package refused: %v", err)
	}
	if err := validate("", ""); err != nil {
		t.Fatalf("forward without a package refused: %v", err)
	}
	for name, pair := range map[string][2]string{
		"another package":       {bound, "77777777-7777-4777-8777-777777777777"},
		"missing package":       {bound, ""},
		"package on unpackaged": {"", bound},
	} {
		if err := validate(pair[0], pair[1]); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}
