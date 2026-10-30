package gateway

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type l4JetStreamStub struct {
	message *nats.Msg
}

func (stub *l4JetStreamStub) PublishMsg(message *nats.Msg, _ ...nats.PubOpt) (*nats.PubAck, error) {
	stub.message = nats.NewMsg(message.Subject)
	stub.message.Data = append([]byte(nil), message.Data...)
	stub.message.Header = make(nats.Header, len(message.Header))
	for key, values := range message.Header {
		stub.message.Header[key] = append([]string(nil), values...)
	}
	return &nats.PubAck{Stream: L4TelemetryIngestStream, Sequence: 7}, nil
}

func (*l4JetStreamStub) StreamInfo(string, ...nats.JSOpt) (*nats.StreamInfo, error) { return nil, nil }

func TestL4TelemetryValidationAndDedicatedNATSPublication(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 10, 0, time.UTC)
	eventID := "l4evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	event := &agentv1.L4SessionEventV1{
		Event: &commonv1.EventMetadata{EventId: eventID, OccurredTime: timestamppb.New(now),
			Traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},
		TenantId: testTelemetryTenantID, SiteId: testTelemetrySiteID, NodeId: testNodeID,
		StreamId: "018f47a2-5b9c-7d31-8a60-104c9c0b7190", ListenerId: "018f47a2-5b9c-7d31-8a60-104c9c0b7190",
		ConfigVersionId: testTelemetryConfigVersionID, ConfigRevision: 9, Protocol: "tcp", ListenPort: 18080,
		SessionId: "42", StartedAt: timestamppb.New(now.Add(-5 * time.Second)), FinalizedAt: timestamppb.New(now),
		BytesUp: 300, BytesDown: 1200, StatusCode: 200, CanonicalEventSha256: bytesOf(1), EvidenceSha256: bytesOf(2),
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
	record := &agentv1.TelemetryRecord{
		Kind: agentv1.TelemetryKind_TELEMETRY_KIND_L4_SESSION_V1, MessageId: envelope.MessageId,
		FirstSequence: 1, LastSequence: 1, LastEventId: eventID, EventCount: 1, Payload: payload,
	}
	batch := &agentv1.TelemetryBatch{FirstSequence: 1, LastSequence: 1, Records: []*agentv1.TelemetryRecord{record}}
	batch.BatchId = telemetryBatchID(batch.Records)
	authorization := telemetryAuthorization{
		installationID: "installation-1", tenantID: testTelemetryTenantID,
		configBySite:       map[telemetryScopeKey]string{{siteID: testTelemetrySiteID, configVersionID: testTelemetryConfigVersionID}: testTelemetryTenantID},
		subscriptionBySite: map[telemetryScopeKey]string{},
	}
	validated, err := validateTelemetryBatch(batch, 1, nodeIdentity{NodeID: testNodeID}, authorization, DefaultTelemetryConfig(), now)
	if err != nil || len(validated) != 1 {
		t.Fatalf("validate L4 batch = %#v, error=%v", validated, err)
	}

	stub := &l4JetStreamStub{}
	config := DefaultNATSTelemetryPublisherConfig()
	publisher := &NATSTelemetryPublisher{l4JS: stub, config: config}
	result, err := publisher.Publish(context.Background(), TelemetryPublication{
		Kind:   agentv1.TelemetryKind_TELEMETRY_KIND_L4_SESSION_V1,
		NodeID: testNodeID, TenantID: testTelemetryTenantID, SiteID: testTelemetrySiteID,
		ConfigVersionID: testTelemetryConfigVersionID, InstallationID: authorization.installationID,
		MessageID: envelope.MessageId, Payload: payload,
	})
	if err != nil || result.Stream != config.L4Stream || result.Sequence != 7 {
		t.Fatalf("publish L4 = %#v, error=%v", result, err)
	}
	if stub.message == nil || stub.message.Subject != L4TelemetrySubjectPrefix+"."+testTelemetryTenantID+"."+testTelemetrySiteID+"."+testNodeID ||
		string(stub.message.Data) != string(payload) || stub.message.Header.Get(nats.MsgIdHdr) != envelope.MessageId {
		t.Fatalf("L4 NATS message = %#v", stub.message)
	}
}

func bytesOf(value byte) []byte {
	result := make([]byte, 32)
	for index := range result {
		result[index] = value
	}
	return result
}
