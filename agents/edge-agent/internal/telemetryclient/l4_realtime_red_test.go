package telemetryclient

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestL4PublicationUsesVersionedTelemetryKindWithoutJSONReencoding(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	envelope := &agentv1.L4SessionEnvelopeV1{
		SchemaVersion: 1,
		TenantId:      testTenantID, NodeId: testNodeID, SiteId: testSiteID,
		ConfigVersionId: "018f47a2-5b9c-7d31-8a60-104c9c0b7191", SourceWatermark: 1,
		ProducedAt: timestamppb.New(now), FinalizedThrough: timestamppb.New(now), EvidenceSha256: bytes32(1),
		Events: []*agentv1.L4SessionEventV1{{
			Event:    &commonv1.EventMetadata{EventId: "l4evt_1", OccurredTime: timestamppb.New(now)},
			TenantId: testTenantID, NodeId: testNodeID, SiteId: testSiteID,
			StreamId: "018f47a2-5b9c-7d31-8a60-104c9c0b7192", ListenerId: "018f47a2-5b9c-7d31-8a60-104c9c0b7192",
			ConfigVersionId: "018f47a2-5b9c-7d31-8a60-104c9c0b7191", ConfigRevision: 1,
			Protocol: "tcp", ListenPort: 18080, SessionId: "42", StartedAt: timestamppb.New(now.Add(-time.Second)),
			FinalizedAt: timestamppb.New(now), BytesUp: 1, BytesDown: 2, StatusCode: 200,
			CanonicalEventSha256: bytes32(2), EvidenceSha256: bytes32(3),
		}},
	}
	envelope.MessageId = eventspool.L4PublicationMessageID(envelope)
	payload, err := (proto.MarshalOptions{Deterministic: true}).Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	sender := &connectionsTransportCaptureSender{ack: SendAck{Accepted: 1}}
	publisher, err := NewPublisher(testNodeID, sender)
	if err != nil {
		t.Fatal(err)
	}
	publication := eventspool.Publication{
		Subject: "cdnca.l4.sessions.v1." + testNodeID, MessageID: envelope.MessageId,
		Payload: payload, FirstSequence: 1, LastSequence: 1, LastEventID: "l4evt_1", EventCount: 1,
	}
	ack, err := publisher.Publish(context.Background(), []eventspool.Publication{publication})
	if err != nil || ack.Acknowledged != 1 || len(sender.batch.Records) != 1 {
		t.Fatalf("L4 publish = %#v, error=%v, batch=%#v", ack, err, sender.batch)
	}
	record := sender.batch.Records[0]
	if record.Kind != "l4_session.v1" || string(record.Payload) != string(payload) {
		t.Fatalf("L4 transport record = %#v", record)
	}
	wire, err := buildWireBatch(sender.batch.Records, sessionLimits{maxRecords: 2, maxRecordBytes: 1 << 20, maxBatchBytes: 2 << 20})
	if err != nil || len(wire.Records) != 1 || wire.Records[0].Kind != agentv1.TelemetryKind_TELEMETRY_KIND_L4_SESSION_V1 ||
		string(wire.Records[0].Payload) != string(payload) {
		t.Fatalf("L4 wire batch = %#v, error=%v", wire, err)
	}
}
