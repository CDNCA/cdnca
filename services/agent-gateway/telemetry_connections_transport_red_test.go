package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	testConnectionsInstallationID = "018f47a2-5b9c-7d31-8a60-104c9c0b7183"
	testConnectionsSubscriptionID = "018f47a2-5b9c-7d31-8a60-104c9c0b7184"
)

type connectionsTelemetryControl struct {
	*fakeControl
}

func (c *connectionsTelemetryControl) GetNodeAuthorization(
	_ context.Context,
	request *controlv1.GetNodeAuthorizationRequest,
) (*controlv1.GetNodeAuthorizationResponse, error) {
	return &controlv1.GetNodeAuthorizationResponse{
		NodeId: request.NodeId, AdministrativeState: controlv1.NodeAdministrativeState_NODE_ADMINISTRATIVE_STATE_ACTIVE,
		ConnectionAllowed: true, AcceptedProtocolVersions: versionRange(1, 0),
		SnapshotExpirationTime: timestamppb.New(time.Now().Add(time.Hour)), ArtifactEncryptionKeyId: "artifact-key",
		InstallationId: testConnectionsInstallationID, TenantId: testTelemetryTenantID,
		TelemetrySiteScopes: []*controlv1.TelemetrySiteScope{{
			SiteId: testTelemetrySiteID, TenantId: testTelemetryTenantID,
			ConfigVersionId: testTelemetryConfigVersionID, PackageSubscriptionId: testConnectionsSubscriptionID,
		}},
	}, nil
}

type connectionsTelemetryCapturePublisher struct {
	mu           sync.Mutex
	publications []TelemetryPublication
	result       TelemetryPublishResult
	err          error
}

func (p *connectionsTelemetryCapturePublisher) Publish(context.Context, TelemetryPublication) (TelemetryPublishResult, error) {
	return TelemetryPublishResult{}, errors.New("connections payload reached analytics publisher")
}

func (p *connectionsTelemetryCapturePublisher) Check(context.Context) error { return nil }

func (p *connectionsTelemetryCapturePublisher) ConnectionsStream() string {
	return ConnectionsTelemetryIngestStream
}

func (p *connectionsTelemetryCapturePublisher) PublishConnections(
	_ context.Context,
	publication TelemetryPublication,
) (TelemetryPublishResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.publications = append(p.publications, publication)
	return p.result, p.err
}

func (p *connectionsTelemetryCapturePublisher) publicationsSnapshot() []TelemetryPublication {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]TelemetryPublication(nil), p.publications...)
}

func TestStreamTelemetryAcceptsAuthorityBoundConnectionsBatchWithExactReceipt(t *testing.T) {
	publisher := &connectionsTelemetryCapturePublisher{result: TelemetryPublishResult{
		Stream: ConnectionsTelemetryIngestStream, Sequence: 41, Duplicate: true,
	}}
	gateway := newTelemetryGateway(t, &connectionsTelemetryControl{fakeControl: defaultFakeControl()}, publisher)
	envelope := validConnectionsTelemetryEnvelope()
	receiptID := testConnectionsReceiptID(envelope)
	batch := connectionsTelemetryBatch(envelope, receiptID)
	stream := connectionsTelemetryStream(t, batch)

	if err := gateway.StreamTelemetry(stream); err != nil {
		t.Fatalf("StreamTelemetry error = %v", err)
	}
	if len(stream.responses) != 2 || stream.responses[0].GetHello() == nil || stream.responses[1].GetAck() == nil {
		t.Fatalf("connections telemetry responses = %+v", stream.responses)
	}
	ack := stream.responses[1].GetAck()
	if ack.BatchId != batch.BatchId || ack.AcceptedRecordCount != 1 || ack.AcceptedThroughSequence != 1 ||
		ack.AcceptedThroughMessageId != receiptID || ack.AcceptedThroughEventId != envelope.GetEvent().GetEventId() ||
		ack.DuplicateRecordCount != 1 {
		t.Fatalf("connections durable ACK = %+v", ack)
	}
	publications := publisher.publicationsSnapshot()
	if len(publications) != 1 {
		t.Fatalf("connections publications = %d, want 1", len(publications))
	}
	publication := publications[0]
	if publication.NodeID != testNodeID || publication.TenantID != testTelemetryTenantID ||
		publication.InstallationID != testConnectionsInstallationID || publication.SiteID != testTelemetrySiteID ||
		publication.ConfigVersionID != "" || publication.BatchID != batch.BatchId || publication.MessageID != receiptID {
		t.Fatalf("connections publication identity = %+v", publication)
	}
	var published agentv1.ConnectionsMetricEnvelopeV1
	if err := proto.Unmarshal(publication.Payload, &published); err != nil || !proto.Equal(&published, envelope) {
		t.Fatalf("connections publication payload mismatch: err=%v payload=%+v", err, &published)
	}
}

func TestStreamTelemetryRejectsInvalidConnectionsPubAckProof(t *testing.T) {
	tests := []struct {
		name   string
		result TelemetryPublishResult
	}{
		{name: "missing proof"},
		{name: "wrong stream", result: TelemetryPublishResult{Stream: "OTHER_STREAM", Sequence: 1}},
		{name: "zero sequence", result: TelemetryPublishResult{Stream: ConnectionsTelemetryIngestStream}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publisher := &connectionsTelemetryCapturePublisher{result: test.result}
			gateway := newTelemetryGateway(t, &connectionsTelemetryControl{fakeControl: defaultFakeControl()}, publisher)
			stream := connectionsTelemetryStream(t, connectionsTelemetryBatch(validConnectionsTelemetryEnvelope(), ""))

			err := gateway.StreamTelemetry(stream)
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("StreamTelemetry code = %v, want Unavailable", status.Code(err))
			}
			if len(stream.responses) != 2 || stream.responses[0].GetHello() == nil || stream.responses[1].GetError() == nil ||
				stream.responses[1].GetAck() != nil {
				t.Fatalf("invalid PubAck responses = %+v", stream.responses)
			}
			if test.result.Stream != "" && strings.Contains(stream.responses[1].GetError().GetError().GetMessage(), test.result.Stream) {
				t.Fatalf("invalid PubAck leaked proof details: %+v", stream.responses[1].GetError())
			}
		})
	}
}

func TestStreamTelemetryRejectsInvalidConnectionsAuthorityAndContent(t *testing.T) {
	base := validConnectionsTelemetryEnvelope()
	tests := []struct {
		name   string
		mutate func(*agentv1.ConnectionsMetricEnvelopeV1)
	}{
		{name: "tenant", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.TenantId = uuid.NewString() }},
		{name: "installation", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.InstallationId = uuid.NewString() }},
		{name: "site", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.SiteId = uuid.NewString() }},
		{name: "subscription", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.PackageSubscriptionId = uuid.NewString() }},
		{name: "missing node", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.NodeId = "" }},
		{name: "wrong node", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.NodeId = uuid.NewString() }},
		{name: "missing domain", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.Domain = "" }},
		{name: "zero listen port", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.ListenPort = 0 }},
		{name: "overflow listen port", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.ListenPort = 65536 }},
		{name: "zero gauge", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.Connections = 0 }},
		{name: "dependency unavailable", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) {
			value.DependencyState = agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_UNAVAILABLE
		}},
		{name: "missing finalized", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.FinalizedThrough = nil }},
		{name: "finalized before event", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) {
			value.FinalizedThrough = timestamppb.New(value.GetEvent().GetOccurredTime().AsTime().Add(-time.Second))
		}},
		{name: "canonical digest", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.CanonicalEventSha256 = []byte{1} }},
		{name: "evidence digest", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.EvidenceSha256 = make([]byte, sha256.Size) }},
		{name: "zero watermark", mutate: func(value *agentv1.ConnectionsMetricEnvelopeV1) { value.SourceWatermark = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			envelope := proto.Clone(base).(*agentv1.ConnectionsMetricEnvelopeV1)
			test.mutate(envelope)
			publisher := &connectionsTelemetryCapturePublisher{}
			gateway := newTelemetryGateway(t, &connectionsTelemetryControl{fakeControl: defaultFakeControl()}, publisher)
			stream := connectionsTelemetryStream(t, connectionsTelemetryBatch(envelope, testConnectionsReceiptID(envelope)))
			if code := status.Code(gateway.StreamTelemetry(stream)); code != codes.InvalidArgument {
				t.Fatalf("StreamTelemetry code = %v, want InvalidArgument", code)
			}
			if len(publisher.publicationsSnapshot()) != 0 {
				t.Fatal("invalid connections envelope reached publisher")
			}
		})
	}

	t.Run("receipt mismatch", func(t *testing.T) {
		publisher := &connectionsTelemetryCapturePublisher{}
		gateway := newTelemetryGateway(t, &connectionsTelemetryControl{fakeControl: defaultFakeControl()}, publisher)
		stream := connectionsTelemetryStream(t, connectionsTelemetryBatch(base, "conn_"+strings.Repeat("0", sha256.Size*2)))
		if code := status.Code(gateway.StreamTelemetry(stream)); code != codes.InvalidArgument {
			t.Fatalf("StreamTelemetry code = %v, want InvalidArgument", code)
		}
	})

	t.Run("conflicting duplicate event", func(t *testing.T) {
		first := proto.Clone(base).(*agentv1.ConnectionsMetricEnvelopeV1)
		second := proto.Clone(base).(*agentv1.ConnectionsMetricEnvelopeV1)
		second.CanonicalEventSha256 = bytes.Repeat([]byte{9}, sha256.Size)
		second.SourceWatermark++
		batch := connectionsTelemetryBatch(first, testConnectionsReceiptID(first))
		batch.Records = append(batch.Records, &agentv1.ConnectionsTelemetryRecordV1{
			ReceiptId: testConnectionsReceiptID(second), Envelope: second,
		})
		batch.LastSequence = 2
		publisher := &connectionsTelemetryCapturePublisher{}
		gateway := newTelemetryGateway(t, &connectionsTelemetryControl{fakeControl: defaultFakeControl()}, publisher)
		stream := connectionsTelemetryStream(t, batch)
		if code := status.Code(gateway.StreamTelemetry(stream)); code != codes.InvalidArgument {
			t.Fatalf("StreamTelemetry code = %v, want InvalidArgument", code)
		}
		if len(publisher.publicationsSnapshot()) != 0 {
			t.Fatal("conflicting connections event reached publisher")
		}
	})
}

func TestStreamTelemetryConnectionsPublicationFailureIsFailClosed(t *testing.T) {
	publisher := &connectionsTelemetryCapturePublisher{err: errors.New("secret nats subject and payload")}
	gateway := newTelemetryGateway(t, &connectionsTelemetryControl{fakeControl: defaultFakeControl()}, publisher)
	stream := connectionsTelemetryStream(t, connectionsTelemetryBatch(validConnectionsTelemetryEnvelope(), ""))
	stream.requests[1].GetConnectionsBatch().Records[0].ReceiptId = testConnectionsReceiptID(
		stream.requests[1].GetConnectionsBatch().Records[0].Envelope,
	)

	err := gateway.StreamTelemetry(stream)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("StreamTelemetry code = %v, want Unavailable", status.Code(err))
	}
	if len(stream.responses) != 2 || stream.responses[1].GetError() == nil ||
		stream.responses[1].GetError().GetError().GetCode() != commonv1.ErrorCode_ERROR_CODE_UNAVAILABLE {
		t.Fatalf("connections failure responses = %+v", stream.responses)
	}
	if strings.Contains(stream.responses[1].GetError().GetError().GetMessage(), "secret") {
		t.Fatalf("connections failure leaked publisher error: %+v", stream.responses[1].GetError())
	}
}

func connectionsTelemetryStream(t *testing.T, batch *agentv1.ConnectionsTelemetryBatchV1) *telemetryTestStream {
	t.Helper()
	return &telemetryTestStream{ctx: authenticatedTestContext(t), requests: []*agentv1.StreamTelemetryRequest{
		telemetryHelloRequest(0, 1), {
			Stream:  &commonv1.StreamMetadata{MessageId: uuid.NewString(), SentTime: timestamppb.Now(), Sequence: 2},
			Payload: &agentv1.StreamTelemetryRequest_ConnectionsBatch{ConnectionsBatch: batch},
		},
	}}
}

func connectionsTelemetryBatch(
	envelope *agentv1.ConnectionsMetricEnvelopeV1,
	receiptID string,
) *agentv1.ConnectionsTelemetryBatchV1 {
	if receiptID == "" {
		receiptID = testConnectionsReceiptID(envelope)
	}
	return &agentv1.ConnectionsTelemetryBatchV1{
		BatchId: "conn_batch_" + uuid.NewString(), FirstSequence: 1, LastSequence: 1,
		Records: []*agentv1.ConnectionsTelemetryRecordV1{{ReceiptId: receiptID, Envelope: envelope}},
	}
}

func validConnectionsTelemetryEnvelope() *agentv1.ConnectionsMetricEnvelopeV1 {
	occurred := time.Now().UTC().Add(-2 * time.Minute)
	return &agentv1.ConnectionsMetricEnvelopeV1{
		SchemaVersion: 1,
		Event:         &commonv1.EventMetadata{EventId: uuid.NewString(), OccurredTime: timestamppb.New(occurred)},
		TenantId:      testTelemetryTenantID, InstallationId: testConnectionsInstallationID,
		SiteId: testTelemetrySiteID, PackageSubscriptionId: testConnectionsSubscriptionID,
		NodeId: testNodeID, Domain: "edge.example.test", ListenPort: 443,
		Connections: 17, CanonicalEventSha256: bytes.Repeat([]byte{1}, sha256.Size),
		DependencyState:  agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_READY,
		FinalizedThrough: timestamppb.New(occurred.Add(time.Minute)),
		EvidenceSha256:   bytes.Repeat([]byte{2}, sha256.Size), SourceWatermark: 7,
	}
}

func testConnectionsReceiptID(envelope *agentv1.ConnectionsMetricEnvelopeV1) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("cdnca.connections.identity.v1\x00"))
	for _, value := range []any{
		envelope.GetTenantId(), envelope.GetInstallationId(), envelope.GetSiteId(), envelope.GetPackageSubscriptionId(),
		envelope.GetNodeId(), envelope.GetDomain(),
	} {
		writeTestConnectionsIdentityPart(digest, value)
	}
	var listenPort [4]byte
	binary.BigEndian.PutUint32(listenPort[:], envelope.GetListenPort())
	_, _ = digest.Write(listenPort[:])
	writeTestConnectionsIdentityPart(digest, envelope.GetEvent().GetEventId())
	if occurred := envelope.GetEvent().GetOccurredTime(); occurred != nil {
		var timestamp [12]byte
		binary.BigEndian.PutUint64(timestamp[:8], uint64(occurred.GetSeconds()))
		binary.BigEndian.PutUint32(timestamp[8:], uint32(occurred.GetNanos()))
		_, _ = digest.Write(timestamp[:])
	}
	writeTestConnectionsIdentityPart(digest, envelope.GetCanonicalEventSha256())
	return "conn_" + hex.EncodeToString(digest.Sum(nil))
}

func writeTestConnectionsIdentityPart(destination hash.Hash, value any) {
	var encoded []byte
	switch value := value.(type) {
	case string:
		encoded = []byte(value)
	case []byte:
		encoded = value
	}
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(encoded)))
	_, _ = destination.Write(length[:])
	_, _ = destination.Write(encoded)
}
