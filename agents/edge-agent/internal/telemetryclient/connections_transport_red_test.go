package telemetryclient

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestConnectionsPublisherAndClientUseDedicatedBatchAndReceipt(t *testing.T) {
	envelope := connectionsTransportEnvelope()
	publication := connectionsTransportPublication(t, envelope)
	sender := &connectionsTransportCaptureSender{ack: SendAck{Accepted: 1}}
	publisher, err := NewPublisher(testNodeID, sender)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := publisher.Publish(context.Background(), []eventspool.Publication{publication})
	if err != nil || ack.Acknowledged != 1 || len(sender.batch.Records) != 0 || len(sender.batch.Connections) != 1 {
		t.Fatalf("connections publication = %+v, %v, batch=%+v", ack, err, sender.batch)
	}
	sentEnvelope := sender.batch.Connections[0].Envelope
	if sender.batch.Connections[0].ReceiptID != publication.MessageID ||
		sender.batch.Connections[0].Sequence != publication.FirstSequence ||
		sentEnvelope.GetEvent().GetEventId() != envelope.GetEvent().GetEventId() ||
		sentEnvelope.GetNodeId() != envelope.GetNodeId() || sentEnvelope.GetDomain() != envelope.GetDomain() ||
		sentEnvelope.GetListenPort() != envelope.GetListenPort() {
		t.Fatalf("connections receipt identity was not preserved: %+v", sender.batch.Connections[0])
	}

	dialer, cleanup := startGateway(t, func(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(validGatewayHello(1, 1)); err != nil {
			return err
		}
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		batch := request.GetConnectionsBatch()
		if request.GetBatch() != nil || batch == nil || len(batch.Records) != 1 {
			return errors.New("connections payload was mixed into legacy telemetry batch")
		}
		record := batch.Records[0]
		return stream.Send(&agentv1.StreamTelemetryResponse{
			Stream: responseMetadata(2),
			Payload: &agentv1.StreamTelemetryResponse_Ack{Ack: &agentv1.TelemetryAck{
				BatchId: batch.BatchId, AcceptedRecordCount: 1, AcceptedThroughSequence: batch.LastSequence,
				AcceptedThroughMessageId: record.ReceiptId, AcceptedThroughEventId: record.Envelope.GetEvent().GetEventId(),
				AcceptedTime: timestamppb.Now(),
			}},
		})
	})
	defer cleanup()
	client := newTestClient(t, &fixedCursor{}, uuid.NewString(), dialer)
	clientAck, err := client.Send(context.Background(), Batch{Connections: []ConnectionsRecord{{
		ReceiptID: publication.MessageID, Sequence: publication.FirstSequence, Envelope: envelope,
	}}})
	if err != nil || clientAck.Accepted != 1 {
		t.Fatalf("connections client send = %+v, %v", clientAck, err)
	}
}

func TestConnectionsClientReconnectsWithStableReceiptBatch(t *testing.T) {
	envelope := connectionsTransportEnvelope()
	receiptID := "conn_" + strings.Repeat("a", 64)
	var sessions atomic.Int32
	batchIDs := make(chan string, 2)
	dialer, cleanup := startGateway(t, func(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
		session := sessions.Add(1)
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(validGatewayHello(1, 1)); err != nil {
			return err
		}
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		batch := request.GetConnectionsBatch()
		if batch == nil || len(batch.Records) != 1 || batch.Records[0].ReceiptId != receiptID {
			return status.Error(codes.InvalidArgument, "connections receipt identity changed")
		}
		batchIDs <- batch.BatchId
		if session == 1 {
			return status.Error(codes.Unavailable, "unknown durable result")
		}
		record := batch.Records[0]
		return stream.Send(&agentv1.StreamTelemetryResponse{
			Stream: responseMetadata(2),
			Payload: &agentv1.StreamTelemetryResponse_Ack{Ack: &agentv1.TelemetryAck{
				BatchId: batch.BatchId, AcceptedRecordCount: 1, AcceptedThroughSequence: batch.LastSequence,
				AcceptedThroughMessageId: record.ReceiptId, AcceptedThroughEventId: record.Envelope.GetEvent().GetEventId(),
				AcceptedTime: timestamppb.Now(),
			}},
		})
	})
	defer cleanup()
	client := newTestClient(t, &fixedCursor{}, uuid.NewString(), dialer)
	client.jitter = func(time.Duration) time.Duration { return 0 }
	ack, err := client.Send(context.Background(), Batch{Connections: []ConnectionsRecord{{
		ReceiptID: receiptID, Sequence: 1, Envelope: envelope,
	}}})
	if err != nil || ack.Accepted != 1 {
		t.Fatalf("reconnect connections send = %+v, %v", ack, err)
	}
	firstID, secondID := <-batchIDs, <-batchIDs
	if firstID == "" || firstID != secondID {
		t.Fatalf("retransmitted connections batch IDs = %q, %q", firstID, secondID)
	}
}

type connectionsTransportCaptureSender struct {
	batch Batch
	ack   SendAck
	err   error
}

func (s *connectionsTransportCaptureSender) Send(_ context.Context, batch Batch) (SendAck, error) {
	s.batch = batch
	return s.ack, s.err
}

func connectionsTransportEnvelope() *agentv1.ConnectionsMetricEnvelopeV1 {
	now := time.Unix(1_700_000_000, 0).UTC()
	return &agentv1.ConnectionsMetricEnvelopeV1{
		SchemaVersion: 1,
		Event:         &commonv1.EventMetadata{EventId: uuid.NewString(), OccurredTime: timestamppb.New(now)},
		TenantId:      testTenantID, InstallationId: testNodeID, SiteId: testSiteID, PackageSubscriptionId: testSiteID,
		NodeId: testNodeID, Domain: "edge.example.test", ListenPort: 443,
		Connections: 3, CanonicalEventSha256: bytes32(1),
		DependencyState:  agentv1.ConnectionsDependencyStateV1_CONNECTIONS_DEPENDENCY_STATE_V1_READY,
		FinalizedThrough: timestamppb.New(now.Add(time.Minute)), EvidenceSha256: bytes32(2), SourceWatermark: 1,
	}
}

func bytes32(value byte) []byte {
	result := make([]byte, 32)
	for index := range result {
		result[index] = value
	}
	return result
}

func connectionsTransportPublication(t *testing.T, envelope *agentv1.ConnectionsMetricEnvelopeV1) eventspool.Publication {
	t.Helper()
	root := t.TempDir()
	_ = os.Chmod(root, 0o700)
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	spool, err := eventspool.New(eventspool.Config{
		Root: root, MaxEventBytes: 2048, MaxSegmentBytes: 4096,
		SoftLimitBytes: 32 << 10, HardLimitBytes: 64 << 10, MaxTenantBytes: 48 << 10,
		MaxBatchEvents: 1000, PressureMode: eventspool.PressureBackpressure,
		SoftAgeLimit: 24 * time.Hour, HardAgeLimit: 7 * 24 * time.Hour,
		Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.AppendConnections(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	collector := &connectionsTransportPublicationCollector{}
	if result, err := spool.FlushConnections(context.Background(), collector, 1); err != nil || result.Published != 1 {
		t.Fatalf("flush connections = %+v, %v", result, err)
	}
	if len(collector.publications) != 1 {
		t.Fatal("connections spool did not produce one publication")
	}
	return collector.publications[0]
}

type connectionsTransportPublicationCollector struct {
	publications []eventspool.Publication
}

func (c *connectionsTransportPublicationCollector) Publish(_ context.Context, publications []eventspool.Publication) (eventspool.PublishAck, error) {
	c.publications = append(c.publications, publications...)
	return eventspool.PublishAck{Acknowledged: len(publications)}, nil
}
