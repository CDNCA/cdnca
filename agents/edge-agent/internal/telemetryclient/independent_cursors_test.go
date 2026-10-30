package telemetryclient

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestIndependentCursorsShareRPCAndSurvivePartialAck(t *testing.T) {
	accessCursor, connectionCursor := &fixedCursor{sequence: 40}, &fixedCursor{sequence: 3}
	var sessions atomic.Int32
	dialer, cleanup := startGateway(t, func(stream grpc.BidiStreamingServer[agentv1.StreamTelemetryRequest, agentv1.StreamTelemetryResponse]) error {
		session := sessions.Add(1)
		request, err := stream.Recv()
		if err != nil {
			return err
		}
		hello := request.GetHello()
		if hello.LastDurableAcknowledgedSequence != 40+uint64(session-1) || hello.LastDurableConnectionsAcknowledgedSequence == nil || hello.GetLastDurableConnectionsAcknowledgedSequence() != 3+uint64(session-1) {
			return status.Error(codes.InvalidArgument, "queue cursors were mixed")
		}
		response := validGatewayHello(1, 64)
		response.GetHello().IndependentQueueCursors = true
		if err := stream.Send(response); err != nil {
			return err
		}
		if session == 1 {
			request, err = stream.Recv()
			if err != nil {
				return err
			}
			batch := request.GetBatch()
			if batch == nil || batch.FirstSequence != 41 {
				return status.Error(codes.InvalidArgument, "missing access batch")
			}
			if err := stream.Send(ackResponse(2, batch.BatchId, 1, 0, batch.Records[0])); err != nil {
				return err
			}
		}
		request, err = stream.Recv()
		if err != nil {
			return err
		}
		batch := request.GetConnectionsBatch()
		if batch == nil || batch.FirstSequence != uint64(3+session) {
			return status.Error(codes.InvalidArgument, "wrong connections batch")
		}
		record := batch.Records[0]
		sequence := uint64(2)
		if session == 1 {
			sequence = 3
		}
		if err := stream.Send(&agentv1.StreamTelemetryResponse{Stream: responseMetadata(sequence), Payload: &agentv1.StreamTelemetryResponse_Ack{Ack: &agentv1.TelemetryAck{
			BatchId: batch.BatchId, AcceptedRecordCount: 1, AcceptedThroughSequence: batch.FirstSequence,
			AcceptedThroughMessageId: record.ReceiptId, AcceptedThroughEventId: record.Envelope.GetEvent().GetEventId(), AcceptedTime: timestamppb.Now(),
		}}}); err != nil {
			return err
		}
		<-stream.Context().Done()
		return stream.Context().Err()
	})
	defer cleanup()
	client := newTestClient(t, accessCursor, uuid.NewString(), dialer)
	client.config.ConnectionsCursor = connectionCursor
	defer client.closeSession()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if ack, err := client.Send(ctx, Batch{Records: []Record{testRecord(41)}}); err != nil || ack.Accepted != 1 {
		t.Fatalf("access: %+v %v", ack, err)
	}
	accessCursor.sequence = 41 // Only the durable queue owner advances its ACK.
	batch := Batch{Connections: []ConnectionsRecord{
		{Sequence: 4, ReceiptID: "conn_" + strings.Repeat("a", 64), Envelope: connectionsTransportEnvelope()},
		{Sequence: 5, ReceiptID: "conn_" + strings.Repeat("b", 64), Envelope: connectionsTransportEnvelope()},
	}}
	batch.Connections[1].Envelope.SourceWatermark++
	batch.Connections[1].Envelope.Event.EventId = uuid.NewString()
	if ack, err := client.Send(ctx, batch); !errors.Is(err, ErrPartialAcknowledged) || ack.Accepted != 1 {
		t.Fatalf("partial: %+v %v", ack, err)
	}
	connectionCursor.sequence = 4
	batch.Connections = batch.Connections[1:]
	if ack, err := client.Send(ctx, batch); err != nil || ack.Accepted != 1 {
		t.Fatalf("reconnect: %+v %v", ack, err)
	}
	if sessions.Load() != 2 || accessCursor.calls.Load() != 2 || connectionCursor.calls.Load() != 2 {
		t.Fatal("queues did not share one session per connection")
	}
}

func TestIndependentCursorsFailClosedWithLegacyGateway(t *testing.T) {
	client := newTestClient(t, &fixedCursor{}, uuid.NewString(), &bufDialer{})
	client.config.ConnectionsCursor = &fixedCursor{}
	if _, err := client.validateHello(validGatewayHello(1, 64).GetHello()); !errors.Is(err, ErrPermanentProtocol) {
		t.Fatalf("unsupported independent mode accepted: %v", err)
	}
}
