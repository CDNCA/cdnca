package gateway

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type mixedQueuePublisher struct {
	connectionsTelemetryCapturePublisher
}

func (p *mixedQueuePublisher) Publish(context.Context, TelemetryPublication) (TelemetryPublishResult, error) {
	return TelemetryPublishResult{Stream: "CDNCA_ANALYTICS", Sequence: 1}, nil
}

func TestTelemetryIndependentQueueSequences(t *testing.T) {
	for _, connectionFirst := range []bool{false, true} {
		publisher := &mixedQueuePublisher{connectionsTelemetryCapturePublisher{result: TelemetryPublishResult{
			Stream: ConnectionsTelemetryIngestStream, Sequence: 1,
		}}}
		gateway := newTelemetryGateway(t, &connectionsTelemetryControl{fakeControl: defaultFakeControl()}, publisher)
		connections := connectionsTelemetryBatch(validConnectionsTelemetryEnvelope(), "")
		connections.FirstSequence, connections.LastSequence = 4, 4
		stream := connectionsTelemetryStream(t, connections)
		hello := stream.requests[0].GetHello()
		hello.LastDurableAcknowledgedSequence = 40
		hello.LastDurableConnectionsAcknowledgedSequence = proto.Uint64(3)
		access := telemetryBatchRequest(telemetryBatch(t, 41, 41), 3)
		stream.requests = append(stream.requests, access)
		if !connectionFirst {
			stream.requests[1], stream.requests[2] = stream.requests[2], stream.requests[1]
			stream.requests[1].Stream.Sequence, stream.requests[2].Stream.Sequence = 2, 3
		}
		stream.requests = append(stream.requests, telemetryBatchRequest(telemetryBatch(t, 42, 42), 4))
		if err := gateway.StreamTelemetry(stream); err != nil {
			t.Fatalf("connectionFirst=%v: %v", connectionFirst, err)
		}
		if len(stream.responses) != 4 || !stream.responses[0].GetHello().GetIndependentQueueCursors() || stream.responses[3].GetAck().GetAcceptedThroughSequence() != 42 {
			t.Fatalf("mixed queue acknowledgements = %v", stream.responses)
		}
	}
}

func TestTelemetryRejectsExhaustedIndependentCursor(t *testing.T) {
	gateway := newTelemetryGateway(t, &connectionsTelemetryControl{fakeControl: defaultFakeControl()}, &mixedQueuePublisher{})
	stream := connectionsTelemetryStream(t, connectionsTelemetryBatch(validConnectionsTelemetryEnvelope(), ""))
	stream.requests[0].GetHello().LastDurableConnectionsAcknowledgedSequence = proto.Uint64(^uint64(0))
	if err := gateway.StreamTelemetry(stream); status.Code(err) != codes.InvalidArgument || len(stream.responses) != 0 {
		t.Fatalf("exhausted queue cursor accepted: %v", err)
	}
}
