package agentv1

import (
	"testing"

	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestConnectionsTelemetryTransportContract(t *testing.T) {
	if TelemetryKind_TELEMETRY_KIND_CONNECTIONS_V1 != 3 {
		t.Fatalf("connections telemetry kind = %d, want 3", TelemetryKind_TELEMETRY_KIND_CONNECTIONS_V1)
	}

	request := &StreamTelemetryRequest{
		Stream: &commonv1.StreamMetadata{MessageId: "conn-stream", Sequence: 2},
		Payload: &StreamTelemetryRequest_ConnectionsBatch{ConnectionsBatch: &ConnectionsTelemetryBatchV1{
			BatchId:       "conn-batch",
			FirstSequence: 7,
			LastSequence:  7,
			Records: []*ConnectionsTelemetryRecordV1{{
				ReceiptId: "conn_receipt",
				Envelope:  &ConnectionsMetricEnvelopeV1{SchemaVersion: 1},
			}},
		}},
	}

	field := request.ProtoReflect().Descriptor().Fields().ByName("connections_batch")
	if field == nil || field.Number() != 4 {
		t.Fatalf("connections_batch field = %v, want oneof field number 4", field)
	}
	for name, want := range map[string]int32{"hello": 2, "batch": 3} {
		field := request.ProtoReflect().Descriptor().Fields().ByName(protoreflect.Name(name))
		if field == nil || int32(field.Number()) != want {
			t.Fatalf("legacy %s field = %v, want %d", name, field, want)
		}
	}

	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil || len(wire) == 0 {
		t.Fatalf("marshal connections telemetry request: %v", err)
	}
}
