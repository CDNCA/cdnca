package edgeartifact

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var validationNow = time.Date(2026, 7, 22, 9, 30, 0, 0, time.UTC)

func TestNormalizeRequest(t *testing.T) {
	request := validFetchRequest()
	normalized, err := normalizeRequest(request, DefaultConfig(), validationNow)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.requestID.String() != request.Request.RequestId || normalized.eventID.String() != request.EventId ||
		normalized.nodeID.String() != request.NodeId || normalized.deploymentID.String() != request.DeploymentId ||
		normalized.artifactID.String() != request.ArtifactId || normalized.attempt != 1 || normalized.offset != 7 {
		t.Fatalf("normalized identity = %+v", normalized)
	}
	copy := proto.Clone(request).(*controlv1.FetchArtifactRequest)
	second, err := normalizeRequest(copy, DefaultConfig(), validationNow)
	if err != nil || normalized.digest != second.digest {
		t.Fatalf("deterministic digest changed: %x %x, %v", normalized.digest, second.digest, err)
	}
}

func TestNormalizeRequestRejectsInvalidInput(t *testing.T) {
	validTraceparentValue := "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	taskID := "task:edge_1"
	base := validFetchRequest()
	base.Request.Traceparent = validTraceparentValue
	base.Request.TaskId = &taskID
	tests := []struct {
		name   string
		mutate func(*controlv1.FetchArtifactRequest)
	}{
		{name: "nil metadata", mutate: func(value *controlv1.FetchArtifactRequest) { value.Request = nil }},
		{name: "nil sent time", mutate: func(value *controlv1.FetchArtifactRequest) { value.Request.SentTime = nil }},
		{name: "invalid sent time", mutate: func(value *controlv1.FetchArtifactRequest) {
			value.Request.SentTime = &timestamppb.Timestamp{Seconds: math.MaxInt64}
		}},
		{name: "future sent time", mutate: func(value *controlv1.FetchArtifactRequest) {
			value.Request.SentTime = timestamppb.New(validationNow.Add(6 * time.Minute))
		}},
		{name: "stale sent time", mutate: func(value *controlv1.FetchArtifactRequest) {
			value.Request.SentTime = timestamppb.New(validationNow.Add(-16 * time.Minute))
		}},
		{name: "request ID", mutate: func(value *controlv1.FetchArtifactRequest) {
			value.Request.RequestId = strings.ToUpper(value.Request.RequestId)
		}},
		{name: "event ID", mutate: func(value *controlv1.FetchArtifactRequest) { value.EventId = "event" }},
		{name: "node ID", mutate: func(value *controlv1.FetchArtifactRequest) { value.NodeId = uuid.Nil.String() }},
		{name: "deployment ID", mutate: func(value *controlv1.FetchArtifactRequest) { value.DeploymentId = "deployment" }},
		{name: "artifact ID", mutate: func(value *controlv1.FetchArtifactRequest) { value.ArtifactId = "artifact" }},
		{name: "gateway ID", mutate: func(value *controlv1.FetchArtifactRequest) { value.GatewayInstanceId = "gateway" }},
		{name: "zero attempt", mutate: func(value *controlv1.FetchArtifactRequest) { value.Attempt = 0 }},
		{name: "large attempt", mutate: func(value *controlv1.FetchArtifactRequest) { value.Attempt = math.MaxInt32 + 1 }},
		{name: "large offset", mutate: func(value *controlv1.FetchArtifactRequest) { value.Offset = math.MaxInt64 + 1 }},
		{name: "invalid traceparent", mutate: func(value *controlv1.FetchArtifactRequest) {
			value.Request.Traceparent = strings.ToUpper(validTraceparentValue)
		}},
		{name: "zero trace ID", mutate: func(value *controlv1.FetchArtifactRequest) {
			value.Request.Traceparent = "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
		}},
		{name: "correlation ID", mutate: func(value *controlv1.FetchArtifactRequest) { value.Request.CorrelationId = "correlation" }},
		{name: "empty task ID", mutate: func(value *controlv1.FetchArtifactRequest) { empty := ""; value.Request.TaskId = &empty }},
		{name: "unknown request field", mutate: func(value *controlv1.FetchArtifactRequest) { value.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01}) }},
		{name: "unknown metadata field", mutate: func(value *controlv1.FetchArtifactRequest) {
			value.Request.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := proto.Clone(base).(*controlv1.FetchArtifactRequest)
			test.mutate(request)
			if _, err := normalizeRequest(request, DefaultConfig(), validationNow); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", err)
			}
		})
	}
	t.Run("oversize metadata", func(t *testing.T) {
		request := validFetchRequest()
		request.Request.Traceparent = strings.Repeat("x", DefaultConfig().MaxRequestBytes)
		if _, err := normalizeRequest(request, DefaultConfig(), validationNow); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("error = %v, want ErrInvalidRequest", err)
		}
	})
}

func TestConfigValidation(t *testing.T) {
	valid := DefaultConfig()
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	tests := []Config{
		{},
		{MaxChunkBytes: HardMaxChunkBytes + 1, MaxRequestBytes: valid.MaxRequestBytes, MaxFutureSkew: time.Second, MaxRequestAge: time.Second},
		{MaxChunkBytes: valid.MaxChunkBytes, MaxRequestBytes: HardMaxRequestBytes + 1, MaxFutureSkew: time.Second, MaxRequestAge: time.Second},
		{MaxChunkBytes: valid.MaxChunkBytes, MaxRequestBytes: valid.MaxRequestBytes, MaxFutureSkew: 0, MaxRequestAge: time.Second},
	}
	for index, config := range tests {
		if err := config.validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("config %d error = %v", index, err)
		}
	}
}

func validFetchRequest() *controlv1.FetchArtifactRequest {
	return &controlv1.FetchArtifactRequest{
		Request: &commonv1.RequestMetadata{
			RequestId: uuid.NewString(), SentTime: timestamppb.New(validationNow), CorrelationId: uuid.NewString(),
		},
		EventId: uuid.NewString(), NodeId: uuid.NewString(), DeploymentId: uuid.NewString(),
		Attempt: 1, ArtifactId: uuid.NewString(), Offset: 7, GatewayInstanceId: uuid.NewString(),
	}
}

// A session without deployments (cleanup_only) never gets a configuration
// artifact, whatever the request names.
func TestFetchChunkRefusesCleanupOnlyRequests(t *testing.T) {
	store := &Store{config: DefaultConfig(), now: func() time.Time { return validationNow }}
	request := validFetchRequest()
	request.CleanupOnly = true
	if _, err := store.FetchChunk(t.Context(), request); !errors.Is(err, ErrDeploymentIneligible) {
		t.Fatalf("cleanup_only configuration fetch: %v", err)
	}
}

// A scoped deployment (migration 289) is agent_queued and started on the node
// before it fetches its artifacts (gatewayclient records STARTED when its
// queue takes the command): both stay fetchable, staged and later do not.
func TestFetchableDeploymentStates(t *testing.T) {
	for state, want := range map[string]bool{
		"queued": true, "delivered": true, "agent_queued": true, "started": true,
		"staged": false, "prechecked": false, "activated": false, "healthy": false, "failed": false, "cancelled": false,
	} {
		if got := fetchableDeploymentState(state); got != want {
			t.Errorf("fetchableDeploymentState(%q) = %v, want %v", state, got, want)
		}
	}
}
