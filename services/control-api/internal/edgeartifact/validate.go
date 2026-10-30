package edgeartifact

import (
	"crypto/sha256"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	controlv1 "github.com/cdnca/cdnca/proto/gen/go/controlinternal/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

var (
	identifierPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	artifactRecipientPattern = regexp.MustCompile(`^x25519:[0-9a-f]{64}$`)
)

type normalizedRequest struct {
	requestID    uuid.UUID
	eventID      uuid.UUID
	nodeID       uuid.UUID
	deploymentID uuid.UUID
	artifactID   uuid.UUID
	attempt      int32
	offset       int64
	digest       [sha256.Size]byte
}

func normalizeRequest(request *controlv1.FetchArtifactRequest, config Config, now time.Time) (normalizedRequest, error) {
	if request == nil || proto.Size(request) > config.MaxRequestBytes ||
		len(request.ProtoReflect().GetUnknown()) != 0 {
		return normalizedRequest{}, fmt.Errorf("%w: message", ErrInvalidRequest)
	}
	metadata := request.Request
	if metadata == nil || len(metadata.ProtoReflect().GetUnknown()) != 0 ||
		metadata.SentTime == nil || len(metadata.SentTime.ProtoReflect().GetUnknown()) != 0 ||
		metadata.SentTime.CheckValid() != nil {
		return normalizedRequest{}, fmt.Errorf("%w: request metadata", ErrInvalidRequest)
	}
	sentAt := metadata.SentTime.AsTime()
	if sentAt.After(now.Add(config.MaxFutureSkew)) || sentAt.Before(now.Add(-config.MaxRequestAge)) {
		return normalizedRequest{}, fmt.Errorf("%w: request time", ErrInvalidRequest)
	}
	requestID, err := canonicalUUID(metadata.RequestId)
	if err != nil {
		return normalizedRequest{}, fmt.Errorf("%w: request ID", ErrInvalidRequest)
	}
	eventID, err := canonicalUUID(request.EventId)
	if err != nil {
		return normalizedRequest{}, fmt.Errorf("%w: event ID", ErrInvalidRequest)
	}
	nodeID, err := canonicalUUID(request.NodeId)
	if err != nil {
		return normalizedRequest{}, fmt.Errorf("%w: node ID", ErrInvalidRequest)
	}
	deploymentID, err := canonicalUUID(request.DeploymentId)
	if err != nil {
		return normalizedRequest{}, fmt.Errorf("%w: deployment ID", ErrInvalidRequest)
	}
	artifactID, err := canonicalUUID(request.ArtifactId)
	if err != nil {
		return normalizedRequest{}, fmt.Errorf("%w: artifact ID", ErrInvalidRequest)
	}
	if _, err := canonicalUUID(request.GatewayInstanceId); err != nil {
		return normalizedRequest{}, fmt.Errorf("%w: gateway instance ID", ErrInvalidRequest)
	}
	if request.Attempt == 0 || uint64(request.Attempt) > math.MaxInt32 || request.Offset > math.MaxInt64 {
		return normalizedRequest{}, fmt.Errorf("%w: attempt or offset", ErrInvalidRequest)
	}
	if !validTraceparent(metadata.Traceparent) {
		return normalizedRequest{}, fmt.Errorf("%w: traceparent", ErrInvalidRequest)
	}
	if metadata.CorrelationId != "" {
		if _, err := canonicalUUID(metadata.CorrelationId); err != nil {
			return normalizedRequest{}, fmt.Errorf("%w: correlation ID", ErrInvalidRequest)
		}
	}
	if metadata.TaskId != nil && !identifierPattern.MatchString(metadata.GetTaskId()) {
		return normalizedRequest{}, fmt.Errorf("%w: task ID", ErrInvalidRequest)
	}
	cloned := proto.Clone(request).(*controlv1.FetchArtifactRequest)
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(cloned)
	if err != nil || len(encoded) > config.MaxRequestBytes {
		return normalizedRequest{}, fmt.Errorf("%w: deterministic request", ErrInvalidRequest)
	}
	return normalizedRequest{
		requestID: requestID, eventID: eventID, nodeID: nodeID,
		deploymentID: deploymentID, artifactID: artifactID, attempt: int32(request.Attempt),
		offset: int64(request.Offset), digest: sha256.Sum256(encoded),
	}, nil
}

func canonicalUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil || parsed.String() != value {
		return uuid.Nil, fmt.Errorf("not a canonical UUID")
	}
	return parsed, nil
}

func validTraceparent(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 55 || strings.TrimSpace(value) != value || value[2] != '-' || value[35] != '-' || value[52] != '-' || value[:2] != "00" {
		return false
	}
	traceID, spanID, flags := value[3:35], value[36:52], value[53:55]
	if !lowerHex(traceID) || !lowerHex(spanID) || !lowerHex(flags) ||
		traceID == strings.Repeat("0", 32) || spanID == strings.Repeat("0", 16) {
		return false
	}
	return true
}

func lowerHex(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}
