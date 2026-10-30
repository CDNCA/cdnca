package nodemonitoringpublication

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const NodeMonitoringCommandStream = "NODE_MONITORING_COMMANDS"

var ErrInvalidPublication = errors.New("invalid node monitoring publication")

type PubAck struct {
	Stream   string
	Sequence uint64
	Replayed bool
}

type Publisher interface {
	PublishNodeMonitoringArtifact(context.Context, *agentv1.NodeMonitoringArtifact) (PubAck, error)
}

type Adapter struct {
	publisher Publisher
	now       func() time.Time
}

type Result struct {
	EventID        string
	ConfigRevision uint64
	Stream         string
	Sequence       uint64
	Replayed       bool
}

func NewAdapter(publisher Publisher) (*Adapter, error) {
	if publisher == nil {
		return nil, ErrInvalidPublication
	}
	return &Adapter{publisher: publisher, now: time.Now}, nil
}

func (adapter *Adapter) Publish(ctx context.Context, nodeID string, document systemconfig.CategoryDocument) (Result, error) {
	if adapter == nil || adapter.publisher == nil || ctx == nil {
		return Result{}, ErrInvalidPublication
	}
	artifact, err := BuildArtifact(nodeID, document, adapter.now())
	if err != nil {
		return Result{}, err
	}
	ack, err := adapter.publisher.PublishNodeMonitoringArtifact(ctx, proto.Clone(artifact).(*agentv1.NodeMonitoringArtifact))
	if err != nil {
		return Result{}, err
	}
	if ack.Stream != NodeMonitoringCommandStream || ack.Sequence == 0 {
		return Result{}, ErrInvalidPublication
	}
	return Result{EventID: artifact.GetEvent().GetEventId(), ConfigRevision: artifact.ConfigRevision, Stream: ack.Stream,
		Sequence: ack.Sequence, Replayed: ack.Replayed}, nil
}

func BuildArtifact(nodeID string, document systemconfig.CategoryDocument, occurredAt time.Time) (*agentv1.NodeMonitoringArtifact, error) {
	return BuildNodeArtifact(nodeID, document, nodemonitoringconfig.Override{}, occurredAt)
}

// BuildNodeArtifact builds the artifact for one node: the active platform
// policy overlaid by the node's override, bound to its effective revision.
func BuildNodeArtifact(
	nodeID string,
	document systemconfig.CategoryDocument,
	override nodemonitoringconfig.Override,
	occurredAt time.Time,
) (*agentv1.NodeMonitoringArtifact, error) {
	parsedNode, err := uuid.Parse(nodeID)
	if err != nil || parsedNode == uuid.Nil || parsedNode.String() != nodeID || occurredAt.IsZero() {
		return nil, ErrInvalidPublication
	}
	payload, revision, err := nodemonitoringconfig.CompileNodeDocument(document, override)
	if err != nil {
		return nil, fmt.Errorf("%w: compile active category: %v", ErrInvalidPublication, err)
	}
	digest := sha256.Sum256(payload)
	eventID := uuid.NewSHA1(parsedNode, append([]byte("node-monitoring/"), digest[:]...)).String()
	requestID := uuid.NewSHA1(parsedNode, []byte(fmt.Sprintf("node-monitoring-request/%d", revision))).String()
	return &agentv1.NodeMonitoringArtifact{
		Event: &commonv1.EventMetadata{EventId: eventID, RequestId: requestID,
			OccurredTime: timestamppb.New(occurredAt.UTC())},
		Schema: agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1, NodeId: nodeID,
		ConfigRevision: uint64(revision), PublicationSequence: uint64(revision),
		CanonicalConfigJson: append([]byte(nil), payload...), ConfigSha256: digest[:],
	}, nil
}
