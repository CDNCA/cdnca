package nodemonitoringpublication

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"google.golang.org/protobuf/proto"
)

type capturePublisher struct {
	artifact *agentv1.NodeMonitoringArtifact
	ack      PubAck
}

func (publisher *capturePublisher) PublishNodeMonitoringArtifact(_ context.Context, artifact *agentv1.NodeMonitoringArtifact) (PubAck, error) {
	publisher.artifact = artifact
	return publisher.ack, nil
}

func TestAdapterPublishesActiveRevisionBoundArtifact(t *testing.T) {
	publisher := &capturePublisher{ack: PubAck{Stream: "NODE_MONITORING_COMMANDS", Sequence: 41}}
	adapter, err := NewAdapter(publisher)
	if err != nil {
		t.Fatalf("NewAdapter() error = %v", err)
	}
	document := systemconfig.CategoryDocument{
		Category: systemconfig.CategoryNodeMonitoring, HeadRevision: 9, ActiveRevision: 7, Revision: 7,
		Value: systemconfig.NodeMonitoringConfiguration{
			PortMode: "default", ProbeIntervalMS: 10_000, ProbeTimeoutMS: 3_000,
			FailureThreshold: 3, RecoveryThreshold: 3, RecoveryNotificationEnabled: true,
		},
	}
	nodeID := "01990000-0000-7000-8000-000000000007"
	result, err := adapter.Publish(t.Context(), nodeID, document)
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	if result.ConfigRevision != 7 || result.Stream != publisher.ack.Stream || result.Sequence != 41 || result.Replayed {
		t.Fatalf("result = %#v", result)
	}
	artifact := publisher.artifact
	if artifact == nil || artifact.Schema != agentv1.NodeMonitoringSchema_NODE_MONITORING_SCHEMA_V1 ||
		artifact.NodeId != nodeID || artifact.ConfigRevision != 7 || artifact.PublicationSequence != 7 ||
		len(artifact.ConfigSha256) != 32 || len(artifact.CanonicalConfigJson) == 0 {
		t.Fatalf("artifact = %#v", artifact)
	}

	publisher.ack.Replayed = true
	replayed, err := adapter.Publish(t.Context(), nodeID, document)
	if err != nil || !replayed.Replayed || replayed.EventID != result.EventID {
		t.Fatalf("replayed Publish() = (%#v, %v)", replayed, err)
	}
}

func TestAdapterRejectsInvalidNodeOrPubAck(t *testing.T) {
	publisher := &capturePublisher{ack: PubAck{Stream: "wrong", Sequence: 1}}
	adapter, _ := NewAdapter(publisher)
	document := systemconfig.CategoryDocument{Category: systemconfig.CategoryNodeMonitoring, ActiveRevision: 1, Revision: 1, HeadRevision: 1,
		Value: systemconfig.NodeMonitoringConfiguration{PortMode: "default", ProbeIntervalMS: 10_000, ProbeTimeoutMS: 3_000, FailureThreshold: 3, RecoveryThreshold: 3}}
	if _, err := adapter.Publish(context.Background(), "wrong-node", document); err == nil {
		t.Fatal("invalid node identity was accepted")
	}
	if _, err := adapter.Publish(context.Background(), "01990000-0000-7000-8000-000000000007", document); err == nil {
		t.Fatal("invalid PubAck was accepted")
	}
}

func TestBuildNodeArtifactWithoutOverrideMatchesPlatformArtifact(t *testing.T) {
	document := systemconfig.CategoryDocument{Category: systemconfig.CategoryNodeMonitoring, ActiveRevision: 4, Revision: 4, HeadRevision: 4,
		Value: systemconfig.NodeMonitoringConfiguration{PortMode: "default", ProbeIntervalMS: 10_000, ProbeTimeoutMS: 3_000, FailureThreshold: 3, RecoveryThreshold: 3}}
	nodeID := "01990000-0000-7000-8000-000000000007"
	at := time.Date(2026, 10, 13, 8, 0, 0, 0, time.UTC)
	platform, err := BuildArtifact(nodeID, document, at)
	if err != nil {
		t.Fatal(err)
	}
	node, err := BuildNodeArtifact(nodeID, document, nodemonitoringconfig.Override{}, at)
	if err != nil || !proto.Equal(platform, node) {
		t.Fatalf("node artifact differs without override: %v", err)
	}
	protocol := "http"
	overridden, err := BuildNodeArtifact(nodeID, document, nodemonitoringconfig.Override{Revision: 2, Protocol: protocol}, at)
	if err != nil || overridden.ConfigRevision != 6 || overridden.PublicationSequence != 6 ||
		overridden.Event.EventId == platform.Event.EventId || overridden.Event.RequestId == platform.Event.RequestId {
		t.Fatalf("overridden artifact = %#v, %v", overridden, err)
	}
}
