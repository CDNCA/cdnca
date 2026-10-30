package gateway

import (
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/artifactset"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

// A node artifact set or segment deployment (ARTIFACT_SET v1) never becomes
// the node's running configuration, so its healthy status carries no active
// config identity; the command must still be acknowledged, or the command
// stream redelivers it forever.
func TestGatewayNodeArtifactSetHealthyWithoutConfigIdentityAcks(t *testing.T) {
	for _, mediaType := range []string{artifactset.MediaTypeSet, artifactset.MediaTypeSegment} {
		t.Run(mediaType, func(t *testing.T) {
			config := DefaultNATSCommandBusConfig()
			store := &testTerminalReceiptStore{receipts: make(map[deploymentKey]*terminalCommandReceipt)}
			bus := &terminalReceiptPublicationBus{
				testTerminalReceiptBus: newTestTerminalReceiptBus(store),
				publication:            DeploymentStatusPublication{Stream: config.StatusStream, Sequence: 130},
			}
			gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
			command := validDeploymentCommand()
			command.ConfigVersionId = uuid.NewString()
			command.Artifacts[0].MediaType = mediaType
			deploymentStatus := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY)
			deploymentStatus.ActiveConfigIdentityCapability = testActiveIdentityCapability()
			delivery := &testTerminalReceiptDelivery{
				fakeCommandDelivery: &fakeCommandDelivery{command: command}, identity: "stream:130",
			}
			pending := pendingCommandSet{commandKey(command): {command: command, deliveries: []CommandDelivery{delivery}}}

			receipt, err := gateway.persistStatusAndAckCommandReceipt(t.Context(), testNodeID, deploymentStatus, pending, true, true)
			if err != nil || receipt == nil || delivery.acks.Load() != 1 || len(pending) != 0 || len(bus.published) != 1 {
				t.Fatalf("node artifact terminal = (%+v, %v), acks=%d pending=%d publishes=%d",
					receipt, err, delivery.acks.Load(), len(pending), len(bus.published))
			}
		})
	}
}
