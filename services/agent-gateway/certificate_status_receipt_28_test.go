package gateway

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func TestGatewayCertificateHealthyWithoutConfigIdentityPersistsReceiptAndAcks28(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	store := &testTerminalReceiptStore{receipts: make(map[deploymentKey]*terminalCommandReceipt)}
	bus := &terminalReceiptPublicationBus{
		testTerminalReceiptBus: newTestTerminalReceiptBus(store),
		publication:            DeploymentStatusPublication{Stream: config.StatusStream, Sequence: 128},
	}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validEncryptedDeploymentCommand(agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE)
	command.ConfigVersionId = uuid.NewString()
	command.Artifacts[0].MediaType = "application/vnd.cdnca.edge-certificate-bundle+json;version=1"
	deploymentStatus := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY)
	deploymentStatus.ActiveConfigIdentityCapability = testActiveIdentityCapability()
	delivery := &testTerminalReceiptDelivery{
		fakeCommandDelivery: &fakeCommandDelivery{command: command}, identity: "stream:128",
	}
	pending := pendingCommandSet{commandKey(command): {
		command: command, deliveries: []CommandDelivery{delivery},
	}}

	receipt, err := gateway.persistStatusAndAckCommandReceipt(
		t.Context(), testNodeID, deploymentStatus, pending, true, true,
	)
	if err != nil || receipt == nil || receipt.PublishedStream != config.StatusStream ||
		receipt.PublishedSequence != 128 || delivery.acks.Load() != 1 || len(pending) != 0 ||
		store.count() != 1 || len(bus.published) != 1 {
		t.Fatalf("certificate terminal receipt = (%+v, %v), acks=%d pending=%d receipts=%d publishes=%d",
			receipt, err, delivery.acks.Load(), len(pending), store.count(), len(bus.published))
	}
}

func TestGatewayConfigurationHealthyWithoutActiveIdentityRemainsPending28(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	store := &testTerminalReceiptStore{receipts: make(map[deploymentKey]*terminalCommandReceipt)}
	bus := &terminalReceiptPublicationBus{
		testTerminalReceiptBus: newTestTerminalReceiptBus(store),
		publication:            DeploymentStatusPublication{Stream: config.StatusStream, Sequence: 129},
	}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	deploymentStatus := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY)
	deploymentStatus.ActiveConfigIdentityCapability = testActiveIdentityCapability()
	delivery := &testTerminalReceiptDelivery{
		fakeCommandDelivery: &fakeCommandDelivery{command: command}, identity: "stream:129",
	}
	pending := pendingCommandSet{commandKey(command): {
		command: command, deliveries: []CommandDelivery{delivery},
	}}

	receipt, err := gateway.persistStatusAndAckCommandReceipt(
		t.Context(), testNodeID, deploymentStatus, pending, true, true,
	)
	if err != nil || receipt != nil || delivery.acks.Load() != 0 || len(pending) != 1 ||
		store.count() != 0 || len(bus.published) != 1 {
		t.Fatalf("configuration without identity = (%+v, %v), acks=%d pending=%d receipts=%d publishes=%d",
			receipt, err, delivery.acks.Load(), len(pending), store.count(), len(bus.published))
	}
}
