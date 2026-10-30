package gateway

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

const testURLAuthArtifactMediaType = "application/vnd.cdnca.edge-url-auth-bundle+json;version=1"

func TestGatewayValidatesURLAuthArtifactContractBeforeDispatch(t *testing.T) {
	gateway := newCommandGateway(t, defaultFakeControl(), &fakeCommandBus{}, nil)
	valid := validURLAuthDeploymentCommand()
	if err := gateway.validateDeploymentCommand(valid, valid.Artifacts[0].GetRecipientKeyId(), true); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*agentv1.DeploymentCommand)
	}{
		{name: "multiple artifacts", mutate: func(value *agentv1.DeploymentCommand) { value.Artifacts = append(value.Artifacts, value.Artifacts[0]) }},
		{name: "wrong kind", mutate: func(value *agentv1.DeploymentCommand) {
			value.Artifacts[0].Kind = agentv1.ArtifactKind_ARTIFACT_KIND_CONFIGURATION
		}},
		{name: "compressed", mutate: func(value *agentv1.DeploymentCommand) {
			value.Artifacts[0].Compression = agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_ZSTD
		}},
		{name: "plaintext", mutate: func(value *agentv1.DeploymentCommand) {
			value.Artifacts[0].EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_NONE
			value.Artifacts[0].RecipientKeyId = nil
		}},
		{name: "missing scope", mutate: func(value *agentv1.DeploymentCommand) { value.ConfigurationScopeId = nil }},
		{name: "nil scope", mutate: func(value *agentv1.DeploymentCommand) { value.ConfigurationScopeId = ptr(uuid.Nil.String()) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := validURLAuthDeploymentCommand()
			test.mutate(candidate)
			if err := gateway.validateDeploymentCommand(candidate, valid.Artifacts[0].GetRecipientKeyId(), true); err == nil {
				t.Fatal("invalid URL auth command accepted")
			}
		})
	}
}

func TestGatewayPersistsIndependentURLAuthTerminalReceiptsForTwoNodesAndForwardRecovery(t *testing.T) {
	config := DefaultNATSCommandBusConfig()
	store := &testTerminalReceiptStore{receipts: make(map[deploymentKey]*terminalCommandReceipt)}
	bus := &terminalReceiptPublicationBus{
		testTerminalReceiptBus: newTestTerminalReceiptBus(store),
		publication:            DeploymentStatusPublication{Stream: config.StatusStream, Sequence: 909},
	}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	nodes := []string{testNodeID, uuid.NewString()}
	for index, nodeID := range nodes {
		command := validURLAuthDeploymentCommand()
		if index == 1 {
			command.ConfigVersionId = uuid.NewString()
			command.Artifacts[0].ArtifactId = uuid.NewString()
			command.Artifacts[0].Sha256[0] = 1
		}
		status := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY)
		status.ActiveConfigIdentityCapability = testActiveIdentityCapability()
		delivery := &testTerminalReceiptDelivery{fakeCommandDelivery: &fakeCommandDelivery{command: command}, identity: "url-auth-node-" + nodeID}
		pending := pendingCommandSet{commandKey(command): {command: command, deliveries: []CommandDelivery{delivery}}}
		receipt, err := gateway.persistStatusAndAckCommandReceipt(t.Context(), nodeID, status, pending, true, true)
		if err != nil || receipt == nil || receipt.NodeID != nodeID || receipt.ConfigVersionID != command.ConfigVersionId ||
			receipt.ArtifactSetSHA256 == "" || receipt.PublishedStream != config.StatusStream || receipt.PublishedSequence != 909 ||
			delivery.acks.Load() != 1 || len(pending) != 0 {
			t.Fatalf("node %d receipt = (%+v, %v), acks=%d pending=%d", index, receipt, err, delivery.acks.Load(), len(pending))
		}
	}
	if store.count() != 2 || len(bus.published) != 2 {
		t.Fatalf("multi-node receipt count=%d publications=%d", store.count(), len(bus.published))
	}
}

func validURLAuthDeploymentCommand() *agentv1.DeploymentCommand {
	command := validEncryptedDeploymentCommand(agentv1.ArtifactKind_ARTIFACT_KIND_NODE_SECRET_BUNDLE)
	command.ConfigVersionId = uuid.NewString()
	command.ConfigurationScopeId = ptr(uuid.NewString())
	command.Artifacts[0].MediaType = testURLAuthArtifactMediaType
	command.Artifacts[0].Compression = agentv1.ArtifactCompression_ARTIFACT_COMPRESSION_NONE
	return command
}

func ptr(value string) *string { return &value }
