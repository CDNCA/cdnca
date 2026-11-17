//go:build integration

package gateway

// On the production session loop and a real JetStream: the incident (an execution v3 command
// ended every session with "node upgrade command delivery failed") and the durable handling of commands the
// Gateway refuses (terminated once, the session keeps serving).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func integrationUpgradeCommandWithExecution(t *testing.T, nodeID, installationID string,
	execution func(planID string, revision uint64, batchID string) map[string]any) UpgradeCommandRecord {
	t.Helper()
	wire := upgradeCommandWire{
		Schema: UpgradeCommandSchema, CommandID: uuid.NewString(), PlanID: uuid.NewString(), PlanRevision: 1,
		BatchID: uuid.NewString(), InstallationID: installationID, NodeID: nodeID, Action: "upgrade",
		SignedExecution: []byte("{}"),
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	encoded = gatewayTestCommandWithExecution(t, UpgradeCommandRecord{Encoded: encoded},
		execution(wire.PlanID, wire.PlanRevision, wire.BatchID))
	record, err := decodeUpgradeCommandRecord(encoded)
	if err != nil {
		// Tampered fixtures: keep the identifiers so the test can publish them on the node subject.
		return UpgradeCommandRecord{CommandID: wire.CommandID, PlanID: wire.PlanID, PlanRevision: wire.PlanRevision,
			BatchID: wire.BatchID, InstallationID: installationID, NodeID: nodeID, Encoded: encoded,
			SHA256: sha256.Sum256(encoded)}
	}
	return record
}

func TestGatewayUpgradeSessionServesV3AndTerminatesInvalidCommands(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	connection := connectIntegrationNATS(t, natsURL)
	t.Cleanup(connection.Close)
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ensureUpgradeIntegrationStreams(t, js)
	config := DefaultNATSCommandBusConfig()
	config.AckWait = 300 * time.Millisecond
	config.OperationTimeout = 500 * time.Millisecond
	bus, err := NewNATSUpgradeCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	nodeID, installationID := uuid.NewString(), uuid.NewString()
	consumer := upgradeConsumerConfig(nodeID, config.AckWait, config.MaxWaiting, config.MaxAckPending, config.OperationTimeout)
	ensureUpgradeIntegrationConsumer(t, js, consumer)

	gatewayConfig := DefaultConfig()
	gatewayConfig.GatewayInstanceID = "upgrade-v3-integration"
	gatewayConfig.GatewayVersion = "test"
	gatewayConfig.CommandOperationTimeout = config.OperationTimeout
	service := &Gateway{config: gatewayConfig, upgrades: bus, now: time.Now}
	lease, err := NewMemorySessionCoordinator().Acquire(t.Context(), nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	ctx, cancel := context.WithCancel(context.Background())
	stream := &capturingBidiStream{ctx: ctx, sent: make(chan *agentv1.ConnectResponse, 8)}
	received := make(chan connectReceive, 4)
	done := make(chan error, 1)
	go func() {
		done <- service.serveSessionWithInstallation(
			stream, received, lease, newMessageReplayWindow(defaultMessageReplayWindow), 1,
			nodeIdentity{NodeID: nodeID, SerialNumber: "10"}, "test-agent", versionRange(1, 0),
			&commonv1.ProtocolVersion{Major: 1}, "artifact-key", installationID,
			time.Now().Add(time.Hour), true, false, false, false, false, true, true,
		)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("upgrade Gateway session did not stop")
		}
	}()
	expectCommand := func(command UpgradeCommandRecord) {
		t.Helper()
		select {
		case response := <-stream.sent:
			delivered := response.GetUpgradeCommand()
			if delivered == nil || !bytes.Equal(delivered.Command, command.Encoded) ||
				!bytes.Equal(delivered.CommandSha256, command.SHA256[:]) {
				t.Fatalf("unexpected Gateway response: %+v", response)
			}
		case err := <-done:
			t.Fatalf("session ended instead of delivering the upgrade command: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatal("upgrade command was not delivered")
		}
	}
	expectNothing := func(window time.Duration) {
		t.Helper()
		select {
		case response := <-stream.sent:
			t.Fatalf("refused upgrade command reached the node: %+v", response)
		case err := <-done:
			t.Fatalf("refused upgrade command ended the session: %v", err)
		case <-time.After(window):
		}
	}
	acceptStatus := func(command UpgradeCommandRecord, sequence uint64) {
		t.Helper()
		status := agentUpgradeStatusV2(t, command, 1, "accepted", "", nil)
		statusDigest := sha256.Sum256(status)
		received <- connectReceive{request: &agentv1.ConnectRequest{
			Stream: &commonv1.StreamMetadata{MessageId: uuid.NewString(), SentTime: timestamppb.Now(), Sequence: sequence},
			Payload: &agentv1.ConnectRequest_UpgradeStatus{UpgradeStatus: &agentv1.UpgradeStatus{
				Status: status, StatusSha256: statusDigest[:]}},
		}}
		select {
		case response := <-stream.sent:
			if ack := response.GetUpgradeStatusAck(); ack == nil || ack.CommandId != command.CommandID ||
				ack.PublishedStream != UpgradeStatusStream || ack.PublishedSequence == 0 {
				t.Fatalf("agent status v2 acknowledgement = %+v", response)
			}
		case err := <-done:
			t.Fatalf("agent status v2 ended the session: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatal("agent status v2 was not acknowledged")
		}
	}
	drained := func(message string) {
		t.Helper()
		eventually(t, 3*time.Second, func() bool {
			info, err := js.ConsumerInfo(UpgradeCommandStream, consumer.Durable)
			return err == nil && info.NumAckPending == 0 && info.NumPending == 0
		}, message)
	}

	// Same-version re-release, execution v3.
	reRelease := integrationUpgradeCommandWithExecution(t, nodeID, installationID,
		func(planID string, revision uint64, batchID string) map[string]any {
			return gatewayTestExecution("cdnca.upgrade.execution/v3", planID, revision, batchID, 3, 12, 11)
		})
	publishUpgradeIntegrationCommand(t, js, reRelease, nil)
	expectCommand(reRelease)
	acceptStatus(reRelease, 2)
	drained("accepted v3 command remained pending")

	// A command that can never become valid: terminated once, never redelivered, the session keeps serving.
	tampered := integrationUpgradeCommandWithExecution(t, nodeID, installationID,
		func(planID string, revision uint64, batchID string) map[string]any {
			return gatewayTestExecution("cdnca.upgrade.execution/v3", planID, revision, batchID, 0, 12, 11)
		})
	publishUpgradeIntegrationCommand(t, js, tampered, nil)
	expectNothing(4 * config.AckWait)
	drained("refused upgrade command was not terminated")
	foreign := integrationUpgradeCommandWithExecution(t, nodeID, uuid.NewString(),
		func(planID string, revision uint64, batchID string) map[string]any {
			return gatewayTestExecution("cdnca.upgrade.execution/v3", planID, revision, batchID, 3, 12, 0)
		})
	publishUpgradeIntegrationCommand(t, js, foreign, nil)
	expectNothing(4 * config.AckWait)
	drained("upgrade command for another installation was not terminated")

	// Cross-version v3 and the v2 wire still flow on the same session.
	crossVersion := integrationUpgradeCommandWithExecution(t, nodeID, installationID,
		func(planID string, revision uint64, batchID string) map[string]any {
			return gatewayTestExecution("cdnca.upgrade.execution/v3", planID, revision, batchID, 4, 12, 0)
		})
	publishUpgradeIntegrationCommand(t, js, crossVersion, nil)
	expectCommand(crossVersion)
	acceptStatus(crossVersion, 3)
	legacy := integrationUpgradeCommandWithExecution(t, nodeID, installationID,
		func(planID string, revision uint64, batchID string) map[string]any {
			return gatewayTestExecution(upgradeExecutionV2Schema, planID, revision, batchID, 0, 12, 0)
		})
	publishUpgradeIntegrationCommand(t, js, legacy, nil)
	expectCommand(legacy)
	acceptStatus(legacy, 4)
	drained("accepted commands remained pending")
	expectNothing(2 * config.AckWait)
}
