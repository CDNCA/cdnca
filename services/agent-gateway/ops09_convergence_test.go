package gateway

import (
	"context"
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestOPS09GatewayPersistsExactRollbackActiveIdentity(t *testing.T) {
	bus := &fakeCommandBus{}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	command := validRollbackDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	command.PreviousConfigVersionId = proto.String(uuid.NewString())
	delivery := &fakeCommandDelivery{command: command}
	status := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED)
	status.ActiveConfigIdentityCapability = testActiveIdentityCapability()
	status.ActiveConfigIdentity = testActiveIdentity(command.ConfigVersionId, make([]byte, 32))
	status.Checks = []*agentv1.CheckResult{{
		Name: "edge_active_config_probe", Succeeded: true,
		Summary: "active config runtime probe passed", LatencyDuration: durationpb.New(0),
	}}
	pending := pendingCommandSet{commandKey(command): {command: command, deliveries: []CommandDelivery{delivery}}}

	if err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, status, pending, true); err != nil {
		t.Fatalf("persist rollback convergence status: %v", err)
	}
	if delivery.acks.Load() != 1 || len(pending) != 0 || len(bus.published) != 1 ||
		!proto.Equal(bus.published[0], status) {
		t.Fatalf("rollback convergence persistence = acks:%d pending:%d publications:%d",
			delivery.acks.Load(), len(pending), len(bus.published))
	}
}

func TestOPS09GatewayRejectsRollbackIdentityWithoutRollbackCommand(t *testing.T) {
	command := validDeploymentCommand()
	command.ConfigVersionId = uuid.NewString()
	status := terminalStatusForCommand(t, command, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED)
	status.ActiveConfigIdentityCapability = testActiveIdentityCapability()
	status.ActiveConfigIdentity = testActiveIdentity(command.ConfigVersionId, make([]byte, 32))
	status.Checks = []*agentv1.CheckResult{{
		Name: "edge_active_config_probe", Succeeded: true,
		Summary: "active config runtime probe passed", LatencyDuration: durationpb.New(0),
	}}

	if err := validateDeploymentStatusActiveIdentityCommandBinding(status, command); err == nil {
		t.Fatal("reverted active identity accepted without an authoritative rollback command")
	}
	bus := &fakeCommandBus{}
	gateway := newCommandGateway(t, defaultFakeControl(), bus, nil)
	delivery := &fakeCommandDelivery{command: command}
	pending := pendingCommandSet{commandKey(command): {command: command, deliveries: []CommandDelivery{delivery}}}
	err := gateway.persistStatusAndAckCommand(context.Background(), testNodeID, status, pending, true)
	if grpcstatus.Code(err) != codes.FailedPrecondition || delivery.acks.Load() != 0 || len(bus.published) != 0 {
		t.Fatalf("unbound rollback identity = code:%v acks:%d publications:%d",
			grpcstatus.Code(err), delivery.acks.Load(), len(bus.published))
	}
}
