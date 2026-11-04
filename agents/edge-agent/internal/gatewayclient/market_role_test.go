package gatewayclient

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type recordingRoleAssigner struct{ assigned chan agentv1.MarketProbeRole }

func (a recordingRoleAssigner) AssignMarketRole(_ context.Context, role agentv1.MarketProbeRole) (agentv1.MarketProbeRole, string) {
	a.assigned <- role
	return role, "assigned"
}

func roleCommand(nodeID string, role agentv1.MarketProbeRole) *agentv1.MarketProbeCommand {
	return &agentv1.MarketProbeCommand{Event: &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(),
		OccurredTime: timestamppb.Now()}, NodeId: nodeID, ExpireTime: timestamppb.New(time.Now().Add(time.Minute)), AssignedRole: role}
}

// MARKET_ROLE is declared with an assigner, an assignment
// reaches it (not the probe executor) and is answered with the role in
// effect and no target results.
func TestClientAppliesMarketRoleAssignment(t *testing.T) {
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	assigner := recordingRoleAssigner{assigned: make(chan agentv1.MarketProbeRole, 2)}
	command := roleCommand(config.NodeID, agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET)
	gateway := &marketProbeGateway{enable: true, hellos: make(chan *agentv1.AgentHello, 4),
		results: make(chan *agentv1.MarketProbeResult, 4), commands: []*agentv1.MarketProbeCommand{
			command,
			roleCommand(config.NodeID, agentv1.MarketProbeRole_MARKET_PROBE_ROLE_DISABLED), // not assignable: dropped
		}}
	executor := blockingExecutor{nodeID: config.NodeID, release: make(chan struct{})}
	client := startBufconnClient(t, gateway, config, testTrust(t), WithMarketProbeExecutor(executor), WithMarketRoleAssigner(assigner))
	defer client.cancel()
	if hello := <-gateway.hellos; !hasCapability(hello.GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_MARKET_ROLE) {
		t.Fatalf("hello does not declare MARKET_ROLE: %v", hello.GetCapabilities().GetFeatures())
	}
	select {
	case role := <-assigner.assigned:
		if role != agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET {
			t.Fatalf("assigned %v", role)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("assignment not applied")
	}
	select {
	case result := <-gateway.results:
		if result.CommandEventId != command.Event.EventId || len(result.Results) != 0 ||
			result.EffectiveRole != agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET || result.RoleSource != "assigned" {
			t.Fatalf("role answer %+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no role answer")
	}
	select {
	case result := <-gateway.results:
		t.Fatalf("unassignable role answered: %+v", result)
	case role := <-assigner.assigned:
		t.Fatalf("unassignable role applied: %v", role)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestClientWithoutAssignerDoesNotDeclareMarketRole(t *testing.T) {
	config := testClientConfig(filepath.Join(secureTempDir(t), "journal"))
	gateway := &marketProbeGateway{enable: true, hellos: make(chan *agentv1.AgentHello, 4), results: make(chan *agentv1.MarketProbeResult, 4)}
	client := startBufconnClient(t, gateway, config, testTrust(t),
		WithMarketProbeExecutor(blockingExecutor{nodeID: config.NodeID, release: make(chan struct{})}))
	defer client.cancel()
	if hello := <-gateway.hellos; hasCapability(hello.GetCapabilities(), agentv1.CapabilityName_CAPABILITY_NAME_MARKET_ROLE) {
		t.Fatal("MARKET_ROLE declared without an assigner")
	}
}

func TestRuntimeStatusFollowsMarketRole(t *testing.T) {
	role := agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY
	client := &Client{}
	if err := WithRuntimeStatusProbe(RuntimeStatusProbe{OpenResty: func(context.Context, string) error { return nil },
		MarketProbeRoleNow: func() agentv1.MarketProbeRole { return role }})(client); err != nil {
		t.Fatal(err)
	}
	role = agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET
	if got := client.runtimeStatus(context.Background(), nil).GetMarketProbe(); got != role {
		t.Fatalf("heartbeat market_probe = %v", got)
	}
}
