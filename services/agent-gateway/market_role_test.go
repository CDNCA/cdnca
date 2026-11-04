package gateway

import (
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// A role assignment is a MarketProbeCommand with
// assigned_role and no targets; the Agent answers the role in effect.

func testMarketRoleCommand(nodeID string, role agentv1.MarketProbeRole) *agentv1.MarketProbeCommand {
	return &agentv1.MarketProbeCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: nodeID, ExpireTime: timestamppb.New(time.Now().Add(time.Minute)), AssignedRole: role,
	}
}

func testMarketRoleResult(command *agentv1.MarketProbeCommand, role agentv1.MarketProbeRole, source string) *agentv1.MarketProbeResult {
	return &agentv1.MarketProbeResult{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.Now()},
		NodeId: command.NodeId, CommandEventId: command.Event.EventId, EffectiveRole: role, RoleSource: source,
	}
}

func TestValidateMarketRoleAssignment(t *testing.T) {
	now := time.Now()
	join := testMarketRoleCommand(testNodeID, agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET)
	if err := validateMarketProbeCommand(join, testNodeID, now); err != nil {
		t.Fatalf("valid assignment rejected: %v", err)
	}
	for name, mutate := range map[string]func(*agentv1.MarketProbeCommand){
		"disabled role": func(value *agentv1.MarketProbeCommand) {
			value.AssignedRole = agentv1.MarketProbeRole_MARKET_PROBE_ROLE_DISABLED
		},
		"unknown role": func(value *agentv1.MarketProbeCommand) { value.AssignedRole = 9 },
		"with target": func(value *agentv1.MarketProbeCommand) {
			value.Targets = []*agentv1.MarketProbeTarget{{TaskId: "a", Ip: "8.8.8.8", Port: 80}}
		},
		"benchmark": func(value *agentv1.MarketProbeCommand) {
			value.Benchmark = &agentv1.MarketBenchmarkSpec{Connections: 1}
		},
		"other node": func(value *agentv1.MarketProbeCommand) { value.NodeId = uuid.NewString() },
		"expired":    func(value *agentv1.MarketProbeCommand) { value.ExpireTime = timestamppb.New(now.Add(-time.Second)) },
	} {
		changed := proto.Clone(join).(*agentv1.MarketProbeCommand)
		mutate(changed)
		if err := validateMarketProbeCommand(changed, testNodeID, now); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	result := testMarketRoleResult(join, agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY, "local_leave")
	if err := validateMarketProbeResult(result, join, testNodeID); err != nil {
		t.Fatalf("valid role answer rejected: %v", err)
	}
	for name, mutate := range map[string]func(*agentv1.MarketProbeResult){
		"no role": func(value *agentv1.MarketProbeResult) { value.EffectiveRole = 0 },
		"disabled": func(value *agentv1.MarketProbeResult) {
			value.EffectiveRole = agentv1.MarketProbeRole_MARKET_PROBE_ROLE_DISABLED
		},
		"source": func(value *agentv1.MarketProbeResult) { value.RoleSource = "guess" },
		"results": func(value *agentv1.MarketProbeResult) {
			value.Results = []*agentv1.MarketProbeTargetResult{{TaskId: "a", Outcome: 1}}
		},
		"no source": func(value *agentv1.MarketProbeResult) { value.RoleSource = "" },
	} {
		changed := proto.Clone(result).(*agentv1.MarketProbeResult)
		mutate(changed)
		if err := validateMarketProbeResult(changed, join, testNodeID); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// A probe result never carries a role.
	probe := testMarketProbeCommand(testNodeID)
	answer := testMarketProbeResult(probe)
	answer.EffectiveRole, answer.RoleSource = agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET, "assigned"
	if err := validateMarketProbeResult(answer, probe, testNodeID); err == nil {
		t.Fatal("probe result with a role accepted")
	}
}

func TestSessionMarketProbesRefuseRolesWithoutCapability(t *testing.T) {
	now := time.Now()
	replies := make(chan *agentv1.MarketProbeResult, 4)
	command := testMarketRoleCommand(testNodeID, agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET)
	older := &sessionMarketProbes{pending: map[string]pendingMarketProbe{}}
	if _, ok := older.admit(&marketProbeRequestStub{command: command, replies: replies}, testNodeID, now); ok || <-replies != nil {
		t.Fatal("role assignment admitted for an Agent without MARKET_ROLE")
	}
	// Probes still go to that Agent.
	if _, ok := older.admit(&marketProbeRequestStub{command: testMarketProbeCommand(testNodeID), replies: replies}, testNodeID, now); !ok {
		t.Fatal("probe refused")
	}
	session := &sessionMarketProbes{pending: map[string]pendingMarketProbe{}, roles: true}
	if _, ok := session.admit(&marketProbeRequestStub{command: command, replies: replies}, testNodeID, now); !ok {
		t.Fatal("role assignment refused for an Agent with MARKET_ROLE")
	}
	result := testMarketRoleResult(command, agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET, "assigned")
	if err := session.settle(result, testNodeID); err != nil {
		t.Fatal(err)
	}
	if got := <-replies; !proto.Equal(got, result) {
		t.Fatalf("replied %v", got)
	}
	if !marketRoleCapable([]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_MARKET_ROLE, ApiVersion: 1}}) ||
		marketRoleCapable([]*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, ApiVersion: 3}}) {
		t.Fatal("market role capability detection")
	}
}
