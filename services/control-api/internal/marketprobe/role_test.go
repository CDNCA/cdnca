package marketprobe

import (
	"context"
	"net/netip"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

// Role assignments and the reasons a pool node is left out.

func roleReply(role agentv1.MarketProbeRole, source string) func(*agentv1.MarketProbeCommand) ([]byte, error) {
	return func(command *agentv1.MarketProbeCommand) ([]byte, error) {
		return proto.Marshal(&agentv1.MarketProbeResult{NodeId: command.NodeId, CommandEventId: command.Event.EventId,
			EffectiveRole: role, RoleSource: source})
	}
}

func TestAssignSendsRoleAndReadsAnswer(t *testing.T) {
	node := uuid.NewString()
	nodes := &fakeNodes{reply: roleReply(agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY, RoleSourceLocalLeave)}
	s := New(nil, nil, nodes, Config{}, quiet())
	got, err := s.assign(context.Background(), node, agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET)
	if err != nil || got.Role != agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY || got.Source != RoleSourceLocalLeave ||
		got.Desired != agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET {
		t.Fatalf("answer %+v %v", got, err)
	}
	sent := nodes.commands[node][0]
	if sent.AssignedRole != agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET || len(sent.Targets) != 0 || sent.Benchmark != nil {
		t.Fatalf("sent %v", sent)
	}
	for name, reply := range map[string]func(*agentv1.MarketProbeCommand) ([]byte, error){
		"refused":  func(*agentv1.MarketProbeCommand) ([]byte, error) { return nil, nil },
		"disabled": roleReply(agentv1.MarketProbeRole_MARKET_PROBE_ROLE_DISABLED, RoleSourceAssigned),
		"source":   roleReply(agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET, "guess"),
		"other command": func(command *agentv1.MarketProbeCommand) ([]byte, error) {
			return proto.Marshal(&agentv1.MarketProbeResult{NodeId: command.NodeId, CommandEventId: uuid.NewString(),
				EffectiveRole: agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET, RoleSource: RoleSourceAssigned})
		},
	} {
		s := New(nil, nil, &fakeNodes{reply: reply}, Config{}, quiet())
		if _, err := s.assign(context.Background(), node, agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET); err == nil {
			t.Fatalf("%s answer accepted", name)
		}
	}
}

func TestAssignmentDue(t *testing.T) {
	join := agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET
	probe := agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY
	now := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	joined := roleAnswer{Desired: join, Role: join, Source: RoleSourceAssigned, At: now.Add(-10 * time.Minute)}
	fresh := joined
	fresh.At = now.Add(-30 * time.Second)
	for _, test := range []struct {
		name     string
		previous roleAnswer
		known    bool
		desired  agentv1.MarketProbeRole
		presence *string
		want     bool
	}{
		{"never asked", roleAnswer{}, false, join, role("probe_only"), true},
		{"answered, heartbeat agrees", joined, true, join, role("join_market"), false},
		{"answered, no heartbeat", joined, true, join, nil, false},
		{"answered just now, heartbeat not yet in", fresh, true, join, role("probe_only"), false},
		{"node restarted probe-only", joined, true, join, role("probe_only"), true},
		{"pool left the offer", joined, true, probe, role("join_market"), true},
		{"local leave stays", roleAnswer{Desired: join, Role: probe, Source: RoleSourceLocalLeave, At: joined.At}, true, join,
			role("probe_only"), false},
	} {
		if got := assignmentDue(test.previous, test.known, test.desired, test.presence, now); got != test.want {
			t.Errorf("%s: due = %v", test.name, got)
		}
	}
}

func TestClassifySaysWhyNodesAreLeftOut(t *testing.T) {
	capable := capabilities(t, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE)
	old := capabilities(t, agentv1.CapabilityName_CAPABILITY_NAME_NODE_MONITORING)
	ready, legacy, probeOnly, private, noRegion, noCarrier := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	addr := netip.MustParseAddr
	join := role(roleJoinMarket)
	nodes, excluded := classify([]candidate{
		{NodeID: ready, Address: addr("8.8.8.8"), Region: "CN", Carrier: "电信", Capabilities: capable, Role: join},
		{NodeID: legacy, Address: addr("9.9.9.9"), Region: "CN", Carrier: "电信", Capabilities: old, Role: join},
		{NodeID: probeOnly, Address: addr("9.9.9.10"), Region: "CN", Carrier: "电信", Capabilities: capable, Role: role("probe_only")},
		{NodeID: private, Address: addr("10.0.0.1"), Region: "CN", Carrier: "电信", Capabilities: capable, Role: join},
		{NodeID: private, Address: addr("10.0.0.2"), Region: "CN", Carrier: "电信", Capabilities: capable, Role: join},
		{NodeID: noRegion, Address: addr("8.8.4.4"), Region: "华南", Carrier: "移动", Capabilities: capable, Role: join},
		// A node whose IP 归属 is region CN with no carrier.
		{NodeID: noCarrier, Address: addr("11.0.0.118"), Region: "CN", Carrier: "", Capabilities: capable, Role: join},
	})
	if len(nodes) != 1 || nodes[0].NodeID != ready.String() {
		t.Fatalf("reported %v", nodes)
	}
	want := map[uuid.UUID]Excluded{
		legacy:    {NodeID: legacy, Reason: ReasonAgentLacksProbe},
		probeOnly: {NodeID: probeOnly, Reason: ReasonNotJoinMarket},
		private:   {NodeID: private, Reason: ReasonAddressNotPublic, Value: "10.0.0.1"},
		noRegion:  {NodeID: noRegion, Reason: ReasonRegionUnmapped, Value: "华南"},
		noCarrier: {NodeID: noCarrier, Reason: ReasonCarrierUnmapped, Value: ""},
	}
	if len(excluded) != len(want) {
		t.Fatalf("excluded %v", excluded)
	}
	for _, e := range excluded {
		if want[e.NodeID] != e {
			t.Errorf("excluded %+v, want %+v", e, want[e.NodeID])
		}
	}
}

func TestWithAnswersOverridesHeartbeatRole(t *testing.T) {
	node := uuid.New()
	candidates := []candidate{{NodeID: node, Role: role("probe_only")}}
	got := withAnswers(candidates, map[string]roleAnswer{node.String(): {Role: agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET}})
	if *got[0].Role != roleJoinMarket || *candidates[0].Role != "probe_only" {
		t.Fatalf("role %v (input %v)", *got[0].Role, *candidates[0].Role)
	}
}

// The seller's pool report gives each node the inventory's reason.
func TestBuildReportExplainsEveryNode(t *testing.T) {
	capable := capabilities(t, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_ROLE)
	ready, empty, idle, off := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	addr := netip.MustParseAddr
	nodes := []poolNode{
		{NodeID: ready, Name: "a", Active: true, Address: "8.8.8.8", Region: "CN", Carrier: "电信", Role: role("probe_only"), Snapshot: capable},
		{NodeID: empty, Name: "118", Active: true, Address: "11.0.0.118", Region: "CN", Role: role("join_market"), Snapshot: capable},
		{NodeID: idle, Name: "c", Active: true, Address: "8.8.8.9", Region: "CN", Carrier: "电信", Snapshot: capable},
		{NodeID: off, Name: "d", Active: false, Address: "8.8.8.10", Region: "CN", Carrier: "电信"},
	}
	candidates := []candidate{
		{NodeID: ready, Address: addr("8.8.8.8"), Region: "CN", Carrier: "电信", Capabilities: capable, Role: role("probe_only")},
		{NodeID: empty, Address: addr("11.0.0.118"), Region: "CN", Capabilities: capable, Role: role("join_market")},
	}
	// ready joined this round: its answer stands for the heartbeat.
	answers := map[string]roleAnswer{ready.String(): {Role: agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET, Source: RoleSourceAssigned}}
	report := buildReport("", nodes, candidates, answers)
	if report.Probe != "running" || report.Total != 4 || report.Reportable != 1 {
		t.Fatalf("report %+v", report)
	}
	want := map[uuid.UUID]string{ready: "", empty: ReasonCarrierUnmapped, idle: ReasonNotServing, off: ReasonNodeInactive}
	for _, n := range report.Nodes {
		if n.Reason != want[n.NodeID] {
			t.Errorf("%s reason %q, want %q", n.Name, n.Reason, want[n.NodeID])
		}
	}
	if report.Nodes[0].Role != "join_market" || report.Nodes[0].RoleSource != RoleSourceAssigned || !report.Nodes[0].RoleCapable {
		t.Fatalf("role %+v", report.Nodes[0])
	}
	if off := buildReport(OffNoEdgeNATS, nodes, candidates, answers); off.Probe != OffNoEdgeNATS || off.Reportable != 0 {
		t.Fatalf("reports off: %+v", off)
	}
	if NewReporter(nil, nil, "").off != OffDisabled {
		t.Fatal("reporter without a service must say reports are off")
	}
}
