package marketprobe

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
	"github.com/cdnca/cdnca/libs/marketproto/nodeaction"
	"github.com/cdnca/cdnca/libs/marketproto/nodeload"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

type fakeMarket struct {
	tasks     []marketclient.ProbeTask
	submitted []marketclient.ProbeResult
	offers    []marketclient.OwnOffer
	reports   map[string][]marketclient.PoolNode
	online    map[string]*int
	loads     []nodeload.Report
	actions   []nodeaction.Report
	// actionErr fails ReportNodeActions (a lost market answer).
	actionErr error
}

func (m *fakeMarket) ReportNodeActions(_ context.Context, self marketclient.Identity, report nodeaction.Report) (marketclient.NodeActionResult, error) {
	report.LeafMemberID = self.MemberID
	m.actions = append(m.actions, report)
	if m.actionErr != nil {
		return marketclient.NodeActionResult{}, m.actionErr
	}
	return marketclient.NodeActionResult{Accepted: len(report.Items)}, nil
}

func (m *fakeMarket) ReportNodeLoad(_ context.Context, self marketclient.Identity, report nodeload.Report) (marketclient.NodeLoadResult, error) {
	report.LeafMemberID = self.MemberID
	m.loads = append(m.loads, report)
	return marketclient.NodeLoadResult{Accepted: len(report.Items)}, nil
}

func (m *fakeMarket) OwnOffers(context.Context) ([]marketclient.OwnOffer, error) {
	return m.offers, nil
}
func (m *fakeMarket) ReportPoolNodes(_ context.Context, pool string, nodes []marketclient.PoolNode, online *int) error {
	if m.reports == nil {
		m.reports = map[string][]marketclient.PoolNode{}
		m.online = map[string]*int{}
	}
	m.reports[pool] = nodes
	m.online[pool] = online
	return nil
}
func (m *fakeMarket) ProbeTasks(context.Context) ([]marketclient.ProbeTask, error) {
	return m.tasks, nil
}
func (m *fakeMarket) SubmitProbeResults(_ context.Context, results []marketclient.ProbeResult) (int, error) {
	m.submitted = append(m.submitted, results...)
	return len(results), nil
}

// fakeNodes answers each command with outcome(task) per target.
type fakeNodes struct {
	mu       sync.Mutex
	commands map[string][]*agentv1.MarketProbeCommand
	reply    func(*agentv1.MarketProbeCommand) ([]byte, error)
}

func (n *fakeNodes) Request(_ context.Context, nodeID string, payload []byte) ([]byte, error) {
	var command agentv1.MarketProbeCommand
	if err := proto.Unmarshal(payload, &command); err != nil {
		return nil, err
	}
	n.mu.Lock()
	if n.commands == nil {
		n.commands = map[string][]*agentv1.MarketProbeCommand{}
	}
	n.commands[nodeID] = append(n.commands[nodeID], &command)
	n.mu.Unlock()
	return n.reply(&command)
}

func answer(outcome func(*agentv1.MarketProbeTarget) (agentv1.MarketProbeOutcome, string)) func(*agentv1.MarketProbeCommand) ([]byte, error) {
	return func(command *agentv1.MarketProbeCommand) ([]byte, error) {
		result := &agentv1.MarketProbeResult{Event: &commonv1.EventMetadata{EventId: uuid.NewString()}, NodeId: command.NodeId,
			CommandEventId: command.Event.EventId}
		for _, target := range command.Targets {
			o, code := outcome(target)
			result.Results = append(result.Results, &agentv1.MarketProbeTargetResult{TaskId: target.TaskId, Outcome: o,
				ErrorCode: code, LatencyMillis: 25})
		}
		return proto.Marshal(result)
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func task(node, ip string, port int, now time.Time) marketclient.ProbeTask {
	return marketclient.ProbeTask{RoundID: uuid.New(), ProberNodeID: node, TargetIP: ip, Port: port, Path: contract.Path,
		TimeoutMillis: 3000, ExpiresAt: now.Add(time.Minute)}
}

func TestDispatchRelaysAdmittedTasksAndNeverVotesSkips(t *testing.T) {
	now := time.Now()
	nodeA, nodeB, stranger := uuid.NewString(), uuid.NewString(), uuid.NewString()
	ok, failed, skipped := task(nodeA, "8.8.8.8", 80, now), task(nodeA, "1.1.1.1", 443, now), task(nodeB, "9.9.9.9", 80, now)
	badPath := task(nodeA, "8.8.4.4", 80, now)
	badPath.Path = "/other"
	badPort := task(nodeA, "8.8.4.4", 8080, now)
	private := task(nodeA, "10.0.0.1", 80, now)
	expired := task(nodeA, "8.8.4.4", 80, now)
	expired.ExpiresAt = now.Add(-time.Second)
	foreign := task(stranger, "8.8.4.4", 80, now)
	market := &fakeMarket{tasks: []marketclient.ProbeTask{ok, failed, skipped, badPath, badPort, private, expired, foreign}}
	nodes := &fakeNodes{reply: answer(func(target *agentv1.MarketProbeTarget) (agentv1.MarketProbeOutcome, string) {
		switch target.TaskId {
		case ok.RoundID.String():
			return agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, ""
		case failed.RoundID.String():
			return agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "timeout"
		}
		return agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "rate_limited"
	})}
	s := New(nil, market, nodes, Config{Now: func() time.Time { return now }}, quiet())
	s.known = map[string]bool{nodeA: true, nodeB: true}
	accepted, err := s.Dispatch(context.Background())
	if err != nil || accepted != 2 {
		t.Fatalf("accepted %d err %v", accepted, err)
	}
	if len(nodes.commands[nodeA]) != 1 || len(nodes.commands[nodeA][0].Targets) != 2 || len(nodes.commands[nodeB]) != 1 ||
		nodes.commands[stranger] != nil {
		t.Fatalf("commands %+v", nodes.commands)
	}
	command := nodes.commands[nodeA][0]
	if command.NodeId != nodeA || command.TimeoutMillis != 3000 || !command.ExpireTime.AsTime().Equal(now.Add(time.Minute)) {
		t.Fatalf("command %+v", command)
	}
	byRound := map[uuid.UUID]marketclient.ProbeResult{}
	for _, r := range market.submitted {
		byRound[r.RoundID] = r
	}
	if got := byRound[ok.RoundID]; !got.OK || got.LatencyMs != 25 || got.ProberNodeID != nodeA {
		t.Fatalf("ok result %+v", got)
	}
	if got, exists := byRound[failed.RoundID]; !exists || got.OK {
		t.Fatalf("failed result %+v", got)
	}
	if _, exists := byRound[skipped.RoundID]; exists {
		t.Fatal("a skipped probe was submitted as a vote")
	}
}

func TestDispatchSubmitsNothingForUnusableReplies(t *testing.T) {
	now := time.Now()
	node := uuid.NewString()
	for name, reply := range map[string]func(*agentv1.MarketProbeCommand) ([]byte, error){
		"offline": func(*agentv1.MarketProbeCommand) ([]byte, error) { return nil, ErrOffline },
		"refused": func(*agentv1.MarketProbeCommand) ([]byte, error) { return nil, nil },
		"garbage": func(*agentv1.MarketProbeCommand) ([]byte, error) { return []byte{0xff, 0x01}, nil },
		"other command": func(c *agentv1.MarketProbeCommand) ([]byte, error) {
			c.Event.EventId = uuid.NewString()
			return answer(func(*agentv1.MarketProbeTarget) (agentv1.MarketProbeOutcome, string) {
				return agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, ""
			})(c)
		},
		"other node": func(c *agentv1.MarketProbeCommand) ([]byte, error) {
			c.NodeId = uuid.NewString()
			return answer(func(*agentv1.MarketProbeTarget) (agentv1.MarketProbeOutcome, string) {
				return agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, ""
			})(c)
		},
		"task mismatch": func(c *agentv1.MarketProbeCommand) ([]byte, error) {
			c.Targets[0].TaskId = uuid.NewString()
			return answer(func(*agentv1.MarketProbeTarget) (agentv1.MarketProbeOutcome, string) {
				return agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, ""
			})(c)
		},
	} {
		market := &fakeMarket{tasks: []marketclient.ProbeTask{task(node, "8.8.8.8", 80, now)}}
		s := New(nil, market, &fakeNodes{reply: reply}, Config{Now: func() time.Time { return now }}, quiet())
		s.known = map[string]bool{node: true}
		if accepted, err := s.Dispatch(context.Background()); err != nil || accepted != 0 || len(market.submitted) != 0 {
			t.Fatalf("%s: accepted %d err %v submitted %+v", name, accepted, err, market.submitted)
		}
	}
}

func TestDispatchChunksAndClampsCommands(t *testing.T) {
	now := time.Now()
	node := uuid.NewString()
	var tasks []marketclient.ProbeTask
	for range contract.MaxTargets + 5 {
		item := task(node, "8.8.8.8", 80, now)
		item.TimeoutMillis = 60_000
		tasks = append(tasks, item)
	}
	tasks[3].ExpiresAt = now.Add(30 * time.Second)
	nodes := &fakeNodes{reply: answer(func(*agentv1.MarketProbeTarget) (agentv1.MarketProbeOutcome, string) {
		return agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, ""
	})}
	market := &fakeMarket{tasks: tasks}
	s := New(nil, market, nodes, Config{Now: func() time.Time { return now }}, quiet())
	s.known = map[string]bool{node: true}
	if accepted, err := s.Dispatch(context.Background()); err != nil || accepted != len(tasks) {
		t.Fatalf("accepted %d err %v", accepted, err)
	}
	commands := nodes.commands[node]
	if len(commands) != 2 {
		t.Fatalf("commands %d", len(commands))
	}
	sizes := map[int]bool{len(commands[0].Targets): true, len(commands[1].Targets): true}
	if !sizes[contract.MaxTargets] || !sizes[5] {
		t.Fatalf("chunk sizes %v", sizes)
	}
	for _, c := range commands {
		if c.TimeoutMillis != contract.MaxTimeoutMillis {
			t.Fatalf("timeout not clamped: %d", c.TimeoutMillis)
		}
		if len(c.Targets) == contract.MaxTargets && !c.ExpireTime.AsTime().Equal(now.Add(30*time.Second)) {
			t.Fatalf("chunk expiry is not the earliest task's: %v", c.ExpireTime.AsTime())
		}
	}
}

func capabilities(t *testing.T, names ...agentv1.CapabilityName) []byte {
	t.Helper()
	value := &agentv1.AgentCapabilities{AgentVersion: "test"}
	for _, name := range names {
		value.Features = append(value.Features, &agentv1.Capability{Name: name, ApiVersion: 1})
	}
	encoded, err := proto.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestFilterKeepsProbeReadyMappedPublicNodes(t *testing.T) {
	capable := capabilities(t, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE)
	old := capabilities(t, agentv1.CapabilityName_CAPABILITY_NAME_NODE_MONITORING)
	ready, dual, legacy, noRegion, noCarrier, private := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	probeOnly, disabled, unreported := uuid.New(), uuid.New(), uuid.New()
	addr := netip.MustParseAddr
	s := New(nil, nil, nil, Config{}, quiet())
	got := s.filter("pool", joinMarket([]candidate{
		// Only join_market nodes enter an offer's pool inventory.
		{NodeID: probeOnly, Address: addr("8.8.8.9"), Region: "广东", Carrier: "电信", Capabilities: capable, Role: role("probe_only")},
		{NodeID: disabled, Address: addr("8.8.8.10"), Region: "广东", Carrier: "电信", Capabilities: capable, Role: role("disabled")},
		{NodeID: unreported, Address: addr("8.8.8.11"), Region: "广东", Carrier: "电信", Capabilities: capable, Role: nil},
	}, []candidate{
		{NodeID: ready, Address: addr("8.8.8.8"), Region: "广东", Carrier: "电信", Capabilities: capable},
		// Rows come ordered by family: the first public address wins, a private one is passed over.
		{NodeID: dual, Address: addr("10.0.0.9"), Region: "香港", Carrier: "BGP", Capabilities: capable},
		{NodeID: dual, Address: addr("1.1.1.1"), Region: "香港", Carrier: "BGP", Capabilities: capable},
		{NodeID: dual, Address: addr("2606:4700::1111"), Region: "香港", Carrier: "BGP", Capabilities: capable},
		{NodeID: legacy, Address: addr("9.9.9.9"), Region: "cn", Carrier: "联通", Capabilities: old},
		{NodeID: legacy, Address: addr("9.9.9.10"), Region: "cn", Carrier: "联通", Capabilities: nil},
		{NodeID: noRegion, Address: addr("8.8.4.4"), Region: "华南", Carrier: "移动", Capabilities: capable},
		{NodeID: noCarrier, Address: addr("8.8.4.5"), Region: "us", Carrier: "Cogent", Capabilities: capable},
		{NodeID: private, Address: addr("192.168.1.1"), Region: "cn", Carrier: "电信", Capabilities: capable},
	}))
	want := []marketclient.PoolNode{
		{NodeID: ready.String(), IP: "8.8.8.8", Region: "cn", Carrier: "telecom"},
		{NodeID: dual.String(), IP: "1.1.1.1", Region: "hk", Carrier: "bgp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("filter = %+v", got)
	}
	if probeCapable([]byte{0xff}) || probeCapable(nil) {
		t.Fatal("broken snapshot treated as capable")
	}
}

func TestSkipLogIsRateLimited(t *testing.T) {
	now := time.Now()
	var buffer syncBuffer
	s := New(nil, nil, nil, Config{Now: func() time.Time { return now }}, slog.New(slog.NewTextHandler(&buffer, nil)))
	for range 5 {
		s.skip("node", reasonRegion)
	}
	s.skip("node", reasonCarrier)
	if buffer.lines() != 2 {
		t.Fatalf("logged %d lines", buffer.lines())
	}
	now = now.Add(61 * time.Minute)
	s.skip("node", reasonRegion)
	if buffer.lines() != 3 {
		t.Fatalf("logged %d lines after an hour", buffer.lines())
	}
}

func TestSyncInventoryClearsPoolsOnlyDelistedOffersUse(t *testing.T) {
	type component = struct {
		Kind        string `json:"kind"`
		NodePoolRef string `json:"node_pool_ref"`
	}
	market := &fakeMarket{offers: []marketclient.OwnOffer{
		{Status: "delisted", Components: []component{{Kind: "own_pool", NodePoolRef: "not-a-uuid-gone"}}},
		{Status: "delisted", Components: []component{{Kind: "own_pool", NodePoolRef: "not-a-uuid-shared"}}},
		{Status: "draft", Components: []component{{Kind: "own_pool", NodePoolRef: "not-a-uuid-shared"},
			{Kind: "upstream", NodePoolRef: ""}}},
	}}
	s := New(nil, market, nil, Config{}, quiet())
	if err := s.SyncInventory(context.Background()); err != nil {
		t.Fatal(err)
	}
	if nodes, cleared := market.reports["not-a-uuid-gone"]; !cleared || len(nodes) != 0 {
		t.Fatalf("delisted-only pool not cleared: %v %v", nodes, cleared)
	}
	if nodes, reported := market.reports["not-a-uuid-shared"]; !reported || len(nodes) != 0 {
		t.Fatalf("draft pool not reported: %v %v", nodes, reported)
	}
	if len(market.reports) != 2 {
		t.Fatalf("reports %v", market.reports)
	}
}

type syncBuffer struct {
	mu    sync.Mutex
	count int
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range p {
		if c == '\n' {
			b.count++
		}
	}
	return len(p), nil
}

func (b *syncBuffer) lines() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.count
}

func role(value string) *string { return &value }

// joinMarket returns fixed followed by candidates marked join_market.
func joinMarket(fixed []candidate, candidates []candidate) []candidate {
	out := append([]candidate(nil), fixed...)
	for _, c := range candidates {
		c.Role = role("join_market")
		out = append(out, c)
	}
	return out
}

func TestFilterFollowsMarketProbeRole(t *testing.T) {
	capable := capabilities(t, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE)
	node := uuid.New()
	s := New(nil, nil, nil, Config{}, quiet())
	at := func(r *string) []marketclient.PoolNode {
		return s.filter("pool", []candidate{{NodeID: node, Address: netip.MustParseAddr("8.8.8.8"), Region: "广东",
			Carrier: "电信", Capabilities: capable, Role: r}})
	}
	if got := at(role("probe_only")); len(got) != 0 {
		t.Fatalf("probe-only node reported: %+v", got)
	}
	if got := at(role("join_market")); len(got) != 1 || got[0].NodeID != node.String() {
		t.Fatalf("join_market node not reported: %+v", got)
	}
	if got := at(role("disabled")); len(got) != 0 {
		t.Fatalf("disabled node reported: %+v", got)
	}
}

type fakePlugins struct {
	codes map[uuid.UUID][]string
	err   error
	asked []uuid.UUID
}

func (f *fakePlugins) NodePluginCodes(_ context.Context, ids []uuid.UUID) (map[uuid.UUID][]string, error) {
	f.asked = append(f.asked, ids...)
	return f.codes, f.err
}

// TestInventoryReportsPerNodePlugins: each reported node carries its own
// plugins; a pool whose plugins cannot be read is not reported this round.
func TestInventoryReportsPerNodePlugins(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	plugins := &fakePlugins{codes: map[uuid.UUID][]string{a: {"module.autodefense", "pack.crs"}}}
	s := New(nil, &fakeMarket{}, nil, Config{Plugins: plugins}, quiet())
	nodes := []marketclient.PoolNode{{NodeID: a.String()}, {NodeID: b.String()}}
	if err := s.withPlugins(context.Background(), nodes); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(nodes[0].Plugins, []string{"module.autodefense", "pack.crs"}) || nodes[1].Plugins != nil ||
		!reflect.DeepEqual(plugins.asked, []uuid.UUID{a, b}) {
		t.Fatalf("nodes %+v asked %v", nodes, plugins.asked)
	}
	plugins.err = errors.New("db down")
	if err := s.withPlugins(context.Background(), nodes); err == nil {
		t.Fatal("plugin read failure must fail the pool report")
	}
	// Without a plugin source nothing is filled or asked.
	plain := New(nil, &fakeMarket{}, nil, Config{}, quiet())
	if err := plain.withPlugins(context.Background(), []marketclient.PoolNode{{NodeID: a.String()}}); err != nil {
		t.Fatal(err)
	}
}
