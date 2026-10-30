package marketprobe

import (
	"context"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

type benchMarket struct {
	fakeMarket
	benchTasks []marketclient.BenchmarkTask
	benchOut   []marketclient.BenchmarkResult
}

func (m *benchMarket) BenchmarkTasks(context.Context) ([]marketclient.BenchmarkTask, error) {
	return m.benchTasks, nil
}
func (m *benchMarket) SubmitBenchmarkResults(_ context.Context, r []marketclient.BenchmarkResult) (int, error) {
	m.benchOut = append(m.benchOut, r...)
	return len(r), nil
}

func TestCapabilitySnapshotsGateProbeAndBenchmark(t *testing.T) {
	snapshot := func(names ...agentv1.CapabilityName) []byte {
		c := &agentv1.AgentCapabilities{}
		for _, n := range names {
			c.Features = append(c.Features, &agentv1.Capability{Name: n, ApiVersion: 1})
		}
		raw, _ := proto.Marshal(c)
		return raw
	}
	both := snapshot(agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_BENCHMARK)
	if !probeCapable(both) || !hasCapability(both, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_BENCHMARK) {
		t.Fatal("both capabilities")
	}
	if hasCapability(snapshot(agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE), agentv1.CapabilityName_CAPABILITY_NAME_MARKET_BENCHMARK) {
		t.Fatal("probe-only node reported as benchmark capable")
	}
}

func TestDispatchBenchmarksRelaysOnlyToCapableNodes(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	capable, old := uuid.NewString(), uuid.NewString()
	round := uuid.New()
	task := func(node string) marketclient.BenchmarkTask {
		return marketclient.BenchmarkTask{RoundID: round, ProberNodeID: node, TargetIP: "8.8.8.8", Port: 80, Path: contract.BenchmarkPath,
			Connections: 4, TimeoutMillis: 10_000, ExpiresAt: now.Add(time.Minute)}
	}
	bad := task(capable)
	bad.TargetIP = "10.0.0.1"
	market := &benchMarket{benchTasks: []marketclient.BenchmarkTask{task(capable), task(old), bad}}
	nodes := &fakeNodes{reply: func(c *agentv1.MarketProbeCommand) ([]byte, error) {
		if c.Benchmark.GetConnections() != 4 || len(c.Targets) != 1 || c.TimeoutMillis != 10_000 {
			t.Errorf("command %+v", c)
		}
		r := &agentv1.MarketProbeResult{Event: &commonv1.EventMetadata{EventId: uuid.NewString()}, NodeId: c.NodeId,
			CommandEventId: c.Event.EventId, Results: []*agentv1.MarketProbeTargetResult{{TaskId: c.Targets[0].TaskId,
				Outcome: agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, ThroughputKbps: 150_000, TtfbMillis: 80}}}
		return proto.Marshal(r)
	}}
	s := New(nil, market, nodes, Config{Now: func() time.Time { return now }}, quiet())
	s.benchable = map[string]bool{capable: true, old: false}
	n, err := s.DispatchBenchmarks(context.Background())
	if err != nil || n != 1 || len(market.benchOut) != 1 {
		t.Fatalf("dispatch: %d %v %+v", n, err, market.benchOut)
	}
	got := market.benchOut[0]
	if !got.OK || got.Kbps != 150_000 || got.TTFBMillis != 80 || got.ProberNodeID != capable || len(nodes.commands[old]) != 0 {
		t.Fatalf("result %+v, commands to old node %d", got, len(nodes.commands[old]))
	}

	// A skipped download is not submitted.
	market.benchOut = nil
	nodes.reply = answer(func(*agentv1.MarketProbeTarget) (agentv1.MarketProbeOutcome, string) {
		return agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "benchmark_disabled"
	})
	market.benchTasks = []marketclient.BenchmarkTask{task(capable)}
	if n, err := s.DispatchBenchmarks(context.Background()); err != nil || n != 0 || len(market.benchOut) != 0 {
		t.Fatalf("skipped submitted: %d %v %+v", n, err, market.benchOut)
	}
	// A market client without benchmark support is a no-op.
	plain := New(nil, &fakeMarket{}, nodes, Config{Now: func() time.Time { return now }}, quiet())
	if n, err := plain.DispatchBenchmarks(context.Background()); n != 0 || err != nil {
		t.Fatalf("plain market: %d %v", n, err)
	}
}

// legacyMarket behaves like a market-service without M4: strict JSON rejects
// the benchmark field, and there are no benchmark routes.
type legacyMarket struct {
	benchMarket
	reports [][]marketclient.PoolNode
}

func (m *legacyMarket) ReportPoolNodes(_ context.Context, _ string, nodes []marketclient.PoolNode, _ *int) error {
	for _, n := range nodes {
		if n.Benchmark {
			return &marketclient.RejectedError{Status: 400, Code: "invalid_json"}
		}
	}
	m.reports = append(m.reports, nodes)
	return nil
}
func (m *legacyMarket) BenchmarkTasks(context.Context) ([]marketclient.BenchmarkTask, error) {
	return nil, &marketclient.RejectedError{Status: 404, Code: ""}
}

// A controller upgraded before its market keeps reporting inventory and
// simply does not relay benchmarks.
func TestNewControllerWithOldMarket(t *testing.T) {
	market := &legacyMarket{}
	s := New(nil, market, &fakeNodes{}, Config{}, quiet())
	nodes := []marketclient.PoolNode{{NodeID: "a", IP: "8.8.8.8", Region: "cn", Carrier: "telecom", Benchmark: true}}
	if err := s.reportPool(context.Background(), "p", nodes, nil); err != nil {
		t.Fatalf("report against an old market: %v", err)
	}
	if len(market.reports) != 1 || market.reports[0][0].Benchmark || !nodes[0].Benchmark {
		t.Fatalf("reports %+v (caller slice must stay untouched)", market.reports)
	}
	if err := s.reportPool(context.Background(), "p", nodes, nil); err != nil || len(market.reports) != 2 {
		t.Fatalf("second report: %v %d", err, len(market.reports))
	}
	if n, err := s.DispatchBenchmarks(context.Background()); n != 0 || err != nil {
		t.Fatalf("benchmarks against an old market: %d %v", n, err)
	}
	// Discovered through the routes alone (no benchmark-capable node yet).
	fresh := New(nil, &legacyMarket{}, &fakeNodes{}, Config{}, quiet())
	if n, err := fresh.DispatchBenchmarks(context.Background()); n != 0 || err != nil || !fresh.legacyMarket {
		t.Fatalf("404 must turn benchmarks off quietly: %d %v %v", n, err, fresh.legacyMarket)
	}
}

// A v2 agent (host targets) still serves market IP probes; host probes for
// the aggregated edge need v2.
func TestMarketProbeVersions(t *testing.T) {
	encode := func(version uint32) []byte {
		raw, err := proto.Marshal(&agentv1.AgentCapabilities{AgentVersion: "test", Features: []*agentv1.Capability{{
			Name: agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, ApiVersion: version}}})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	v1, v2 := encode(1), encode(2)
	if !probeCapable(v1) || !probeCapable(v2) {
		t.Fatal("market inventory must accept MARKET_PROBE v1 and v2")
	}
	if HasCapability(v1, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, HostProbeVersion) ||
		!HasCapability(v2, agentv1.CapabilityName_CAPABILITY_NAME_MARKET_PROBE, HostProbeVersion) {
		t.Fatal("host probes need MARKET_PROBE v2")
	}
}
