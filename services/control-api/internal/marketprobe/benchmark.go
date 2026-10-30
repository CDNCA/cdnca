package marketprobe

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BenchmarkMarket is the optional part of Market for node-market admission
// benchmarks (M4). marketclient.Client implements it; a market without it
// simply gets no benchmark relay.
type BenchmarkMarket interface {
	BenchmarkTasks(ctx context.Context) ([]marketclient.BenchmarkTask, error)
	SubmitBenchmarkResults(ctx context.Context, results []marketclient.BenchmarkResult) (int, error)
}

// maxBenchmarksInFlight bounds parallel benchmark downloads from this
// controller's nodes (each pulls at most MaxBenchmarkConnections × 8 MiB).
const maxBenchmarksInFlight = 4

// DispatchBenchmarks relays the open benchmark tasks of this member's nodes
// that advertise CAPABILITY_NAME_MARKET_BENCHMARK, one command per task (a
// download uses the whole timeout), and submits what was executed. Skipped
// downloads are never submitted: they say nothing about the target. Against
// a market without benchmark routes it turns itself off (no error).
func (s *Service) DispatchBenchmarks(ctx context.Context) (int, error) {
	market, ok := s.market.(BenchmarkMarket)
	s.mu.Lock()
	legacy := s.legacyMarket
	s.mu.Unlock()
	if !ok || legacy {
		return 0, nil
	}
	tasks, err := market.BenchmarkTasks(ctx)
	if status, _, rejected := marketclient.Rejected(err); rejected && (status == 404 || status == 405) {
		// The market predates benchmarks: not an error, the feature is off.
		s.markLegacyMarket("benchmark_routes_missing")
		return 0, nil
	}
	if err != nil || len(tasks) == 0 {
		return 0, err
	}
	now := s.cfg.Now()
	s.mu.Lock()
	benchable := s.benchable
	s.mu.Unlock()
	var (
		mu      sync.Mutex
		results []marketclient.BenchmarkResult
		wg      sync.WaitGroup
		slots   = make(chan struct{}, maxBenchmarksInFlight)
	)
	for _, task := range tasks {
		if reason := admitBenchmark(task, benchable, now); reason != "" {
			s.skip(task.ProberNodeID, reason)
			continue
		}
		slots <- struct{}{}
		wg.Add(1)
		go func() {
			defer func() { <-slots; wg.Done() }()
			if r, ok := s.benchmark(ctx, task); ok {
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(results) == 0 {
		return 0, nil
	}
	return market.SubmitBenchmarkResults(ctx, results)
}

// admitBenchmark returns why a task cannot be relayed, or "".
func admitBenchmark(task marketclient.BenchmarkTask, benchable map[string]bool, now time.Time) string {
	switch {
	case !benchable[task.ProberNodeID]:
		return "prober_lacks_market_benchmark"
	case task.Path != contract.BenchmarkPath:
		return "benchmark_path_unsupported"
	case task.Port != 80:
		return "benchmark_port_unsupported"
	case task.Connections < 1 || task.Connections > contract.MaxBenchmarkConnections:
		return "benchmark_connections_invalid"
	case !now.Before(task.ExpiresAt):
		return "task_expired"
	}
	ip, err := netip.ParseAddr(task.TargetIP)
	if err != nil || !contract.Public(ip) {
		return "target_not_public"
	}
	return ""
}

func (s *Service) benchmark(ctx context.Context, task marketclient.BenchmarkTask) (marketclient.BenchmarkResult, bool) {
	timeout := max(contract.MinTimeoutMillis, min(contract.MaxTimeoutMillis, task.TimeoutMillis))
	target := &agentv1.MarketProbeTarget{TaskId: task.RoundID.String(), Ip: task.TargetIP, Port: uint32(task.Port)}
	command := &agentv1.MarketProbeCommand{
		Event:  &commonv1.EventMetadata{EventId: uuid.NewString(), RequestId: uuid.NewString(), OccurredTime: timestamppb.New(s.cfg.Now())},
		NodeId: task.ProberNodeID, Targets: []*agentv1.MarketProbeTarget{target}, TimeoutMillis: uint32(timeout),
		ExpireTime: timestamppb.New(task.ExpiresAt), Benchmark: &agentv1.MarketBenchmarkSpec{Connections: uint32(task.Connections)},
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		return marketclient.BenchmarkResult{}, false
	}
	ctx, cancel := context.WithDeadline(ctx, task.ExpiresAt)
	defer cancel()
	reply, err := s.nodes.Request(ctx, task.ProberNodeID, payload)
	if err != nil {
		if !errors.Is(err, ErrOffline) && !errors.Is(err, context.DeadlineExceeded) {
			s.log.Warn("market benchmark request failed", "node", task.ProberNodeID, "err", err)
		}
		return marketclient.BenchmarkResult{}, false
	}
	if len(reply) == 0 {
		s.skip(task.ProberNodeID, "gateway_refused")
		return marketclient.BenchmarkResult{}, false
	}
	var result agentv1.MarketProbeResult
	if proto.Unmarshal(reply, &result) != nil || result.NodeId != task.ProberNodeID || result.CommandEventId != command.Event.EventId ||
		len(result.Results) != 1 || result.Results[0].GetTaskId() != target.TaskId {
		s.skip(task.ProberNodeID, "invalid_result")
		return marketclient.BenchmarkResult{}, false
	}
	item := result.Results[0]
	out := marketclient.BenchmarkResult{RoundID: task.RoundID, ProberNodeID: task.ProberNodeID,
		Kbps: int64(min(item.ThroughputKbps, 400_000_000)), TTFBMillis: int64(item.TtfbMillis)}
	switch item.Outcome {
	case agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK:
		out.OK = true
	case agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED:
	default:
		s.skip(task.ProberNodeID, "agent_skipped_"+item.ErrorCode)
		return marketclient.BenchmarkResult{}, false
	}
	return out, true
}
