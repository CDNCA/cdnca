package marketprobe

import (
	"bytes"
	"net/http"
	"sync/atomic"
	"testing"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/marketprobe"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func benchmarkCommand(connections uint32, targets ...*agentv1.MarketProbeTarget) *agentv1.MarketProbeCommand {
	c := command(targets...)
	c.Benchmark = &agentv1.MarketBenchmarkSpec{Connections: connections}
	return c
}

func TestBenchmarkDownloadsInParallelAndMeasures(t *testing.T) {
	var hits atomic.Int32
	payload := bytes.Repeat([]byte("x"), contract.BenchmarkBytes)
	server := probeServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != contract.BenchmarkPath || r.Header.Get("Accept-Encoding") != "identity" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		hits.Add(1)
		_, _ = w.Write(payload)
	})
	r := run(t, executor(t, server, Limits{Benchmark: true}), benchmarkCommand(4, target("a", publicV4, 80)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_OK, "")
	if hits.Load() != 4 || r[0].BytesReceived != 4*contract.BenchmarkBytes || r[0].ThroughputKbps == 0 {
		t.Fatalf("hits %d, result %+v", hits.Load(), r[0])
	}
}

func TestBenchmarkFailuresAndRefusals(t *testing.T) {
	short := probeServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("tiny")) })
	r := run(t, executor(t, short, Limits{Benchmark: true}), benchmarkCommand(2, target("a", publicV4, 80)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "short")

	missing := probeServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusMisdirectedRequest) })
	r = run(t, executor(t, missing, Limits{Benchmark: true}), benchmarkCommand(2, target("a", publicV4, 80)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_FAILED, "status")

	// An Agent without the benchmark setting, port 443, private targets and
	// too many connections are refused, never counted against the target.
	r = run(t, executor(t, missing, Limits{}), benchmarkCommand(2, target("a", publicV4, 80)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "benchmark_disabled")
	r = run(t, executor(t, missing, Limits{Benchmark: true}), benchmarkCommand(2, target("a", publicV4, 443),
		target("b", "10.0.0.1", 80)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "rejected_port")
	expect(t, r[1], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "rejected_address")
	r = run(t, executor(t, missing, Limits{Benchmark: true}), benchmarkCommand(9, target("a", publicV4, 80)))
	expect(t, r[0], agentv1.MarketProbeOutcome_MARKET_PROBE_OUTCOME_SKIPPED, "invalid_benchmark")
}
