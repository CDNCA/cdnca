package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/marketprobe"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

// marketProbeSettings are two separate switches:
//
//   - Enabled (probe only, the installer default): the node runs probes the
//     controller asks for (external probing of other nodes' public IPs, per
//     monitoring group) and answers the probe path on port 80 so others can
//     probe it. It does not join the node market and takes no market traffic.
//   - JoinMarket: the node also takes part in node-market admission: it
//     serves the benchmark object and, with Benchmark, runs benchmark
//     downloads against other sellers' nodes (CAPABILITY_NAME_MARKET_BENCHMARK).
//
// Zero limits take the executor's defaults (8 concurrent, 120 per minute).
type marketProbeSettings struct {
	Enabled     bool `json:"enabled"`
	JoinMarket  bool `json:"join_market"`
	Concurrency int  `json:"concurrency"`
	PerMinute   int  `json:"per_minute"`
	Benchmark   bool `json:"benchmark"`
}

func (s marketProbeSettings) validate() error {
	if s.Concurrency < 0 || s.Concurrency > 32 || s.PerMinute < 0 || s.PerMinute > 600 {
		return errors.New("market_probe.concurrency must be 0..32 and market_probe.per_minute 0..600")
	}
	if s.JoinMarket && !s.Enabled {
		return errors.New("market_probe.join_market requires market_probe.enabled")
	}
	if s.Benchmark && !s.JoinMarket {
		return errors.New("market_probe.benchmark requires market_probe.join_market")
	}
	return nil
}

// role is the market probe role the heartbeat reports
// (EdgeRuntimeStatus.market_probe); validate keeps JoinMarket within Enabled.
func (s marketProbeSettings) role() agentv1.MarketProbeRole {
	switch {
	case !s.Enabled:
		return agentv1.MarketProbeRole_MARKET_PROBE_ROLE_DISABLED
	case s.JoinMarket:
		return agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET
	default:
		return agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY
	}
}

func assembleMarketProbe(settings marketProbeSettings, nodeID string) (*marketprobe.Executor, error) {
	if !settings.Enabled {
		return nil, nil
	}
	executor, err := marketprobe.New(nodeID, marketprobe.Limits{Concurrency: settings.Concurrency,
		PerMinute: settings.PerMinute, Benchmark: settings.Benchmark}, time.Now)
	if err != nil {
		return nil, fmt.Errorf("configure market probe executor: %w", err)
	}
	return executor, nil
}
