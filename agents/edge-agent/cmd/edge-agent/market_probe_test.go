package main

import (
	"testing"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
)

func TestMarketProbeSettings(t *testing.T) {
	executor, err := assembleMarketProbe(marketProbeSettings{}, "8f3c2d1e-0000-4000-8000-000000000001")
	if err != nil || executor != nil {
		t.Fatalf("disabled by default: %v %v", executor, err)
	}
	if defaultFileConfig().MarketProbe.Enabled {
		t.Fatal("market probe must default off")
	}
	executor, err = assembleMarketProbe(marketProbeSettings{Enabled: true}, "8f3c2d1e-0000-4000-8000-000000000001")
	if err != nil || executor == nil {
		t.Fatalf("enabled: %v %v", executor, err)
	}
	for _, bad := range []marketProbeSettings{{Concurrency: -1}, {Concurrency: 33}, {PerMinute: -1}, {PerMinute: 601}} {
		if bad.validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if (marketProbeSettings{Enabled: true, Concurrency: 4, PerMinute: 60}).validate() != nil {
		t.Fatal("rejected valid limits")
	}
	if (marketProbeSettings{Benchmark: true}).validate() == nil {
		t.Fatal("benchmark without market probe accepted")
	}
	// Probe only and joining the market are separate switches.
	if (marketProbeSettings{JoinMarket: true}).validate() == nil {
		t.Fatal("join_market without enabled accepted")
	}
	if (marketProbeSettings{Enabled: true, Benchmark: true}).validate() == nil {
		t.Fatal("benchmark without join_market accepted")
	}
	executor, err = assembleMarketProbe(marketProbeSettings{Enabled: true}, "8f3c2d1e-0000-4000-8000-000000000001")
	if err != nil || executor.BenchmarkEnabled() {
		t.Fatalf("probe only must not benchmark: %v %v", executor, err)
	}
	executor, err = assembleMarketProbe(marketProbeSettings{Enabled: true, JoinMarket: true, Benchmark: true}, "8f3c2d1e-0000-4000-8000-000000000001")
	if err != nil || !executor.BenchmarkEnabled() {
		t.Fatalf("benchmark: %v %v", executor, err)
	}
}

func TestMarketProbeSettingsRole(t *testing.T) {
	for _, test := range []struct {
		settings marketProbeSettings
		want     agentv1.MarketProbeRole
	}{
		{marketProbeSettings{}, agentv1.MarketProbeRole_MARKET_PROBE_ROLE_DISABLED},
		{marketProbeSettings{Enabled: true}, agentv1.MarketProbeRole_MARKET_PROBE_ROLE_PROBE_ONLY},
		{marketProbeSettings{Enabled: true, JoinMarket: true}, agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET},
		{marketProbeSettings{Enabled: true, JoinMarket: true, Benchmark: true}, agentv1.MarketProbeRole_MARKET_PROBE_ROLE_JOIN_MARKET},
	} {
		if got := test.settings.role(); got != test.want {
			t.Errorf("%+v role = %v, want %v", test.settings, got, test.want)
		}
	}
}
