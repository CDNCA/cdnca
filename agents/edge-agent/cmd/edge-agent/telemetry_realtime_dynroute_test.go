package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/dynroute"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/eventspool"
	"github.com/cdnca/cdnca/agents/edge-agent/internal/realtimecapture"
)

// D13-b2 交接 4: on a dynamic routing node two sites share one port; each
// gets its own gauge from the per-site in-flight counters, and an hour of
// continuous observation with the shared access proof certifies a window.
func TestIndependentSourceDynamicRoutingPerSite(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	state := filepath.Join(root, "state")
	for _, directory := range []string{logs, state} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	logs, _ = filepath.EvalSymlinks(logs)
	state, _ = filepath.EvalSymlinks(state)
	access := filepath.Join(logs, "access.jsonl")
	if err := os.WriteFile(access, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tailer, err := eventspool.NewTailer(eventspool.TailConfig{SourcePath: access, StateDir: state,
		Identity: eventspool.TrustedIdentity{EnrollmentNodeID: telemetryTestNodeID}, MaxLineBytes: 4096, MaxBatchEvents: 10,
		MaxQuarantineBytes: 1 << 20, Resolve: func(raw []byte) (eventspool.ResolvedLine, error) { return eventspool.ResolvedLine{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	const version, installation = "0d13b200-0000-4000-8000-000000000001", "0d13b200-0000-4000-8000-0000000000aa"
	shop, blog := "0d13b200-0000-4000-8000-000000000011", "0d13b200-0000-4000-8000-000000000012"
	sites := []dynroute.MetricSite{
		{TenantID: telemetryTestTenantID, SiteID: shop, Domain: "shop.example.test", ConfigVersionID: version, InstallationID: installation, Port: 80},
		{TenantID: telemetryTestTenantID, SiteID: blog, Domain: "blog.example.test", ConfigVersionID: version, InstallationID: installation, Port: 80},
	}
	reads := 0
	config := telemetrySourceConfig{EnrollmentNodeID: telemetryTestNodeID, DynamicRouting: &dynamicRoutingTelemetry{
		Sites: func() []dynroute.MetricSite { return sites },
		Connections: func(context.Context) ([]dynroute.SiteConnection, [32]byte, error) {
			reads++
			return []dynroute.SiteConnection{{SiteID: shop, Port: 80, Connections: 3}}, [32]byte{1}, nil
		}}}
	sink := &independentTestSink{}
	source := &independentMetricsSource{config: config, sink: sink, trackers: map[string]*realtimecapture.Tracker{}}
	start := time.Date(2026, 9, 25, 8, 0, 0, 0, time.UTC)
	now := start
	source.now = func() time.Time { return now }
	for elapsed := time.Duration(0); elapsed <= time.Hour+realtimecapture.FinalizationGrace; elapsed += 5 * time.Second {
		now = start.Add(elapsed)
		if err := source.collectDynamicRouting(context.Background(), tailer, true); err != nil {
			t.Fatalf("%s: %v", elapsed, err)
		}
	}
	if len(sink.metrics) < 2 || reads == 0 {
		t.Fatalf("metrics %d reads %d", len(sink.metrics), reads)
	}
	gauge := map[string]uint64{}
	for _, metric := range sink.metrics {
		if metric.GetInstallationId() != installation || metric.GetConfigVersionId() != version || metric.GetListenPort() != 80 {
			t.Fatalf("metric identity %+v", metric)
		}
		gauge[metric.GetSiteId()] = metric.GetConnections()
	}
	if gauge[shop] != 3 || gauge[blog] != 0 || len(gauge) != 2 {
		t.Fatalf("per-site gauges %v", gauge)
	}
	if len(sink.windows) != 2 {
		t.Fatalf("certified windows %d, want one per site", len(sink.windows))
	}
}
