package nodemonitoring

import (
	"context"
	"testing"
	"time"
)

type fixedLoadCollector struct{ metrics *LoadMetrics }

func (collector *fixedLoadCollector) Collect(context.Context, time.Time) (*LoadMetrics, error) {
	copy := *collector.metrics
	return &copy, nil
}

func TestRuntimeCarriesTypedLoadMetricsWithoutChangingProbePayload(t *testing.T) {
	now := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	runtime, err := NewRuntime(Options{
		StateDir: t.TempDir(), NodeID: "node-load", DefaultPort: 8080, Probe: &fakeProbe{},
		Now: func() time.Time { return now }, LoadCollector: &fixedLoadCollector{metrics: &LoadMetrics{
			ObservedAt: now, CPUPercent: 12.5, MemoryUsedBytes: 512, MemoryTotalBytes: 1024,
			ActiveConnections: 7, RXBandwidthBPS: 8000, TXBandwidthBPS: 4000,
		}},
	})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	if _, err := runtime.Apply(t.Context(), testConfig(t, 12, "default", nil, 0, 0, false)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	report, err := runtime.RunOnce(t.Context())
	if err != nil || report.LoadMetrics == nil || report.LoadMetrics.CPUPercent != 12.5 ||
		report.LoadMetrics.ObservedAt != report.ObservedAt {
		t.Fatalf("RunOnce() = (%#v, %v)", report, err)
	}
}

func TestRuntimeAttachesValidDDoSDropsToNodeTelemetry(t *testing.T) {
	now := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	runtime, err := NewRuntime(Options{
		StateDir: t.TempDir(), NodeID: "node-load", DefaultPort: 8080, Probe: &fakeProbe{},
		Now: func() time.Time { return now }, LoadCollector: &fixedLoadCollector{metrics: &LoadMetrics{
			ObservedAt: now, CPUPercent: 1, MemoryUsedBytes: 1, MemoryTotalBytes: 2,
			Telemetry: &TelemetryMetrics{SchemaVersion: 1},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Apply(t.Context(), testConfig(t, 12, "default", nil, 0, 0, false)); err != nil {
		t.Fatal(err)
	}
	drops := []DDoSDropMetrics{{Kind: "ct_invalid", Packets: 3, Bytes: 120}, {Kind: "tcp_null", Packets: 9, Bytes: 360}}
	runtime.SetDDoSDrops(func(context.Context) []DDoSDropMetrics { return drops })
	report, err := runtime.RunOnce(t.Context())
	if err != nil || report.LoadMetrics == nil || report.LoadMetrics.Telemetry == nil ||
		len(report.LoadMetrics.Telemetry.DDoSDrops) != 2 || report.LoadMetrics.Telemetry.DDoSDrops[1].Packets != 9 {
		t.Fatalf("RunOnce() = (%#v, %v)", report.LoadMetrics, err)
	}
	// Unsorted, unknown: the sample goes out without them.
	for _, bad := range [][]DDoSDropMetrics{
		{{Kind: "tcp_null"}, {Kind: "ct_invalid"}},
		{{Kind: "tcp_ack"}},
		{{Kind: "tcp_null"}, {Kind: "tcp_null"}},
	} {
		drops = bad
		report, err = runtime.RunOnce(t.Context())
		if err != nil || report.LoadMetrics == nil || report.LoadMetrics.Telemetry.DDoSDrops != nil {
			t.Fatalf("invalid drops %v carried: %#v %v", bad, report.LoadMetrics, err)
		}
	}
}

func TestRuntimeAttachesValidXDPStatusToNodeTelemetry(t *testing.T) {
	now := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	runtime, err := NewRuntime(Options{
		StateDir: t.TempDir(), NodeID: "node-load", DefaultPort: 8080, Probe: &fakeProbe{},
		Now: func() time.Time { return now }, LoadCollector: &fixedLoadCollector{metrics: &LoadMetrics{
			ObservedAt: now, CPUPercent: 1, MemoryUsedBytes: 1, MemoryTotalBytes: 2,
			Telemetry: &TelemetryMetrics{SchemaVersion: 1},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Apply(t.Context(), testConfig(t, 12, "default", nil, 0, 0, false)); err != nil {
		t.Fatal(err)
	}
	status := &XDPStatusMetrics{Mode: "native", Interfaces: []string{"eth0=native", "eth1=native"},
		Drops: []DDoSDropMetrics{{Kind: "tcp_null", Packets: 1, Bytes: 60}, {Kind: "xdp_rate", Packets: 9, Bytes: 540}}}
	runtime.SetXDP(func(context.Context) *XDPStatusMetrics { return status })
	report, err := runtime.RunOnce(t.Context())
	if err != nil || report.LoadMetrics.Telemetry.XDP == nil || report.LoadMetrics.Telemetry.XDP.Drops[1].Packets != 9 {
		t.Fatalf("RunOnce() = (%#v, %v)", report.LoadMetrics, err)
	}
	for _, good := range []*XDPStatusMetrics{
		{Mode: "nftables", Reason: "bpf_unavailable", Detail: "function not implemented"},
		{Mode: "disabled", Reason: "disabled"},
		{Mode: "generic", Interfaces: []string{"ens3=generic", "ens4=native"}},
	} {
		if !validXDPStatus(good) {
			t.Errorf("%+v refused", good)
		}
	}
	for _, bad := range []*XDPStatusMetrics{
		{Mode: "fast"},
		{Mode: "native"},
		{Mode: "native", Reason: "verify_failed", Interfaces: []string{"eth0=native"}},
		{Mode: "nftables"},
		{Mode: "nftables", Reason: "because"},
		{Mode: "nftables", Reason: "attach_failed", Drops: []DDoSDropMetrics{{Kind: "xdp_ban", Packets: 1}}},
		{Mode: "generic", Interfaces: []string{"eth1=generic", "eth0=generic"}},
		{Mode: "generic", Interfaces: []string{"eth0"}},
		{Mode: "generic", Interfaces: []string{"eth0=offload"}},
		{Mode: "generic", Interfaces: []string{"eth0=generic"}, Drops: []DDoSDropMetrics{{Kind: "ct_invalid"}}},
		{Mode: "nftables", Reason: "load_failed", Detail: "a\nb"},
	} {
		status = bad
		report, err = runtime.RunOnce(t.Context())
		if err != nil || report.LoadMetrics.Telemetry.XDP != nil {
			t.Errorf("invalid status %+v carried", bad)
		}
	}
}

func TestRuntimeAttachesValidSiteDropToNodeTelemetry(t *testing.T) {
	now := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	runtime, err := NewRuntime(Options{
		StateDir: t.TempDir(), NodeID: "node-load", DefaultPort: 8080, Probe: &fakeProbe{},
		Now: func() time.Time { return now }, LoadCollector: &fixedLoadCollector{metrics: &LoadMetrics{
			ObservedAt: now, CPUPercent: 1, MemoryUsedBytes: 1, MemoryTotalBytes: 2,
			Telemetry: &TelemetryMetrics{SchemaVersion: 1},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Apply(t.Context(), testConfig(t, 12, "default", nil, 0, 0, false)); err != nil {
		t.Fatal(err)
	}
	drop := &SiteDropMetrics{SiteIDs: []string{"11111111-1111-4111-8111-111111111111"}, Packets: 5, Bytes: 300}
	runtime.SetSiteDrop(func(context.Context) *SiteDropMetrics { return drop })
	report, err := runtime.RunOnce(t.Context())
	if err != nil || report.LoadMetrics == nil || report.LoadMetrics.Telemetry.SiteDrop == nil ||
		report.LoadMetrics.Telemetry.SiteDrop.Packets != 5 {
		t.Fatalf("RunOnce() = (%#v, %v)", report.LoadMetrics, err)
	}
	for _, bad := range []*SiteDropMetrics{
		{},
		{SiteIDs: []string{"not-a-uuid"}},
		{SiteIDs: []string{"22222222-2222-4222-8222-222222222222", "11111111-1111-4111-8111-111111111111"}},
		{SiteIDs: []string{"11111111-1111-4111-8111-111111111111"}, Packets: 1 << 63},
	} {
		drop = bad
		report, err = runtime.RunOnce(t.Context())
		if err != nil || report.LoadMetrics == nil || report.LoadMetrics.Telemetry.SiteDrop != nil {
			t.Fatalf("invalid site drop %#v carried: %v", bad, err)
		}
	}
}

// E1: the node DDoS protection state rides every load sample.
func TestRuntimeAttachesDDoSProtectionToNodeTelemetry(t *testing.T) {
	now := time.Date(2026, 10, 24, 2, 0, 0, 0, time.UTC)
	runtime, err := NewRuntime(Options{
		StateDir: t.TempDir(), NodeID: "node-load", DefaultPort: 8080, Probe: &fakeProbe{},
		Now: func() time.Time { return now }, LoadCollector: &fixedLoadCollector{metrics: &LoadMetrics{
			ObservedAt: now, CPUPercent: 1, MemoryUsedBytes: 1, MemoryTotalBytes: 2,
			Telemetry: &TelemetryMetrics{SchemaVersion: 1},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Apply(t.Context(), testConfig(t, 12, "default", nil, 0, 0, false)); err != nil {
		t.Fatal(err)
	}
	runtime.SetDDoSProtection(func(context.Context) *DDoSProtectionMetrics {
		return &DDoSProtectionMetrics{State: "failed", Detail: "nft: Error: Could not process rule"}
	})
	report, err := runtime.RunOnce(t.Context())
	if err != nil || report.LoadMetrics.Telemetry.DDoSProtection == nil || report.LoadMetrics.Telemetry.DDoSProtection.State != "failed" {
		t.Fatalf("RunOnce() = (%#v, %v)", report.LoadMetrics, err)
	}
	for _, good := range []*DDoSProtectionMetrics{
		{State: "applied"}, {State: "off"}, {State: "pending"}, {State: "failed", Detail: "x"},
		{State: "unavailable", Reason: "nft_missing", Detail: "nft command not found"},
	} {
		if !validDDoSProtection(good) {
			t.Errorf("%+v refused", good)
		}
	}
	for _, bad := range []*DDoSProtectionMetrics{
		{State: "broken"}, {State: "unavailable"}, {State: "unavailable", Reason: "because"},
		{State: "applied", Reason: "nft_missing"}, {State: "applied", Detail: "x"}, {State: "failed", Detail: "a\nb"},
	} {
		if validDDoSProtection(bad) {
			t.Errorf("%+v accepted", bad)
		}
	}
}
