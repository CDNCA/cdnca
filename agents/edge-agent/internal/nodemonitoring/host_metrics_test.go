package nodemonitoring

import (
	"context"
	"errors"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"
)

func TestHostMetricsWithoutProbePolicy(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh node", true: "probe disabled"}[disabled], func(t *testing.T) {
			now := time.Date(2026, 10, 9, 8, 0, 0, 0, time.UTC)
			probe := &fakeProbe{}
			runtime, err := NewRuntime(Options{
				StateDir: t.TempDir(), NodeID: "host-metrics", DefaultPort: 80, Probe: probe,
				Now: func() time.Time { return now }, LoadCollector: &fixedLoadCollector{metrics: &LoadMetrics{
					ObservedAt: now, CPUPercent: 12, MemoryUsedBytes: 512, MemoryTotalBytes: 1024,
					RXBandwidthBPS: 8000, TXBandwidthBPS: 4000,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if disabled {
				config, err := decodeConfig(testConfig(t, 7, "default", nil, 0, 0, false))
				if err != nil {
					t.Fatal(err)
				}
				enabled := false
				config.MonitorEnabled = &enabled
				runtime.active = &config
			}
			runtime.wait = func(_ context.Context, interval time.Duration) error {
				if interval != 10*time.Second {
					t.Fatalf("host interval = %s", interval)
				}
				return context.Canceled
			}
			sink := &metricSink{}
			if err := runtime.Run(t.Context(), sink); !errors.Is(err, context.Canceled) {
				t.Fatalf("Run: %v", err)
			}
			if len(probe.calls) != 0 {
				t.Fatal("basic host metrics performed a service probe")
			}
			if len(sink.reports) != 1 {
				t.Fatalf("host reports = %d", len(sink.reports))
			}
			report := sink.reports[0]
			if report.LoadMetrics == nil || report.LoadMetrics.RXBandwidthBPS != 8000 || report.LoadMetrics.TXBandwidthBPS != 4000 ||
				report.ConfigRevision != 0 || report.ActiveConfigRevision != 0 || report.ProbePort != 0 || report.ProbesTotal != 0 || report.Healthy {
				t.Fatalf("host report fabricated probe evidence: %+v", report)
			}
		})
	}
}

func TestLinuxHostMetricsFromProc(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux procfs")
	}
	probe := &fakeProbe{}
	run, err := NewRuntime(Options{StateDir: t.TempDir(), NodeID: "host-proc-test", DefaultPort: 80, Probe: probe})
	if err != nil {
		t.Fatal(err)
	}
	loops := 0
	run.wait = func(ctx context.Context, _ time.Duration) error {
		loops++
		if loops >= 4 {
			return context.Canceled
		}
		return waitDuration(ctx, 300*time.Millisecond, nil)
	}
	sink := &metricSink{}
	if err := run.Run(t.Context(), sink); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(probe.calls) != 0 || len(sink.reports) < 2 {
		t.Fatalf("probes=%d reports=%d", len(probe.calls), len(sink.reports))
	}
	for _, report := range sink.reports {
		if report.ConfigRevision != 0 || report.LoadMetrics == nil || report.LoadMetrics.Telemetry == nil ||
			len(report.LoadMetrics.Telemetry.NetworkInterfaces) == 0 {
			t.Fatalf("missing procfs host metrics: %+v", report)
		}
		if expected := os.Getenv("CDNCA_EXPECT_EGRESS"); expected != "" {
			selection := report.LoadMetrics.Telemetry.NetworkSelection
			if selection == nil || selection.Source != "default_route" || !slices.Equal(selection.Interfaces, []string{expected}) {
				t.Fatalf("real egress selection = %+v, want %s", selection, expected)
			}
		}
	}
	t.Logf("real procfs host samples=%d, interfaces=%d, no active probe policy", len(sink.reports), len(sink.reports[0].LoadMetrics.Telemetry.NetworkInterfaces))
	t.Logf("monitoring egress selection=%+v", sink.reports[0].LoadMetrics.Telemetry.NetworkSelection)
}

type backpressureMetricSink struct{ calls int }

func (sink *backpressureMetricSink) ReportNodeMonitoring(context.Context, MetricReport) error {
	sink.calls++
	if sink.calls == 1 {
		return ErrMetricBackpressure
	}
	return nil
}

func TestHostMetricsBackpressure(t *testing.T) {
	now := time.Now().UTC()
	run, err := NewRuntime(Options{StateDir: t.TempDir(), NodeID: "host-backpressure", DefaultPort: 80, Probe: &fakeProbe{},
		Now: func() time.Time { return now }, LoadCollector: &fixedLoadCollector{metrics: &LoadMetrics{
			ObservedAt: now, MemoryTotalBytes: 2, MemoryUsedBytes: 1,
		}}})
	if err != nil {
		t.Fatal(err)
	}
	waits := 0
	run.wait = func(context.Context, time.Duration) error {
		waits++
		if waits == 2 {
			return context.Canceled
		}
		return nil
	}
	sink := &backpressureMetricSink{}
	if err := run.Run(t.Context(), sink); !errors.Is(err, context.Canceled) || sink.calls != 2 {
		t.Fatalf("queue saturation stopped basic sampling: calls=%d err=%v", sink.calls, err)
	}
}
