package nodemonitoring

import (
	"context"
	"errors"
	"testing"
	"time"
)

type metricSink struct {
	reports []MetricReport
}

func (sink *metricSink) ReportNodeMonitoring(_ context.Context, report MetricReport) error {
	sink.reports = append(sink.reports, report)
	return nil
}

func TestRunUsesConfiguredIntervalAndReportsBoundIdentity(t *testing.T) {
	probe := &fakeProbe{}
	runtime, err := NewRuntime(Options{
		StateDir: t.TempDir(), NodeID: "node-metrics", DefaultPort: 8080, Probe: probe,
	})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	if _, err := runtime.Apply(context.Background(), testConfig(t, 11, "default", nil, 0, 0, true)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	var waited time.Duration
	runtime.wait = func(_ context.Context, duration time.Duration) error {
		waited = duration
		return context.Canceled
	}
	sink := &metricSink{}
	if err := runtime.Run(context.Background(), sink); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
	if waited != 10*time.Second {
		t.Fatalf("waited = %v, want 10s", waited)
	}
	if len(sink.reports) != 1 || sink.reports[0].NodeID != "node-metrics" ||
		sink.reports[0].ConfigRevision != 11 || sink.reports[0].ActiveConfigRevision != 11 {
		t.Fatalf("reports = %#v", sink.reports)
	}
}
