package nodemonitoring

import (
	"context"
	"testing"
	"time"
)

// Telemetry field 16: refused string sets ride on every load report with node
// telemetry; an invalid list is left out, the report goes.
func TestRuntimeAttachesStringSetOverBudget(t *testing.T) {
	now := time.Date(2026, 11, 12, 2, 0, 0, 0, time.UTC)
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
	sets := []StringSetOverBudgetMetrics{{SetID: "aaa", Revision: 2, Mode: "contains", Members: 9000,
		EstimateBytes: 70 << 20, LiveBytes: 1 << 20, BudgetBytes: 64 << 20}}
	runtime.SetStringSetOverBudget(func(context.Context) []StringSetOverBudgetMetrics { return sets })
	report, err := runtime.RunOnce(t.Context())
	if err != nil || report.LoadMetrics == nil || len(report.LoadMetrics.Telemetry.StringSetOverBudget) != 1 ||
		report.LoadMetrics.Telemetry.StringSetOverBudget[0].SetID != "aaa" {
		t.Fatalf("RunOnce() = (%#v, %v)", report.LoadMetrics, err)
	}
	for name, bad := range map[string][]StringSetOverBudgetMetrics{
		"empty id":   {{SetID: "", Revision: 1, Mode: "exact"}},
		"unsorted":   {{SetID: "b", Revision: 1, Mode: "exact"}, {SetID: "a", Revision: 1, Mode: "exact"}},
		"duplicate":  {{SetID: "a", Revision: 1, Mode: "exact"}, {SetID: "a", Revision: 1, Mode: "exact"}},
		"revision 0": {{SetID: "a", Revision: 0, Mode: "exact"}},
		"too many":   make([]StringSetOverBudgetMetrics, StringSetOverBudgetMax+1),
	} {
		if validStringSetOverBudget(bad) {
			t.Fatalf("%s accepted", name)
		}
	}
}
