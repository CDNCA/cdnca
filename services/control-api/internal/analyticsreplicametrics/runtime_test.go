package analyticsreplicametrics

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
)

func TestRuntimePublishesBoundedReplicaGaugesAndAlert(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	source := &replicaHealthSourceStub{snapshot: analyticslog.ReplicaHealthSnapshot{
		Database: "private_customer_database", ObservedAt: now, Healthy: false,
		Tables: []analyticslog.ReplicaTableHealth{
			{
				Table: "private_tenant_site_table", Healthy: false,
				Reasons: []analyticslog.ReplicaHealthReason{
					analyticslog.ReplicaUnavailable,
					analyticslog.ReplicaReadOnly,
					analyticslog.ReplicaSessionExpired,
				},
			},
			{
				Table: "private_replica_identity", Healthy: false,
				Reasons: []analyticslog.ReplicaHealthReason{
					analyticslog.ReplicaQueueBacklog,
					analyticslog.ReplicaDelayExceeded,
					analyticslog.ReplicaLogLagExceeded,
				},
			},
		},
	}}
	runtime := newReplicaMetricsTestRuntime(t, source, now)
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	waitReplicaMetrics(t, func() bool { return runtime.Ready() == nil })

	snapshot := runtime.Snapshot()
	if snapshot.SourceUp != 1 || snapshot.AlertStatus != AlertFiring ||
		snapshot.ReplicaMissing != 1 || snapshot.ReplicaReadOnly != 1 ||
		snapshot.SessionExpired != 1 || snapshot.QueueBacklog != 1 ||
		snapshot.DelayExceeded != 1 || snapshot.LogLagExceeded != 1 ||
		!snapshot.ObservedAt.Equal(now) || !snapshot.EvaluatedAt.Equal(now) {
		t.Fatalf("Snapshot() = %#v", snapshot)
	}
	samples := snapshot.PrometheusGauges()
	if len(samples) != 8 {
		t.Fatalf("gauge count = %d, want 8", len(samples))
	}
	wantNames := []string{
		MetricSourceUp, MetricReplicaMissing, MetricReplicaReadOnly, MetricSessionExpired,
		MetricQueueBacklog, MetricDelayExceeded, MetricLogLagExceeded, MetricAlertStatus,
	}
	for index, sample := range samples {
		if sample.Name != wantNames[index] {
			t.Fatalf("sample %d = %#v, want name %q", index, sample, wantNames[index])
		}
	}
	exposed := fmt.Sprintf("%+v %+v", snapshot, samples)
	for _, forbidden := range []string{"private_customer_database", "private_tenant_site_table", "private_replica_identity", "tenant_id", "site_id", "replica_id"} {
		if strings.Contains(exposed, forbidden) {
			t.Fatalf("metrics exposed %q: %s", forbidden, exposed)
		}
	}

	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if !errors.Is(runtime.Ready(), ErrClosed) {
		t.Fatalf("Ready() after close = %v", runtime.Ready())
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second Close() = %v", err)
	}
}

func TestRuntimeFailsClosedForUnavailableOrInvalidSource(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		source *replicaHealthSourceStub
	}{
		{name: "unavailable", source: &replicaHealthSourceStub{err: analyticslog.ErrStorageUnavailable}},
		{name: "unknown reason", source: &replicaHealthSourceStub{snapshot: analyticslog.ReplicaHealthSnapshot{
			Database: "cdnca", ObservedAt: now, Healthy: false,
			Tables: []analyticslog.ReplicaTableHealth{{Table: "access_events", Healthy: false, Reasons: []analyticslog.ReplicaHealthReason{"unbounded_dynamic_reason"}}},
		}}},
		{name: "stale snapshot", source: &replicaHealthSourceStub{snapshot: analyticslog.ReplicaHealthSnapshot{
			Database: "cdnca", ObservedAt: now.Add(-time.Minute), Healthy: true,
			Tables: []analyticslog.ReplicaTableHealth{{Table: "access_events", Healthy: true}},
		}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := newReplicaMetricsTestRuntime(t, test.source, now)
			done := make(chan error, 1)
			go func() { done <- runtime.Run(context.Background()) }()
			waitReplicaMetrics(t, func() bool {
				return errors.Is(runtime.Ready(), ErrSourceUnavailable)
			})
			snapshot := runtime.Snapshot()
			if snapshot.SourceUp != 0 || snapshot.AlertStatus != AlertSourceUnavailable ||
				snapshot.ReplicaMissing != 0 || snapshot.ReplicaReadOnly != 0 ||
				snapshot.SessionExpired != 0 || snapshot.QueueBacklog != 0 ||
				snapshot.DelayExceeded != 0 || snapshot.LogLagExceeded != 0 {
				t.Fatalf("failed snapshot = %#v", snapshot)
			}
			if err := runtime.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatalf("Run() = %v", err)
			}
		})
	}
}

func TestRuntimeKeepsCapabilityUnsupportedSeparateFromSourceFailure(t *testing.T) {
	now := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	runtime := newReplicaMetricsTestRuntime(t, &replicaHealthSourceStub{err: analyticslog.ErrCapabilityUnsupported}, now)
	done := make(chan error, 1)
	go func() { done <- runtime.Run(context.Background()) }()
	waitReplicaMetrics(t, func() bool { return runtime.Ready() == nil })

	snapshot := runtime.Snapshot()
	if snapshot.SourceUp != 1 || snapshot.AlertStatus != AlertCapabilityUnsupported ||
		snapshot.ReplicaMissing != 0 || snapshot.ReplicaReadOnly != 0 ||
		snapshot.SessionExpired != 0 || snapshot.QueueBacklog != 0 ||
		snapshot.DelayExceeded != 0 || snapshot.LogLagExceeded != 0 ||
		!snapshot.EvaluatedAt.Equal(now) {
		t.Fatalf("unsupported capability snapshot = %#v", snapshot)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Run() = %v", err)
	}
}

func TestNewRuntimeRejectsUnboundedOrMissingInputs(t *testing.T) {
	valid := Config{
		PollInterval: 20 * time.Millisecond, ReadTimeout: 100 * time.Millisecond,
		MaxTables: 8, MaxStaleness: 30 * time.Second, Now: time.Now,
	}
	source := &replicaHealthSourceStub{}
	for _, test := range []struct {
		name   string
		config Config
		source HealthSource
	}{
		{name: "nil source", config: valid},
		{name: "zero config", source: source},
		{name: "too many tables", config: func() Config { value := valid; value.MaxTables = 2048; return value }(), source: source},
	} {
		t.Run(test.name, func(t *testing.T) {
			if runtime, err := New(test.config, test.source); runtime != nil || !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("New() = (%v, %v)", runtime, err)
			}
		})
	}
}

func newReplicaMetricsTestRuntime(t *testing.T, source HealthSource, now time.Time) *Runtime {
	t.Helper()
	runtime, err := New(Config{
		PollInterval: 20 * time.Millisecond, ReadTimeout: 100 * time.Millisecond,
		MaxTables: 8, MaxStaleness: 30 * time.Second, Now: func() time.Time { return now },
	}, source)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

type replicaHealthSourceStub struct {
	mu       sync.Mutex
	snapshot analyticslog.ReplicaHealthSnapshot
	err      error
}

func (source *replicaHealthSourceStub) Read(context.Context) (analyticslog.ReplicaHealthSnapshot, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.snapshot, source.err
}

func waitReplicaMetrics(t *testing.T, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !ready() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !ready() {
		t.Fatal("runtime state did not converge")
	}
}
