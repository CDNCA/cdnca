package nodemonitoring

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"
)

var errProbeFailed = errors.New("probe failed")

type probeCall struct {
	port    uint16
	timeout time.Duration
}

type fakeProbe struct {
	results []error
	calls   []probeCall
}

func (probe *fakeProbe) Probe(_ context.Context, port uint16, timeout time.Duration) error {
	probe.calls = append(probe.calls, probeCall{port: port, timeout: timeout})
	if len(probe.results) == 0 {
		return nil
	}
	result := probe.results[0]
	probe.results = probe.results[1:]
	return result
}

type fakeNotifier struct {
	events  []RecoveryEvent
	results []error
}

func (notifier *fakeNotifier) NotifyRecovery(_ context.Context, event RecoveryEvent) error {
	notifier.events = append(notifier.events, event)
	if len(notifier.results) == 0 {
		return nil
	}
	result := notifier.results[0]
	notifier.results = notifier.results[1:]
	return result
}

func TestRuntimePreservesLKGOnPreflightFailureAndRollsBackAfterThreshold(t *testing.T) {
	clock := time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)
	probe := &fakeProbe{}
	runtime, err := NewRuntime(Options{
		StateDir: t.TempDir(), NodeID: "node-07", DefaultPort: 8080, Probe: probe,
		Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}

	if _, err := runtime.Apply(context.Background(), testConfig(t, 1, "default", nil, 0, 0, true)); err != nil {
		t.Fatalf("Apply(revision 1) error = %v", err)
	}
	customPort := uint16(9443)
	probe.results = append(probe.results, errProbeFailed)
	if _, err := runtime.Apply(context.Background(), testConfig(t, 2, "custom", &customPort, 0, 0, true)); !errors.Is(err, ErrPreflight) {
		t.Fatalf("Apply(failed revision 2) error = %v, want ErrPreflight", err)
	}
	if status := runtime.Status(); status.ConfigRevision != 1 || !status.Healthy {
		t.Fatalf("status after failed preflight = %#v", status)
	}

	if _, err := runtime.Apply(context.Background(), testConfig(t, 2, "custom", &customPort, 0, 0, true)); err != nil {
		t.Fatalf("Apply(revision 2) error = %v", err)
	}
	probe.results = append(probe.results, errProbeFailed, errProbeFailed, errProbeFailed)
	for attempt := 1; attempt <= 3; attempt++ {
		report, err := runtime.RunOnce(context.Background())
		if !errors.Is(err, errProbeFailed) {
			t.Fatalf("RunOnce(%d) error = %v", attempt, err)
		}
		if report.NodeID != "node-07" || report.ConfigRevision != 2 {
			t.Fatalf("RunOnce(%d) report identity = %#v", attempt, report)
		}
		if attempt < 3 && report.RolledBack {
			t.Fatalf("RunOnce(%d) rolled back before threshold", attempt)
		}
		if attempt == 3 && (!report.RolledBack || report.ActiveConfigRevision != 1) {
			t.Fatalf("threshold report = %#v", report)
		}
	}
	if status := runtime.Status(); status.ConfigRevision != 1 || !status.Healthy {
		t.Fatalf("status after rollback = %#v", status)
	}
	if got := probe.calls; !reflect.DeepEqual(got[:3], []probeCall{
		{port: 8080, timeout: 3 * time.Second},
		{port: 9443, timeout: 3 * time.Second},
		{port: 9443, timeout: 3 * time.Second},
	}) {
		t.Fatalf("apply probe calls = %#v", got)
	}

	restarted, err := NewRuntime(Options{
		StateDir: runtime.stateDir, NodeID: "node-07", DefaultPort: 8080, Probe: &fakeProbe{},
		Now: func() time.Time { return clock },
	})
	if err != nil {
		t.Fatalf("NewRuntime(restart) error = %v", err)
	}
	if status := restarted.Status(); status.ConfigRevision != 1 || !status.Healthy {
		t.Fatalf("restarted status = %#v", status)
	}
}

func TestRuntimeDebouncesFailureAndRecoveryAndNotifiesOnce(t *testing.T) {
	now := time.Date(2026, 8, 8, 13, 0, 0, 0, time.UTC)
	probe := &fakeProbe{}
	notifier := &fakeNotifier{}
	runtime, err := NewRuntime(Options{
		StateDir: t.TempDir(), NodeID: "node-recovery", DefaultPort: 80,
		Probe: probe, Notifier: notifier, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	if _, err := runtime.Apply(context.Background(), testConfig(t, 8, "default", nil, 2_000, 2_000, true)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	probe.results = append(probe.results, errProbeFailed, errProbeFailed, errProbeFailed, errProbeFailed)
	for attempt := 0; attempt < 3; attempt++ {
		_, _ = runtime.RunOnce(context.Background())
	}
	if status := runtime.Status(); !status.Healthy {
		t.Fatalf("failure debounce was skipped: %#v", status)
	}
	now = now.Add(2 * time.Second)
	_, _ = runtime.RunOnce(context.Background())
	if status := runtime.Status(); status.Healthy {
		t.Fatalf("failure transition missing: %#v", status)
	}

	for attempt := 0; attempt < 3; attempt++ {
		if _, err := runtime.RunOnce(context.Background()); err != nil {
			t.Fatalf("recovery RunOnce(%d) error = %v", attempt, err)
		}
	}
	if status := runtime.Status(); status.Healthy {
		t.Fatalf("recovery debounce was skipped: %#v", status)
	}
	now = now.Add(2 * time.Second)
	report, err := runtime.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("recovery RunOnce() error = %v", err)
	}
	if !report.Recovered || !report.RecoveryNotified || !report.Healthy ||
		report.NodeID != "node-recovery" || report.ConfigRevision != 8 || report.ActiveConfigRevision != 8 {
		t.Fatalf("recovery report = %#v", report)
	}
	if len(notifier.events) != 1 || notifier.events[0].NodeID != "node-recovery" || notifier.events[0].ConfigRevision != 8 {
		t.Fatalf("recovery events = %#v", notifier.events)
	}
	if _, err := runtime.RunOnce(context.Background()); err != nil {
		t.Fatalf("post-recovery RunOnce() error = %v", err)
	}
	if len(notifier.events) != 1 {
		t.Fatalf("duplicate recovery notification = %#v", notifier.events)
	}
}

func TestRuntimeRetriesFailedRecoveryNotification(t *testing.T) {
	now := time.Date(2026, 8, 8, 14, 0, 0, 0, time.UTC)
	probe := &fakeProbe{}
	errNotification := errors.New("notification unavailable")
	notifier := &fakeNotifier{results: []error{errNotification, nil}}
	runtime, err := NewRuntime(Options{
		StateDir: t.TempDir(), NodeID: "node-notify-retry", DefaultPort: 80,
		Probe: probe, Notifier: notifier, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	if _, err := runtime.Apply(context.Background(), testConfig(t, 9, "default", nil, 0, 0, true)); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	probe.results = append(probe.results, errProbeFailed, errProbeFailed, errProbeFailed)
	for attempt := 0; attempt < 3; attempt++ {
		_, _ = runtime.RunOnce(context.Background())
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := runtime.RunOnce(context.Background()); err != nil {
			t.Fatalf("recovery RunOnce(%d) error = %v", attempt, err)
		}
	}
	failed, err := runtime.RunOnce(context.Background())
	if !errors.Is(err, errNotification) || !failed.Recovered || failed.RecoveryNotified {
		t.Fatalf("failed notification report = %#v, error = %v", failed, err)
	}
	retried, err := runtime.RunOnce(context.Background())
	if err != nil || retried.Recovered || !retried.RecoveryNotified ||
		retried.ConfigRevision != 9 || retried.ActiveConfigRevision != 9 {
		t.Fatalf("retried notification report = %#v, error = %v", retried, err)
	}
	if len(notifier.events) != 2 || notifier.events[0] != notifier.events[1] {
		t.Fatalf("notification attempts = %#v", notifier.events)
	}
	if _, err := runtime.RunOnce(context.Background()); err != nil {
		t.Fatalf("post-retry RunOnce() error = %v", err)
	}
	if len(notifier.events) != 2 {
		t.Fatalf("duplicate notification after retry = %#v", notifier.events)
	}
}

func TestRuntimeDisableClosedPortPersistsAndReenables(t *testing.T) {
	listener, port := listenRuntimeTCP(t)
	probe := &runtimeTCPProbe{}
	now := time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)
	options := Options{
		StateDir: t.TempDir(), NodeID: "node-disable", DefaultPort: port, Probe: probe,
		Now: func() time.Time { return now }, LoadCollector: &fixedLoadCollector{metrics: &LoadMetrics{
			ObservedAt: now, MemoryUsedBytes: 1, MemoryTotalBytes: 2,
		}},
	}
	runtime, err := NewRuntime(options)
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := decodeConfig(testConfig(t, 1, "default", nil, 0, 0, true))
	if err != nil {
		t.Fatal(err)
	}
	encode := func(config Config) []byte {
		payload, err := canonicalConfig(config)
		if err != nil {
			t.Fatal(err)
		}
		return payload
	}
	if result, err := runtime.Apply(t.Context(), encode(enabled)); err != nil || result != (ApplyResult{ConfigRevision: 1}) {
		t.Fatalf("initial enabled apply = %+v, %v", result, err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := probe.Probe(t.Context(), port, time.Second); err == nil {
		t.Fatal("closed TCP listener remains reachable")
	}
	beforeDisable := probe.calls
	disabled := cloneConfig(enabled)
	disabled.ConfigRevision = 2
	monitorEnabled := false
	disabled.MonitorEnabled = &monitorEnabled
	if result, err := runtime.Apply(t.Context(), encode(disabled)); err != nil || result != (ApplyResult{ConfigRevision: 2, PreviousRevision: 1}) {
		t.Fatalf("disable with closed TCP port = %+v, %v", result, err)
	}
	if result, err := runtime.Apply(t.Context(), encode(disabled)); err != nil || result != (ApplyResult{ConfigRevision: 2, Replayed: true}) {
		t.Fatalf("disabled replay = %+v, %v", result, err)
	}
	for _, test := range []struct {
		name   string
		change func(*Config)
		want   error
	}{
		{"older revision", func(config *Config) { config.ConfigRevision = 1 }, ErrConflict},
		{"different same revision", func(config *Config) { config.FailureThreshold++ }, ErrConflict},
		{"invalid disabled config", func(config *Config) { config.ConfigRevision = 3; config.ProbeIntervalMS = 0 }, ErrInvalidConfig},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := cloneConfig(disabled)
			test.change(&config)
			if result, err := runtime.Apply(t.Context(), encode(config)); !errors.Is(err, test.want) || result != (ApplyResult{}) {
				t.Fatalf("rejected apply = %+v, %v, want %v", result, err, test.want)
			}
		})
	}
	if probe.calls != beforeDisable {
		t.Fatalf("disable/replay/rejections performed TCP probes: %d -> %d", beforeDisable, probe.calls)
	}
	runtime, err = NewRuntime(options)
	if err != nil || !reflect.DeepEqual(runtime.active, &disabled) || !reflect.DeepEqual(runtime.lkg, &enabled) {
		t.Fatalf("restart did not preserve disabled active and enabled LKG: %v", err)
	}
	assertDisabledHostOnly(t, runtime, probe)

	reenabled := cloneConfig(disabled)
	reenabled.ConfigRevision = 3
	enabledValue := true
	for _, value := range []*bool{nil, &enabledValue} {
		reenabled.MonitorEnabled = value
		if result, err := runtime.Apply(t.Context(), encode(reenabled)); !errors.Is(err, ErrPreflight) || result != (ApplyResult{}) {
			t.Fatalf("reenable with closed TCP port = %+v, %v", result, err)
		}
	}
	if !reflect.DeepEqual(runtime.active, &disabled) || !reflect.DeepEqual(runtime.lkg, &enabled) {
		t.Fatal("failed reenable changed active or LKG configuration")
	}
	listener, port = listenRuntimeTCP(t)
	reenabled.MonitorPort = &port
	if result, err := runtime.Apply(t.Context(), encode(reenabled)); err != nil || result != (ApplyResult{ConfigRevision: 3, PreviousRevision: 2}) {
		t.Fatalf("reenable with open TCP port = %+v, %v", result, err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		report, err := runtime.RunOnce(t.Context())
		if err == nil || report.ProbeSucceeded || report.ConfigRevision != 3 || report.RolledBack != (attempt == 3) {
			t.Fatalf("closed reenabled port attempt %d = %+v, %v", attempt, report, err)
		}
		if attempt == 3 && report.ActiveConfigRevision != 2 {
			t.Fatalf("failure did not roll back to disabled revision: %+v", report)
		}
	}
	runtime, err = NewRuntime(options)
	if err != nil || !reflect.DeepEqual(runtime.active, &disabled) {
		t.Fatalf("restart did not preserve rollback to disabled: %v", err)
	}
	assertDisabledHostOnly(t, runtime, probe)
}

func TestRuntimeDisabledFirstApplyAndPersistenceFailure(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		t.Run(map[bool]string{false: "first disabled config", true: "state persistence failure"}[blocked], func(t *testing.T) {
			probe := &fakeProbe{results: []error{errProbeFailed}}
			runtime, err := NewRuntime(Options{StateDir: t.TempDir(), NodeID: "node-first-disabled", DefaultPort: 80, Probe: probe})
			if err != nil {
				t.Fatal(err)
			}
			config, err := decodeConfig(testConfig(t, 1, "default", nil, 0, 0, false))
			if err != nil {
				t.Fatal(err)
			}
			enabled := false
			config.MonitorEnabled = &enabled
			if blocked {
				if err := os.Mkdir(filepath.Join(runtime.stateDir, activeFileName), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			payload, err := canonicalConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			result, err := runtime.Apply(t.Context(), payload)
			if blocked {
				if err == nil || errors.Is(err, ErrPreflight) || result != (ApplyResult{}) || runtime.active != nil {
					t.Fatalf("failed persistence accepted disabled config: %+v, %v", result, err)
				}
			} else {
				if err != nil || result != (ApplyResult{ConfigRevision: 1}) {
					t.Fatalf("first disabled apply = %+v, %v", result, err)
				}
				stored, err := loadStoredConfig(filepath.Join(runtime.stateDir, activeFileName))
				if err != nil || !reflect.DeepEqual(stored, &config) {
					t.Fatalf("disabled state was not persisted: %+v, %v", stored, err)
				}
			}
			if len(probe.calls) != 0 || runtime.lkg != nil {
				t.Fatal("first disabled apply probed or fabricated LKG")
			}
			entries, err := os.ReadDir(runtime.stateDir)
			if err != nil || len(entries) != 1 || entries[0].Name() != activeFileName {
				t.Fatalf("unexpected state/temporary files after apply: %+v, %v", entries, err)
			}
		})
	}
}

func TestRuntimeQueuedProbeRechecksDisabledConfig(t *testing.T) {
	for _, reenable := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "reenabled"}[reenable], func(t *testing.T) {
			probe := &fakeProbe{}
			runtime, err := NewRuntime(Options{StateDir: t.TempDir(), NodeID: "node-queued-disable", DefaultPort: 80, Probe: probe})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runtime.Apply(t.Context(), testConfig(t, 1, "default", nil, 0, 0, false)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			selected, resume := make(chan bool, 1), make(chan struct{})
			type outcome struct {
				report MetricReport
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				defer close(done)
				// Hold the same gap as Run's enabled snapshot before its RunOnce call.
				runtime.mu.Lock()
				enabled := runtime.active != nil && (runtime.active.MonitorEnabled == nil || *runtime.active.MonitorEnabled)
				runtime.mu.Unlock()
				selected <- enabled
				select {
				case <-resume:
					if enabled {
						report, err := runtime.RunOnce(ctx)
						done <- outcome{report, err}
					}
				case <-ctx.Done():
				}
			}()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Error("queued probe did not stop")
				}
			})
			select {
			case enabled := <-selected:
				if !enabled {
					t.Fatal("test did not select an enabled probe")
				}
			case <-ctx.Done():
				t.Fatal("probe selection timed out")
			}
			disabled, err := decodeConfig(testConfig(t, 2, "default", nil, 0, 0, false))
			if err != nil {
				t.Fatal(err)
			}
			monitorEnabled := false
			disabled.MonitorEnabled = &monitorEnabled
			payload, err := canonicalConfig(disabled)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runtime.Apply(ctx, payload); err != nil {
				t.Fatal(err)
			}
			if reenable {
				if _, err := runtime.Apply(ctx, testConfig(t, 3, "default", nil, 0, 0, false)); err != nil {
					t.Fatal(err)
				}
			}
			close(resume)
			select {
			case result, ok := <-done:
				if !ok || result.err != nil {
					t.Fatalf("queued probe result = %+v, received=%t", result, ok)
				}
				if !reenable {
					if len(probe.calls) != 1 || !reflect.DeepEqual(result.report, MetricReport{}) || runtime.probes != 0 {
						t.Fatalf("queued probe ran after disable: calls=%d report=%+v", len(probe.calls), result.report)
					}
					restarted, err := NewRuntime(Options{StateDir: runtime.stateDir, NodeID: "node-queued-disable", DefaultPort: 80, Probe: probe})
					if err != nil || !reflect.DeepEqual(restarted.active, &disabled) {
						t.Fatalf("disabled configuration did not survive restart: %v", err)
					}
					if report, err := restarted.RunOnce(ctx); err != nil || !reflect.DeepEqual(report, MetricReport{}) || len(probe.calls) != 1 {
						t.Fatalf("restarted disabled runtime probed: calls=%d report=%+v error=%v", len(probe.calls), report, err)
					}
				} else if len(probe.calls) != 3 || result.report.ConfigRevision != 3 ||
					result.report.ActiveConfigRevision != 3 || !result.report.ProbeSucceeded || runtime.probes != 1 {
					t.Fatalf("reenabled probe did not use current revision: calls=%d report=%+v", len(probe.calls), result.report)
				}
			case <-ctx.Done():
				t.Fatal("queued probe timed out")
			}
		})
	}
}

func TestRuntimeDisableWaitsForInFlightProbe(t *testing.T) {
	for _, completion := range []string{"success", "cancel", "timeout"} {
		t.Run(completion, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			calls := 0
			probe := runtimeBoundaryProbe(func(ctx context.Context, _ uint16, timeout time.Duration) error {
				calls++
				if calls == 1 { // Initial enabled preflight.
					return nil
				}
				if calls != 2 {
					return errProbeFailed
				}
				close(entered)
				probeCtx, cancel := context.WithTimeout(ctx, timeout)
				defer cancel()
				select {
				case <-release:
					return nil
				case <-probeCtx.Done():
					return probeCtx.Err()
				}
			})
			runtime, err := NewRuntime(Options{StateDir: t.TempDir(), NodeID: "node-inflight-disable", DefaultPort: 80, Probe: probe})
			if err != nil {
				t.Fatal(err)
			}
			config, err := decodeConfig(testConfig(t, 1, "default", nil, 0, 0, false))
			if err != nil {
				t.Fatal(err)
			}
			config.ProbeTimeoutMS = 500
			payload, err := canonicalConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := runtime.Apply(t.Context(), payload); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			probeCtx, cancelProbe := context.WithCancel(ctx)
			runDone := make(chan error, 1)
			go func() { defer close(runDone); _, err := runtime.RunOnce(probeCtx); runDone <- err }()
			t.Cleanup(func() {
				cancelProbe()
				select {
				case <-runDone:
				case <-time.After(3 * time.Second):
					t.Error("in-flight probe did not stop")
				}
			})
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("probe did not enter")
			}
			config.ConfigRevision = 2
			enabled := false
			config.MonitorEnabled = &enabled
			payload, err = canonicalConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			applyDone := make(chan error, 1)
			go func() { defer close(applyDone); _, err := runtime.Apply(ctx, payload); applyDone <- err }()
			t.Cleanup(func() {
				cancelProbe()
				select {
				case <-applyDone:
				case <-time.After(3 * time.Second):
					t.Error("disable did not stop")
				}
			})
			select {
			case err := <-applyDone:
				t.Fatalf("disable returned before in-flight probe completed: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			var want error
			switch completion {
			case "success":
				close(release)
			case "cancel":
				cancelProbe()
				want = context.Canceled
			case "timeout":
				want = context.DeadlineExceeded
			}
			select {
			case err := <-runDone:
				if !errors.Is(err, want) {
					t.Fatalf("probe result = %v, want %v", err, want)
				}
			case <-ctx.Done():
				t.Fatal("probe did not finish")
			}
			select {
			case err := <-applyDone:
				if err != nil {
					t.Fatalf("disable after probe = %v", err)
				}
			case <-ctx.Done():
				t.Fatal("disable remained blocked after probe")
			}
			if report, err := runtime.RunOnce(ctx); err != nil || !reflect.DeepEqual(report, MetricReport{}) || calls != 2 {
				t.Fatalf("probe restarted after completed disable: calls=%d report=%+v error=%v", calls, report, err)
			}
			if stored, err := loadStoredConfig(filepath.Join(runtime.stateDir, activeFileName)); err != nil || !reflect.DeepEqual(stored, &config) {
				t.Fatalf("disabled configuration was not durable: %+v, %v", stored, err)
			}
		})
	}
}

type runtimeBoundaryProbe func(context.Context, uint16, time.Duration) error

func (probe runtimeBoundaryProbe) Probe(ctx context.Context, port uint16, timeout time.Duration) error {
	return probe(ctx, port, timeout)
}

type runtimeTCPProbe struct{ calls int }

func (probe *runtimeTCPProbe) Probe(ctx context.Context, port uint16, timeout time.Duration) error {
	probe.calls++
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		return err
	}
	return connection.Close()
}

func listenRuntimeTCP(t *testing.T) (net.Listener, uint16) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener, uint16(listener.Addr().(*net.TCPAddr).Port)
}

func assertDisabledHostOnly(t *testing.T, runtime *Runtime, probe *runtimeTCPProbe) {
	t.Helper()
	before := probe.calls
	runtime.wait = func(context.Context, time.Duration) error { return context.Canceled }
	sink := &metricSink{}
	if err := runtime.Run(t.Context(), sink); !errors.Is(err, context.Canceled) {
		t.Fatalf("disabled Run = %v", err)
	}
	if probe.calls != before || len(sink.reports) != 1 {
		t.Fatalf("disabled Run performed a probe or lost host metrics: calls=%d reports=%d", probe.calls-before, len(sink.reports))
	}
	report := sink.reports[0]
	if report.LoadMetrics == nil || report.ConfigRevision != 0 || report.ActiveConfigRevision != 0 ||
		report.ProbePort != 0 || report.ProbesTotal != 0 || report.ProbeSucceeded || report.Healthy {
		t.Fatalf("disabled report fabricated probe evidence: %+v", report)
	}
}

func testConfig(t *testing.T, revision uint64, mode string, port *uint16, failureDebounceMS, recoveryDebounceMS uint32, notify bool) []byte {
	t.Helper()
	payload, err := json.Marshal(Config{
		SchemaVersion: SchemaVersion, ConfigRevision: revision, PortMode: mode, CustomPort: port,
		ProbeIntervalMS: 10_000, ProbeTimeoutMS: 3_000, FailureThreshold: 3, RecoveryThreshold: 3,
		FailureDebounceMS: failureDebounceMS, RecoveryDebounceMS: recoveryDebounceMS,
		RecoveryNotificationEnabled: notify,
	})
	if err != nil {
		t.Fatalf("encode config: %v", err)
	}
	return payload
}
