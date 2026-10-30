package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcilehttpmtls"
)

type namedReadinessProbe struct{ err error }

func (probe *namedReadinessProbe) Ready() error { return probe.err }

// The 1.0.29 -> 1.0.33 upgrade on the management host kept /health/ready at
// 503 for two minutes and the journal never said which probe failed.
func TestRequireReadinessLogsFailingProbeAtBoundedRate(t *testing.T) {
	var output bytes.Buffer
	now := time.Unix(1_800_000_000, 0)
	reporter := &readinessReporter{logger: slog.New(slog.NewTextHandler(&output, nil)),
		now: func() time.Time { return now }, interval: time.Minute}
	healthy := &fakeReadinessProbe{}
	failing := &namedReadinessProbe{err: errors.New("control upgrade runtime worker is unhealthy")}
	handler := requireReadinessWithReporter(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), reporter, healthy, failing)
	ready := func() int {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
		return response.Code
	}
	for range 30 { // the runner polls about once a second
		if code := ready(); code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d", code)
		}
		now = now.Add(time.Second)
	}
	logged := output.String()
	if strings.Count(logged, "readiness probe failed") != 1 ||
		!strings.Contains(logged, "probe=*main.namedReadinessProbe") || !strings.Contains(logged, "index=1") ||
		!strings.Contains(logged, `error="control upgrade runtime worker is unhealthy"`) {
		t.Fatalf("log = %q", logged)
	}
	now = now.Add(time.Minute)
	ready()
	if strings.Count(output.String(), "readiness probe failed") != 2 {
		t.Fatalf("a persisting failure must be repeated once per interval: %q", output.String())
	}
	failing.err = nil
	if code := ready(); code != http.StatusOK {
		t.Fatalf("recovered status = %d", code)
	}
	ready()
	if strings.Count(output.String(), "readiness probes recovered") != 1 {
		t.Fatalf("recovery log = %q", output.String())
	}
	output.Reset()
	response := httptest.NewRecorder()
	requireReadinessWithReporter(http.NotFoundHandler(), reporter, nil).
		ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(output.String(), "readiness probe is not configured") {
		t.Fatalf("nil probe status=%d log=%q", response.Code, output.String())
	}
}

// runWithDBBackoff re-runs the edge runtime after a transient database error;
// the retried runtime must report ready again instead of staying 503 forever.
func TestEdgeDeploymentRuntimeIsReadyAgainAfterRetry(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	running := make(chan struct{})
	runtime := &edgeDeploymentRuntime{
		connection: fakeNATSRuntimeConnection{connected: true},
		workers: []runtimeWorker{fakeRuntimeWorker{run: func(ctx context.Context) error {
			mu.Lock()
			attempts++
			attempt := attempts
			mu.Unlock()
			if attempt == 1 {
				return errors.New("FATAL: terminating connection due to administrator command (SQLSTATE 57P01)")
			}
			close(running)
			<-ctx.Done()
			return ctx.Err()
		}}},
	}
	runtime.ready.Store(true)
	if err := runtime.Run(context.Background()); err == nil || !isTransientDBError(err) {
		t.Fatalf("first attempt = %v", err)
	}
	if runtime.Ready() == nil {
		t.Fatal("stopped runtime reported ready")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	<-running
	if err := runtime.Ready(); err != nil {
		t.Fatalf("retried runtime is not ready: %v", err)
	}
	cancel()
	<-done
	if runtime.Ready() == nil {
		t.Fatal("cancelled runtime reported ready")
	}
}

// Single-host installs run DNS reconcile without the workload mTLS listener;
// stopping control-api then exited 1 with "invalid DNS reconcile workload
// mTLS listener configuration" on every restart.
func TestDNSReconcileShutdownWithoutWorkloadListener(t *testing.T) {
	var server *dnsreconcilehttpmtls.Server
	if err := server.Shutdown(context.Background()); !errors.Is(err, dnsreconcilehttpmtls.ErrInvalidConfig) {
		t.Fatalf("nil listener Shutdown() = %v", err)
	}
	runtime := &dnsReconcileProductionRuntime{}
	if err := runtime.shutdownWorkloadServer(context.Background()); err != nil {
		t.Fatalf("shutdown without workload listener = %v", err)
	}
	var missing *dnsReconcileProductionRuntime
	if err := missing.shutdownWorkloadServer(context.Background()); err != nil {
		t.Fatalf("shutdown without runtime = %v", err)
	}
}
