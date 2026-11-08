package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

func TestOpenAnalyticsIngestRuntimeDisabledHasNoDependencies(t *testing.T) {
	called := false
	runtime, err := openAnalyticsIngestRuntime(context.Background(), config.Config{}, nil, nil,
		func(string, ...nats.Option) (*nats.Conn, error) {
			called = true
			return nil, errors.New("must not connect")
		}, nil)
	if err != nil || runtime != nil || called {
		t.Fatalf("disabled runtime = (%v, %v), connector called=%t", runtime, err, called)
	}
}

func TestOpenAnalyticsIngestRuntimeRejectsMissingHistoryAuthorityBeforeNetwork(t *testing.T) {
	base := config.Config{
		ControlInstallationID: "11111111-1111-4111-8111-111111111111",
		ShutdownPeriod:        time.Second,
		AnalyticsIngest: config.AnalyticsIngestConfig{
			Enabled: true, ConnectTimeout: time.Second, WriteTimeout: time.Second,
			SupervisorBackoffMin: time.Second,
			JetStream:            analytics.DefaultJetStreamConfig(),
		},
	}
	for _, test := range []struct {
		name string
		cfg  config.Config
		pool *pgxpool.Pool
	}{
		{name: "missing postgres authority", cfg: base},
		{name: "missing installation", cfg: func() config.Config {
			candidate := base
			candidate.ControlInstallationID = ""
			return candidate
		}(), pool: new(pgxpool.Pool)},
	} {
		t.Run(test.name, func(t *testing.T) {
			var connectorCalls atomic.Int32
			httpClient := &analyticsIngestNetworkProbe{}
			runtime, err := openAnalyticsIngestRuntime(context.Background(), test.cfg, test.pool, nil,
				func(string, ...nats.Option) (*nats.Conn, error) {
					connectorCalls.Add(1)
					return nil, errors.New("must not connect")
				}, httpClient)
			if err == nil || runtime != nil || connectorCalls.Load() != 0 || httpClient.calls.Load() != 0 {
				t.Fatalf("missing history runtime=%v error=%v connector_calls=%d http_calls=%d",
					runtime, err, connectorCalls.Load(), httpClient.calls.Load())
			}
		})
	}
}

func TestOpenAnalyticsIngestRuntimeBoundsHistoryAuthorityBeforeNetwork(t *testing.T) {
	const operationTimeout = 40 * time.Millisecond
	poolConfig, err := pgxpool.ParseConfig("postgres://127.0.0.1:1/runtime?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	dialStarted := make(chan struct{}, 1)
	releaseDial := make(chan struct{})
	defer close(releaseDial)
	poolConfig.ConnConfig.DialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		select {
		case dialStarted <- struct{}{}:
		default:
		}
		select {
		case <-releaseDial:
			return nil, errors.New("release blocked analytics history dial")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	jetstreamConfig := analytics.DefaultJetStreamConfig()
	jetstreamConfig.OperationTimeout = operationTimeout
	cfg := config.Config{
		ControlInstallationID: "11111111-1111-4111-8111-111111111111",
		ShutdownPeriod:        time.Second,
		AnalyticsIngest: config.AnalyticsIngestConfig{
			Enabled: true, ConnectTimeout: time.Second, WriteTimeout: time.Second,
			SupervisorBackoffMin: time.Second,
			JetStream:            jetstreamConfig,
		},
	}
	var connectorCalls atomic.Int32
	httpClient := &analyticsIngestNetworkProbe{}
	parentCtx, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	type openResult struct {
		runtime *analyticsIngestProcessRuntime
		err     error
	}
	results := make(chan openResult, 1)
	started := time.Now()
	go func() {
		runtime, openErr := openAnalyticsIngestRuntime(parentCtx, cfg, pool, nil,
			func(string, ...nats.Option) (*nats.Conn, error) {
				connectorCalls.Add(1)
				return nil, errors.New("must not connect")
			}, httpClient)
		results <- openResult{runtime: runtime, err: openErr}
	}()

	var result openResult
	var resultReady bool
	select {
	case <-dialStarted:
	case result = <-results:
		resultReady = true
		select {
		case <-dialStarted:
		default:
			if connectorCalls.Load() != 0 || httpClient.calls.Load() != 0 {
				t.Fatalf("history authority failure dispatched network: connector_calls=%d http_calls=%d",
					connectorCalls.Load(), httpClient.calls.Load())
			}
			t.Fatalf("history authority returned before bounded PostgreSQL dial: %v", result.err)
		}
	case <-time.After(time.Second):
		cancelParent()
		t.Fatal("history authority did not start PostgreSQL dial")
	}
	if !resultReady {
		select {
		case result = <-results:
		case <-time.After(time.Second):
			cancelParent()
			t.Fatal("history authority did not return after its operation timeout")
		}
	}
	if elapsed := time.Since(started); elapsed < operationTimeout/2 || elapsed > 5*operationTimeout {
		t.Fatalf("history authority returned after %s, want about %s", elapsed, operationTimeout)
	}
	if result.runtime != nil || result.err == nil || result.err.Error() != "open analytics ingest history authority" ||
		!errors.Is(result.err, context.DeadlineExceeded) || connectorCalls.Load() != 0 || httpClient.calls.Load() != 0 {
		t.Fatalf("bounded history runtime=%v error=%v connector_calls=%d http_calls=%d",
			result.runtime, result.err, connectorCalls.Load(), httpClient.calls.Load())
	}
}

type analyticsIngestNetworkProbe struct{ calls atomic.Int32 }

func (client *analyticsIngestNetworkProbe) Do(*http.Request) (*http.Response, error) {
	client.calls.Add(1)
	return nil, errors.New("must not use analytics HTTP")
}

func TestAnalyticsIngestRuntimeSupervisesFailuresWithoutLeakingErrors(t *testing.T) {
	const secret = "dependency-visible-secret"
	worker := &scriptedAnalyticsIngestWorker{firstError: errors.New(secret)}
	var logs bytes.Buffer
	runtime := &analyticsIngestProcessRuntime{
		worker: worker, logger: slog.New(slog.NewTextHandler(&logs, nil)), health: newAnalyticsIngestHealth(true),
		backoffMin: 20 * time.Millisecond, backoffMax: 40 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	waitForCondition(t, time.Second, func() bool {
		return runtime.Health().State == "degraded" && runtime.Health().RestartCount == 1
	})
	waitForCondition(t, time.Second, func() bool { return worker.calls.Load() >= 2 })
	if state := runtime.Health().State; state != "degraded" {
		t.Fatalf("health state after retry started = %q, want degraded until proven recovery", state)
	}
	if bytes.Contains(logs.Bytes(), []byte(secret)) {
		t.Fatalf("supervisor log leaked dependency error: %s", logs.String())
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("supervised runtime did not stop after cancellation")
	}
}

func TestAnalyticsIngestRuntimeUsesBoundedBackoff(t *testing.T) {
	worker := &alwaysFailAnalyticsIngestWorker{}
	runtime := &analyticsIngestProcessRuntime{
		worker: worker, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), health: newAnalyticsIngestHealth(true),
		backoffMin: 20 * time.Millisecond, backoffMax: 40 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 115*time.Millisecond)
	defer cancel()
	if err := runtime.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run() error = %v", err)
	}
	if calls := worker.calls.Load(); calls < 3 || calls > 5 {
		t.Fatalf("worker calls = %d, want bounded retries", calls)
	}
}

func TestAnalyticsIngestHealthTracksIndependentFailuresAndIgnoresLateCallbacks(t *testing.T) {
	health := newAnalyticsIngestHealth(true)
	health.markStarted()
	if state := health.snapshot().State; state != "running" {
		t.Fatalf("started state = %q", state)
	}
	if !health.markDegraded(analyticsIngestDegradedNATS) || !health.markDegraded(analyticsIngestDegradedWorker) {
		t.Fatal("independent dependency failures were not recorded")
	}
	recoverWorker := func() { health.markRecovered(analyticsIngestDegradedWorker) }
	recoverWorker()
	if health.snapshot().State != "degraded" || health.degraded.Load() != analyticsIngestDegradedNATS {
		t.Fatalf("empty worker fetch cleared unrelated NATS failure: %#v causes=%b", health.snapshot(), health.degraded.Load())
	}
	if !health.markRecovered(analyticsIngestDegradedNATS) || health.snapshot().State != "running" {
		t.Fatalf("independent recovery did not restore health: %#v", health.snapshot())
	}

	health.markStopping()
	if health.markDegraded(analyticsIngestDegradedNATS) || health.markRecovered(analyticsIngestDegradedNATS) ||
		health.snapshot().State != "stopping" {
		t.Fatalf("late callback changed stopping health: %#v", health.snapshot())
	}
	health.markStopped()
	if health.markDegraded(analyticsIngestDegradedNATS) || health.markRecovered(analyticsIngestDegradedNATS) ||
		health.snapshot().State != "stopped" {
		t.Fatalf("late callback changed stopped health: %#v", health.snapshot())
	}
}

// Close flushes and closes the NATS connection (no Drain):
// the consumer's pull subscription is already gone, and Drain returned at once
// and left the close to a background goroutine bounded only by DrainTimeout.
func TestAnalyticsIngestRuntimeCloseOrdersResources(t *testing.T) {
	var mu sync.Mutex
	var operations []string
	record := func(operation string) {
		mu.Lock()
		operations = append(operations, operation)
		mu.Unlock()
	}
	connection := &orderedAnalyticsIngestConnection{connected: true, record: record}
	runtime := &analyticsIngestProcessRuntime{
		worker:     &orderedAnalyticsIngestWorker{close: func() error { record("consumer"); return nil }},
		connection: connection,
		closeHTTP:  func() { record("http") }, health: newAnalyticsIngestHealth(true), shutdownTimeout: time.Second,
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := strings.Join(operations, ",")
	mu.Unlock()
	if got != "consumer,flush,close,http" || !connection.IsClosed() || runtime.Health().State != "stopped" {
		t.Fatalf("shutdown operations=%q closed=%t health=%#v", got, connection.IsClosed(), runtime.Health())
	}
}

func TestAnalyticsIngestRuntimeCloseBoundsFlushByCallerDeadline(t *testing.T) {
	connection := &orderedAnalyticsIngestConnection{connected: true, blockFlush: true}
	runtime := &analyticsIngestProcessRuntime{
		worker: &orderedAnalyticsIngestWorker{}, connection: connection,
		health: newAnalyticsIngestHealth(true), shutdownTimeout: time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := runtime.CloseContext(ctx)
	if elapsed := time.Since(started); elapsed < 10*time.Millisecond || elapsed > 250*time.Millisecond {
		t.Fatalf("CloseContext elapsed %s, want the caller deadline", elapsed)
	}
	if err == nil || err.Error() != "flush analytics ingest NATS connection" || !connection.IsClosed() ||
		runtime.Health().State != "stopped" {
		t.Fatalf("CloseContext error=%v closed=%t health=%#v", err, connection.IsClosed(), runtime.Health())
	}
}

func TestAnalyticsIngestRuntimeCloseSkipsFlushWhenDisconnected(t *testing.T) {
	var operations []string
	connection := &orderedAnalyticsIngestConnection{record: func(operation string) { operations = append(operations, operation) }}
	runtime := &analyticsIngestProcessRuntime{
		worker: &orderedAnalyticsIngestWorker{}, connection: connection,
		health: newAnalyticsIngestHealth(true), shutdownTimeout: time.Second,
	}
	if err := runtime.Close(); err != nil || strings.Join(operations, ",") != "close" || runtime.Health().State != "stopped" {
		t.Fatalf("disconnected Close error=%v operations=%v health=%#v", err, operations, runtime.Health())
	}
}

func TestAnalyticsIngestRuntimeLateRunExitDoesNotRegressStoppedHealth(t *testing.T) {
	worker := &orderedAnalyticsIngestWorker{}
	runtime := &analyticsIngestProcessRuntime{
		worker: worker, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), health: newAnalyticsIngestHealth(true),
		backoffMin: time.Millisecond, backoffMax: time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	waitForCondition(t, time.Second, func() bool { return runtime.Health().State == "running" })
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run() cancellation error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not exit after cancellation")
	}
	if state := runtime.Health().State; state != "stopped" {
		t.Fatalf("late Run exit regressed stopped health to %q", state)
	}
}

func TestAnalyticsIngestHealthDetailIsSafeAndDoesNotGateReadiness(t *testing.T) {
	runtime := &analyticsIngestProcessRuntime{health: newAnalyticsIngestHealth(true)}
	runtime.health.state.Store(analyticsIngestStateDegraded)
	runtime.health.failures.Store(3)
	called := 0
	handler := withAnalyticsIngestHealth(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		called++
		writer.WriteHeader(http.StatusNoContent)
	}), runtime)

	detail := httptest.NewRecorder()
	handler.ServeHTTP(detail, httptest.NewRequest(http.MethodGet, "/health/detail", nil))
	if detail.Code != http.StatusOK || called != 0 || detail.Header().Get("Cache-Control") != "no-store" ||
		detail.Body.String() != "{\"analytics_ingest\":{\"enabled\":true,\"state\":\"degraded\",\"restart_count\":3}}\n" ||
		strings.Contains(detail.Body.String(), "nats") || strings.Contains(detail.Body.String(), "clickhouse") {
		t.Fatalf("health detail status=%d headers=%v body=%q", detail.Code, detail.Header(), detail.Body.String())
	}

	ready := httptest.NewRecorder()
	handler.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if ready.Code != http.StatusNoContent || called != 1 {
		t.Fatalf("degraded ingest gated readiness status=%d called=%d", ready.Code, called)
	}

	disabled := httptest.NewRecorder()
	withAnalyticsIngestHealth(http.NotFoundHandler(), nil).ServeHTTP(disabled, httptest.NewRequest(http.MethodGet, "/health/detail", nil))
	if disabled.Body.String() != "{\"analytics_ingest\":{\"enabled\":false,\"state\":\"disabled\",\"restart_count\":0}}\n" {
		t.Fatalf("disabled health detail = %q", disabled.Body.String())
	}
}

type scriptedAnalyticsIngestWorker struct {
	firstError error
	calls      atomic.Int32
}

func (worker *scriptedAnalyticsIngestWorker) Run(ctx context.Context) error {
	if worker.calls.Add(1) == 1 {
		return worker.firstError
	}
	<-ctx.Done()
	return ctx.Err()
}

func (*scriptedAnalyticsIngestWorker) Close() error { return nil }

type alwaysFailAnalyticsIngestWorker struct {
	calls atomic.Int32
}

func (worker *alwaysFailAnalyticsIngestWorker) Run(context.Context) error {
	worker.calls.Add(1)
	return errors.New("dependency failed")
}

func (*alwaysFailAnalyticsIngestWorker) Close() error { return nil }

type orderedAnalyticsIngestWorker struct {
	close func() error
}

func (*orderedAnalyticsIngestWorker) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (worker *orderedAnalyticsIngestWorker) Close() error {
	if worker.close == nil {
		return nil
	}
	return worker.close()
}

type orderedAnalyticsIngestConnection struct {
	connected  bool
	blockFlush bool
	record     func(string)
	closed     atomic.Bool
}

func (connection *orderedAnalyticsIngestConnection) note(operation string) {
	if connection.record != nil {
		connection.record(operation)
	}
}
func (connection *orderedAnalyticsIngestConnection) IsConnected() bool {
	return connection.connected && !connection.closed.Load()
}
func (connection *orderedAnalyticsIngestConnection) FlushWithContext(ctx context.Context) error {
	connection.note("flush")
	if connection.blockFlush {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}
func (connection *orderedAnalyticsIngestConnection) Close() {
	connection.note("close")
	connection.closed.Store(true)
}
func (connection *orderedAnalyticsIngestConnection) IsClosed() bool { return connection.closed.Load() }

func waitForCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}
