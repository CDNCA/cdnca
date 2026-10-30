package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gateway "github.com/cdnca/cdnca/services/agent-gateway"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
)

func TestHealthHandlerTransitionsFromStartupToReady(t *testing.T) {
	liveness := &livenessState{}
	var dependencyReady atomic.Bool
	readiness := newRuntimeReadiness(func(context.Context) error {
		if !dependencyReady.Load() {
			return errors.New("database-url=do-not-log")
		}
		return nil
	})
	handler := newHealthHandler(liveness, readiness, 100*time.Millisecond)

	assertHealthResponse(t, handler, http.MethodGet, "/health/live", http.StatusServiceUnavailable, `{"status":"not_live"}`+"\n")
	liveness.set(true)
	assertHealthResponse(t, handler, http.MethodGet, "/health/live", http.StatusOK, `{"status":"live"}`+"\n")
	assertHealthResponse(t, handler, http.MethodGet, "/health/ready", http.StatusServiceUnavailable, `{"status":"not_ready"}`+"\n")
	dependencyReady.Store(true)
	assertHealthResponse(t, handler, http.MethodGet, "/health/ready", http.StatusOK, `{"status":"ready"}`+"\n")
	liveness.set(false)
	assertHealthResponse(t, handler, http.MethodGet, "/health/ready", http.StatusServiceUnavailable, `{"status":"not_ready"}`+"\n")
}

func TestHealthHandlerBoundsAndSanitizesFailedChecks(t *testing.T) {
	liveness := &livenessState{}
	liveness.set(true)
	handler := newHealthHandler(liveness, newRuntimeReadiness(func(ctx context.Context) error {
		<-ctx.Done()
		return errors.New("redis://user:do-not-log@redis:6379")
	}), 20*time.Millisecond)

	startedAt := time.Now()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if elapsed := time.Since(startedAt); elapsed > time.Second {
		t.Fatalf("readiness response exceeded its bound: %s", elapsed)
	}
	if recorder.Code != http.StatusServiceUnavailable || recorder.Body.String() != `{"status":"not_ready"}`+"\n" {
		t.Fatalf("failed readiness response = %d %q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "do-not-log") || len(recorder.Body.String()) > 64 {
		t.Fatalf("readiness response leaked or was unbounded: %q", recorder.Body.String())
	}
}

func TestHealthHandlerRejectsUnknownPathsAndMethods(t *testing.T) {
	handler := newHealthHandler(&livenessState{}, newRuntimeReadiness(func(context.Context) error { return nil }), time.Second)
	assertHealthResponse(t, handler, http.MethodGet, "/healthz", http.StatusNotFound, `{"status":"not_found"}`+"\n")
	assertHealthResponse(t, handler, http.MethodPost, "/health/live", http.StatusMethodNotAllowed, `{"status":"method_not_allowed"}`+"\n")
}

func TestRuntimeReadinessChecksEveryDependencyAndFailsClosed(t *testing.T) {
	var calls atomic.Int32
	checks := []readinessCheck{
		func(context.Context) error { calls.Add(1); return nil },
		func(context.Context) error { calls.Add(1); return errors.New("Redis unavailable") },
		func(context.Context) error { calls.Add(1); return errors.New("NATS unavailable") },
		func(context.Context) error { calls.Add(1); return errors.New("Control unavailable") },
		func(context.Context) error { calls.Add(1); return errors.New("listener unavailable") },
	}
	if err := newRuntimeReadiness(checks...).ready(context.Background()); err == nil {
		t.Fatal("degraded dependency set was reported ready")
	}
	if calls.Load() != int32(len(checks)) {
		t.Fatalf("readiness checks called %d times, want %d", calls.Load(), len(checks))
	}
}

func TestDependencyHealthChecksRejectClosedClients(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	redisClient := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	if err := redisClient.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verifyRedisHealth(ctx, redisClient); err == nil {
		t.Fatal("closed Redis client was reported healthy")
	}
	if err := verifyNATSHealth(ctx, &nats.Conn{}, gateway.DefaultNATSCommandBusConfig()); err == nil {
		t.Fatal("disconnected NATS client was reported healthy")
	}
}

func TestReadyListenerTracksAcceptAndClose(t *testing.T) {
	listener := newReadyListener(listenLocal(t))
	accepted := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if connection != nil {
			_ = connection.Close()
		}
		accepted <- err
	}()
	deadline := time.Now().Add(time.Second)
	for !listener.isReady() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !listener.isReady() {
		t.Fatal("listener did not become ready after entering Accept")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-accepted:
		if err == nil {
			t.Fatal("closed listener Accept returned no error")
		}
	case <-time.After(time.Second):
		t.Fatal("listener Accept did not unblock on close")
	}
	if listener.isReady() {
		t.Fatal("closed listener remained ready")
	}
}

func assertHealthResponse(t *testing.T, handler http.Handler, method, path string, status int, body string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
	if recorder.Code != status || recorder.Body.String() != body {
		t.Fatalf("%s %s = %d %q, want %d %q", method, path, recorder.Code, recorder.Body.String(), status, body)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("health response headers = %#v", recorder.Header())
	}
}
