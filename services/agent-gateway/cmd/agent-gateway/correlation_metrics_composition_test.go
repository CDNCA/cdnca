package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gateway "github.com/cdnca/cdnca/services/agent-gateway"
)

func TestCorrelationMetricsCompositionPreservesHealthRoutesAndLifecycle(t *testing.T) {
	liveness := &livenessState{}
	liveness.set(true)
	readiness := newRuntimeReadiness(func(context.Context) error { return nil })
	telemetry := gateway.NewTelemetryHealth()
	correlation := gateway.NewCorrelationHealth()
	correlation.RecordAccepted()
	correlation.RecordReplayed()
	correlation.RecordRejected()
	correlation.RecordPublishFailed()
	var detailChecks atomic.Uint64
	check := func(context.Context) error {
		detailChecks.Add(1)
		return nil
	}

	handler, err := newHealthComposition(liveness, readiness, telemetry, correlation, check, 250*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	metrics, ok := handler.(*correlationMetricsHandler)
	if !ok {
		t.Fatalf("outer handler = %T, want *correlationMetricsHandler", handler)
	}
	if metrics.health != correlation {
		t.Fatalf("metrics correlation = %p, want %p", metrics.health, correlation)
	}
	detail, ok := metrics.base.(*telemetryHealthHandler)
	if !ok {
		t.Fatalf("metrics base = %T, want *telemetryHealthHandler", metrics.base)
	}
	if detail.correlation != correlation {
		t.Fatalf("detail correlation = %p, want %p", detail.correlation, correlation)
	}
	if _, ok := detail.base.(*healthHandler); !ok {
		t.Fatalf("telemetry base = %T, want *healthHandler", detail.base)
	}

	assertCorrelationCompositionResponse(t, handler, http.MethodGet, "/metrics", http.StatusOK,
		"cdnca_agent_gateway_correlation_accepted_total 1\n", "text/plain; version=0.0.4; charset=utf-8")
	assertCorrelationCompositionResponse(t, handler, http.MethodGet, "/health/live", http.StatusOK,
		`{"status":"live"}`, "application/json")
	assertCorrelationCompositionResponse(t, handler, http.MethodGet, "/health/ready", http.StatusOK,
		`{"status":"ready"}`, "application/json")
	assertCorrelationCompositionResponse(t, handler, http.MethodGet, "/health/detail", http.StatusOK,
		`"correlation":{"accepted":1,"replayed":1,"rejected":1,"publish_failed":1,"terminal_succeeded":0,"terminal_failed":0,"last_result_code":"CORRELATION_PUBLISH_FAILED"}`, "application/json")
	if detailChecks.Load() != 1 {
		t.Fatalf("detail checks = %d, want 1", detailChecks.Load())
	}

	method := httptest.NewRecorder()
	handler.ServeHTTP(method, httptest.NewRequest(http.MethodPost, "/metrics", strings.NewReader("sensitive")))
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") != http.MethodGet ||
		method.Body.Len() != 0 || detailChecks.Load() != 1 {
		t.Fatalf("POST metrics code=%d allow=%q body=%q checks=%d", method.Code,
			method.Header().Get("Allow"), method.Body.String(), detailChecks.Load())
	}
	assertCorrelationCompositionResponse(t, handler, http.MethodGet, "/unknown", http.StatusNotFound,
		`{"status":"not_found"}`, "application/json")

	server := newHealthHTTPServer(handler, 250*time.Millisecond)
	if server.Handler != handler || server.ReadHeaderTimeout != 2*time.Second ||
		server.ReadTimeout != 1250*time.Millisecond || server.WriteTimeout != 1250*time.Millisecond ||
		server.IdleTimeout != 30*time.Second || server.MaxHeaderBytes != 8<<10 {
		t.Fatalf("health server lifecycle changed: %+v", server)
	}

	source, err := os.ReadFile("runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "healthHandler, err := newHealthComposition(") ||
		!strings.Contains(text, "r.healthServer = newHealthHTTPServer(healthHandler, c.healthCheckTimeout)") {
		t.Fatal("buildRuntime does not mount the composed handler on the existing health server lifecycle")
	}
}

func assertCorrelationCompositionResponse(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	wantStatus int,
	wantBody string,
	wantContentType string,
) {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(method, path, nil))
	if response.Code != wantStatus || !strings.Contains(response.Body.String(), wantBody) {
		t.Fatalf("%s %s = %d %q", method, path, response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != wantContentType ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%s %s headers = %#v", method, path, response.Header())
	}
}
