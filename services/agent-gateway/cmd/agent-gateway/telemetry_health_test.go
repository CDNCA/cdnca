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
)

func TestTelemetryHealthDetailIsDegradedWithoutGatingCoreReadiness(t *testing.T) {
	liveness := &livenessState{}
	liveness.set(true)
	health := gateway.NewTelemetryHealth()
	correlation := gateway.NewCorrelationHealth()
	correlation.RecordAccepted()
	correlation.RecordReplayed()
	correlation.RecordRejected()
	correlation.RecordPublishFailed()
	var telemetryAvailable atomic.Bool
	check := func(context.Context) error {
		if !telemetryAvailable.Load() {
			return errors.New("nats://user:do-not-log@nats:4222")
		}
		return nil
	}
	handler := newTelemetryHealthHandler(
		newHealthHandler(liveness, newRuntimeReadiness(func(context.Context) error { return nil }), time.Second),
		liveness, health, correlation, check, time.Second,
	)

	assertHealthResponse(t, handler, http.MethodGet, "/health/ready", http.StatusOK, `{"status":"ready"}`+"\n")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health/detail", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"telemetry":"degraded"`) ||
		!strings.Contains(recorder.Body.String(), `"correlation":{"accepted":1,"replayed":1,"rejected":1,"publish_failed":1,"terminal_succeeded":0,"terminal_failed":0,"last_result_code":"CORRELATION_PUBLISH_FAILED"}`) ||
		strings.Contains(recorder.Body.String(), "do-not-log") {
		t.Fatalf("degraded telemetry detail = %d %q", recorder.Code, recorder.Body.String())
	}

	telemetryAvailable.Store(true)
	health.RecordAccepted(true)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health/detail", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"telemetry":"healthy"`) ||
		!strings.Contains(recorder.Body.String(), `"accepted_records":1`) || !strings.Contains(recorder.Body.String(), `"duplicate_records":1`) {
		t.Fatalf("healthy telemetry detail = %d %q", recorder.Code, recorder.Body.String())
	}
}
