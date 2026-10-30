package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gateway "github.com/cdnca/cdnca/services/agent-gateway"
)

func TestCorrelationMetricsConstructorFailsClosed(t *testing.T) {
	health := gateway.NewCorrelationHealth()
	var typedNil *http.ServeMux
	for name, candidate := range map[string]struct {
		base   http.Handler
		health *gateway.CorrelationHealth
	}{
		"nil base":       {health: health},
		"typed nil base": {base: typedNil, health: health},
		"nil health":     {base: http.NotFoundHandler()},
	} {
		t.Run(name, func(t *testing.T) {
			handler, err := newCorrelationMetricsHandler(candidate.base, candidate.health)
			if handler != nil || !errors.Is(err, errCorrelationMetricsInvalidConfig) {
				t.Fatalf("newCorrelationMetricsHandler() = (%T, %v), want nil invalid config", handler, err)
			}
		})
	}
}

func TestCorrelationMetricsUsesOneBoundedLabelFreeSnapshot(t *testing.T) {
	health := gateway.NewCorrelationHealth()
	health.RecordAccepted()
	health.RecordAccepted()
	health.RecordReplayed()
	health.RecordRejected()
	health.RecordRejected()
	health.RecordRejected()
	health.RecordPublishFailed()

	baseCalls := 0
	handler, err := newCorrelationMetricsHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		baseCalls++
	}), health)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	const want = "# HELP cdnca_agent_gateway_correlation_accepted_total Accepted correlation commands.\n" +
		"# TYPE cdnca_agent_gateway_correlation_accepted_total counter\n" +
		"cdnca_agent_gateway_correlation_accepted_total 2\n" +
		"# HELP cdnca_agent_gateway_correlation_replayed_total Replayed correlation commands.\n" +
		"# TYPE cdnca_agent_gateway_correlation_replayed_total counter\n" +
		"cdnca_agent_gateway_correlation_replayed_total 1\n" +
		"# HELP cdnca_agent_gateway_correlation_rejected_total Rejected correlation commands.\n" +
		"# TYPE cdnca_agent_gateway_correlation_rejected_total counter\n" +
		"cdnca_agent_gateway_correlation_rejected_total 3\n" +
		"# HELP cdnca_agent_gateway_correlation_publish_failed_total Correlation command publish failures.\n" +
		"# TYPE cdnca_agent_gateway_correlation_publish_failed_total counter\n" +
		"cdnca_agent_gateway_correlation_publish_failed_total 1\n" +
		"# HELP cdnca_agent_gateway_correlation_terminal_succeeded_total Successfully activated or reverted terminal deployments.\n" +
		"# TYPE cdnca_agent_gateway_correlation_terminal_succeeded_total counter\n" +
		"cdnca_agent_gateway_correlation_terminal_succeeded_total 0\n" +
		"# HELP cdnca_agent_gateway_correlation_terminal_failed_total Failed terminal deployments.\n" +
		"# TYPE cdnca_agent_gateway_correlation_terminal_failed_total counter\n" +
		"cdnca_agent_gateway_correlation_terminal_failed_total 0\n"
	if response.Code != http.StatusOK || response.Body.String() != want || baseCalls != 0 {
		t.Fatalf("metrics code=%d body=%q base_calls=%d", response.Code, response.Body.String(), baseCalls)
	}
	if got := response.Header().Get("Content-Type"); got != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("safety headers = %#v", response.Header())
	}
	for _, forbidden := range []string{"{", "request_id", "task_id", "traceparent", "tenant", "site", "replica", "error"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("metrics expose forbidden value %q", forbidden)
		}
	}
}

func TestCorrelationMetricsPassesOtherPathsAndRejectsOtherMethods(t *testing.T) {
	baseCalls := 0
	handler, err := newCorrelationMetricsHandler(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		baseCalls++
		response.Header().Set("X-Base-Path", request.URL.Path)
		response.WriteHeader(http.StatusTeapot)
	}), gateway.NewCorrelationHealth())
	if err != nil {
		t.Fatal(err)
	}

	other := httptest.NewRecorder()
	handler.ServeHTTP(other, httptest.NewRequest(http.MethodGet, "/health", nil))
	if other.Code != http.StatusTeapot || other.Header().Get("X-Base-Path") != "/health" || baseCalls != 1 {
		t.Fatalf("base passthrough code=%d headers=%#v calls=%d", other.Code, other.Header(), baseCalls)
	}

	method := httptest.NewRecorder()
	handler.ServeHTTP(method, httptest.NewRequest(http.MethodPost, "/metrics", strings.NewReader("secret")))
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Allow") != http.MethodGet ||
		method.Body.Len() != 0 || baseCalls != 1 {
		t.Fatalf("method response code=%d allow=%q body=%q calls=%d", method.Code,
			method.Header().Get("Allow"), method.Body.String(), baseCalls)
	}
	if method.Header().Get("Cache-Control") != "no-store" ||
		method.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("method safety headers = %#v", method.Header())
	}
}
