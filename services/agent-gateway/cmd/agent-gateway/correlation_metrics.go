package main

import (
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	gateway "github.com/cdnca/cdnca/services/agent-gateway"
)

var errCorrelationMetricsInvalidConfig = errors.New("correlation metrics configuration invalid")

type correlationMetricsHandler struct {
	base   http.Handler
	health *gateway.CorrelationHealth
}

func newCorrelationMetricsHandler(base http.Handler, health *gateway.CorrelationHealth) (http.Handler, error) {
	if nilHTTPHandler(base) || health == nil {
		return nil, errCorrelationMetricsInvalidConfig
	}
	return &correlationMetricsHandler{base: base, health: health}, nil
}

func (handler *correlationMetricsHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/metrics" {
		handler.base.ServeHTTP(response, request)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	snapshot := handler.health.Snapshot()
	metrics := [...]struct {
		name  string
		help  string
		value uint64
	}{
		{"cdnca_agent_gateway_correlation_accepted_total", "Accepted correlation commands.", snapshot.Accepted},
		{"cdnca_agent_gateway_correlation_replayed_total", "Replayed correlation commands.", snapshot.Replayed},
		{"cdnca_agent_gateway_correlation_rejected_total", "Rejected correlation commands.", snapshot.Rejected},
		{"cdnca_agent_gateway_correlation_publish_failed_total", "Correlation command publish failures.", snapshot.PublishFailed},
		{"cdnca_agent_gateway_correlation_terminal_succeeded_total", "Successfully activated or reverted terminal deployments.", snapshot.TerminalSucceeded},
		{"cdnca_agent_gateway_correlation_terminal_failed_total", "Failed terminal deployments.", snapshot.TerminalFailed},
	}
	var body strings.Builder
	for _, metric := range metrics {
		body.WriteString("# HELP ")
		body.WriteString(metric.name)
		body.WriteByte(' ')
		body.WriteString(metric.help)
		body.WriteByte('\n')
		body.WriteString("# TYPE ")
		body.WriteString(metric.name)
		body.WriteString(" counter\n")
		body.WriteString(metric.name)
		body.WriteByte(' ')
		body.WriteString(strconv.FormatUint(metric.value, 10))
		body.WriteByte('\n')
	}
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write([]byte(body.String()))
}

func nilHTTPHandler(value http.Handler) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
