package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	gateway "github.com/cdnca/cdnca/services/agent-gateway"
)

type telemetryHealthHandler struct {
	base        http.Handler
	liveness    *livenessState
	health      *gateway.TelemetryHealth
	correlation *gateway.CorrelationHealth
	check       func(context.Context) error
	timeout     time.Duration
}

func newTelemetryHealthHandler(
	base http.Handler,
	liveness *livenessState,
	health *gateway.TelemetryHealth,
	correlation *gateway.CorrelationHealth,
	check func(context.Context) error,
	timeout time.Duration,
) http.Handler {
	return &telemetryHealthHandler{base: base, liveness: liveness, health: health,
		correlation: correlation, check: check, timeout: timeout}
}

func (h *telemetryHealthHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/health/detail" {
		h.base.ServeHTTP(response, request)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodGet {
		response.Header().Set("Allow", http.MethodGet)
		writeHealthResponse(response, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	healthy := false
	if h.check != nil && h.timeout > 0 {
		ctx, cancel := context.WithTimeout(request.Context(), h.timeout)
		healthy = h.check(ctx) == nil
		cancel()
	}
	h.health.SetDependencyHealthy(healthy)
	snapshot := h.health.Snapshot()
	state := "healthy"
	if snapshot.Degraded {
		state = "degraded"
	}
	core := "not_live"
	if h.liveness.isLive() {
		core = "live"
	}
	response.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(response).Encode(struct {
		Status      string                            `json:"status"`
		Telemetry   string                            `json:"telemetry"`
		Metrics     gateway.TelemetryHealthSnapshot   `json:"metrics"`
		Correlation gateway.CorrelationHealthSnapshot `json:"correlation"`
	}{Status: core, Telemetry: state, Metrics: snapshot, Correlation: h.correlation.Snapshot()})
}
