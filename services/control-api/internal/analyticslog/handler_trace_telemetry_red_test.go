package analyticslog

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandlerPropagatesTraceCorrelation(t *testing.T) {
	now := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	actor := Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}
	store := &recordingStore{accessPage: AccessPage{}}
	handler := newTestHandler(t, store, actor, HandlerConfig{})

	request := httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access?"+
		queryValues(now.Add(-time.Hour), now).Encode(), nil)
	request.Header.Set("X-Request-ID", "trace-request")
	request.Header.Set("X-Trace-ID", "trace-correlation")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("X-Request-ID") != "trace-request" ||
		response.Header().Get("X-Trace-ID") != "trace-correlation" {
		t.Fatalf("correlation headers=%v", response.Header())
	}

	store.err = errors.New("private ClickHouse detail")
	errorRequest := httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access?"+
		queryValues(now.Add(-time.Hour), now).Encode(), nil)
	errorRequest.Header.Set("X-Request-ID", "trace-error-request")
	errorRequest.Header.Set("X-Trace-ID", "trace-error")
	errorResponse := httptest.NewRecorder()
	handler.ServeHTTP(errorResponse, errorRequest)
	if errorResponse.Code != http.StatusServiceUnavailable ||
		errorResponse.Header().Get("X-Trace-ID") != "trace-error" {
		t.Fatalf("error status=%d headers=%v body=%s", errorResponse.Code, errorResponse.Header(), errorResponse.Body.String())
	}
	var envelope struct {
		Error struct {
			TraceID string `json:"trace_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(errorResponse.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.TraceID != "trace-error" {
		t.Fatalf("error trace_id=%q", envelope.Error.TraceID)
	}
}
