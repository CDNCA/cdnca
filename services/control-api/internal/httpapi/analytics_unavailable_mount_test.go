package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAnalyticsRoutesExposeUnavailableStateWithoutAnalyticsHandler(t *testing.T) {
	handler := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}).Handler()
	for _, path := range []string{
		"/v1/analytics/summary?from=2026-08-23T00:00:00Z&to=2026-08-23T01:00:00Z",
		"/v1/admin/analytics/top/domain?from=2026-08-23T00:00:00Z&to=2026-08-23T01:00:00Z",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("analytics route %s status = %d, want 503", path, response.Code)
		}
		var envelope struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.NewDecoder(response.Body).Decode(&envelope); err != nil {
			t.Fatalf("analytics route %s response: %v", path, err)
		}
		if envelope.Error.Code != "analytics_storage_unavailable" {
			t.Fatalf("analytics route %s error code = %q", path, envelope.Error.Code)
		}
	}
}

func TestAnalyticsLogsRemainDisabledWhenOnlyAnalyticsIsUnavailable(t *testing.T) {
	handler := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}).Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/analytics/logs/access", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("analytics logs route status = %d, want 404", response.Code)
	}
}
