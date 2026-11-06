package analyticsgeohttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 错误体回显 withRequestID 写到响应头的 X-Request-ID。
func TestErrorBodyCarriesRequestID(t *testing.T) {
	recorder := httptest.NewRecorder()
	recorder.Header().Set("X-Request-ID", "req-error-body-1")
	writeError(recorder, http.StatusNotFound, "analytics_geo_evidence_not_found", "evidence not found")
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s: %v", recorder.Body.String(), err)
	}
	if got := body["error"].(map[string]any)["request_id"]; got != "req-error-body-1" {
		t.Fatalf("request_id=%v body=%s", got, recorder.Body.String())
	}
}
