package firewallactionhttp

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/firewallactioncontrol"
)

// 错误体回显 withRequestID 写到响应头的 X-Request-ID。
func TestErrorBodyCarriesRequestID(t *testing.T) {
	recorder := httptest.NewRecorder()
	recorder.Header().Set("X-Request-ID", "req-error-body-1")
	writeError(recorder, firewallactioncontrol.ErrNotFound)
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s: %v", recorder.Body.String(), err)
	}
	if got := body["request_id"]; got != "req-error-body-1" {
		t.Fatalf("request_id=%v body=%s", got, recorder.Body.String())
	}
}
