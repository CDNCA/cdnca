package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/apikey"
)

// AA-KEY-01：撤权后签发被拒仍是 403 permission_denied，details 说明哪些权限已被收回；普通权限不足不带 details。
func TestAPIKeyScopesUnavailableErrorEnvelope(t *testing.T) {
	write := func(err error) (int, map[string]any) {
		recorder := httptest.NewRecorder()
		(&Server{}).writeError(recorder, httptest.NewRequest(http.MethodPost, "/v1/account/api-keys", nil), err)
		var body struct {
			Error map[string]any `json:"error"`
		}
		if decodeErr := json.Unmarshal(recorder.Body.Bytes(), &body); decodeErr != nil {
			t.Fatalf("decode: %v", decodeErr)
		}
		return recorder.Code, body.Error
	}
	status, body := write(fmt.Errorf("create: %w", &apikey.ScopesUnavailableError{Scopes: []string{"sites.manage"}}))
	details, _ := body["details"].(map[string]any)
	scopes, _ := details["scopes"].([]any)
	if status != http.StatusForbidden || body["code"] != "permission_denied" || details["reason"] != "scopes_revoked" ||
		len(scopes) != 1 || scopes[0] != "sites.manage" {
		t.Fatalf("scopes unavailable = %d %v", status, body)
	}
	status, body = write(apikey.ErrPermissionDenied)
	if _, has := body["details"]; status != http.StatusForbidden || body["code"] != "permission_denied" || has {
		t.Fatalf("plain permission denied = %d %v", status, body)
	}
}
