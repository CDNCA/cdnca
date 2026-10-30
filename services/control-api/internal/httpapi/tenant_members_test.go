package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// A member that must change its password gets 403 password_change_required.
func TestPasswordChangeRequiredIs403(t *testing.T) {
	server := &Server{}
	recorder := httptest.NewRecorder()
	server.writeError(recorder, httptest.NewRequest(http.MethodGet, "/v1/sites", nil), fmt.Errorf("auth: %w", identity.ErrPasswordChangeRequired))
	var body struct {
		Error map[string]string `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != http.StatusForbidden || body.Error["code"] != "password_change_required" {
		t.Fatalf("response %d %v", recorder.Code, body.Error)
	}
}
