package systemsettingshttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemsettings"
)

// fix-fielderr-be: a located save refusal keeps 400
// system_settings_validation_error and adds details.field/reason.
func TestHandlerNamesRefusedSettingsField(t *testing.T) {
	session := testSession()
	stub := &handlerServiceStub{saveErr: fmt.Errorf("save: %w",
		fielderr.New(systemsettings.ErrInvalidInput, "value.system_name", fielderr.Required))}
	handler, err := New(stub, func(*http.Request, string) (identity.AuthenticatedSession, error) { return session, nil })
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"value": systemsettings.DefaultSettings()})
	request := httptest.NewRequest(http.MethodPut, route, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer session-token")
	request.Header.Set("If-Match", `"0"`)
	request.Header.Set("Idempotency-Key", "system-settings-test")
	request.Header.Set("X-Request-ID", "system-settings-request")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var envelope struct {
		Error struct {
			Code      string            `json:"code"`
			RequestID string            `json:"request_id"`
			Details   map[string]string `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusBadRequest || envelope.Error.Code != "system_settings_validation_error" ||
		envelope.Error.RequestID != "system-settings-request" ||
		envelope.Error.Details["field"] != "value.system_name" || envelope.Error.Details["reason"] != fielderr.Required {
		t.Fatalf("%d %s", response.Code, response.Body.String())
	}
}
