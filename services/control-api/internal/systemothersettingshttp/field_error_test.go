package systemothersettingshttp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemothersettings"
)

// fix-fielderr-be2: a located save refusal keeps 400 system_other_settings_validation_error and adds
// details.field/reason; other refusals carry no details.
func TestHandlerNamesRefusedSettingsField(t *testing.T) {
	for _, check := range []struct {
		err     error
		details map[string]string
	}{
		{fmt.Errorf("save: %w", fielderr.New(systemothersettings.ErrInvalidInput, "value.sync_batch", fielderr.Invalid)), map[string]string{"field": "value.sync_batch", "reason": fielderr.Invalid}},
		{systemothersettings.ErrInvalidInput, nil},
	} {
		h, err := New(&serviceStub{saveErr: check.err}, func(*http.Request, string) (identity.AuthenticatedSession, error) { return session(), nil })
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPut, route, strings.NewReader(`{"value":{}}`))
		request.Header.Set("Authorization", "Bearer session")
		request.Header.Set("X-Request-ID", "field-error-1")
		request.Header.Set("Idempotency-Key", "field-error-1")
		request.Header.Set("If-Match", `"1"`)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
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
		if response.Code != http.StatusBadRequest || envelope.Error.Code != "system_other_settings_validation_error" || envelope.Error.RequestID != "field-error-1" ||
			fmt.Sprint(envelope.Error.Details) != fmt.Sprint(check.details) {
			t.Fatalf("%d %s", response.Code, response.Body.String())
		}
	}
}
