package systemmailsettingshttp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
)

// fix-fielderr-be2: a located save refusal keeps 400 system_mail_settings_validation_error and adds
// details.field/reason; other refusals carry no details.
func TestHandlerNamesRefusedSettingsField(t *testing.T) {
	for _, check := range []struct {
		err     error
		details map[string]string
	}{
		{fmt.Errorf("save: %w", fielderr.New(systemmailsettings.ErrInvalidInput, "value.smtp_port", fielderr.Invalid)), map[string]string{"field": "value.smtp_port", "reason": fielderr.Invalid}},
		{systemmailsettings.ErrInvalidInput, nil},
	} {
		h, err := New(&serviceStub{saveErr: check.err}, func(*http.Request, string) (identity.AuthenticatedSession, error) { return testSession(), nil })
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
		if response.Code != http.StatusBadRequest || envelope.Error.Code != "system_mail_settings_validation_error" || envelope.Error.RequestID != "field-error-1" ||
			fmt.Sprint(envelope.Error.Details) != fmt.Sprint(check.details) {
			t.Fatalf("%d %s", response.Code, response.Body.String())
		}
	}
}

// a refused test recipient keeps 400 system_mail_settings_validation_error
// and adds details.field=to with its reason; an unlocated refusal still has no details.
func TestHandlerNamesRefusedTestRecipient(t *testing.T) {
	for _, check := range []struct {
		err     error
		details map[string]string
	}{
		{fielderr.New(systemmailsettings.ErrInvalidInput, "to", fielderr.InvalidFormat), map[string]string{"field": "to", "reason": fielderr.InvalidFormat}},
		{fielderr.New(systemmailsettings.ErrInvalidInput, "to", fielderr.Required), map[string]string{"field": "to", "reason": fielderr.Required}},
		{systemmailsettings.ErrInvalidInput, nil},
	} {
		h, err := New(&testerStub{err: check.err}, func(*http.Request, string) (identity.AuthenticatedSession, error) { return testSession(), nil })
		if err != nil {
			t.Fatal(err)
		}
		h.WithTestSender(func(context.Context, systemmailsettings.TestTarget) (string, error) { return "", nil })
		request := httptest.NewRequest(http.MethodPost, route+"/tests", strings.NewReader(`{"value":{},"to":"ops.example.com"}`))
		request.Header.Set("Authorization", "Bearer session")
		request.Header.Set("X-Request-ID", "field-error-to")
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		var envelope struct {
			Error struct {
				Code    string            `json:"code"`
				Details map[string]string `json:"details"`
			} `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusBadRequest || envelope.Error.Code != "system_mail_settings_validation_error" ||
			fmt.Sprint(envelope.Error.Details) != fmt.Sprint(check.details) {
			t.Fatalf("%d %s", response.Code, response.Body.String())
		}
	}
}
