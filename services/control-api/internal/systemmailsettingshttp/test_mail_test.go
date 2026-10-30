package systemmailsettingshttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemmailsettings"
)

type testerStub struct {
	serviceStub
	request systemmailsettings.TestRequest
	result  systemmailsettings.TestResult
	err     error
}

func (s *testerStub) Test(_ context.Context, _ systemmailsettings.Actor, request systemmailsettings.TestRequest,
	send systemmailsettings.TestSender) (systemmailsettings.TestResult, error) {
	s.request = request
	if send == nil {
		return systemmailsettings.TestResult{}, systemmailsettings.ErrInvalidInput
	}
	return s.result, s.err
}

func TestHandlerSendsTestMailWithUnsavedProvider(t *testing.T) {
	stub := &testerStub{result: systemmailsettings.TestResult{OK: true, Provider: "sendgrid", MessageID: "sg-1"}}
	handler, err := New(stub, func(*http.Request, string) (identity.AuthenticatedSession, error) { return testSession(), nil })
	if err != nil {
		t.Fatal(err)
	}
	handler.WithTestSender(func(context.Context, systemmailsettings.TestTarget) (string, error) { return "sg-1", nil })
	value := systemmailsettings.DefaultSettings()
	value.MailProvider, value.MailFrom = "sendgrid", "noreply@example.com"
	body, _ := json.Marshal(map[string]any{"value": value, "mail_secret": "SG.key", "to": "ops@example.com"})
	request := httptest.NewRequest(http.MethodPost, route+"/tests", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer session")
	request.Header.Set("X-Request-ID", "mail-test-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"ok":true`) ||
		strings.Contains(response.Body.String(), "SG.key") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if stub.request.MailSecret != "SG.key" || stub.request.To != "ops@example.com" || stub.request.Value.MailProvider != "sendgrid" ||
		stub.request.RequestID != "mail-test-1" {
		t.Fatalf("request %+v", stub.request)
	}
	get := httptest.NewRequest(http.MethodGet, route+"/tests", nil)
	get.Header.Set("Authorization", "Bearer session")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, get)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET tests status=%d", response.Code)
	}
}

func TestHandlerTestMailUnavailableWithoutSender(t *testing.T) {
	handler, _ := New(&testerStub{}, func(*http.Request, string) (identity.AuthenticatedSession, error) { return testSession(), nil })
	request := httptest.NewRequest(http.MethodPost, route+"/tests", strings.NewReader(`{"value":{},"to":"a@example.com"}`))
	request.Header.Set("Authorization", "Bearer session")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "system_mail_settings_test_unavailable") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHandlerMapsUnlicensedMailModuleToForbidden(t *testing.T) {
	stub := &testerStub{err: systemmailsettings.ErrModuleNotLicensed}
	handler, _ := New(stub, func(*http.Request, string) (identity.AuthenticatedSession, error) { return testSession(), nil })
	handler.WithTestSender(func(context.Context, systemmailsettings.TestTarget) (string, error) { return "", nil })
	value := systemmailsettings.DefaultSettings()
	value.MailProvider, value.MailFrom = "sendgrid", "noreply@example.com"
	body, _ := json.Marshal(map[string]any{"value": value, "mail_secret": "SG.key", "to": "ops@example.com"})
	request := httptest.NewRequest(http.MethodPost, route+"/tests", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer session")
	request.Header.Set("X-Request-ID", "mail-test-2")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "system_mail_settings_module_not_licensed") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}
