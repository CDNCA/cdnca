package systemusersettingshttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
)

// the Turnstile secret is a write-only body field next to
// value; absent means keep, and the response never echoes it.
func TestHandlerForwardsWriteOnlyTurnstileSecret(t *testing.T) {
	document := settingsDocument(5)
	document.CaptchaTurnstileSecretConfigured, document.CaptchaTurnstileSecretFingerprint = true, "0123456789abcdef"
	stub := &serviceStub{document: document}
	response := httptest.NewRecorder()
	newTestHandler(t, stub).ServeHTTP(response, putRequest(t, map[string]any{
		"value": systemusersettings.DefaultSettings(), "captcha_turnstile_secret": "0x4AAAAAAAturnstile-secret"}))
	if response.Code != http.StatusOK || stub.saved == nil || stub.saved.Secrets[systemusersettings.SecretCaptchaTurnstileSecret] == nil ||
		*stub.saved.Secrets[systemusersettings.SecretCaptchaTurnstileSecret] != "0x4AAAAAAAturnstile-secret" {
		t.Fatalf("status=%d request=%#v", response.Code, stub.saved)
	}
	if body := response.Body.String(); strings.Contains(body, "turnstile-secret") ||
		!strings.Contains(body, `"captcha_turnstile_secret_configured":true`) {
		t.Fatalf("response=%s", body)
	}
	stub.saved = nil
	response = httptest.NewRecorder()
	newTestHandler(t, stub).ServeHTTP(response, putRequest(t, map[string]any{"value": systemusersettings.DefaultSettings()}))
	if response.Code != http.StatusOK || stub.saved == nil || stub.saved.Secrets[systemusersettings.SecretCaptchaTurnstileSecret] != nil {
		t.Fatalf("absent secret must keep the stored one: status=%d request=%#v", response.Code, stub.saved)
	}
}
