package accountloginchallenge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
)

// an external CAPTCHA that is not fully
// configured falls back to the local CAPTCHA instead of blocking code login.
func TestExternalCaptchaNotConfiguredFallsBackToLocal(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()

	configured := newCaptchaTestVerifier(t, server, captchaTestRuntime("tencent", "190000001"), captchaTestSecrets())
	if !configured.Configured(t.Context(), "tencent") {
		t.Fatal("a complete Tencent configuration reported not configured")
	}
	for _, test := range []struct {
		name, mode string
		verifier   *ExternalCaptchaVerifier
	}{
		{"no app ID", "tencent", newCaptchaTestVerifier(t, server, captchaTestRuntime("tencent", ""), captchaTestSecrets())},
		{"secret unresolved", "tencent", newCaptchaTestVerifier(t, server, captchaTestRuntime("tencent", "190000001"), StaticSecretResolver{})},
		{"other provider", "tencent", newCaptchaTestVerifier(t, server, captchaTestRuntime("geetest_v4", "gt-1"), captchaTestSecrets())},
		{"geetest no secret", "geetest_v4", newCaptchaTestVerifier(t, server,
			systemusersettings.CaptchaRuntime{Provider: "geetest_v4", AppID: "gt-1"}, StaticSecretResolver{})},
	} {
		if test.verifier.Configured(t.Context(), test.mode) {
			t.Fatalf("%s: reported configured", test.name)
		}
	}
	if !newCaptchaTestVerifier(t, server, captchaTestRuntime("geetest_v4", "gt-1"), captchaTestSecrets()).Configured(t.Context(), "geetest_v4") {
		t.Fatal("a complete GeeTest configuration reported not configured")
	}

	// the service: no verifier or an incomplete one serves the local CAPTCHA
	if mode := (&Service{}).effectiveMode(t.Context(), "tencent"); mode != "native" {
		t.Fatalf("no verifier: mode %q", mode)
	}
	incomplete := &Service{human: newCaptchaTestVerifier(t, server, captchaTestRuntime("tencent", ""), captchaTestSecrets())}
	if mode := incomplete.effectiveMode(t.Context(), "tencent"); mode != "native" {
		t.Fatalf("incomplete verifier: mode %q", mode)
	}
	complete := &Service{human: configured}
	if mode := complete.effectiveMode(t.Context(), "tencent"); mode != "tencent" {
		t.Fatalf("complete verifier: mode %q", mode)
	}
	if mode := complete.effectiveMode(t.Context(), "none"); mode != "none" {
		t.Fatalf("non-external mode changed to %q", mode)
	}
}
