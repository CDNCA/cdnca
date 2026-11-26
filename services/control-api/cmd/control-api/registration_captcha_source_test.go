package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/accountregistrationchallenge"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// browserBoundCaptchas mimics identity_login_captchas: a CAPTCHA is spent
// once, only with the binding cookie it was issued with.
type browserBoundCaptchas map[uuid.UUID]string

func (captchas browserBoundCaptchas) ConsumeCaptcha(_ context.Context, proof identity.LoginCaptchaProof) error {
	issued, found := captchas[proof.ID]
	delete(captchas, proof.ID)
	if !found || issued != proof.Binding {
		return identity.ErrLoginCaptchaInvalid
	}
	return nil
}

// the Turnstile
// registration runtime with Turnstile not configured checks the built-in
// image CAPTCHA. Behind a CDN without origin authentication the code request
// comes through another edge than POST /v1/auth/login-captchas did; the
// CAPTCHA is spent with the browser binding cookie the runtime's challenge
// route passes on (httpapi.WithLoginCaptchaBinding), whatever the source.
func TestRegistrationCaptchaFallbackSpendsWithTheBindingCookie(t *testing.T) {
	notConfigured := func(context.Context) (bool, error) { return false, nil }
	send := func(cookie string) error {
		t.Helper()
		id := uuid.New()
		captchas := browserBoundCaptchas{id: "browser-binding"}
		verifier := registrationHumanVerifier{turnstile: &recordingHumanVerifier{},
			fallback: registrationCaptchaFallback(captchas), ready: notConfigured}
		var verifyErr error
		route := httpapi.WithLoginCaptchaBinding(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			verifyErr = verifier.Verify(r.Context(), accountregistrationchallenge.HumanVerification{
				Token: accountregistrationchallenge.CaptchaTokenPrefix + id.String() + ":AB2CD", Source: "203.0.113.50",
			})
		}))
		request := httptest.NewRequest(http.MethodPost, "https://console.example.com/v1/auth/registration-challenges", nil)
		request.RemoteAddr = "162.159.2.20:443" // not the edge the image came through
		if cookie != "" {
			request.AddCookie(&http.Cookie{Name: identity.LoginCaptchaBindingCookie, Value: cookie})
		}
		route.ServeHTTP(httptest.NewRecorder(), request)
		return verifyErr
	}
	if err := send("browser-binding"); err != nil {
		t.Fatalf("same browser, other edge: %v", err)
	}
	for _, cookie := range []string{"", "another-browser"} {
		if err := send(cookie); !errors.Is(err, accountregistrationchallenge.ErrHumanInvalid) {
			t.Fatalf("cookie %q = %v, want ErrHumanInvalid", cookie, err)
		}
	}
}
