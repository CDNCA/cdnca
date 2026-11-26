package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

// a CAPTCHA spent from a human token (registration code
// challenges) gets the binding cookie through the context; no cookie is "".
// the image's own cookie comes first.
func TestWithLoginCaptchaBindingRecordsTheCookie(t *testing.T) {
	mine, other := uuid.New(), uuid.New()
	var seen []string
	handler := WithLoginCaptchaBinding(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = append(seen, identity.LoginCaptchaBindingFrom(r.Context(), mine), identity.LoginCaptchaBindingFrom(r.Context(), other))
	}))
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/registration-challenges", nil)
	request.AddCookie(&http.Cookie{Name: identity.LoginCaptchaBindingCookie, Value: "browser-binding"})
	request.AddCookie(&http.Cookie{Name: identity.LoginCaptchaImageBindingCookie(mine), Value: "image-binding"})
	handler.ServeHTTP(httptest.NewRecorder(), request)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/auth/registration-challenges", nil))
	if strings.Join(seen, ",") != "image-binding,browser-binding,," {
		t.Fatalf("bindings = %q", seen)
	}
}
