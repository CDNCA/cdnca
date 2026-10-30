package errorpagecontrol

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReviewFollowupAuthenticationSentinelsMapTo401(t *testing.T) {
	for _, authErr := range []error{ErrInvalidCredential, ErrUnauthenticated} {
		handler, err := NewHandler(&fakeHTTPDomain{}, &reviewAuthenticator{err: authErr})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodGet, "http://control.test/v1/error-pages/assets", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized ||
			!strings.Contains(response.Body.String(), `"code":"authentication_required"`) {
			t.Fatalf("auth_error=%v status=%d body=%s", authErr, response.Code, response.Body.String())
		}

		direct := httptest.NewRecorder()
		writeHTTPError(direct, authErr)
		if direct.Code != http.StatusUnauthorized ||
			!strings.Contains(direct.Body.String(), `"code":"authentication_required"`) {
			t.Fatalf("direct_error=%v status=%d body=%s", authErr, direct.Code, direct.Body.String())
		}
	}

	handler, err := NewHandler(&fakeHTTPDomain{}, &reviewAuthenticator{err: errors.New("auth database unavailable")})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://control.test/v1/error-pages/assets", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"code":"service_unavailable"`) {
		t.Fatalf("dependency status=%d body=%s", response.Code, response.Body.String())
	}
}
