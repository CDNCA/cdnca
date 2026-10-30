package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSiteCaptureMountForwardsOnlyExactRoute(t *testing.T) {
	path := "/v1/tenant-scopes/11111111-1111-4111-8111-111111111111/sites/22222222-2222-4222-8222-222222222222/telemetry-capture-policy"
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			called := false
			probe := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				called = true
				if request.URL.Path != path || request.PathValue("scope_id") == "" || request.PathValue("site_id") == "" ||
					request.Header.Get("X-Request-ID") != "capture-mount" {
					t.Fatalf("forwarded request path=%q scope=%q site=%q headers=%v", request.URL.Path,
						request.PathValue("scope_id"), request.PathValue("site_id"), request.Header)
				}
				response.WriteHeader(http.StatusNoContent)
			})
			api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), SiteCaptureHandler: probe}).Handler()
			request := httptest.NewRequest(method, path, nil)
			request.Header.Set("X-Request-ID", "capture-mount")
			response := httptest.NewRecorder()
			api.ServeHTTP(response, request)
			if !called || response.Code != http.StatusNoContent {
				t.Fatalf("called=%v status=%d", called, response.Code)
			}
		})
	}

	for _, path := range []string{
		"/v1/tenant-scopes/11111111-1111-4111-8111-111111111111/sites/22222222-2222-4222-8222-222222222222/telemetry-capture-policy/extra",
		"/v1/tenant-scopes/11111111-1111-4111-8111-111111111111/sites/22222222-2222-4222-8222-222222222222/other",
	} {
		response := httptest.NewRecorder()
		New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), SiteCaptureHandler: http.NotFoundHandler()}).Handler().ServeHTTP(
			response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("path=%q status=%d", path, response.Code)
		}
	}
}

func TestSiteCaptureMountRejectsTypedNilHandler(t *testing.T) {
	var handler *typedNilSiteCaptureHandler
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), SiteCaptureHandler: handler})
	if api.InitializationError() == nil {
		t.Fatal("typed nil site capture handler accepted")
	}
}

type typedNilSiteCaptureHandler struct{}

func (*typedNilSiteCaptureHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}
