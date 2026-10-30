package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTenantScopeRouteIsMountedAndRequiresPlatformSession(t *testing.T) {
	api := New(nil, nil, Config{})
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		request := httptest.NewRequest(method, "/v1/admin/tenant-scopes", nil)
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if method == http.MethodGet && response.Code != http.StatusUnauthorized {
			t.Fatalf("GET tenant scope route status=%d, want %d", response.Code, http.StatusUnauthorized)
		}
		if method == http.MethodPost && response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("POST tenant scope route status=%d, want %d", response.Code, http.StatusMethodNotAllowed)
		}
	}

	for _, path := range []string{"/v1/admin/tenant-scopes/", "/v1/admin/tenant-scopes/extra"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("adjacent tenant scope path %s status=%d, want %d", path, response.Code, http.StatusNotFound)
		}
	}
}
