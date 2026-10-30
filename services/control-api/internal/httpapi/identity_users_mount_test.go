package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIdentityUserBatchRouteIsMounted(t *testing.T) {
	for _, route := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPatch, "/v1/admin/users", `[]`},
		{http.MethodGet, "/v1/admin/user-groups", ``},
		{http.MethodPost, "/v1/admin/user-groups", `{}`},
		{http.MethodPatch, "/v1/admin/user-groups/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", `{}`},
		{http.MethodDelete, "/v1/admin/user-groups/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", `{}`},
	} {
		request := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		New(nil, nil, Config{}).Handler().ServeHTTP(response, request)
		if response.Code == http.StatusNotFound || response.Code == http.StatusMethodNotAllowed {
			t.Fatalf("identity user route %s %s is not mounted: status=%d", route.method, route.path, response.Code)
		}
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated identity user route %s %s status=%d, want %d", route.method, route.path, response.Code, http.StatusUnauthorized)
		}
	}
}
