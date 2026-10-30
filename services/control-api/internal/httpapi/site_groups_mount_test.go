package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSiteGroupRoutesFailClosedWhenServiceIsUnavailable(t *testing.T) {
	api := New(nil, nil, Config{})
	for _, route := range []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/v1/site-groups?scope_id=018cc251-f400-7def-8000-000000000050", http.StatusServiceUnavailable},
		{http.MethodPost, "/v1/site-groups", http.StatusServiceUnavailable},
		{http.MethodPatch, "/v1/site-groups/018cc251-f400-7def-8000-000000000060", http.StatusBadRequest},
		{http.MethodDelete, "/v1/site-groups/018cc251-f400-7def-8000-000000000060", http.StatusBadRequest},
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != route.status {
			t.Errorf("%s %s status = %d, want %d", route.method, route.path, response.Code, route.status)
		}
	}
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/site-groups-extra", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("adjacent route status = %d, want 404", response.Code)
	}
}
