package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFirewallActionHandlerFactoryMountsExactProductionRoutes(t *testing.T) {
	calls := 0
	probe := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		calls++
		response.WriteHeader(http.StatusNoContent)
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), FirewallActionHandlerFactory: func() (http.Handler, error) { return probe, nil }})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/firewall-actions/policy?target_scope_id=x&site_id=y", nil),
		httptest.NewRequest(http.MethodPut, "/v1/firewall-actions/policy?target_scope_id=x&site_id=y", nil),
		httptest.NewRequest(http.MethodPost, "/v1/firewall-actions/policy/recover?target_scope_id=x&site_id=y", nil),
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s %s status=%d", request.Method, request.URL.Path, response.Code)
		}
	}
	for _, path := range []string{
		"/v1/firewall-actions/policy/",
		"/v1/firewall-actions/policy/recover/neighbor",
		"/v1/firewall-actions/policy-extra",
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("adjacent route %s status=%d", path, response.Code)
		}
	}
	if calls != 3 {
		t.Fatalf("mounted calls=%d, want 3", calls)
	}
}
