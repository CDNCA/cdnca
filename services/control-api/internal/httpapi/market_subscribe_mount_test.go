package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMarketSubscribeMountForwardsItsRoutesOnly(t *testing.T) {
	probe := &dnsReconcileMountProbe{}
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		MarketSubscribeHandlerFactory: func() (http.Handler, error) { return probe, nil }})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	site, supply := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	routes := []struct{ method, path string }{
		{http.MethodGet, "/v1/admin/market/supplies"},
		{http.MethodPut, "/v1/admin/sites/" + site + "/market-supplies/" + supply},
		{http.MethodDelete, "/v1/admin/sites/" + site + "/market-supplies/" + supply},
		{http.MethodPost, "/v1/admin/sites/" + site + "/market-rollout/preview"},
		{http.MethodPost, "/v1/admin/sites/" + site + "/market-rollout/apply"},
		// MC12 E2: choose a saved site; the server compiles the revision.
		{http.MethodGet, "/v1/admin/sites/" + site + "/market-supplies"},
		{http.MethodPost, "/v1/admin/sites/" + site + "/market-rollout/site-preview"},
		{http.MethodPost, "/v1/admin/sites/" + site + "/market-rollout/site-apply"},
		{http.MethodGet, "/v1/admin/sites/" + site + "/market-rollout/leaves"},
	}
	for _, route := range routes {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusNoContent {
			t.Errorf("%s %s status=%d", route.method, route.path, response.Code)
		}
	}
	if probe.calls != len(routes) {
		t.Fatalf("calls=%d want=%d", probe.calls, len(routes))
	}
}

func TestMarketSubscribeUnmountedWithoutFactory(t *testing.T) {
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)})
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/admin/market/supplies", nil))
	if response.Code == http.StatusNoContent || response.Code == http.StatusOK {
		t.Fatalf("market routes must stay unmounted without the runtime: %d", response.Code)
	}
}
