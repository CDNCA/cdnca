package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type dnsReconcileMountProbe struct{ calls int }

func (probe *dnsReconcileMountProbe) ServeHTTP(writer http.ResponseWriter, _ *http.Request) {
	probe.calls++
	writer.WriteHeader(http.StatusNoContent)
}

func TestDNSReconcileMountForwardsOnlyFiveTenantRoutes(t *testing.T) {
	probe := &dnsReconcileMountProbe{}
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), DNSReconcileHandlerFactory: func() (http.Handler, error) { return probe, nil }})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	siteID := "11111111-1111-4111-8111-111111111111"
	taskID := "22222222-2222-4222-8222-222222222222"
	routes := []struct{ method, path string }{
		{http.MethodPost, "/v1/sites/" + siteID + "/dns-reconcile/dry-run"},
		{http.MethodPost, "/v1/sites/" + siteID + "/dns-reconcile/apply"},
		{http.MethodGet, "/v1/sites/" + siteID + "/dns-reconcile/tasks/" + taskID},
		{http.MethodPost, "/v1/sites/" + siteID + "/dns-reconcile/tasks/" + taskID + "/commit"},
		{http.MethodPost, "/v1/sites/" + siteID + "/dns-reconcile/tasks/" + taskID + "/cancel"},
	}
	for _, route := range routes {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusNoContent {
			t.Errorf("%s %s status=%d", route.method, route.path, response.Code)
		}
	}
	internal := httptest.NewRecorder()
	api.Handler().ServeHTTP(internal, httptest.NewRequest(http.MethodPost,
		"/internal/v1/dns/reconcile/tasks/"+taskID+"/provider-reports", nil))
	if internal.Code != http.StatusNotFound || probe.calls != len(routes) {
		t.Fatalf("internal route status=%d calls=%d want=%d", internal.Code, probe.calls, len(routes))
	}
}

func TestDNSReconcileMountFactoryFailureFailsStartup(t *testing.T) {
	want := errors.New("dns reconcile unavailable")
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), DNSReconcileHandlerFactory: func() (http.Handler, error) { return nil, want }})
	if !errors.Is(api.InitializationError(), want) {
		t.Fatalf("initialization error=%v", api.InitializationError())
	}
}
