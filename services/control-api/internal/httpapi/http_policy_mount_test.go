package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type httpPolicyMountProbe struct {
	observed []string
	routes   *http.ServeMux
}

func newHTTPPolicyMountProbe() *httpPolicyMountProbe {
	probe := &httpPolicyMountProbe{routes: http.NewServeMux()}
	for _, route := range httpPolicyMountRoutes() {
		probe.routes.HandleFunc(route.method+" "+httpPolicyMountTemplatePath(route.path), func(w http.ResponseWriter, r *http.Request) {
			probe.observed = append(probe.observed, r.Method+" "+r.URL.Path+" "+r.PathValue("tenant_scope_id")+" "+r.PathValue("policy_id"))
			w.WriteHeader(http.StatusNoContent)
		})
	}
	return probe
}

func httpPolicyMountTemplatePath(path string) string {
	return strings.NewReplacer(
		"11111111-1111-4111-8111-111111111111", "{tenant_scope_id}",
		"22222222-2222-4222-8222-222222222222", "{policy_id}",
	).Replace(path)
}

func (probe *httpPolicyMountProbe) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	probe.routes.ServeHTTP(w, r)
}

type httpPolicyMountTypedNilHandler struct{}

func (*httpPolicyMountTypedNilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestHTTPPolicyMountDisabledAndFailedFactoryStayClosed(t *testing.T) {
	for _, route := range httpPolicyMountRoutes() {
		response := httptest.NewRecorder()
		New(nil, nil, Config{}).Handler().ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("disabled %s %s status = %d, want 404", route.method, route.path, response.Code)
		}
	}
	factoryErr := errors.New("HTTP policy dependency unavailable")
	config := Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
	httpPolicySetMountedFactory(t, &config, nil, factoryErr)
	if api := New(nil, nil, config); !errors.Is(api.InitializationError(), factoryErr) {
		t.Fatalf("factory error = %v, want %v", api.InitializationError(), factoryErr)
	}
	var typedNil *httpPolicyMountTypedNilHandler
	config = Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
	httpPolicySetMountedFactory(t, &config, typedNil, nil)
	if New(nil, nil, config).InitializationError() == nil {
		t.Fatal("typed nil HTTP policy handler did not fail startup")
	}
}

func TestHTTPPolicyMountForwardsOnlyFrozenRoutes(t *testing.T) {
	probe := newHTTPPolicyMountProbe()
	config := Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
	httpPolicySetMountedFactory(t, &config, probe, nil)
	api := New(nil, nil, config)
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	for _, route := range httpPolicyMountRoutes() {
		request := httptest.NewRequest(route.method, route.path, strings.NewReader("{}"))
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("%s %s status = %d, want 204", route.method, route.path, response.Code)
		}
	}
	if len(probe.observed) != len(httpPolicyMountRoutes()) {
		t.Fatalf("forwarded calls = %d, want %d", len(probe.observed), len(httpPolicyMountRoutes()))
	}
	for _, observation := range probe.observed {
		if !strings.Contains(observation, "11111111-1111-4111-8111-111111111111") {
			t.Errorf("tenant_scope_id was not forwarded: %s", observation)
		}
		if strings.Contains(observation, "/http-policies/22222222-") && !strings.HasSuffix(observation, "22222222-2222-4222-8222-222222222222") {
			t.Errorf("policy_id was not forwarded: %s", observation)
		}
	}
	before := len(probe.observed)
	for _, path := range []string{
		"/v1/tenant-scopes/11111111-1111-4111-8111-111111111111/http-policies/",
		"/v1/tenant-scopes/11111111-1111-4111-8111-111111111111/http-policies-extra",
		"/v1/tenant-scopes/11111111-1111-4111-8111-111111111111/http-policies/22222222-2222-4222-8222-222222222222/enable/neighbor",
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("adjacent route %s status = %d, want 404", path, response.Code)
		}
	}
	if len(probe.observed) != before {
		t.Fatal("adjacent HTTP policy route reached package handler")
	}
}

func TestHTTPPolicyCanonicalContractAggregatesFrozenFragment(t *testing.T) {
	paths := []string{
		"/v1/tenant-scopes/{tenant_scope_id}/http-policies",
		"/v1/tenant-scopes/{tenant_scope_id}/http-policies/publication-preview",
		"/v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}",
		"/v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}/enable",
		"/v1/tenant-scopes/{tenant_scope_id}/http-policies/{policy_id}/disable",
	}
	sharedRuntimeIIRequireCanonicalAggregation(t, "control-http-policies.openapi.yaml", paths)
	sharedRuntimeIIRequireUniqueOperationIDs(t, []string{
		"listHTTPPolicies", "createHTTPPolicy", "previewHTTPPolicyPublication", "getHTTPPolicy",
		"updateHTTPPolicy", "deleteHTTPPolicy", "enableHTTPPolicy", "disableHTTPPolicy",
	})
}

func httpPolicyMountRoutes() []struct{ method, path string } {
	prefix := "/v1/tenant-scopes/11111111-1111-4111-8111-111111111111/http-policies"
	policy := "/22222222-2222-4222-8222-222222222222"
	return []struct{ method, path string }{
		{http.MethodGet, prefix}, {http.MethodPost, prefix},
		{http.MethodGet, prefix + "/publication-preview"},
		{http.MethodGet, prefix + policy}, {http.MethodPatch, prefix + policy}, {http.MethodDelete, prefix + policy},
		{http.MethodPost, prefix + policy + "/enable"}, {http.MethodPost, prefix + policy + "/disable"},
	}
}

func httpPolicySetMountedFactory(t *testing.T, config *Config, handler http.Handler, factoryErr error) {
	t.Helper()
	field := reflect.ValueOf(config).Elem().FieldByName("HTTPPolicyHandlerFactory")
	sharedRuntimeIISetMountedFactory(t, field, "HTTPPolicyHandlerFactory", handler, factoryErr)
}
