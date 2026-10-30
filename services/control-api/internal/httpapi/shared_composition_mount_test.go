package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtimehttp"
)

type sharedCompositionTypedNilHandler struct{}

func (*sharedCompositionTypedNilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestSharedCompositionMountsRealtimeAnalyticsAndCustomRBACExactly(t *testing.T) {
	analyticsProbe := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	})
	rbacProbe := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusAccepted)
	})
	api := New(nil, nil, Config{
		APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		AnalyticsRealtimeHandlerFactory: func(authenticate analyticsrealtimehttp.Authenticator) (http.Handler, error) {
			if authenticate == nil {
				t.Fatal("realtime analytics authenticator is nil")
			}
			return analyticsProbe, nil
		},
		CustomRBACHandlerFactory: func() (http.Handler, error) { return rbacProbe, nil },
	})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/analytics/site-monitoring", "/v1/admin/analytics/site-monitoring"} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNoContent {
			t.Fatalf("analytics route %s status = %d, want 204", path, response.Code)
		}
	}
	roleID := "11111111-1111-4111-8111-111111111111"
	grantID := "22222222-2222-4222-8222-222222222222"
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/v1/custom-rbac/permissions"},
		{http.MethodGet, "/v1/custom-rbac/roles"},
		{http.MethodPost, "/v1/custom-rbac/roles"},
		{http.MethodGet, "/v1/custom-rbac/roles/" + roleID},
		{http.MethodPost, "/v1/custom-rbac/roles/" + roleID + "/rename"},
		{http.MethodPost, "/v1/custom-rbac/roles/" + roleID + "/publish"},
		{http.MethodPost, "/v1/custom-rbac/roles/" + roleID + "/deactivate"},
		{http.MethodGet, "/v1/custom-rbac/grants"},
		{http.MethodPost, "/v1/custom-rbac/grants"},
		{http.MethodPost, "/v1/custom-rbac/grants/" + grantID + "/revoke"},
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusAccepted {
			t.Fatalf("custom RBAC route %s %s status = %d, want 202", route.method, route.path, response.Code)
		}
	}
	for _, path := range []string{
		"/v1/analytics/site-monitoring-extra",
		"/v1/custom-rbac/roles-extra",
		"/v1/custom-rbac/roles/" + roleID + "/publish-extra",
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code == http.StatusNoContent || response.Code == http.StatusAccepted {
			t.Fatalf("adjacent route %s reached a shared composition handler", path)
		}
	}
}

func TestSharedCompositionFactoriesFailClosed(t *testing.T) {
	want := errors.New("dependency unavailable")
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnalyticsRealtimeHandlerFactory: func(analyticsrealtimehttp.Authenticator) (http.Handler, error) {
		return nil, want
	}})
	if !errors.Is(api.InitializationError(), want) {
		t.Fatalf("analytics factory error = %v, want %v", api.InitializationError(), want)
	}
	api = New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CustomRBACHandlerFactory: func() (http.Handler, error) { return nil, want }})
	if !errors.Is(api.InitializationError(), want) {
		t.Fatalf("custom RBAC factory error = %v, want %v", api.InitializationError(), want)
	}
	var typedNil *sharedCompositionTypedNilHandler
	api = New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), CustomRBACHandlerFactory: func() (http.Handler, error) { return typedNil, nil }})
	if api.InitializationError() == nil {
		t.Fatal("typed-nil custom RBAC handler was accepted")
	}
}

func TestSharedCompositionCanonicalContractAggregatesFrozenFragments(t *testing.T) {
	sharedRuntimeIIRequireCanonicalAggregation(t, "control-analytics-realtime.openapi.yaml", []string{
		"/v1/analytics/site-monitoring", "/v1/admin/analytics/site-monitoring",
	})
	sharedRuntimeIIRequireCanonicalAggregation(t, "control-custom-rbac.openapi.yaml", []string{
		"/v1/custom-rbac/permissions", "/v1/custom-rbac/roles", "/v1/custom-rbac/roles/{role_id}",
		"/v1/custom-rbac/roles/{role_id}/rename", "/v1/custom-rbac/roles/{role_id}/publish",
		"/v1/custom-rbac/roles/{role_id}/deactivate", "/v1/custom-rbac/grants",
		"/v1/custom-rbac/grants/{grant_id}/revoke",
	})
}
