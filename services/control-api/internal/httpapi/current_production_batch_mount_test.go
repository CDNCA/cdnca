package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

type currentProductionBatchTypedNilHandler struct{}

func (*currentProductionBatchTypedNilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestCurrentProductionBatchMountsOnlyExactRoutes(t *testing.T) {
	config := Config{
		APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		ControlPlaneUpgradeHandler: http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("X-Current-Batch-Probe", "upgrade")
			response.WriteHeader(http.StatusNoContent)
		}),
		ControlPlaneUpgradeGate: func(handler http.Handler) http.Handler { return handler },
	}
	for field, label := range map[string]string{
		"OriginAuthPublicationHandlerFactory":       "origin-auth-publication",
		"ErrorPagePublicationHandlerFactory":        "error-page-publication",
		"AnalyticsGeoHandlerFactory":                "analytics-geo",
		"SecurityCoordinationMetricsHandlerFactory": "security-coordination-metrics",
		"ControlUpgradePlanHandlerFactory":          "control-upgrade-plan",
	} {
		label := label
		setCurrentProductionBatchFactory(t, &config, field, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set("X-Current-Batch-Probe", label)
			response.WriteHeader(http.StatusNoContent)
		}), nil)
	}
	api := New(nil, nil, config)
	if err := api.InitializationError(); err != nil {
		t.Fatalf("initialize current production batch: %v", err)
	}

	tenantScopeID := "11111111-1111-4111-8111-111111111111"
	publicationID := "22222222-2222-4222-8222-222222222222"
	eventID := "event-1"
	routes := []struct{ method, path, label string }{
		{http.MethodPost, "/v1/tenant-scopes/" + tenantScopeID + "/origin-auth/edge-publications", "origin-auth-publication"},
		{http.MethodGet, "/v1/tenant-scopes/" + tenantScopeID + "/origin-auth/edge-publications/" + publicationID, "origin-auth-publication"},
		{http.MethodPost, "/v1/tenant-scopes/" + tenantScopeID + "/error-page-publications", "error-page-publication"},
		{http.MethodGet, "/v1/tenant-scopes/" + tenantScopeID + "/error-page-publications/" + publicationID, "error-page-publication"},
		{http.MethodGet, "/v1/admin/analytics/logs/access/geo-evidence/" + eventID, "analytics-geo"},
		{http.MethodGet, "/v1/analytics/logs/block/geo-evidence/" + eventID, "analytics-geo"},
		{http.MethodGet, "/v1/admin/security/coordination/metrics", "security-coordination-metrics"},
		{http.MethodGet, "/v1/admin/control-upgrade-plan", "upgrade"},
		{http.MethodPost, "/v1/admin/control-upgrade-plan", "upgrade"},
		{http.MethodGet, "/v1/admin/control-upgrade-plan/run-log", "upgrade"},
		{http.MethodGet, "/v1/admin/control-upgrade-plan/options", "upgrade"},
		{http.MethodPost, "/v1/admin/control-upgrade-plan/issue", "upgrade"},
		{http.MethodGet, "/v1/internal/control-upgrade/plan", "control-upgrade-plan"},
		{http.MethodPost, "/v1/internal/control-upgrade/drain", "upgrade"},
		{http.MethodPost, "/v1/internal/control-upgrade/resume", "upgrade"},
		{http.MethodGet, "/v1/internal/control-upgrade/health", "upgrade"},
		{http.MethodGet, "/v1/internal/control-upgrade/version", "upgrade"},
	}
	handler := api.Handler()
	for _, route := range routes {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusNoContent || response.Header().Get("X-Current-Batch-Probe") != route.label {
			t.Errorf("%s %s = (%d,%q), want (204,%q)", route.method, route.path, response.Code,
				response.Header().Get("X-Current-Batch-Probe"), route.label)
		}
	}

	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/v1/admin/security/coordination/metrics/neighbor"},
		{http.MethodGet, "/v1/analytics/logs/block/geo-evidence/" + eventID + "/neighbor"},
		{http.MethodPost, "/v1/tenant-scopes/" + tenantScopeID + "/error-page-publications/" + publicationID + "/neighbor"},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Header().Get("X-Current-Batch-Probe") != "" {
			t.Errorf("adjacent route %s %s reached %q", route.method, route.path,
				response.Header().Get("X-Current-Batch-Probe"))
		}
	}
}

func TestCurrentProductionBatchFactoriesFailClosed(t *testing.T) {
	fields := []string{
		"OriginAuthPublicationHandlerFactory",
		"ErrorPagePublicationHandlerFactory",
		"AnalyticsGeoHandlerFactory",
		"SecurityCoordinationMetricsHandlerFactory",
		"ControlUpgradePlanHandlerFactory",
	}
	for _, field := range fields {
		t.Run(field+" error", func(t *testing.T) {
			config := Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
			want := errors.New("current production dependency unavailable")
			if !setCurrentProductionBatchFactory(t, &config, field, nil, want) {
				return
			}
			if err := New(nil, nil, config).InitializationError(); !errors.Is(err, want) {
				t.Fatalf("initialization error = %v, want %v", err, want)
			}
		})
		t.Run(field+" typed nil", func(t *testing.T) {
			config := Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
			var typedNil *currentProductionBatchTypedNilHandler
			if !setCurrentProductionBatchFactory(t, &config, field, typedNil, nil) {
				return
			}
			if err := New(nil, nil, config).InitializationError(); err == nil {
				t.Fatal("typed-nil handler was accepted")
			}
		})
	}
}

func setCurrentProductionBatchFactory(t *testing.T, config *Config, fieldName string, handler http.Handler, factoryErr error) bool {
	t.Helper()
	field := reflect.ValueOf(config).Elem().FieldByName(fieldName)
	if !field.IsValid() {
		t.Errorf("httpapi.Config is missing %s", fieldName)
		return false
	}
	factory := reflect.MakeFunc(field.Type(), func([]reflect.Value) []reflect.Value {
		handlerValue := reflect.Zero(reflect.TypeOf((*http.Handler)(nil)).Elem())
		if handler != nil {
			handlerValue = reflect.ValueOf(handler)
		}
		errorValue := reflect.Zero(reflect.TypeOf((*error)(nil)).Elem())
		if factoryErr != nil {
			errorValue = reflect.ValueOf(factoryErr)
		}
		return []reflect.Value{handlerValue, errorValue}
	})
	field.Set(factory)
	return true
}
