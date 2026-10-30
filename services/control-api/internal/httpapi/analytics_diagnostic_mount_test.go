package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsdiagnostichttp"
)

type analyticsDiagnosticMountTypedNilHandler struct{}

func (*analyticsDiagnosticMountTypedNilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestAnalyticsDiagnosticMountDisabledAndFailedFactoryStayClosed(t *testing.T) {
	paths := []string{"/v1/admin/analytics/site-quality-diagnostics", "/v1/analytics/site-quality-diagnostics"}
	for _, path := range paths {
		response := httptest.NewRecorder()
		New(nil, nil, Config{}).Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("disabled %s status = %d, want 404", path, response.Code)
		}
	}
	factoryErr := errors.New("analytics diagnostic dependency unavailable")
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnalyticsDiagnosticHandlerFactory: func(analyticsdiagnostichttp.Authenticator) (http.Handler, error) {
		return nil, factoryErr
	}})
	if !errors.Is(api.InitializationError(), factoryErr) {
		t.Fatalf("factory error = %v, want %v", api.InitializationError(), factoryErr)
	}
	var typedNil *analyticsDiagnosticMountTypedNilHandler
	api = New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnalyticsDiagnosticHandlerFactory: func(analyticsdiagnostichttp.Authenticator) (http.Handler, error) {
		return typedNil, nil
	}})
	if api.InitializationError() == nil {
		t.Fatal("typed nil analytics diagnostic handler did not fail startup")
	}
}

func TestAnalyticsDiagnosticMountForwardsOnlyExactRoutes(t *testing.T) {
	observed := make([]string, 0, 2)
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = append(observed, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnalyticsDiagnosticHandlerFactory: func(authenticate analyticsdiagnostichttp.Authenticator) (http.Handler, error) {
		if authenticate == nil {
			t.Fatal("analytics diagnostic authenticator is nil")
		}
		return probe, nil
	}})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/admin/analytics/site-quality-diagnostics", "/v1/analytics/site-quality-diagnostics"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("Authorization", "Bearer preserved")
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("%s status = %d, want 204", path, response.Code)
		}
	}
	for _, path := range []string{
		"/v1/admin/analytics/site-quality-diagnostics/",
		"/v1/analytics/site-quality-diagnostics/neighbor",
		"/v1/analytics/site-quality-diagnostics-extra",
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("adjacent route %s status = %d, want 404", path, response.Code)
		}
	}
	if len(observed) != 2 || observed[0] != "GET /v1/admin/analytics/site-quality-diagnostics Bearer preserved" ||
		observed[1] != "GET /v1/analytics/site-quality-diagnostics Bearer preserved" {
		t.Fatalf("analytics diagnostic observations = %#v", observed)
	}
}

func TestAnalyticsDiagnosticCanonicalContractAggregatesFrozenFragment(t *testing.T) {
	canonical := string(sharedRuntimeIIReadFile(t, "../../../../api/openapi/v1/control.yaml"))
	for _, path := range []string{
		"/v1/admin/analytics/site-quality-diagnostics",
		"/v1/analytics/site-quality-diagnostics",
	} {
		if !strings.Contains(canonical, path+":") {
			t.Errorf("canonical OpenAPI omits path %s", path)
		}
	}
	for _, ref := range []string{
		"../../control-quality-diagnostics.openapi.yaml#/paths/~1v1~1admin~1analytics~1quality-diagnostics",
		"../../control-quality-diagnostics.openapi.yaml#/paths/~1v1~1analytics~1quality-diagnostics",
		"../../control-quality-diagnostics.openapi.yaml#/components/securitySchemes/sessionBearer",
		"../../control-quality-diagnostics.openapi.yaml#/components/schemas/QualityDiagnostic",
		"../../control-quality-diagnostics.openapi.yaml#/components/schemas/QualityDiagnosticsResponse",
		"../../control-quality-diagnostics.openapi.yaml#/components/schemas/FinalizedSnapshot",
		"../../control-quality-diagnostics.openapi.yaml#/components/responses/QualityDiagnostics",
	} {
		if !strings.Contains(canonical, "$ref: '"+ref+"'") {
			t.Errorf("canonical OpenAPI omits finalized quality diagnostics ref %s", ref)
		}
	}
}
