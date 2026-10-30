package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsdiagnostic"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/qualitydiagnostics"
	"github.com/cdnca/cdnca/services/control-api/internal/qualitydiagnosticshttp"
)

func TestBuildAnalyticsDiagnosticHandlerFactoryFailsClosedAndBuildsOfficialHandler(t *testing.T) {
	productionConfig := qualitydiagnosticshttp.ProductionConfig{
		Source:  analyticslog.FinalizedAccessConfig{QueryTimeout: time.Second},
		Service: qualitydiagnostics.RuntimeConfig{CursorKey: []byte(strings.Repeat("d", 32))},
		Handler: qualitydiagnosticshttp.Config{QueryTimeout: time.Second},
	}
	factory, err := buildAnalyticsDiagnosticHandlerFactory(false, nil, productionConfig)
	if err != nil || factory != nil {
		t.Fatalf("disabled factory = (%T, %v), want (nil, nil)", factory, err)
	}
	if factory, err = buildAnalyticsDiagnosticHandlerFactory(true, nil, productionConfig); err == nil || factory != nil {
		t.Fatalf("enabled nil-client factory = (%T, %v), want error", factory, err)
	}
	client, err := analyticslog.NewClient(analyticslog.ClientConfig{
		Endpoint: "http://127.0.0.1:1", Database: "quality_diagnostics_composition", QueryTimeout: time.Second,
		CursorKeyring: analyticslog.CursorKeyring{ActiveKID: "active", Keys: map[string][]byte{
			"active": []byte(strings.Repeat("c", 32)),
		}},
	}, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	factory, err = buildAnalyticsDiagnosticHandlerFactory(true, client, productionConfig)
	if err != nil || factory == nil {
		t.Fatalf("enabled factory = (%T, %v)", factory, err)
	}
	if handler, err := factory(nil); err == nil || handler != nil {
		t.Fatalf("nil-authenticator handler = (%T, %v), want error", handler, err)
	}
	handler, err := factory(func(*http.Request) (analyticsdiagnostic.Actor, error) {
		return analyticsdiagnostic.Actor{}, identity.ErrInvalidSession
	})
	if err != nil || handler == nil {
		t.Fatalf("official handler = (%T, %v)", handler, err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet,
		"/v1/analytics/site-quality-diagnostics?from=2026-08-08T00:00:00Z&to=2026-08-08T01:00:00Z", nil)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("diagnostic runtime status = %d, want 401", response.Code)
	}
}

func TestAnalyticsDiagnosticCompositionUsesFinalizedAuthorityAndCanonicalContract(t *testing.T) {
	mainSource, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"analyticsdiagnostichttp.NewFinalizedProductionHandler",
		"qualitydiagnosticshttp.ProductionConfig",
		"analyticsDiagnosticClient = client",
	} {
		if !strings.Contains(string(mainSource), required) {
			t.Errorf("control-api diagnostics composition missing %q", required)
		}
	}
	rootContract, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	contract := string(rootContract)
	if !strings.Contains(contract, "control-quality-diagnostics.openapi.yaml") {
		t.Error("root OpenAPI does not reference finalized quality diagnostics contract")
	}
	if strings.Contains(contract, "control-analytics-diagnostics.openapi.yaml") {
		t.Error("root OpenAPI still references legacy non-finalized diagnostics contract")
	}
}
