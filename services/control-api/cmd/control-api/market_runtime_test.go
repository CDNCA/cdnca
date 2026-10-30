package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestBuildMarketRuntimeDisabledByDefault(t *testing.T) {
	t.Setenv("MARKET_RUNTIME_ENABLED", "")
	runtime, err := buildMarketRuntime(nil, nil, nil)
	if runtime != nil || err != nil {
		t.Fatalf("disabled market runtime = %v, %v", runtime, err)
	}
	t.Setenv("MARKET_RUNTIME_ENABLED", "true")
	if _, err := buildMarketRuntime(nil, nil, nil); err == nil {
		t.Fatal("enabled without trust must fail startup")
	}
}

func TestParseMarketKeys(t *testing.T) {
	keys, err := parseMarketKeys(`[{"key_id":"market-2026-10","public_key":"nMiT8UsLoNyFbTfkHNuSJ0vJybR9lDutRPlFKmyFwhM="}]`)
	if err != nil || len(keys["market-2026-10"]) != 32 {
		t.Fatalf("keys = %v, %v", keys, err)
	}
	for _, bad := range []string{"", "[]", `[{"key_id":"k","public_key":"short"}]`, `[{"key_id":"","public_key":"nMiT8UsLoNyFbTfkHNuSJ0vJybR9lDutRPlFKmyFwhM="}]`} {
		if _, err := parseMarketKeys(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestBuildMarketProbeSwitch(t *testing.T) {
	if probe, err := buildMarketProbe("false", nil, nil, nil, nil, nil, nil); probe != nil || err != nil {
		t.Fatalf("disabled probe = %v, %v", probe, err)
	}
	if _, err := buildMarketProbe("yes", nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("invalid switch accepted")
	}
	if _, err := buildMarketProbe("true", nil, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("enabled without edge NATS must fail startup")
	}
}

// Plugin advisories do not depend on the node market: with the market runtime
// off the factory still mounts the advisory routes once the plugin runtime
// reaches the license service, and nothing at all without either.
func TestMarketHandlerFactoryServesAdvisoriesWithoutMarketRuntime(t *testing.T) {
	pool := &pgxpool.Pool{}
	if factory := marketSubscribeHandlerFactory(nil, nil, nil, pool, nil, nil); factory != nil {
		t.Fatal("no market and no plugin runtime must leave the routes unmounted")
	}
	plugins := &pluginInstallationRuntime{licenseHTTP: &http.Client{}, providerURL: "https://license.example",
		installationID: uuid.New()}
	advisories, err := buildMarketAdvisorySync(plugins, pool)
	if err != nil || advisories == nil {
		t.Fatalf("advisory sync = %v, %v", advisories, err)
	}
	if none, err := buildMarketAdvisorySync(nil, pool); none != nil || err != nil {
		t.Fatalf("without plugin runtime = %v, %v", none, err)
	}
	if _, err := buildMarketAdvisorySync(&pluginInstallationRuntime{licenseHTTP: &http.Client{}, providerURL: "http://plain",
		installationID: uuid.New()}, pool); err == nil {
		t.Fatal("plain http provider accepted")
	}
	factory := marketSubscribeHandlerFactory(nil, nil, nil, pool, advisories, nil)
	if factory == nil {
		t.Fatal("advisories must mount without the market runtime")
	}
	handler, err := factory()
	if err != nil || handler == nil {
		t.Fatalf("handler = %v, %v", handler, err)
	}
	// Unauthenticated requests are refused before any store access; node
	// market routes are not registered at all.
	for path, want := range map[string]int{
		"/v1/admin/market/advisories": http.StatusForbidden,
		"/v1/admin/market/supplies":   http.StatusNotFound,
		"/v1/admin/market/offers":     http.StatusNotFound,
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Errorf("%s = %d, want %d", path, w.Code, want)
		}
	}
}
