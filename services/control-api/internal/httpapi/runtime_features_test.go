package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrolhttp"
)

// The runtime feature flags are derived from the mounted handlers, so a menu
// hidden by them is exactly the set of routes that would answer 404.
func TestRuntimeFeaturesReflectMountedOptionalRuntimes(t *testing.T) {
	noContent := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})
	for _, test := range []struct {
		name   string
		config Config
		want   runtimeFeaturesResponse
	}{
		{name: "none mounted", config: Config{}, want: runtimeFeaturesResponse{}},
		{name: "all mounted", config: Config{
			CacheControlHandlerFactory: func(cachecontrolhttp.AuthenticateFunc) (http.Handler, error) { return noContent, nil },
			CustomRBACHandlerFactory:   func() (http.Handler, error) { return noContent, nil },
			// E1: /sys/plugin-webhooks is gated on this flag, not only on permissions.
			PluginWebhookHandlerFactory:   func() (http.Handler, error) { return noContent, nil },
			MarketSubscribeHandlerFactory: func() (http.Handler, error) { return noContent, nil },
			MarketRuntime:                 true,
			OriginAuthHandlerFactory:      func() (http.Handler, error) { return noContent, nil },
		}, want: runtimeFeaturesResponse{CacheControl: true, CustomRBAC: true, PluginWebhooks: true, Market: true, OriginAuth: true}},
		// The market routes mounted only for plugin advisories
		// (MARKET_RUNTIME_ENABLED off) do not make the market menus visible.
		{name: "market advisories only", config: Config{
			MarketSubscribeHandlerFactory: func() (http.Handler, error) { return noContent, nil },
		}, want: runtimeFeaturesResponse{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.config.APIKeyPepper = bytes.Repeat([]byte{0x52}, 32)
			api := New(nil, nil, test.config)
			if got := api.runtimeFeatures(t.Context()); got != test.want {
				t.Fatalf("runtime features = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestRuntimeFeaturesRequireSession(t *testing.T) {
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)})
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/runtime-features", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["features"] != nil {
		t.Fatalf("unauthenticated body leaked features: %s", response.Body.String())
	}
}
