package httpapi

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type pluginWebhookMountObservation struct {
	path             string
	tenantScopeID    string
	subscriptionID   string
	deliveryID       string
	rotationID       string
	authorization    string
	forwardedRequest string
}

type pluginWebhookMountProbe struct {
	observations []pluginWebhookMountObservation
}

func (probe *pluginWebhookMountProbe) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	probe.observations = append(probe.observations, pluginWebhookMountObservation{
		path: request.URL.Path, tenantScopeID: request.PathValue("tenant_scope_id"),
		subscriptionID: request.PathValue("subscription_id"), deliveryID: request.PathValue("delivery_id"),
		rotationID: request.PathValue("rotation_id"), authorization: request.Header.Get("Authorization"),
		forwardedRequest: request.Header.Get("X-Request-ID"),
	})
	response.WriteHeader(http.StatusNoContent)
}

type pluginWebhookMountTypedNilHandler struct{}

func (*pluginWebhookMountTypedNilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestPluginWebhookMountForwardsExactlyTenCanonicalRoutePatterns(t *testing.T) {
	probe := &pluginWebhookMountProbe{}
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), PluginWebhookHandlerFactory: func() (http.Handler, error) { return probe, nil }})
	if err := api.InitializationError(); err != nil {
		t.Fatalf("initialize plugin webhook mount: %v", err)
	}
	handler := api.Handler()
	for _, route := range pluginWebhookMountRoutes() {
		request := httptest.NewRequest(route.method, route.path, nil)
		request.Header.Set("Authorization", "Bearer plugin-webhook-session")
		request.Header.Set("X-Request-ID", "plugin-webhook-mount-request")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("%s %s status = %d, want 204", route.method, route.path, response.Code)
		}
	}
	if len(probe.observations) != 10 {
		t.Fatalf("plugin webhook forwarded calls = %d, want 10", len(probe.observations))
	}
	for _, observation := range probe.observations {
		if observation.tenantScopeID == "" || observation.authorization != "Bearer plugin-webhook-session" ||
			observation.forwardedRequest != "plugin-webhook-mount-request" {
			t.Errorf("plugin webhook forwarded metadata = %#v", observation)
		}
		if observation.path != pluginWebhookSubscriptionsPath() && observation.subscriptionID == "" {
			t.Errorf("plugin webhook mount dropped subscription_id for %s", observation.path)
		}
		if strings.Contains(observation.path, "/deliveries/44444444-") && observation.deliveryID == "" {
			t.Errorf("plugin webhook mount dropped delivery_id for %s", observation.path)
		}
		if strings.Contains(observation.path, "/secret-rotations/55555555-") && observation.rotationID == "" {
			t.Errorf("plugin webhook mount dropped rotation_id for %s", observation.path)
		}
	}

	before := len(probe.observations)
	for _, path := range []string{
		"/v1/admin/plugin-webhook-subscriptions",
		"/v1/admin/tenant-scopes/11111111-1111-4111-8111-111111111111/plugin-webhook-subscriptions",
		pluginWebhookSubscriptionsPath() + "-extra",
		pluginWebhookSubscriptionsPath() + "/33333333-3333-4333-8333-333333333333/neighbor",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("non-canonical plugin webhook route %s status = %d, want 404", path, response.Code)
		}
	}
	if len(probe.observations) != before {
		t.Fatalf("non-canonical routes reached plugin webhook handler: %#v", probe.observations[before:])
	}
}

func TestPluginWebhookMountFactoryFailureAndNilHandlerFailClosed(t *testing.T) {
	factoryErr := errors.New("plugin webhook runtime dependency unavailable")
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), PluginWebhookHandlerFactory: func() (http.Handler, error) {
		return nil, factoryErr
	}})
	if !errors.Is(api.InitializationError(), factoryErr) {
		t.Fatalf("factory initialization error = %v, want %v", api.InitializationError(), factoryErr)
	}
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, pluginWebhookSubscriptionsPath(), nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("failed factory exposed plugin webhook route: status=%d", response.Code)
	}

	for name, factory := range map[string]MountedHandlerFactory{
		"nil": func() (http.Handler, error) { return nil, nil },
		"typed nil": func() (http.Handler, error) {
			var handler *pluginWebhookMountTypedNilHandler
			return handler, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), PluginWebhookHandlerFactory: factory})
			if api.InitializationError() == nil {
				t.Fatal("nil plugin webhook handler did not fail startup")
			}
			response := httptest.NewRecorder()
			api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, pluginWebhookSubscriptionsPath(), nil))
			if response.Code != http.StatusNotFound {
				t.Fatalf("failed factory exposed plugin webhook route: status=%d", response.Code)
			}
		})
	}
}

func pluginWebhookMountRoutes() []struct{ method, path string } {
	prefix := pluginWebhookSubscriptionsPath()
	subscription := "/33333333-3333-4333-8333-333333333333"
	delivery := "/44444444-4444-4444-8444-444444444444"
	rotation := "/55555555-5555-4555-8555-555555555555"
	return []struct{ method, path string }{
		{http.MethodGet, prefix},
		{http.MethodGet, prefix + subscription},
		{http.MethodPost, prefix + subscription + "/test-deliveries"},
		{http.MethodGet, prefix + subscription + "/deliveries"},
		{http.MethodGet, prefix + subscription + "/deliveries" + delivery},
		{http.MethodPost, prefix + subscription + "/deliveries" + delivery + "/replays"},
		{http.MethodPost, prefix + subscription + "/delivery-replays"},
		{http.MethodPost, prefix + subscription + "/secret-rotations"},
		{http.MethodPost, prefix + subscription + "/secret-rotations" + rotation + "/activate"},
		{http.MethodPost, prefix + subscription + "/revoke"},
	}
}

func pluginWebhookSubscriptionsPath() string {
	return "/v1/tenant-scopes/11111111-1111-4111-8111-111111111111/plugin-webhook-subscriptions"
}
