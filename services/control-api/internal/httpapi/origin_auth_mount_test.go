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

type originAuthMountObservation struct {
	method        string
	path          string
	tenantScopeID string
	credentialID  string
	ruleID        string
	authorization string
	requestID     string
}

type originAuthMountProbe struct {
	observations []originAuthMountObservation
	routes       *http.ServeMux
}

func (probe *originAuthMountProbe) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	probe.routes.ServeHTTP(response, request)
}

func newOriginAuthMountProbe() *originAuthMountProbe {
	probe := &originAuthMountProbe{routes: http.NewServeMux()}
	for _, route := range originAuthMountRoutes() {
		probe.routes.HandleFunc(route.method+" "+sharedRuntimeIITemplatePath(route.path), probe.observe)
	}
	return probe
}

func (probe *originAuthMountProbe) observe(response http.ResponseWriter, request *http.Request) {
	probe.observations = append(probe.observations, originAuthMountObservation{
		method: request.Method, path: request.URL.Path,
		tenantScopeID: request.PathValue("tenant_scope_id"),
		credentialID:  request.PathValue("credential_id"), ruleID: request.PathValue("rule_id"),
		authorization: request.Header.Get("Authorization"), requestID: request.Header.Get("X-Request-ID"),
	})
	response.WriteHeader(http.StatusNoContent)
}

type originAuthMountTypedNilHandler struct{}

func (*originAuthMountTypedNilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

// fix-e1 #2: origin authentication off answers 503 feature_disabled (the pages show "not enabled"), not a 404.
func TestOriginAuthMountDisabledByDefaultAnswersFeatureDisabled(t *testing.T) {
	for _, route := range originAuthMountRoutes() {
		response := httptest.NewRecorder()
		New(nil, nil, Config{}).Handler().ServeHTTP(response,
			httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "feature_disabled") {
			t.Errorf("disabled %s %s status = %d body=%s, want 503 feature_disabled", route.method, route.path, response.Code, response.Body.String())
		}
	}
}

func TestOriginAuthMountFactoryFailureAndTypedNilFailStartup(t *testing.T) {
	factoryErr := errors.New("origin auth runtime dependency is unavailable")
	config := Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
	originAuthSetMountedFactory(t, &config, nil, factoryErr)
	api := New(nil, nil, config)
	if !errors.Is(api.InitializationError(), factoryErr) {
		t.Fatalf("origin auth initialization error = %v, want %v", api.InitializationError(), factoryErr)
	}
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"/v1/tenant-scopes/11111111-1111-4111-8111-111111111111/origin-auth/credentials", nil))
	// Startup fails on InitializationError; until then only the feature_disabled stub answers (no real handler).
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "feature_disabled") {
		t.Fatalf("failed origin auth factory exposed route: status=%d body=%s", response.Code, response.Body.String())
	}

	var typedNil *originAuthMountTypedNilHandler
	config = Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
	originAuthSetMountedFactory(t, &config, typedNil, nil)
	api = New(nil, nil, config)
	if api.InitializationError() == nil {
		t.Fatal("typed-nil origin auth handler did not fail startup")
	}
}

func TestOriginAuthMountForwardsOnlyFrozenHandlerRoutes(t *testing.T) {
	probe := newOriginAuthMountProbe()
	config := Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
	originAuthSetMountedFactory(t, &config, probe, nil)
	api := New(nil, nil, config)
	if err := api.InitializationError(); err != nil {
		t.Fatalf("initialize origin auth mount: %v", err)
	}
	handler := api.Handler()
	for _, route := range originAuthMountRoutes() {
		request := httptest.NewRequest(route.method, route.path, strings.NewReader("{}"))
		request.Header.Set("Authorization", "Bearer preserved-session")
		request.Header.Set("X-Request-ID", "origin-auth-mount-request")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("%s %s status = %d, want 204", route.method, route.path, response.Code)
		}
	}
	if len(probe.observations) != len(originAuthMountRoutes()) {
		t.Fatalf("origin auth forwarded calls = %d, want %d", len(probe.observations), len(originAuthMountRoutes()))
	}
	for _, observation := range probe.observations {
		if observation.tenantScopeID == "" || observation.authorization != "Bearer preserved-session" ||
			observation.requestID != "origin-auth-mount-request" {
			t.Errorf("origin auth forwarded metadata = %#v", observation)
		}
		if strings.Contains(observation.path, "/credentials/") && observation.credentialID == "" {
			t.Errorf("origin auth mount dropped credential_id for %s", observation.path)
		}
		if strings.Contains(observation.path, "/rules/") && observation.ruleID == "" {
			t.Errorf("origin auth mount dropped rule_id for %s", observation.path)
		}
	}

	before := len(probe.observations)
	scope := "11111111-1111-4111-8111-111111111111"
	credential := "22222222-2222-4222-8222-222222222222"
	rule := "33333333-3333-4333-8333-333333333333"
	for _, path := range []string{
		"/v1/tenant-scopes/" + scope + "/origin-auth",
		"/v1/tenant-scopes/" + scope + "/origin-auth/credentials-extra",
		"/v1/tenant-scopes/" + scope + "/origin-auth/credentials/" + credential + "/replace/neighbor",
		"/v1/tenant-scopes/" + scope + "/origin-auth/rules/" + rule + "/rotate/neighbor",
		"/v1/tenant-scopes/" + scope + "/origin-auth/publications/neighbor",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("adjacent origin auth route %s status = %d, want 404", path, response.Code)
		}
	}
	if len(probe.observations) != before {
		t.Fatalf("adjacent origin auth routes reached package handler: observations=%#v", probe.observations[before:])
	}
}

func TestOriginAuthCanonicalContractAggregatesFrozenFragmentAndBearerOnlySecurity(t *testing.T) {
	paths := make([]string, 0)
	seen := make(map[string]bool)
	for _, route := range originAuthMountRoutes() {
		path := sharedRuntimeIITemplatePath(route.path)
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	sharedRuntimeIIRequireCanonicalAggregation(t, "control-origin-auth.openapi.yaml", paths)
	fragment := string(sharedRuntimeIIReadFile(t, "../../../../api/control-origin-auth.openapi.yaml"))
	if !strings.Contains(fragment, "security:\n  - bearerAuth: []") {
		t.Fatal("origin auth fragment does not declare global Bearer security")
	}
	if strings.Contains(fragment, "cdncaApiKey:") {
		t.Fatal("origin auth contract exposes CdncaKey security")
	}
	sharedRuntimeIIRequireUniqueOperationIDs(t, []string{
		"listOriginAuthCredentials", "createOriginAuthCredential", "getOriginAuthCredential",
		"deleteOriginAuthCredential", "replaceOriginAuthCredential", "verifyOriginAuthCredential",
		"disableOriginAuthCredential", "listOriginAuthRules", "createOriginAuthRule", "getOriginAuthRule",
		"updateOriginAuthRule", "deleteOriginAuthRule", "enableOriginAuthRule", "disableOriginAuthRule",
		"rotateOriginAuthRuleCredential", "getLatestOriginAuthPublication", "createOriginAuthPublication",
	})
}

func originAuthMountRoutes() []struct{ method, path string } {
	scope := "11111111-1111-4111-8111-111111111111"
	credential := "22222222-2222-4222-8222-222222222222"
	rule := "33333333-3333-4333-8333-333333333333"
	prefix := "/v1/tenant-scopes/" + scope + "/origin-auth"
	return []struct{ method, path string }{
		{http.MethodGet, prefix + "/credentials"}, {http.MethodPost, prefix + "/credentials"},
		{http.MethodGet, prefix + "/credentials/" + credential},
		{http.MethodDelete, prefix + "/credentials/" + credential},
		{http.MethodPost, prefix + "/credentials/" + credential + "/replace"},
		{http.MethodPost, prefix + "/credentials/" + credential + "/verify"},
		{http.MethodPost, prefix + "/credentials/" + credential + "/disable"},
		{http.MethodGet, prefix + "/rules"}, {http.MethodPost, prefix + "/rules"},
		{http.MethodGet, prefix + "/rules/" + rule}, {http.MethodPatch, prefix + "/rules/" + rule},
		{http.MethodDelete, prefix + "/rules/" + rule},
		{http.MethodPost, prefix + "/rules/" + rule + "/enable"},
		{http.MethodPost, prefix + "/rules/" + rule + "/disable"},
		{http.MethodPost, prefix + "/rules/" + rule + "/rotate"},
		{http.MethodGet, prefix + "/publications"}, {http.MethodPost, prefix + "/publications"},
	}
}

func originAuthSetMountedFactory(t *testing.T, config *Config, handler http.Handler, factoryErr error) {
	t.Helper()
	field := reflect.ValueOf(config).Elem().FieldByName("OriginAuthHandlerFactory")
	sharedRuntimeIISetMountedFactory(t, field, "OriginAuthHandlerFactory", handler, factoryErr)
}

func sharedRuntimeIITemplatePath(path string) string {
	replacer := strings.NewReplacer(
		"11111111-1111-4111-8111-111111111111", "{tenant_scope_id}",
		"22222222-2222-4222-8222-222222222222", "{credential_id}",
		"33333333-3333-4333-8333-333333333333", "{rule_id}",
	)
	return replacer.Replace(path)
}
