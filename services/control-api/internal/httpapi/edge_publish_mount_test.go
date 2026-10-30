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

type edgePublishMountObservation struct {
	method        string
	path          string
	publicationID string
	rolloutID     string
	authorization string
	requestID     string
}

type edgePublishMountProbe struct {
	observations []edgePublishMountObservation
	routes       *http.ServeMux
}

func (probe *edgePublishMountProbe) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	probe.routes.ServeHTTP(response, request)
}

func newEdgePublishMountProbe() *edgePublishMountProbe {
	probe := &edgePublishMountProbe{routes: http.NewServeMux()}
	for _, route := range edgePublishMountRoutes() {
		probe.routes.HandleFunc(route.method+" "+sharedRuntimeIITemplateEdgePublishPath(route.path), probe.observe)
	}
	return probe
}

func (probe *edgePublishMountProbe) observe(response http.ResponseWriter, request *http.Request) {
	probe.observations = append(probe.observations, edgePublishMountObservation{
		method: request.Method, path: request.URL.Path,
		publicationID: request.PathValue("publication_id"), rolloutID: request.PathValue("rollout_id"),
		authorization: request.Header.Get("Authorization"), requestID: request.Header.Get("X-Request-ID"),
	})
	response.WriteHeader(http.StatusNoContent)
}

type edgePublishMountTypedNilHandler struct{}

func (*edgePublishMountTypedNilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestEdgePublishMountDisabledByDefaultHasExactNotFoundSurface(t *testing.T) {
	for _, route := range edgePublishMountRoutes() {
		response := httptest.NewRecorder()
		New(nil, nil, Config{}).Handler().ServeHTTP(response,
			httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("disabled %s %s status = %d, want 404", route.method, route.path, response.Code)
		}
	}
}

func TestEdgePublishMountFactoryFailureAndTypedNilFailStartup(t *testing.T) {
	factoryErr := errors.New("edge publication runtime dependency is unavailable")
	config := Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
	edgePublishSetMountedFactory(t, &config, nil, factoryErr)
	api := New(nil, nil, config)
	if !errors.Is(api.InitializationError(), factoryErr) {
		t.Fatalf("edge publication initialization error = %v, want %v", api.InitializationError(), factoryErr)
	}
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/site-publications", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("failed edge publication factory exposed route: status=%d", response.Code)
	}

	var typedNil *edgePublishMountTypedNilHandler
	config = Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
	edgePublishSetMountedFactory(t, &config, typedNil, nil)
	api = New(nil, nil, config)
	if api.InitializationError() == nil {
		t.Fatal("typed-nil edge publication handler did not fail startup")
	}
}

func TestEdgePublishMountForwardsOnlyFrozenHandlerRoutes(t *testing.T) {
	probe := newEdgePublishMountProbe()
	config := Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
	edgePublishSetMountedFactory(t, &config, probe, nil)
	api := New(nil, nil, config)
	if err := api.InitializationError(); err != nil {
		t.Fatalf("initialize edge publication mount: %v", err)
	}
	handler := api.Handler()
	for _, route := range edgePublishMountRoutes() {
		request := httptest.NewRequest(route.method, route.path, strings.NewReader("payload"))
		request.Header.Set("Authorization", "Bearer preserved-session")
		request.Header.Set("X-Request-ID", "edge-publish-mount-request")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("%s %s status = %d, want 204", route.method, route.path, response.Code)
		}
	}
	if len(probe.observations) != len(edgePublishMountRoutes()) {
		t.Fatalf("edge publication forwarded calls = %d, want %d", len(probe.observations), len(edgePublishMountRoutes()))
	}
	for _, observation := range probe.observations {
		if observation.authorization != "Bearer preserved-session" || observation.requestID != "edge-publish-mount-request" {
			t.Errorf("edge publication forwarded metadata = %#v", observation)
		}
		if strings.Contains(observation.path, "/site-publications/") && observation.publicationID == "" {
			t.Errorf("edge publication mount dropped publication_id for %s", observation.path)
		}
		if strings.Contains(observation.path, "/site-rollouts/") &&
			observation.path != "/v1/admin/site-rollouts/reconciliations" && observation.rolloutID == "" {
			t.Errorf("edge publication mount dropped rollout_id for %s", observation.path)
		}
	}

	before := len(probe.observations)
	publication := "11111111-1111-4111-8111-111111111111"
	rollout := "22222222-2222-4222-8222-222222222222"
	for _, path := range []string{
		"/v1/admin/site-publications-neighbor",
		"/v1/admin/site-publications/" + publication + "/neighbor",
		"/v1/admin/site-rollouts/" + rollout + "/cancel/neighbor",
		"/v1/site-publications/" + publication + "/neighbor",
		"/v1/site-rollouts/" + rollout + "/deployments/neighbor",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("adjacent edge publication route %s status = %d, want 404", path, response.Code)
		}
	}
	if len(probe.observations) != before {
		t.Fatalf("adjacent edge publication routes reached package handler: observations=%#v", probe.observations[before:])
	}
}

func TestEdgePublishCanonicalContractAggregatesFrozenFragmentAndMatchesCredentialModes(t *testing.T) {
	paths := make([]string, 0)
	seen := make(map[string]bool)
	for _, route := range edgePublishMountRoutes() {
		path := sharedRuntimeIITemplateEdgePublishPath(route.path)
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	sharedRuntimeIIRequireCanonicalAggregation(t, "control-site-publications.openapi.yaml", paths)
	fragment := string(sharedRuntimeIIReadFile(t, "../../../../api/control-site-publications.openapi.yaml"))
	if strings.Count(fragment, "- bearerAuth: []") != 25 {
		t.Fatalf("edge publication Bearer security declarations = %d, want 25",
			strings.Count(fragment, "- bearerAuth: []"))
	}
	if strings.Count(fragment, "- cdncaApiKey: []") != 11 {
		t.Fatalf("edge publication CdncaKey security declarations = %d, want 11 tenant reads",
			strings.Count(fragment, "- cdncaApiKey: []"))
	}
	sharedRuntimeIIRequireUniqueOperationIDs(t, []string{
		"listAdminSitePublications", "publishSiteConfiguration", "getAdminSitePublication",
		"rollbackSitePublication",
		"listAdminSiteRollouts", "getAdminSiteRollout", "listAdminSiteRolloutDeployments",
		"cancelSiteRollout", "retryFailedSiteRolloutDeployments", "reconcileAdminNodeConfiguration",
		"listTenantSitePublications",
		"publishTenantSiteConfiguration",
		"getTenantSitePublication", "listTenantSiteRollouts", "getTenantSiteRollout",
		"listTenantSiteRolloutDeployments",
	})
}

func edgePublishMountRoutes() []struct{ method, path string } {
	publication := "11111111-1111-4111-8111-111111111111"
	rollout := "22222222-2222-4222-8222-222222222222"
	return []struct{ method, path string }{
		{http.MethodGet, "/v1/admin/site-publications"},
		{http.MethodPost, "/v1/admin/site-publications"},
		{http.MethodGet, "/v1/admin/site-publications/" + publication},
		{http.MethodPost, "/v1/admin/site-publications/" + publication + "/rollback"},
		{http.MethodGet, "/v1/admin/site-rollouts"},
		{http.MethodPost, "/v1/admin/site-rollouts/reconciliations"},
		{http.MethodGet, "/v1/admin/site-rollouts/" + rollout},
		{http.MethodGet, "/v1/admin/site-rollouts/" + rollout + "/deployments"},
		{http.MethodPost, "/v1/admin/site-rollouts/" + rollout + "/cancel"},
		{http.MethodPost, "/v1/admin/site-rollouts/" + rollout + "/retry-failed"},
		{http.MethodGet, "/v1/site-publications"},
		{http.MethodGet, "/v1/site-publications/" + publication},
		{http.MethodGet, "/v1/site-rollouts"},
		{http.MethodGet, "/v1/site-rollouts/" + rollout},
		{http.MethodGet, "/v1/site-rollouts/" + rollout + "/deployments"},
	}
}

func edgePublishSetMountedFactory(t *testing.T, config *Config, handler http.Handler, factoryErr error) {
	t.Helper()
	field := reflect.ValueOf(config).Elem().FieldByName("EdgePublishHandlerFactory")
	sharedRuntimeIISetMountedFactory(t, field, "EdgePublishHandlerFactory", handler, factoryErr)
}

func sharedRuntimeIITemplateEdgePublishPath(path string) string {
	replacer := strings.NewReplacer(
		"11111111-1111-4111-8111-111111111111", "{publication_id}",
		"22222222-2222-4222-8222-222222222222", "{rollout_id}",
	)
	return replacer.Replace(path)
}
