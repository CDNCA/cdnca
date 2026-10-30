package httpapi

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

var sharedRuntimeIIOpenAPIFiles = []string{
	"../../../../api/openapi/v1/control.yaml",
	"../../../../api/control-analytics-diagnostics.openapi.yaml",
	"../../../../api/control-error-pages.openapi.yaml",
	"../../../../api/control-http-policies.openapi.yaml",
	"../../../../api/control-mfa.openapi.yaml",
	"../../../../api/control-origin-auth.openapi.yaml",
	"../../../../api/control-site-publications.openapi.yaml",
}

type mfaMountObservation struct {
	method        string
	path          string
	credentialID  string
	authorization string
	requestID     string
}

type mfaMountProbe struct {
	observations []mfaMountObservation
	routes       *http.ServeMux
}

func (probe *mfaMountProbe) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	probe.routes.ServeHTTP(response, request)
}

func newMFAMountProbe() *mfaMountProbe {
	probe := &mfaMountProbe{routes: http.NewServeMux()}
	for _, route := range mfaMountRoutes() {
		probe.routes.HandleFunc(route.method+" "+mfaMountTemplatePath(route.path), probe.observe)
	}
	return probe
}

func (probe *mfaMountProbe) observe(response http.ResponseWriter, request *http.Request) {
	probe.observations = append(probe.observations, mfaMountObservation{
		method: request.Method, path: request.URL.Path,
		credentialID:  request.PathValue("credential_id"),
		authorization: request.Header.Get("Authorization"),
		requestID:     request.Header.Get("X-Request-ID"),
	})
	response.WriteHeader(http.StatusNoContent)
}

type mfaMountTypedNilHandler struct{}

func (*mfaMountTypedNilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestMFAMountDisabledByDefaultHasExactNotFoundSurface(t *testing.T) {
	for _, route := range mfaMountRoutes() {
		response := httptest.NewRecorder()
		New(nil, nil, Config{}).Handler().ServeHTTP(response,
			httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("disabled %s %s status = %d, want 404", route.method, route.path, response.Code)
		}
		if response.Header().Get("X-Request-ID") == "" {
			t.Errorf("disabled %s %s omitted X-Request-ID", route.method, route.path)
		}
	}
}

func TestMFAMountFactoryFailureAndTypedNilFailStartup(t *testing.T) {
	factoryErr := errors.New("MFA runtime dependency is unavailable")
	config := Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
	mfaSetMountedFactory(t, &config, nil, factoryErr)
	api := New(nil, nil, config)
	if !errors.Is(api.InitializationError(), factoryErr) {
		t.Fatalf("MFA initialization error = %v, want %v", api.InitializationError(), factoryErr)
	}
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/account/mfa", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("failed MFA factory exposed route: status=%d", response.Code)
	}

	var typedNil *mfaMountTypedNilHandler
	config = Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
	mfaSetMountedFactory(t, &config, typedNil, nil)
	api = New(nil, nil, config)
	if api.InitializationError() == nil {
		t.Fatal("typed-nil MFA handler did not fail startup")
	}
}

func TestMFAMountForwardsOnlyFrozenHandlerRoutes(t *testing.T) {
	probe := newMFAMountProbe()
	config := Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}
	mfaSetMountedFactory(t, &config, probe, nil)
	api := New(nil, nil, config)
	if err := api.InitializationError(); err != nil {
		t.Fatalf("initialize MFA mount: %v", err)
	}
	handler := api.Handler()
	for _, route := range mfaMountRoutes() {
		request := httptest.NewRequest(route.method, route.path, strings.NewReader("payload"))
		request.Header.Set("Authorization", "Bearer preserved-session")
		request.Header.Set("X-Request-ID", "mfa-mount-request")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("%s %s status = %d, want 204", route.method, route.path, response.Code)
		}
		if response.Header().Get("X-Request-ID") != "mfa-mount-request" {
			t.Errorf("%s %s response request ID = %q", route.method, route.path,
				response.Header().Get("X-Request-ID"))
		}
	}
	if len(probe.observations) != len(mfaMountRoutes()) {
		t.Fatalf("MFA forwarded calls = %d, want %d", len(probe.observations), len(mfaMountRoutes()))
	}
	for _, observation := range probe.observations {
		if observation.authorization != "Bearer preserved-session" || observation.requestID != "mfa-mount-request" {
			t.Errorf("MFA forwarded metadata = %#v", observation)
		}
		if strings.Contains(observation.path, "/enrollments/") && observation.credentialID == "" {
			t.Errorf("MFA mount dropped credential_id for %s", observation.path)
		}
	}

	before := len(probe.observations)
	for _, path := range []string{
		"/v1/account/mfa/",
		"/v1/account/mfa-extra",
		"/v1/account/mfa/enrollments/11111111-1111-4111-8111-111111111111/activate/neighbor",
		"/v1/account/mfa/step-up-proofs/11111111-1111-4111-8111-111111111111/consume",
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("adjacent MFA route %s status = %d, want 404", path, response.Code)
		}
	}
	if len(probe.observations) != before {
		t.Fatalf("adjacent MFA routes reached package handler: observations=%#v", probe.observations[before:])
	}
}

func TestMFACanonicalContractAggregatesFrozenFragmentAndBearerOnlySecurity(t *testing.T) {
	paths := make([]string, 0, len(mfaMountRoutes()))
	for _, route := range mfaMountRoutes() {
		path := mfaMountTemplatePath(route.path)
		if len(paths) == 0 || paths[len(paths)-1] != path {
			paths = append(paths, path)
		}
	}
	sharedRuntimeIIRequireCanonicalAggregation(t, "control-mfa.openapi.yaml", paths)
	fragment := string(sharedRuntimeIIReadFile(t, "../../../../api/control-mfa.openapi.yaml"))
	if strings.Count(fragment, "security: [{bearerAuth: []}]") != 6 {
		t.Fatalf("MFA operation bearer security declarations = %d, want 6",
			strings.Count(fragment, "security: [{bearerAuth: []}]"))
	}
	if strings.Contains(fragment, "cdncaApiKey:") {
		t.Fatal("MFA contract exposes CdncaKey security")
	}
	sharedRuntimeIIRequireUniqueOperationIDs(t, []string{
		"getMyMFAStatus", "beginMyMFAEnrollment", "activateMyMFAEnrollment",
		"createMyMFAStepUpProof", "disableMyMFA", "resetMyMFA",
	})
}

func mfaMountTemplatePath(path string) string {
	return strings.Replace(path,
		"11111111-1111-4111-8111-111111111111", "{credential_id}", 1)
}

func mfaMountRoutes() []struct{ method, path string } {
	return []struct{ method, path string }{
		{http.MethodGet, "/v1/account/mfa"},
		{http.MethodPost, "/v1/account/mfa/enrollments"},
		{http.MethodPost, "/v1/account/mfa/enrollments/11111111-1111-4111-8111-111111111111/activate"},
		{http.MethodPost, "/v1/account/mfa/step-up-proofs"},
		{http.MethodPost, "/v1/account/mfa/disable"},
		{http.MethodPost, "/v1/account/mfa/reset"},
	}
}

func mfaSetMountedFactory(t *testing.T, config *Config, handler http.Handler, factoryErr error) {
	t.Helper()
	field := reflect.ValueOf(config).Elem().FieldByName("MFAHandlerFactory")
	sharedRuntimeIISetMountedFactory(t, field, "MFAHandlerFactory", handler, factoryErr)
}

func sharedRuntimeIISetMountedFactory(
	t *testing.T,
	field reflect.Value,
	name string,
	handler http.Handler,
	factoryErr error,
) {
	t.Helper()
	if !field.IsValid() {
		t.Fatalf("httpapi.Config is missing required public %s slot", name)
	}
	typeOfError := reflect.TypeOf((*error)(nil)).Elem()
	typeOfHandler := reflect.TypeOf((*http.Handler)(nil)).Elem()
	if !field.CanSet() || field.Kind() != reflect.Func || field.Type().NumIn() != 0 ||
		field.Type().NumOut() != 2 || field.Type().Out(0) != typeOfHandler ||
		!field.Type().Out(1).Implements(typeOfError) {
		t.Fatalf("httpapi.Config.%s type = %s, want func() (http.Handler, error)", name, field.Type())
	}
	factory := reflect.MakeFunc(field.Type(), func([]reflect.Value) []reflect.Value {
		handlerValue := reflect.Zero(typeOfHandler)
		if handler != nil {
			handlerValue = reflect.ValueOf(handler)
		}
		errorValue := reflect.Zero(typeOfError)
		if factoryErr != nil {
			errorValue = reflect.ValueOf(factoryErr)
		}
		return []reflect.Value{handlerValue, errorValue}
	})
	field.Set(factory)
}

func sharedRuntimeIIRequireCanonicalAggregation(t *testing.T, fragmentName string, paths []string) {
	t.Helper()
	canonical := string(sharedRuntimeIIReadFile(t, "../../../../api/openapi/v1/control.yaml"))
	fragmentPath := "../../../../api/" + fragmentName
	fragment := string(sharedRuntimeIIReadFile(t, fragmentPath))
	for _, path := range paths {
		pathLine := "  " + path + ":"
		if !strings.Contains(canonical, pathLine) {
			t.Errorf("canonical OpenAPI omits path %s", path)
		}
		ref := fmt.Sprintf("$ref: '../../%s#/paths/%s'", fragmentName, sharedRuntimeIIJSONPointerPath(path))
		if !strings.Contains(canonical, ref) {
			t.Errorf("canonical OpenAPI omits frozen path ref %s", ref)
		}
	}
	for section, names := range sharedRuntimeIIComponentNames(fragment) {
		for _, name := range names {
			ref := fmt.Sprintf("$ref: '../../%s#/components/%s/%s'", fragmentName, section, name)
			if !strings.Contains(canonical, ref) {
				t.Errorf("canonical OpenAPI omits frozen component ref %s", ref)
			}
		}
	}
}

func sharedRuntimeIIComponentNames(fragment string) map[string][]string {
	result := make(map[string][]string)
	inComponents := false
	section := ""
	for _, line := range strings.Split(fragment, "\n") {
		if line == "components:" {
			inComponents = true
			continue
		}
		if !inComponents {
			continue
		}
		if line != "" && line[0] != ' ' {
			break
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		separator := strings.IndexByte(trimmed, ':')
		if separator <= 0 {
			continue
		}
		name := trimmed[:separator]
		if indent == 2 {
			section = name
			continue
		}
		if indent == 4 && section != "" {
			if !strings.ContainsAny(name, " {}[]") {
				result[section] = append(result[section], name)
			}
		}
	}
	return result
}

func sharedRuntimeIIJSONPointerPath(path string) string {
	return strings.ReplaceAll(strings.ReplaceAll(path, "~", "~0"), "/", "~1")
}

func sharedRuntimeIIRequireUniqueOperationIDs(t *testing.T, expected []string) {
	t.Helper()
	counts := make(map[string]int)
	for _, path := range sharedRuntimeIIOpenAPIFiles {
		for _, line := range strings.Split(string(sharedRuntimeIIReadFile(t, path)), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "operationId:") {
				counts[strings.TrimSpace(strings.TrimPrefix(trimmed, "operationId:"))]++
			}
		}
	}
	for _, operationID := range expected {
		if counts[operationID] != 1 {
			t.Errorf("operationId %s occurrences = %d, want 1", operationID, counts[operationID])
		}
	}
	for operationID, count := range counts {
		if count != 1 {
			t.Errorf("operationId %s is not globally unique: occurrences=%d", operationID, count)
		}
	}
}

func sharedRuntimeIIReadFile(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return value
}
