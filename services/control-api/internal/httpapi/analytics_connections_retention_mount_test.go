package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type typedNilAnalyticsConnectionsRetentionHandler struct{}

func (*typedNilAnalyticsConnectionsRetentionHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestAnalyticsConnectionsRetentionRoutesAreDisabledByDefault(t *testing.T) {
	for _, path := range []string{
		"/v1/analytics/connections/retention",
		"/v1/admin/analytics/connections/retention",
	} {
		response := httptest.NewRecorder()
		New(nil, nil, Config{}).Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("disabled retention route %s status = %d, want 404", path, response.Code)
		}
	}
}

func TestAnalyticsConnectionsRetentionMountForwardsOnlyExactRoutesAndRequestID(t *testing.T) {
	var forwarded []string
	probe := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		forwarded = append(forwarded, request.Method+" "+request.URL.Path)
		if request.Header.Get("X-Request-ID") != "retention-mount-test" {
			t.Errorf("forwarded request ID = %q", request.Header.Get("X-Request-ID"))
		}
		response.WriteHeader(http.StatusNoContent)
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnalyticsConnectionsRetentionHandler: probe})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/v1/analytics/connections/retention",
		"/v1/admin/analytics/connections/retention",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("X-Request-ID", "retention-mount-test")
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("retention route %s status = %d, want 204", path, response.Code)
		}
	}
	before := len(forwarded)
	for _, path := range []string{
		"/v1/analytics/connections/retention/",
		"/v1/analytics/connections/retention/history",
		"/v1/admin/analytics/connections/retention-extra",
		"/v1/analytics/connections",
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code == http.StatusNoContent {
			t.Errorf("adjacent route %s reached retention handler", path)
		}
	}
	if len(forwarded) != before {
		t.Fatalf("adjacent routes were forwarded: %#v", forwarded[before:])
	}
}

func TestAnalyticsConnectionsRetentionMountRejectsTypedNilHandler(t *testing.T) {
	var handler *typedNilAnalyticsConnectionsRetentionHandler
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnalyticsConnectionsRetentionHandler: handler})
	if api.InitializationError() == nil {
		t.Fatal("typed nil retention handler was accepted")
	}
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/analytics/connections/retention", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("failed retention mount status = %d, want 404", response.Code)
	}
}

func TestAnalyticsConnectionsRetentionOpenAPIIsMountedWithBoundedStableContract(t *testing.T) {
	fragment := readRetentionOpenAPI(t, "control-analytics.openapi.yaml")
	if strings.Contains(fragment, "not yet mounted") {
		t.Fatal("analytics OpenAPI still declares the handler unmounted")
	}
	for _, path := range []string{
		"/v1/analytics/connections/retention:",
		"/v1/admin/analytics/connections/retention:",
	} {
		section := retentionOpenAPISection(t, fragment, path)
		for _, required := range []string{
			"bearerAuth", "SubscriptionID", "From", "To", "Limit",
			"'400'", "'401'", "'403'", "'408'", "'502'", "'503'",
		} {
			if !strings.Contains(section, required) {
				t.Errorf("OpenAPI section %s omitted %q", path, required)
			}
		}
	}
	root := readRetentionOpenAPI(t, filepath.Join("openapi", "v1", "control.yaml"))
	for _, required := range []string{
		"/v1/analytics/connections/retention:",
		"../../control-analytics.openapi.yaml#/paths/~1v1~1analytics~1connections~1retention",
		"/v1/admin/analytics/connections/retention:",
		"../../control-analytics.openapi.yaml#/paths/~1v1~1admin~1analytics~1connections~1retention",
	} {
		if !strings.Contains(root, required) {
			t.Errorf("canonical control OpenAPI omitted %q", required)
		}
	}
}

func readRetentionOpenAPI(t *testing.T, relative string) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "api", relative)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(contents)
}

func retentionOpenAPISection(t *testing.T, document, path string) string {
	t.Helper()
	start := strings.Index(document, "  "+path)
	if start < 0 {
		t.Fatalf("OpenAPI omitted path %s", path)
	}
	rest := document[start+len("  "+path):]
	if next := strings.Index(rest, "\n  /"); next >= 0 {
		rest = rest[:next]
	}
	return rest
}
