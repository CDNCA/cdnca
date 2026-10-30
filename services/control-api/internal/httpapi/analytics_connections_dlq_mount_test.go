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

type typedNilAnalyticsConnectionsDLQHandler struct{}

func (*typedNilAnalyticsConnectionsDLQHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestAnalyticsConnectionsDLQRoutesAreDisabledByDefault(t *testing.T) {
	for _, path := range []string{
		"/v1/analytics/connections/dead-letters",
		"/v1/analytics/connections/dead-letters/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"/v1/admin/analytics/connections/dead-letters",
		"/v1/admin/analytics/connections/dead-letters/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		response := httptest.NewRecorder()
		New(nil, nil, Config{}).Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("disabled DLQ route %s status = %d, want 404", path, response.Code)
		}
	}
}

func TestAnalyticsConnectionsDLQMountForwardsOnlyExactRoutesAndRequestID(t *testing.T) {
	var forwarded []string
	probe := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		forwarded = append(forwarded, request.Method+" "+request.URL.Path)
		if request.Header.Get("X-Request-ID") != "dlq-mount-test" {
			t.Errorf("forwarded request ID = %q", request.Header.Get("X-Request-ID"))
		}
		response.WriteHeader(http.StatusNoContent)
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnalyticsConnectionsDLQHandler: probe})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/v1/analytics/connections/dead-letters",
		"/v1/analytics/connections/dead-letters/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"/v1/admin/analytics/connections/dead-letters",
		"/v1/admin/analytics/connections/dead-letters/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.Header.Set("X-Request-ID", "dlq-mount-test")
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("DLQ route %s status = %d, want 204", path, response.Code)
		}
	}
	before := len(forwarded)
	for _, path := range []string{
		"/v1/analytics/connections/dead-letters/",
		"/v1/analytics/connections/dead-letters/extra/part",
		"/v1/admin/analytics/connections/dead-letters-extra",
		"/v1/analytics/connections",
	} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code == http.StatusNoContent {
			t.Errorf("adjacent route %s reached DLQ handler", path)
		}
	}
	if len(forwarded) != before {
		t.Fatalf("adjacent routes were forwarded: %#v", forwarded[before:])
	}
}

func TestAnalyticsConnectionsDLQMountRejectsTypedNilHandler(t *testing.T) {
	var handler *typedNilAnalyticsConnectionsDLQHandler
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnalyticsConnectionsDLQHandler: handler})
	if api.InitializationError() == nil {
		t.Fatal("typed nil DLQ handler was accepted")
	}
	response := httptest.NewRecorder()
	api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/analytics/connections/dead-letters", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("failed DLQ mount status = %d, want 404", response.Code)
	}
}

func TestAnalyticsConnectionsDLQOpenAPIIsMountedWithBoundedStableContract(t *testing.T) {
	fragment := readDLQOpenAPI(t, "control-analytics.openapi.yaml")
	for _, path := range []string{
		"/v1/analytics/connections/dead-letters:",
		"/v1/analytics/connections/dead-letters/{dead_letter_id}:",
		"/v1/admin/analytics/connections/dead-letters:",
		"/v1/admin/analytics/connections/dead-letters/{dead_letter_id}:",
	} {
		section := dlqOpenAPISection(t, fragment, path)
		requiredFields := []string{"bearerAuth", "'400'", "'401'", "'403'", "'404'", "'408'", "'502'", "'503'"}
		if !strings.Contains(path, "{dead_letter_id}") {
			requiredFields = append(requiredFields, "DeadLetterLimit", "DeadLetterAfterSequence")
		} else {
			requiredFields = append(requiredFields, "DeadLetterID")
		}
		for _, required := range requiredFields {
			if !strings.Contains(section, required) {
				t.Errorf("OpenAPI section %s omitted %q", path, required)
			}
		}
	}
	root := readDLQOpenAPI(t, filepath.Join("openapi", "v1", "control.yaml"))
	for _, required := range []string{
		"/v1/analytics/connections/dead-letters:",
		"../../control-analytics.openapi.yaml#/paths/~1v1~1analytics~1connections~1dead-letters",
		"/v1/analytics/connections/dead-letters/{dead_letter_id}:",
		"../../control-analytics.openapi.yaml#/paths/~1v1~1analytics~1connections~1dead-letters~1{dead_letter_id}",
		"/v1/admin/analytics/connections/dead-letters:",
		"../../control-analytics.openapi.yaml#/paths/~1v1~1admin~1analytics~1connections~1dead-letters",
		"/v1/admin/analytics/connections/dead-letters/{dead_letter_id}:",
		"../../control-analytics.openapi.yaml#/paths/~1v1~1admin~1analytics~1connections~1dead-letters~1{dead_letter_id}",
	} {
		if !strings.Contains(root, required) {
			t.Errorf("canonical control OpenAPI omitted %q", required)
		}
	}
}

func readDLQOpenAPI(t *testing.T, relative string) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "api", relative)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(contents)
}

func dlqOpenAPISection(t *testing.T, document, path string) string {
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
