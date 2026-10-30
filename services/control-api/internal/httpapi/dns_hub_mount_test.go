package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnshubhttp"
)

// Every dnshubhttp route reaches the mounted handler with the caller's
// Authorization; without the handler (no DNS credential cipher) the routes
// stay closed.
func TestDNSHubMountForwardsEveryPattern(t *testing.T) {
	var observed []string
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed = append(observed, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		DNSHubHandlerFactory: func() (http.Handler, error) { return probe, nil }})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	for _, pattern := range dnshubhttp.Patterns {
		method, path, _ := strings.Cut(pattern, " ")
		path = strings.NewReplacer("{provider_id}", "11111111-1111-1111-1111-111111111111",
			"{apex}", "example.com", "{record_ref}", "r1.cg").Replace(path)
		request := httptest.NewRequest(method, path, nil)
		request.Header.Set("Authorization", "Bearer preserved")
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Errorf("%s %s status = %d", method, path, response.Code)
		}
	}
	if len(observed) != len(dnshubhttp.Patterns) {
		t.Fatalf("observed %v", observed)
	}
	for _, line := range observed {
		if !strings.HasSuffix(line, " Bearer preserved") {
			t.Fatalf("authorization not forwarded: %s", line)
		}
	}
	closed := httptest.NewRecorder()
	New(nil, nil, Config{}).Handler().ServeHTTP(closed, httptest.NewRequest(http.MethodGet, "/v1/dns/hub/domains", nil))
	if closed.Code != http.StatusNotFound {
		t.Fatalf("unmounted hub status = %d, want 404", closed.Code)
	}
}
