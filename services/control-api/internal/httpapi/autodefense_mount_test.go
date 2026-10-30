package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The auto defense handler receives both prefixes when its factory is set,
// and the routes are absent otherwise.
func TestAutoDefenseMountForwardsBothPrefixes(t *testing.T) {
	var forwarded []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = append(forwarded, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		AutoDefenseHandlerFactory: func() (http.Handler, error) { return handler, nil }})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/security/autodefense/sites", "/v1/admin/security/autodefense/platform-settings"} {
		response := httptest.NewRecorder()
		api.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusTeapot {
			t.Fatalf("%s status=%d, want forwarded", path, response.Code)
		}
	}
	if len(forwarded) != 2 {
		t.Fatalf("forwarded = %v", forwarded)
	}

	unmounted := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)})
	response := httptest.NewRecorder()
	unmounted.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/security/autodefense/sites", nil))
	if response.Code == http.StatusTeapot || response.Code == http.StatusOK {
		t.Fatalf("unmounted status=%d", response.Code)
	}
}
