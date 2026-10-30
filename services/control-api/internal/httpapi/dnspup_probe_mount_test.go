package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/dnspupprobe"
)

// Every dnspupprobe.Patterns route reaches the dnspup probe handler (the node
// monitoring block 404ed when server.go forwarded only the first three).
func TestDNSPupProbeMountForwardsEveryPattern(t *testing.T) {
	for _, pattern := range dnspupprobe.Patterns {
		method, path, _ := strings.Cut(pattern, " ")
		called := false
		probe := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			called = true
			response.WriteHeader(http.StatusNoContent)
		})
		api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
			ProbeDNSPupHandlerFactory: func() (http.Handler, error) { return probe, nil }}).Handler()
		response := httptest.NewRecorder()
		api.ServeHTTP(response, httptest.NewRequest(method, path, nil))
		if !called || response.Code != http.StatusNoContent {
			t.Errorf("%s: called=%v status=%d", pattern, called, response.Code)
		}
	}
}
