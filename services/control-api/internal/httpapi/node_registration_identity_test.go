package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/node"
)

// fz-x13: the identity recovery endpoint shares the registration rate limit
// (per source IP) and maps a miss to 404 node_identity_not_found.
func TestNodeRegistrationIdentityRateLimitAndErrors(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	server := &Server{nodes: node.NewService(nil), nodeRegistrationLimiter: newRegistrationLimiter(func() time.Time { return now })}
	handler := http.NewServeMux()
	handler.HandleFunc("POST /v1/node-registrations", server.handleRegisterNode)
	handler.HandleFunc("POST /v1/node-registrations/identity", server.handleRecoverNodeRegistrationIdentity)
	post := func(path string) *httptest.ResponseRecorder {
		fields := map[string]string{
			"credential":          "nrk1." + strings.Repeat("0", 32) + "." + strings.Repeat("A", 43),
			"machine_fingerprint": strings.Repeat("ab", 32),
		}
		if strings.HasSuffix(path, "/identity") {
			fields["csr_sha256"] = strings.Repeat("cd", 32)
		}
		body, _ := json.Marshal(fields)
		request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		request.RemoteAddr = "198.51.100.7:40000"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}
	// Registration and recovery draw on one window: half the budget each.
	for index := range registrationLimitPerSource {
		path := "/v1/node-registrations/identity"
		if index%2 == 1 {
			path = "/v1/node-registrations"
		}
		if response := post(path); response.Code != http.StatusServiceUnavailable {
			t.Fatalf("attempt %d %s = %d %s, want 503 (self-registration not configured)", index, path, response.Code, response.Body)
		}
	}
	limited := post("/v1/node-registrations/identity")
	if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") != "60" ||
		!strings.Contains(limited.Body.String(), "node_registration_rate_limited") {
		t.Fatalf("over limit = %d %q %s", limited.Code, limited.Header().Get("Retry-After"), limited.Body)
	}

	for err, want := range map[error]string{
		fmt.Errorf("wrapped: %w", node.ErrRegisteredIdentityNotFound):    "404 node_identity_not_found",
		fmt.Errorf("wrapped: %w", node.ErrInvalidRegistrationCredential): "401 invalid_registration_credential",
		node.ErrInvalidInput: "400 validation_error",
	} {
		recorder := httptest.NewRecorder()
		server.writeNodeRegistrationError(recorder, httptest.NewRequest(http.MethodPost, "/v1/node-registrations/identity", nil), err)
		var envelope testErrorEnvelope
		_ = json.Unmarshal(recorder.Body.Bytes(), &envelope)
		if got := fmt.Sprintf("%d %s", recorder.Code, envelope.Error.Code); got != want {
			t.Errorf("%v -> %s, want %s", err, got, want)
		}
	}
}
