package accountregistrationchallenge

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// with SecretFunc the secret is read on every check, so
// a secret saved on the settings page applies without a restart; no secret
// yet means the human check is unavailable, not invalid.
func TestTurnstileVerifierReadsSecretFuncPerCheck(t *testing.T) {
	var mu sync.Mutex
	var current string
	var currentErr error = errors.New("not configured")
	server, caFile := newTurnstileTestServer(t, tls.VersionTLS13, func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		values, _ := url.ParseQuery(string(body))
		writer.Header().Set("Content-Type", "application/json")
		if values.Get("secret") != "page-saved-turnstile-secret" {
			_, _ = writer.Write([]byte(`{"success":false,"error-codes":["invalid-input-secret"]}`))
			return
		}
		_, _ = writer.Write([]byte(`{"success":true,"hostname":"register.example","action":"register","challenge_ts":"2026-08-08T08:59:00Z"}`))
	})
	config := TurnstileConfig{Endpoint: server.URL, CAFile: caFile,
		SecretFunc: func(context.Context) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			return current, currentErr
		},
		ExpectedHostname: "register.example", ExpectedAction: "register", Timeout: time.Second, MaxResponseBytes: 4096}
	verifier, err := NewTurnstileVerifier(config)
	if err != nil {
		t.Fatal(err)
	}
	request := HumanVerification{Token: strings.Repeat("v", 32), Source: "192.0.2.10", IdempotencyKey: "human-attempt-1"}
	if err := verifier.Verify(t.Context(), request); err != ErrHumanUnavailable {
		t.Fatalf("no secret: %v, want ErrHumanUnavailable", err)
	}
	mu.Lock()
	current, currentErr = "page-saved-turnstile-secret", nil
	mu.Unlock()
	if err := verifier.Verify(t.Context(), request); err != nil {
		t.Fatalf("page secret: %v", err)
	}
	config.Secret = "turnstile-secret-value"
	if _, err := NewTurnstileVerifier(config); err != ErrInvalidConfig {
		t.Fatalf("Secret and SecretFunc together: %v, want ErrInvalidConfig", err)
	}
}
