package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fix-e1 #3: without the account login runtime, GET /v1/auth/login-methods
// answers 200 with every method off (it 404ed on every sign-in page load).
func TestLoginMethodsWithoutLoginRuntimeOffersNothing(t *testing.T) {
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}).Handler()
	response := httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/auth/login-methods", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body)
	}
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"registration_enabled", "email_enabled", "sms_enabled"} {
		if body.Data[key] != false {
			t.Errorf("%s = %v, want false", key, body.Data[key])
		}
	}
}

// With the runtime mounted the route stays with its handler.
func TestLoginMethodsWithLoginRuntimeForwards(t *testing.T) {
	called := false
	probe := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		called = true
		response.WriteHeader(http.StatusNoContent)
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		AccountLoginHandlerFactory: func() (http.Handler, error) { return probe, nil }}).Handler()
	response := httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/auth/login-methods", nil))
	if !called || response.Code != http.StatusNoContent {
		t.Fatalf("called=%v status=%d", called, response.Code)
	}
}
