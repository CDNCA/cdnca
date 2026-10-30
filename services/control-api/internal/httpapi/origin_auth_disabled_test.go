package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fix-e1 #2: origin authentication off answers feature_disabled, not a 404 the
// pages showed as "credential/rule not found in this tenant".
func TestOriginAuthRoutesAnswerFeatureDisabledWhenOff(t *testing.T) {
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)}).Handler()
	scope := "/v1/tenant-scopes/11111111-1111-4111-8111-111111111111/origin-auth"
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, scope + "/credentials"},
		{http.MethodGet, scope + "/rules"},
		{http.MethodPost, scope + "/edge-publications"},
		{http.MethodGet, scope + "/edge-publications/22222222-2222-4222-8222-222222222222"},
	} {
		response := httptest.NewRecorder()
		api.ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		var body errorEnvelope
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil ||
			response.Code != http.StatusServiceUnavailable || body.Error.Code != "feature_disabled" {
			t.Errorf("%s %s: status=%d body=%s", route.method, route.path, response.Code, response.Body)
		}
	}
}

func TestOriginAuthRoutesForwardWhenOn(t *testing.T) {
	called := false
	probe := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		called = true
		response.WriteHeader(http.StatusNoContent)
	})
	api := New(nil, nil, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		OriginAuthHandlerFactory: func() (http.Handler, error) { return probe, nil }}).Handler()
	response := httptest.NewRecorder()
	api.ServeHTTP(response, httptest.NewRequest(http.MethodGet,
		"/v1/tenant-scopes/11111111-1111-4111-8111-111111111111/origin-auth/credentials", nil))
	if !called || response.Code != http.StatusNoContent {
		t.Fatalf("called=%v status=%d", called, response.Code)
	}
}
