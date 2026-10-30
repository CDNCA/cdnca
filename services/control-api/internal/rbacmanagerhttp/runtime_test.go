package rbacmanagerhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRuntimeDisabledReturnsNotFound(t *testing.T) {
	t.Parallel()

	handler, err := NewRuntimeHandler(RuntimeConfig{}, RuntimeDependencies{})
	if err != nil {
		t.Fatalf("disabled runtime: %v", err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/custom-rbac/roles", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestRuntimeEnabledRejectsIncompleteDependencies(t *testing.T) {
	t.Parallel()

	handler, err := NewRuntimeHandler(RuntimeConfig{Enabled: true, CursorKey: make([]byte, 32)}, RuntimeDependencies{})
	if err == nil || handler != nil {
		t.Fatalf("enabled runtime = (%v, %v), want fail-closed dependency error", handler, err)
	}
}

func TestRuntimeAuthenticatorRejectsNonBearerTransports(t *testing.T) {
	t.Parallel()

	authenticator := runtimeSessionAuthenticator{}
	for _, header := range []string{"", "CdncaKey key.secret", "Bearer one,Bearer two", "Basic value"} {
		request := httptest.NewRequest(http.MethodGet, "/v1/custom-rbac/roles", nil)
		if header != "" {
			request.Header.Set("Authorization", header)
		}
		if _, err := authenticator.Authenticate(request); err == nil {
			t.Fatalf("Authorization %q was accepted", header)
		}
	}
}
