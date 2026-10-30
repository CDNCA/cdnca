package nodesshinstall

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/google/uuid"
)

func TestConsoleOrigin(t *testing.T) {
	for origin, want := range map[string]string{
		"https://console.example.com":      "https://console.example.com",
		"https://console.example.com:8443": "https://console.example.com:8443",
		"http://console.example.com":       "",
		"":                                 "",
		"null":                             "",
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/admin/nodes/ssh-installs", nil)
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		got, ok := consoleOrigin(request)
		if got != want || ok != (want != "") {
			t.Errorf("Origin %q = %q %v, want %q", origin, got, ok, want)
		}
	}
}

func TestHandlerRequiresPlatformNodesManage(t *testing.T) {
	service := &Service{}
	sessions := map[string]identity.AuthenticatedSession{
		"tenant":   {SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant", Permissions: []string{PermissionManage}}},
		"readonly": {SessionID: uuid.New(), Principal: identity.Principal{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform", Permissions: []string{"nodes.read"}}},
	}
	handler, err := NewHandler(service, func(_ context.Context, raw string) (identity.AuthenticatedSession, error) {
		session, ok := sessions[raw]
		if !ok {
			return identity.AuthenticatedSession{}, errors.New("unknown")
		}
		return session, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for token, want := range map[string]int{"": http.StatusUnauthorized, "bogus": http.StatusUnauthorized,
		"tenant": http.StatusForbidden, "readonly": http.StatusForbidden} {
		request := httptest.NewRequest(http.MethodPost, "/v1/admin/nodes/ssh-installs", strings.NewReader(`{}`))
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != want || response.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("token %q: status %d, want %d", token, response.Code, want)
		}
	}
}
