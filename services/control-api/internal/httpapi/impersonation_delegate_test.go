package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/impersonationhttp"
)

// fix-imperson: a refused impersonation cookie must never fall back to the
// administrator's Bearer, and the impersonation/auth session routes keep the
// original request.
func TestImpersonationDelegateRefusedCookieDropsAdministratorBearer(t *testing.T) {
	tokens, err := identity.NewTokenManager(string(bytes.Repeat([]byte{0x61}, 32)), 3600e9)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(identity.NewStore(nil), tokens, 3600e9)
	if err != nil {
		t.Fatal(err)
	}
	actions := []string{}
	authorizer := impersonationMountAuthorizer(func(_ *http.Request, action string) (impersonationhttp.AuthorizedSession, error) {
		actions = append(actions, action)
		return impersonationhttp.AuthorizedSession{}, impersonationhttp.ErrUnauthenticated
	})
	api := New(nil, service, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), ImpersonationHandlerFactory: func(impersonationhttp.AuthenticateFunc) (http.Handler, ImpersonationSessionAuthorizer, error) {
		return http.NotFoundHandler(), authorizer, nil
	}})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	var seen []string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusNoContent)
	})
	for _, test := range []struct {
		path, want string
		calls      int
	}{
		{"/v1/dashboard", "", 1},
		{"/v1/tickets", "", 2},
		{"/v1/auth/refresh", "Bearer admin-token", 2},
		{"/v1/admin/impersonation/grants/x/revocations", "Bearer admin-token", 2},
		{"/health/ready", "Bearer admin-token", 2},
	} {
		seen = nil
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		request.Header.Set("Authorization", "Bearer admin-token")
		request.AddCookie(&http.Cookie{Name: impersonationhttp.CookieName, Value: "opaque"})
		// Wrapping twice (main.go wraps the outer chain, Handler() the inner)
		// authorizes the cookie once.
		api.WithImpersonationDelegate(api.WithImpersonationDelegate(next)).ServeHTTP(httptest.NewRecorder(), request)
		if len(seen) != 1 || seen[0] != test.want || len(actions) != test.calls {
			t.Fatalf("%s authorization=%q calls=%d", test.path, seen, len(actions))
		}
	}
	if actions[0] != "identity.impersonation.use" {
		t.Fatalf("action=%q", actions[0])
	}
	// Without the cookie the request is unchanged.
	seen = nil
	request := httptest.NewRequest(http.MethodGet, "/v1/dashboard", nil)
	request.Header.Set("Authorization", "Bearer admin-token")
	api.WithImpersonationDelegate(next).ServeHTTP(httptest.NewRecorder(), request)
	if len(seen) != 1 || seen[0] != "Bearer admin-token" {
		t.Fatalf("plain request authorization=%q", seen)
	}
}
