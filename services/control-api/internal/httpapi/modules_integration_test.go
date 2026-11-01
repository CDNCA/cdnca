package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

const (
	communityModule = "module.icp"
	moduleUnknown   = "module.community_probe_unknown"
)

// Community edition: modules come from the built-in community entitlement,
// not a signed lease. GET /v1/modules lists the community modules for platform
// and tenant sessions alike; a module route answers for a community module and
// 403 entitlement_feature_denied (audited as feature_missing) for a commercial
// module or an unknown code.
func TestModuleEntitlementHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	if _, err := identityStore.BootstrapPlatformUser(context.Background(), "moduleadmin", "Module Admin",
		passwordHash, "module-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tenant := insertSiteTenant(t, pool, "module-tenant", "module-user", "Module User", passwordHash)
	tokens, err := identity.NewTokenManager("module-test-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	api := New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32)})
	mux := http.NewServeMux()
	mux.Handle("/v1/modules", api.Handler())
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.Handle("/v1/probe/community", api.withRequestID(api.requireModule(communityModule, "module_probe", "module_probe.use", ok)))
	mux.Handle("/v1/probe/commercial", api.withRequestID(api.requireModule(entitlement.ModuleAutoDefense, "module_probe", "module_probe.use", ok)))
	mux.Handle("/v1/probe/unknown", api.withRequestID(api.requireModule(moduleUnknown, "module_probe", "module_probe.use", ok)))
	mux.Handle("/", api.Handler())
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	client := server.Client()
	admin, _ := loginOK(t, client, server.URL, "moduleadmin")
	user := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID)

	listModules := func(token string) modulesResponse {
		t.Helper()
		request, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/modules", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("GET /v1/modules = %d %s", response.StatusCode, readBody(response.Body))
		}
		var body modulesResponse
		if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	probe := func(token, path, requestID string) *http.Response {
		t.Helper()
		request, _ := http.NewRequest(http.MethodGet, server.URL+path, nil)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("X-Request-ID", requestID)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	unauthenticated, err := client.Get(server.URL + "/v1/modules")
	if err != nil {
		t.Fatal(err)
	}
	if unauthenticated.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /v1/modules without session = %d", unauthenticated.StatusCode)
	}
	unauthenticated.Body.Close()
	for _, token := range []string{admin.AccessToken, user.AccessToken} {
		got := listModules(token)
		if got.Status != "valid" || !slices.Contains(got.Modules, communityModule) ||
			slices.Contains(got.Modules, entitlement.ModuleAutoDefense) || slices.Contains(got.Modules, moduleUnknown) {
			t.Fatalf("community modules = %+v", got)
		}
	}
	if response := probe(user.AccessToken, "/v1/probe/community", "module-probe-community"); response.StatusCode != http.StatusNoContent {
		t.Fatalf("community module probe = %d %s", response.StatusCode, readBody(response.Body))
	}
	for _, denied := range []struct{ path, requestID string }{
		{"/v1/probe/commercial", "module-probe-commercial"}, {"/v1/probe/unknown", "module-probe-unknown"},
	} {
		response := probe(user.AccessToken, denied.path, denied.requestID)
		assertError(t, response, http.StatusForbidden, "entitlement_feature_denied", denied.requestID)
		response.Body.Close()
		var reason string
		if err := pool.QueryRow(t.Context(), `SELECT payload->>'reason' FROM audit_events
			WHERE action='entitlement.guard.reject' AND request_id=$1`, denied.requestID).Scan(&reason); err != nil ||
			reason != "feature_missing" {
			t.Fatalf("%s denial audit reason = %q, %v", denied.path, reason, err)
		}
	}
}
