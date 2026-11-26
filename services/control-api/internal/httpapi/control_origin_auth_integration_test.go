package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// CDN-ORIGIN-AUTH-HINT through the real handler chain: the console nginx is
// the trusted proxy (X-Forwarded-For is what it wrote), a CDN header passes
// through, X-Cdnca-Origin-Verified is believed only while origin-auth.conf
// exists. GET /v1/admin/control-origin-auth is for platform identities with
// system_configuration.read.
func TestControlOriginAuthStatusThroughTheConsole(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	bootstrap, err := store.BootstrapPlatformUser(t.Context(), "origin-admin", "Origin Admin", passwordHash, "origin-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager("origin-auth-integration-secret-at-least-thirty-two", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identityService.CreateUser(t.Context(), identity.Actor{
		UserID: bootstrap.UserID, ScopeID: bootstrap.ScopeID, ScopeKind: "platform",
	}, identity.CreateUserInput{
		Username: "origin-tenant", Password: testPassword, Fields: identity.UserFields{DisplayName: "Origin Tenant"},
		Role: identity.UserRoleOwner, IdempotencyKey: "origin-create-tenant", RequestID: "origin-create-tenant",
	}); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(t.TempDir(), "origin-auth.conf")
	api := New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		APIKeyTrustedProxyCIDRs: []string{"127.0.0.1/32"}, ControlOriginAuthConf: conf})
	if err := api.InitializationError(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.Handler())
	t.Cleanup(server.Close)
	// sign in as the console nginx forwards it: X-Forwarded-For set
	login := func(username string) string {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"username": username, "password": testPassword})
		request, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/auth/login", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Forwarded-For", "192.0.2.50")
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result testAuthResponse
		if response.StatusCode != http.StatusOK || json.NewDecoder(response.Body).Decode(&result) != nil {
			t.Fatalf("login %s: %d", username, response.StatusCode)
		}
		return result.AccessToken
	}
	admin, tenant := login("origin-admin"), login("origin-tenant")
	read := func(token string, headers map[string]string) (int, controlOriginAuthStatus) {
		t.Helper()
		request, _ := http.NewRequest(http.MethodGet, server.URL+"/v1/admin/control-origin-auth", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("X-Forwarded-For", "104.23.1.10")
		for name, value := range headers {
			request.Header.Set(name, value)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var status controlOriginAuthStatus
		if response.StatusCode == http.StatusOK {
			if response.Header.Get("Cache-Control") != "no-store" || json.NewDecoder(response.Body).Decode(&status) != nil {
				t.Fatal("status response")
			}
		}
		return response.StatusCode, status
	}
	verified := map[string]string{"X-Cdnca-Origin-Verified": "1"}

	// direct access: no hint, nothing confirmed
	if code, status := read(admin, nil); code != http.StatusOK || status.CDNWithoutOriginAuth || status.OriginAuthEnabled ||
		status.VisitorIPConfirmed || status.LastSeenAt != nil {
		t.Fatalf("direct access: %d %+v", code, status)
	}
	if code, _ := read(tenant, nil); code != http.StatusForbidden {
		t.Fatalf("tenant: %d", code)
	}
	// through a CDN without origin authentication; a client's own X-Cdnca-Origin-Verified is not believed
	if code, status := read(admin, map[string]string{"CF-Connecting-IP": "203.0.113.9", "X-Cdnca-Origin-Verified": "1"}); code != http.StatusOK ||
		!status.CDNWithoutOriginAuth || status.VisitorIPConfirmed || status.Header != "CF-Connecting-IP" || status.LastSeenAt == nil {
		t.Fatalf("CDN without origin authentication: %d %+v", code, status)
	}
	// only the generic forwarding headers: visibly not confirmed without origin authentication ...
	if code, status := read(admin, verified); code != http.StatusOK || status.VisitorIPConfirmed || status.OriginAuthEnabled {
		t.Fatalf("generic headers, no origin authentication: %d %+v", code, status)
	}
	// ... and confirmed with it (the conf check is cached for 30 seconds; the test drops the cache)
	if err := os.WriteFile(conf, []byte("# real-ip-header: True-Client-IP\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	api.controlOriginAuth.confCheckedAt.Store(0)
	if code, status := read(admin, verified); code != http.StatusOK || !status.OriginAuthEnabled || !status.VisitorIPConfirmed ||
		status.CDNWithoutOriginAuth || status.LastConfirmedAt == nil {
		t.Fatalf("generic headers, origin authentication: %d %+v", code, status)
	}
	// True-Client-IP chosen and the key matched: a vendor header on the request does not raise the hint again
	if code, status := read(admin, map[string]string{"True-Client-IP": "203.0.113.9", "CF-Connecting-IP": "203.0.113.9",
		"X-Cdnca-Origin-Verified": "1"}); code != http.StatusOK || status.CDNWithoutOriginAuth || !status.VisitorIPConfirmed {
		t.Fatalf("matched with a vendor header: %d %+v", code, status)
	}
	// key matched but the chosen header gave no visitor address (nginx sends key_only), no vendor header either
	if code, status := read(admin, map[string]string{"X-Cdnca-Origin-Verified": "key_only"}); code != http.StatusOK ||
		!status.CDNWithoutOriginAuth || !status.KeyOnly || status.VisitorIPConfirmed || status.Header != "" ||
		status.RealIPHeader != "True-Client-IP" {
		t.Fatalf("key only: %d %+v", code, status)
	}
	// a CDN request without the key (nginx sends 0) raises it
	if code, status := read(admin, map[string]string{"CF-Connecting-IP": "203.0.113.9", "X-Cdnca-Origin-Verified": "0"}); code != http.StatusOK ||
		!status.CDNWithoutOriginAuth || status.VisitorIPConfirmed || status.KeyOnly {
		t.Fatalf("key not matched: %d %+v", code, status)
	}
}
