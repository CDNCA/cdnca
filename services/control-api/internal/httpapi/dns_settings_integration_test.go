package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnssettings"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

func TestPlatformDNSSettingsReadUsesScopeDefaultAndRBAC(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	bootstrap, err := store.BootstrapPlatformUser(
		t.Context(), "dns-settings-admin", "DNS Settings Admin", passwordHash, "dns-settings-bootstrap",
	)
	if err != nil {
		t.Fatal(err)
	}
	insertTestUser(t, pool, bootstrap.ScopeID, "dns-settings-denied", "DNS Settings Denied", passwordHash, "active")

	tokens, err := identity.NewTokenManager("dns-settings-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure: false,
		APIKeyPepper: bytes.Repeat([]byte{0x64}, 32),
	}).Handler())
	t.Cleanup(server.Close)

	admin, _ := loginOK(t, server.Client(), server.URL, "dns-settings-admin")
	response := doRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/dns/settings", nil, nil, admin.AccessToken)
	var settings dnssettings.Settings
	decodeResponse(t, response, http.StatusOK, &settings)
	if etag := response.Header.Get("ETag"); etag != `"1"` {
		t.Fatalf("ETag = %q, want %q", etag, `"1"`)
	}
	response.Body.Close()
	if settings.ScopeID != bootstrap.ScopeID || settings.TTL != dnssettings.DefaultTTL || settings.Revision != 1 || settings.UpdatedAt != nil {
		t.Fatalf("platform DNS settings default = %+v", settings)
	}

	for _, request := range []struct {
		name   string
		method string
		path   string
		body   any
		key    string
		etag   string
	}{
		{name: "update", method: http.MethodPatch, path: "/v1/dns/settings", body: map[string]any{"ttl": 300}, key: "platform-dns-update", etag: `"1"`},
		{name: "repair", method: http.MethodPost, path: "/v1/dns/settings/repair", body: map[string]any{}, key: "platform-dns-repair"},
	} {
		t.Run("platform write remains tenant scoped "+request.name, func(t *testing.T) {
			response := siteRequest(t, server.Client(), request.method, server.URL+request.path,
				request.body, admin.AccessToken, request.key, request.etag, "platform-dns-"+request.name)
			assertError(t, response, http.StatusServiceUnavailable, "dns_settings_unavailable", "platform-dns-"+request.name)
			response.Body.Close()
		})
	}

	denied, _ := loginOK(t, server.Client(), server.URL, "dns-settings-denied")
	response = doRequest(t, server.Client(), http.MethodGet, server.URL+"/v1/dns/settings", nil, nil, denied.AccessToken, "dns-settings-denied")
	assertError(t, response, http.StatusForbidden, "permission_denied", "dns-settings-denied")
	response.Body.Close()
}
