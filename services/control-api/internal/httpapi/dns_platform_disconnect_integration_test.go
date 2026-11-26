package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

// 断开 DNS 服务商 removes the saved
// credentials, disables every tenant copy and keeps the CNAME domains.
func TestPlatformDNSDisconnectHTTPFlow(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	store := identity.NewStore(pool)
	if _, err := store.BootstrapPlatformUser(t.Context(), "dns-disconnect-admin", "DNS Disconnect Admin", passwordHash,
		"dns-disconnect-bootstrap"); err != nil {
		t.Fatal(err)
	}
	tenantA := insertDNSTenant(t, pool, "dns-disconnect-a", "dns-disconnect-user-a", passwordHash, []string{"dns.read", "dns.manage"})
	tenantB := insertDNSTenant(t, pool, "dns-disconnect-b", "dns-disconnect-user-b", passwordHash, []string{"dns.read"})
	tokens, err := identity.NewTokenManager("dns-disconnect-integration-secret-at-least-32-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(store, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("dns-disconnect-v1", bytes.Repeat([]byte{6}, 32))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{
		CookieSecure: false, DNSCredentialCipher: cipher, DNSProviderVerifier: &platformCredentialVerifier{},
		DNSRecordLister:     &platformFakeProvider{records: map[string]dnsproviderremote.ZoneRecord{}},
		DNSZoneApexResolver: hostedDomainsResolver{hosted: []string{"example.com"}},
		APIKeyPepper:        bytes.Repeat([]byte{0x42}, 32),
	}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	admin, _ := loginOK(t, client, server.URL, "dns-disconnect-admin")

	get := func() dnsacme.PlatformConfig {
		t.Helper()
		response := siteRequest(t, client, http.MethodGet, server.URL+"/v1/dns/platform-config", nil, admin.AccessToken, "", "")
		var config dnsacme.PlatformConfig
		decodeResponse(t, response, http.StatusOK, &config)
		response.Body.Close()
		return config
	}
	disconnect := func(token, key, ifMatch string) *http.Response {
		t.Helper()
		return siteRequest(t, client, http.MethodDelete, server.URL+"/v1/dns/platform-config", nil, token, key, ifMatch)
	}
	copyState := func(t *testing.T, tenant dnsTenantFixture) (status string, revoked bool, zones int) {
		t.Helper()
		if err := pool.QueryRow(t.Context(), `SELECT provider.status, provider.credential_revoked,
				(SELECT count(*) FROM dns_zones zone WHERE zone.scope_id=provider.scope_id AND zone.provider_id=provider.id)
			FROM dns_providers provider WHERE provider.scope_id=$1 AND provider.id=$2`,
			tenant.scopeID, dnsacme.PlatformProviderCopyID(tenant.scopeID)).Scan(&status, &revoked, &zones); err != nil {
			t.Fatalf("tenant %s copy: %v", tenant.username, err)
		}
		return status, revoked, zones
	}

	createPlatformZone(t, client, server.URL, admin.AccessToken, "disconnect-zone", "cdn.example.com", "")
	response := siteRequest(t, client, http.MethodPut, server.URL+"/v1/dns/platform-config", map[string]any{
		"provider_type": "dnspod_cn", "credentials": map[string]string{"dp_id": "269638", "dp_key": "secret-token"},
		"ttl": 300, "ip_weight": false,
	}, admin.AccessToken, "disconnect-save", `"1"`)
	var saved dnsacme.PlatformConfig
	decodeResponse(t, response, http.StatusOK, &saved)
	response.Body.Close()
	if saved.ProviderType != "dnspod_cn" || !saved.SecretSaved || saved.Revision != 2 || saved.Sync.Tenants != 2 {
		t.Fatalf("saved platform DNS config = %+v", saved)
	}

	t.Run("callers without platform DNS write permission are refused", func(t *testing.T) {
		readOnly := loginForScope(t, client, server.URL, tenantB.username, tenantB.scopeID)
		response := disconnect(readOnly.AccessToken, "disconnect-denied", `"2"`)
		assertError(t, response, http.StatusForbidden, "permission_denied", "")
		response.Body.Close()
		tenant := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
		response = disconnect(tenant.AccessToken, "disconnect-tenant", `"2"`)
		assertError(t, response, http.StatusForbidden, "dns_platform_only", "")
		response.Body.Close()
		if after := get(); after.ProviderType != "dnspod_cn" || !after.SecretSaved || after.Revision != 2 {
			t.Fatalf("refused disconnect changed the config: %+v", after)
		}
	})

	t.Run("a stale version is a conflict", func(t *testing.T) {
		response := disconnect(admin.AccessToken, "disconnect-stale", `"1"`)
		assertError(t, response, http.StatusConflict, "version_conflict", "")
		response.Body.Close()
		if after := get(); after.ProviderType != "dnspod_cn" || !after.SecretSaved {
			t.Fatalf("stale disconnect changed the config: %+v", after)
		}
	})

	response = disconnect(admin.AccessToken, "disconnect-ok", `"2"`)
	var config dnsacme.PlatformConfig
	decodeResponse(t, response, http.StatusOK, &config)
	response.Body.Close()
	if config.ProviderType != "" || config.SecretSaved || len(config.Identifiers) != 0 || config.Revision != 3 ||
		config.TTL != 300 || config.Sync.Tenants != 0 {
		t.Fatalf("disconnected platform DNS config = %+v", config)
	}
	if read := get(); read.ProviderType != "" || read.SecretSaved || read.Revision != 3 {
		t.Fatalf("read back after disconnect = %+v", read)
	}

	t.Run("tenant copies are disabled and their CNAME domains kept", func(t *testing.T) {
		for _, tenant := range []dnsTenantFixture{tenantA, tenantB} {
			status, revoked, zones := copyState(t, tenant)
			if status != "disabled" || !revoked || zones != 1 {
				t.Fatalf("tenant %s copy = %s revoked=%t zones=%d", tenant.username, status, revoked, zones)
			}
		}
		page := listPlatformZones(t, client, server.URL, admin.AccessToken, "")
		if page.Total != 1 || page.Items[0].Name != "cdn.example.com" {
			t.Fatalf("platform zones after disconnect = %+v", page)
		}
		var audits int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
			WHERE action='dns.platform.config.disconnect' AND payload::text LIKE '%dnspod_cn%'`).Scan(&audits); err != nil {
			t.Fatal(err)
		}
		if audits != 1 {
			t.Fatalf("disconnect audit events = %d", audits)
		}
	})

	t.Run("repeating the disconnect is idempotent", func(t *testing.T) {
		response := disconnect(admin.AccessToken, "disconnect-ok", `"2"`)
		var replay dnsacme.PlatformConfig
		decodeResponse(t, response, http.StatusOK, &replay)
		response.Body.Close()
		if replay.ProviderType != "" || replay.SecretSaved || replay.Revision != 3 {
			t.Fatalf("replayed disconnect = %+v", replay)
		}
		response = disconnect(admin.AccessToken, "disconnect-again", `"3"`)
		decodeResponse(t, response, http.StatusOK, &replay)
		response.Body.Close()
		if replay.ProviderType != "" || replay.Revision != 3 {
			t.Fatalf("second disconnect = %+v", replay)
		}
	})

	t.Run("record repair reports the configuration as missing", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/dns/platform-config/repair", map[string]any{},
			admin.AccessToken, "disconnect-repair", "")
		assertError(t, response, http.StatusConflict, "dns_not_configured", "")
		response.Body.Close()
	})

	t.Run("saving credentials again re-enables the tenant copies", func(t *testing.T) {
		response := siteRequest(t, client, http.MethodPut, server.URL+"/v1/dns/platform-config", map[string]any{
			"provider_type": "dnspod_cn", "credentials": map[string]string{"dp_id": "269638", "dp_key": "new-token"},
			"ttl": 300, "ip_weight": false,
		}, admin.AccessToken, "disconnect-resave", `"3"`)
		var again dnsacme.PlatformConfig
		decodeResponse(t, response, http.StatusOK, &again)
		response.Body.Close()
		if again.ProviderType != "dnspod_cn" || !again.SecretSaved || again.Sync.Tenants != 2 {
			t.Fatalf("saved after disconnect = %+v", again)
		}
		for _, tenant := range []dnsTenantFixture{tenantA, tenantB} {
			if status, revoked, _ := copyState(t, tenant); status != "verified" || revoked {
				t.Fatalf("tenant %s copy after reconnect = %s revoked=%t", tenant.username, status, revoked)
			}
		}
	})
}
