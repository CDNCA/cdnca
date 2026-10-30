//go:build integration

package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/site"
)

// Migration 490: DNS API 备注 round trip, and 默认设置 over HTTP
// with tenant isolation (another tenant's ID is 404, its list is empty).
func TestTenantDNSRemarkAndSiteDefaultsHTTP(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	permissions := []string{"dns.read", "dns.manage", "sites.read", "sites.manage"}
	tenantA := insertDNSTenant(t, pool, "b2-tenant-a", "b2-user-a", passwordHash, permissions)
	tenantB := insertDNSTenant(t, pool, "b2-tenant-b", "b2-user-b", passwordHash, permissions)
	tokens, err := identity.NewTokenManager("b2-integration-secret-at-least-thirty-two-bytes", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identityStore, tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := dnsacme.NewAESGCMCredentialCipher("dns-test-v1", bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		DNSCredentialCipher: cipher}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	authA := loginForScope(t, client, server.URL, tenantA.username, tenantA.scopeID)
	authB := loginForScope(t, client, server.URL, tenantB.username, tenantB.scopeID)

	provider := createDNSProvider(t, client, server.URL, authA.AccessToken, "b2-provider", createDNSProviderRequest{
		Name: "主账号", Remark: "  业务域名用  ", ProviderType: "cloudflare",
		Credentials: map[string]string{"api_token": "cloudflare-token-value-0123456789"},
	})
	if provider.Remark != "业务域名用" {
		t.Fatalf("created remark = %q", provider.Remark)
	}
	remark := "改过的备注"
	response := siteRequest(t, client, http.MethodPatch, server.URL+"/v1/dns/providers/"+provider.ID.String(),
		updateDNSProviderRequest{ExpectedVersion: provider.Revision, Name: provider.Name, Remark: &remark, Status: "unverified"},
		authA.AccessToken, "b2-provider-update", "")
	var updated dnsacme.Provider
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	if updated.Remark != remark {
		t.Fatalf("updated remark = %q", updated.Remark)
	}
	// Omitting remark keeps it.
	response = siteRequest(t, client, http.MethodPatch, server.URL+"/v1/dns/providers/"+provider.ID.String(),
		updateDNSProviderRequest{ExpectedVersion: updated.Revision, Name: "主账号2", Status: "unverified"},
		authA.AccessToken, "b2-provider-rename", "")
	decodeResponse(t, response, http.StatusOK, &updated)
	response.Body.Close()
	if updated.Remark != remark {
		t.Fatalf("remark after rename = %q", updated.Remark)
	}

	response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/site-defaults", map[string]any{
		"setting_name": "balance_way", "setting_value": "ip_hash"}, authA.AccessToken, "b2-default", "")
	var created site.SiteUserDefault
	decodeResponse(t, response, http.StatusCreated, &created)
	response.Body.Close()
	response = siteRequest(t, client, http.MethodPost, server.URL+"/v1/site-defaults", map[string]any{
		"setting_name": "balance_way", "setting_value": "ip_hash"}, authA.AccessToken, "b2-default", "")
	var replay site.SiteUserDefault
	decodeResponse(t, response, http.StatusCreated, &replay)
	response.Body.Close()
	if replay.ID != created.ID {
		t.Fatalf("replayed create = %s, want %s", replay.ID, created.ID)
	}

	var listB site.SiteUserDefaultListResult
	response = siteRequest(t, client, http.MethodGet, server.URL+"/v1/site-defaults", nil, authB.AccessToken, "", "")
	decodeResponse(t, response, http.StatusOK, &listB)
	response.Body.Close()
	if listB.Total != 0 {
		t.Fatalf("tenant B sees %d defaults", listB.Total)
	}
	response = siteRequest(t, client, http.MethodPatch, server.URL+"/v1/site-defaults/"+created.ID.String(),
		map[string]any{"expected_version": 1, "enabled": false}, authB.AccessToken, "b2-b-update", "")
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("tenant B update = %d", response.StatusCode)
	}
	response.Body.Close()
	response = siteRequest(t, client, http.MethodDelete, server.URL+"/v1/site-defaults/"+created.ID.String(), nil,
		authB.AccessToken, "b2-b-delete", "")
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("tenant B delete = %d", response.StatusCode)
	}
	response.Body.Close()
	response = siteRequest(t, client, http.MethodPatch, server.URL+"/v1/site-defaults/"+created.ID.String(),
		map[string]any{"expected_version": 1, "enabled": false}, authA.AccessToken, "b2-a-update", "")
	var disabled site.SiteUserDefault
	decodeResponse(t, response, http.StatusOK, &disabled)
	response.Body.Close()
	if disabled.Enabled || disabled.Revision != 2 {
		t.Fatalf("disabled = %+v", disabled)
	}
	response = siteRequest(t, client, http.MethodDelete, server.URL+"/v1/site-defaults/"+created.ID.String(), nil,
		authA.AccessToken, "b2-a-delete", "")
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("tenant A delete = %d", response.StatusCode)
	}
	response.Body.Close()
}
