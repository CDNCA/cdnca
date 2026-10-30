package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremote"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
)

type hostedDomainsResolver struct{ hosted []string }

func (resolver hostedDomainsResolver) ResolveZoneApex(_ context.Context, _ string, _ map[string]string, zone string) (string, error) {
	best := ""
	for _, domain := range resolver.hosted {
		if (zone == domain || strings.HasSuffix(zone, "."+domain)) && len(domain) > len(best) {
			best = domain
		}
	}
	if best == "" {
		return "", &dnsproviderremote.Error{Code: dnsproviderremote.CodeZoneNotHosted}
	}
	return best, nil
}

// retest-n1 (migration 473): saving a tenant CNAME zone stores the hosted
// apex from the provider's domain list; a zone the account does not host is
// refused with dns_zone_not_hosted; a zone saved before 473 (apex NULL) is
// filled on first use and written back.
func TestDNSZoneSaveStoresProviderApex(t *testing.T) {
	pool := isolatedTestPool(t)
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	identityStore := identity.NewStore(pool)
	tenant := insertDNSTenant(t, pool, "apex-tenant", "apex-user", passwordHash, []string{"dns.read", "dns.manage"})
	tokens, err := identity.NewTokenManager("dns-apex-integration-secret-at-least-thirty-two", 5*time.Minute)
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
	resolver := hostedDomainsResolver{hosted: []string{"868yun.com"}}
	server := httptest.NewServer(New(pool, identityService, Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32),
		CookieSecure: false, DNSCredentialCipher: cipher, DNSZoneApexResolver: resolver}).Handler())
	t.Cleanup(server.Close)
	client := server.Client()
	auth := loginForScope(t, client, server.URL, tenant.username, tenant.scopeID)
	provider := createDNSProvider(t, client, server.URL, auth.AccessToken, "apex-provider", createDNSProviderRequest{
		Name: "DNSPod", ProviderType: "dnspod_cn", Credentials: map[string]string{"dp_id": "123456", "dp_key": "dnspod-secret"},
	})
	apexOf := func(t *testing.T, name string) *string {
		t.Helper()
		var apex *string
		if err := pool.QueryRow(t.Context(), `SELECT provider_zone_apex FROM dns_zones WHERE scope_id=$1 AND name=$2`,
			tenant.scopeID, name).Scan(&apex); err != nil {
			t.Fatal(err)
		}
		return apex
	}
	sub := createDNSZone(t, client, server.URL, auth.AccessToken, "apex-sub", createDNSZoneRequest{
		ProviderID: provider.ID.String(), Name: "cdn.868yun.com"})
	if apex := apexOf(t, "cdn.868yun.com"); apex == nil || *apex != "868yun.com" {
		t.Fatalf("subdomain zone apex = %v", apex)
	}
	createDNSZone(t, client, server.URL, auth.AccessToken, "apex-root", createDNSZoneRequest{
		ProviderID: provider.ID.String(), Name: "868yun.com"})
	if apex := apexOf(t, "868yun.com"); apex == nil || *apex != "868yun.com" {
		t.Fatalf("hosted zone apex = %v", apex)
	}
	response := siteRequest(t, client, http.MethodPost, server.URL+"/v1/dns/zones", createDNSZoneRequest{
		ProviderID: provider.ID.String(), Name: "cdn.other.com"}, auth.AccessToken, "apex-missing", "")
	assertError(t, response, http.StatusUnprocessableEntity, "dns_zone_not_hosted", "")
	response.Body.Close()

	// Legacy zone: clear the apex, fill it on first use.
	if _, err := pool.Exec(t.Context(), `UPDATE dns_zones SET provider_zone_apex=NULL WHERE id=$1`, sub.ID); err != nil {
		t.Fatal(err)
	}
	apex, err := dnsacme.EnsureZoneApex(t.Context(), pool, resolver, tenant.scopeID, sub.ID, "dnspod_cn",
		map[string]string{"dp_id": "123456", "dp_key": "dnspod-secret"}, "cdn.868yun.com", "")
	if err != nil || apex != "868yun.com" {
		t.Fatalf("EnsureZoneApex = %q, %v", apex, err)
	}
	if stored := apexOf(t, "cdn.868yun.com"); stored == nil || *stored != "868yun.com" {
		t.Fatalf("legacy apex not written back: %v", stored)
	}
	// The CHECK rejects an apex that does not cover the zone name.
	if _, err := pool.Exec(t.Context(), `UPDATE dns_zones SET provider_zone_apex='other.com' WHERE id=$1`, sub.ID); err == nil {
		t.Fatal("dns_zones accepted an apex outside the zone name")
	}
}
