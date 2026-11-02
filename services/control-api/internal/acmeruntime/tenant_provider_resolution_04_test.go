package acmeruntime

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestTenantProviderResolution04BuildRequestLocksFrozenAuthority(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	raw, err := os.ReadFile(strings.TrimSuffix(file, "tenant_provider_resolution_04_test.go") + "dispatcher.go")
	if err != nil {
		t.Fatal(err)
	}
	// The zone lookup is shared with order acceptance (dnsacme.ManagedZoneFor).
	zone, err := os.ReadFile(strings.TrimSuffix(file, "acmeruntime/tenant_provider_resolution_04_test.go") + "dnsacme/managed_zone.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "dnsacme.ManagedZoneFor(ctx, tx, scopeID, providerID, domains)") {
		t.Fatal("dispatcher does not resolve the zone through dnsacme.ManagedZoneFor")
	}
	source := string(raw) + string(zone)
	for _, required := range []string{
		"tenant.id", "provider.credential_key_id", "provider.credential_version",
		"provider.credential_revoked", "zone.id", "FOR SHARE", "TenantID: tenantID",
		"ScopeID: lease.ScopeID", "ProviderID: frozenProviderID", "ZoneID: zoneID",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("dispatcher buildRequest lacks frozen authority contract %q", required)
		}
	}
	if strings.Contains(source, "TenantID: lease.ScopeID") {
		t.Fatal("dispatcher still aliases tenant identity to access scope")
	}
}
