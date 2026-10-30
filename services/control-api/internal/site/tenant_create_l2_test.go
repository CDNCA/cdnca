package site

import (
	"testing"

	"github.com/google/uuid"
)

// REF-ROLE-L2-CREATE: a non-platform create follows the package L2 (as the
// update keeps the stored one); the platform's off/custom (and its
// automation: transfer, supply leaf sites) is kept.
func TestTenantCreatePoolForcesPackageL2(t *testing.T) {
	config := uuid.New()
	tenant := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	platform := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "platform"}
	for name, pool := range map[string]OriginPool{
		"off":     {L2Mode: SiteL2Off},
		"custom":  {L2Mode: SiteL2Custom, L2ConfigID: &config},
		"package": {L2Mode: SiteL2Package},
		"omitted": {},
	} {
		sent := pool
		got := tenantCreatePool(tenant, &sent)
		if got.L2Mode != SiteL2Package || got.L2ConfigID != nil {
			t.Fatalf("tenant %s: %+v", name, got)
		}
		if name != "package" && sent.L2Mode != pool.L2Mode {
			t.Fatalf("tenant %s: the request's pool was changed in place", name)
		}
		kept := pool
		if got := tenantCreatePool(platform, &kept); got.L2Mode != pool.L2Mode || got.L2ConfigID != pool.L2ConfigID {
			t.Fatalf("platform %s: %+v", name, got)
		}
	}
	if tenantCreatePool(tenant, nil) != nil {
		t.Fatal("nil pool")
	}
}
