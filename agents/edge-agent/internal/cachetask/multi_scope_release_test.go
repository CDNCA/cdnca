package cachetask

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// Deployment state lives under scopes/<configuration scope id>; the cache
// manifest and cache commands carry the tenant id. They are distinct UUIDs.
const (
	secondTenantID = "77777777-7777-4777-8777-777777777777"
	secondSiteID   = "88888888-8888-4888-8888-888888888888"
	secondVersion  = "99999999-9999-4999-8999-999999999999"
	firstScopeID   = "aaaaaaa1-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
	secondScopeID  = "aaaaaaa2-aaaa-4aaa-8aaa-aaaaaaaaaaa2"
)

// multiScopeRoot lays out a MultiScopeManager state root: one deployment state
// machine per tenant under scopes/<tenant>, and one node activation lock.
func multiScopeRoot(t *testing.T) string {
	t.Helper()
	root := testStateRoot(t)
	if err := os.WriteFile(filepath.Join(root, "node-activation.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{firstScopeID, secondScopeID} {
		for _, dir := range []string{"releases", "state"} {
			if err := os.MkdirAll(filepath.Join(root, "scopes", scope, dir), 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func TestActiveReleaseResolverResolvesEachTenantFromItsOwnScope(t *testing.T) {
	if firstScopeID == productionTenantID || secondScopeID == secondTenantID {
		t.Fatal("fixture must keep scope and tenant ids distinct")
	}
	root := multiScopeRoot(t)
	activateSiteRuntimeReleaseUnder(t, filepath.Join(root, "scopes", firstScopeID), filepath.Dir(root),
		cacheReleaseFilesFor(t, productionTenantID, productionVersionV1, 7, []edgeconfig.CacheListenerPolicy{productionListener(8080)}))
	activateSiteRuntimeReleaseUnder(t, filepath.Join(root, "scopes", secondScopeID), filepath.Dir(root),
		cacheReleaseFilesFor(t, secondTenantID, secondVersion, 3, []edgeconfig.CacheListenerPolicy{tenantListener(secondTenantID, secondSiteID, 8080, secondVersion)}))
	resolver, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatalf("NewActiveReleaseResolver() error = %v", err)
	}
	first, err := resolver.ResolveSite(context.Background(), productionTenantID, productionSiteID, productionVersionV1, 7)
	if err != nil || first.TenantID != productionTenantID || first.CacheIdentity != edgeconfig.CacheNamespaceID(productionTenantID, productionSiteID, productionVersionV1) {
		t.Fatalf("ResolveSite(first tenant) = %+v, %v", first, err)
	}
	second, err := resolver.ResolveSite(context.Background(), secondTenantID, secondSiteID, secondVersion, 3)
	if err != nil || second.TenantID != secondTenantID || second.CacheIdentity != edgeconfig.CacheNamespaceID(secondTenantID, secondSiteID, secondVersion) {
		t.Fatalf("ResolveSite(second tenant) = %+v, %v", second, err)
	}
	for _, identity := range []struct {
		tenant, site, version string
		revision              uint64
	}{
		{secondTenantID, productionSiteID, productionVersionV1, 7},                         // another tenant's site
		{productionTenantID, secondSiteID, secondVersion, 3},                               // another tenant's site
		{"66666666-6666-4666-8666-666666666666", productionSiteID, productionVersionV1, 7}, // scope not carried
		{"../" + productionTenantID, productionSiteID, productionVersionV1, 7},             // unsafe scope
		{firstScopeID, productionSiteID, productionVersionV1, 7},                           // a scope id is not a tenant id
	} {
		if _, err := resolver.ResolveSite(context.Background(), identity.tenant, identity.site, identity.version, identity.revision); !errors.Is(err, ErrSiteNotFound) {
			t.Fatalf("ResolveSite(%+v) error = %v, want ErrSiteNotFound", identity, err)
		}
	}
}

func TestActiveReleaseResolverMultiScopeLeaseUsesNodeActivationLock(t *testing.T) {
	root := multiScopeRoot(t)
	resolver, err := NewActiveReleaseResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	release, err := resolver.lockActiveRelease(context.Background())
	if err != nil {
		t.Fatalf("lockActiveRelease() on a multi-scope root error = %v", err)
	}
	release()
	if err := os.Remove(filepath.Join(root, "node-activation.lock")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := resolver.lockActiveRelease(ctx); err == nil {
		t.Fatal("multi-scope lease succeeded without the node activation lock")
	}
}
