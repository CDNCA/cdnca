//go:build integration

package httpapi

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit/audittest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sitecrs"
)

// TestSiteCRSSetAppsSystem (fix-mktsiteconf3 S4, fix-mktsiteconf5): a market
// leaf sets a site's CRS application types without a WAF binding; an
// undownloaded pack is refused, the same apps write nothing, a change moves
// the site revision and is audited with the system actor; clearing them
// removes the override.
func TestSiteCRSSetAppsSystem(t *testing.T) {
	pool := isolatedTestPool(t)
	ctx := context.Background()
	passwordHash, err := identity.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	tenant := insertSecurityTenant(t, pool, "Site CRS system", "site-crs-system", passwordHash)
	site := insertQuickBlockSite(t, pool, tenant.scopeID, tenant.userID) // no WAF binding
	store := sitecrs.NewStore(pool, time.Now)
	revision := func() int64 {
		t.Helper()
		var value int64
		if err := pool.QueryRow(ctx, `SELECT revision FROM sites WHERE id=$1`, site).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	apps := []string{"system/app-wordpress"}

	// No pack downloaded yet.
	if _, err := store.SetAppsSystem(ctx, tenant.scopeID, site, tenant.userID, apps, "market-crs-1"); !errors.Is(err, sitecrs.ErrAppUnavailable) {
		t.Fatalf("undownloaded pack = %v", err)
	}
	seedCRSProfilePacks(t, pool)
	before := revision()
	changed, err := store.SetAppsSystem(ctx, tenant.scopeID, site, tenant.userID, apps, "market-crs-2")
	if err != nil || !changed {
		t.Fatalf("set apps = %v, %v", changed, err)
	}
	if revision() != before+1 {
		t.Fatalf("site revision %d, want %d", revision(), before+1)
	}
	var stored []string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(ARRAY(SELECT jsonb_array_elements_text(override->'apps')), '{}')
		FROM site_crs_overrides WHERE scope_id=$1 AND site_id=$2`, tenant.scopeID, site).Scan(&stored); err != nil ||
		!slices.Equal(stored, apps) {
		t.Fatalf("stored apps = %v, %v", stored, err)
	}
	events := audittest.Query(t, pool, `scope_id=$1 AND action=$2 AND resource_id=$3 AND actor_kind='system'
		AND actor_ref='job:market_leaf_sync'`, tenant.scopeID, sitecrs.AppsAuditAction, site.String())
	if len(events) != 1 || events[0].RequestID != "market-crs-2" || events[0].Result != "success" {
		t.Fatalf("audit = %+v", events)
	}

	// The same apps again: nothing written.
	if changed, err := store.SetAppsSystem(ctx, tenant.scopeID, site, tenant.userID, apps, "market-crs-3"); err != nil || changed {
		t.Fatalf("same apps = %v, %v", changed, err)
	}
	if revision() != before+1 {
		t.Fatal("an unchanged write moved the site revision")
	}
	// Unknown app, foreign scope.
	if _, err := store.SetAppsSystem(ctx, tenant.scopeID, site, tenant.userID, []string{"wordpress"}, "market-crs-4"); err == nil {
		t.Fatal("an app outside the system namespace was accepted")
	}
	other := insertSecurityTenant(t, pool, "Site CRS other", "site-crs-other", passwordHash)
	if _, err := store.SetAppsSystem(ctx, other.scopeID, site, other.userID, apps, "market-crs-5"); !errors.Is(err, sitecrs.ErrNotFound) {
		t.Fatalf("another scope = %v", err)
	}
	// Clearing them removes the override.
	if changed, err := store.SetAppsSystem(ctx, tenant.scopeID, site, tenant.userID, nil, "market-crs-6"); err != nil || !changed {
		t.Fatalf("clear = %v, %v", changed, err)
	}
	var left bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM site_crs_overrides WHERE site_id=$1)`, site).Scan(&left); err != nil || left {
		t.Fatalf("override left = %v, %v", left, err)
	}
}
