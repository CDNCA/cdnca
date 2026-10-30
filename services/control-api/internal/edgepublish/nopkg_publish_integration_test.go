//go:build integration

package edgepublish

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 无套餐网站真的不下发，写好未跑：
//
//	TEST_DATABASE_URL=... TEST_DATABASE_TEMPLATE=... go -C services/control-api test -tags integration -count=1 -p 1 -v \
//	  -run 'TestNoPackage' ./internal/edgepublish/

func noPackagePublishedSites(t *testing.T, scope *SystemRepublishScope) map[uuid.UUID]bool {
	t.Helper()
	var document siteRuntimeV2Document
	if err := json.Unmarshal(scope.LatestPublication(t).Snapshot, &document); err != nil {
		t.Fatal(err)
	}
	sites := make(map[uuid.UUID]bool, len(document.Sites))
	for _, site := range document.Sites {
		sites[uuid.MustParse(site.ID)] = true
	}
	return sites
}

// A site without a package is not in the publication facts; a site on a
// valid package is.
func TestNoPackageSiteIsNotPublished(t *testing.T) {
	scope := NewSystemRepublishScope(t)
	plain := scope.AddSite(t, "nopkg-plain.example.com", 18082)
	scope.fixture.unbindSitePackage(t, plain)
	node := scope.AddNode(t, 6)
	if err := scope.PublishManually(t, "nopkg-first", node); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if sites := noPackagePublishedSites(t, scope); !sites[scope.SiteID] || sites[plain] || len(sites) != 1 {
		t.Fatalf("published sites %v, want only the packaged %s", sites, scope.SiteID)
	}
}

// has → has not: the next publication withdraws the site.
func TestNoPackageSiteWithdrawnAfterUnbinding(t *testing.T) {
	scope := NewSystemRepublishScope(t)
	other := scope.AddSite(t, "nopkg-other.example.com", 18082)
	node := scope.AddNode(t, 6)
	if err := scope.PublishManually(t, "nopkg-baseline", node); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	if sites := noPackagePublishedSites(t, scope); !sites[scope.SiteID] || !sites[other] {
		t.Fatalf("baseline sites %v", sites)
	}
	scope.fixture.unbindSitePackage(t, other)
	scope.AdvanceRevision(t)
	if err := scope.PublishManually(t, "nopkg-unbound", node); err != nil {
		t.Fatalf("publish after unbinding: %v", err)
	}
	if sites := noPackagePublishedSites(t, scope); !sites[scope.SiteID] || sites[other] {
		t.Fatalf("after unbinding sites %v, want %s withdrawn", sites, other)
	}
}

// A disabled (admin_enabled=false) or deleted package withdraws its sites;
// an enabled one keeps them.
func TestNoPackageSiteWithdrawnWhenPackageDisabled(t *testing.T) {
	for _, change := range []string{"admin_enabled=false", "deleted_at=clock_timestamp()"} {
		t.Run(change, func(t *testing.T) {
			scope := NewSystemRepublishScope(t)
			node := scope.AddNode(t, 6)
			if err := scope.PublishManually(t, "nopkg-pkg-baseline", node); err != nil {
				t.Fatal(err)
			}
			scope.SettleDeployments(t)
			if sites := noPackagePublishedSites(t, scope); !sites[scope.SiteID] {
				t.Fatalf("baseline sites %v", sites)
			}
			if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
				if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
					return err
				}
				_, err := tx.Exec(t.Context(), `UPDATE package_subscriptions SET `+change+` WHERE id=$1`, scope.SubscriptionID)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			scope.AdvanceRevision(t)
			if err := scope.PublishManually(t, "nopkg-pkg-off", node); err != nil {
				t.Fatalf("publish after package %s: %v", change, err)
			}
			if sites := noPackagePublishedSites(t, scope); sites[scope.SiteID] {
				t.Fatalf("package %s: sites %v still carry %s", change, sites, scope.SiteID)
			}
		})
	}
}
