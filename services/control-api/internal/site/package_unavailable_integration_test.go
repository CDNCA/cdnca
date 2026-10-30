//go:build integration

package site

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fix-nopkgpub2 ①: the site read (list and detail share siteColumns and
// scanSite) carries why a site is not served: its package is disabled,
// deleted, or none is bound; nothing while the package is valid.
func TestPackageUnavailableReasonPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	manager := addonSiteInsertPlatformActor(t, pool, "nopkgpub2-admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "No package reason", "nopkgpub2-owner")
	subscription, siteID, product := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	exec := func(query string, args ...any) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, query, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,site_limit,
		domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,tcp_factor_numerator,
		tcp_factor_denominator,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,$5,1,'{"revision":1,"name":"reason","spec":{}}',1,1,1,0,$3,$3::timestamptz+interval '30 days',
		'UTC','monthly',1,1,$4,$4,$3,$3)`, subscription, tenant.scopeID, now, manager.UserID, product)
	exec(`INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,package_subscription_id,package_id,
		created_by_user_id,updated_by_user_id)
		VALUES($1,$2,48200,$3,'reason.example.test',ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$4,$5,$3,$3)`,
		siteID, tenant.scopeID, tenant.userID, subscription, product)
	exec(`INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID)
	exec(`INSERT INTO site_origins(site_id,position,host,port,weight,enabled) VALUES($1,1,'192.0.2.10',80,1,true)`, siteID)

	reason := func() *string {
		t.Helper()
		var item Site
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var err error
			item, err = selectSite(ctx, tx, siteID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if toListItem(item).PackageUnavailableReason != item.PackageUnavailableReason {
			t.Fatal("list item and detail disagree")
		}
		return item.PackageUnavailableReason
	}
	expect := func(step, want string) {
		t.Helper()
		got := reason()
		switch {
		case want == "" && got != nil:
			t.Fatalf("%s: reason = %q, want none", step, *got)
		case want != "" && (got == nil || *got != want):
			t.Fatalf("%s: reason = %v, want %q", step, got, want)
		}
	}
	expect("valid", "")
	exec(`UPDATE package_subscriptions SET admin_enabled=false WHERE id=$1`, subscription)
	expect("disabled", PackageUnavailableDisabled)
	exec(`UPDATE package_subscriptions SET deleted_at=$2 WHERE id=$1`, subscription, now)
	expect("deleted", PackageUnavailableDeleted)
	exec(`UPDATE package_subscriptions SET admin_enabled=true,deleted_at=NULL WHERE id=$1`, subscription)
	expect("restored", "")
	exec(`UPDATE sites SET package_subscription_id=NULL,package_id=NULL WHERE id=$1`, siteID)
	expect("unbound", PackageUnavailableNoPackage)
}
