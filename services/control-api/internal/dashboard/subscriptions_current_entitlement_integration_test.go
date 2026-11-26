//go:build integration

package dashboard

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 租户首页的套餐名与限额按生效的权益显示。
// 初购 A（5 站点）、改到 B（100 站点）后显示 B 的名称与限额，初购快照与订阅行仍是 A。
func TestTenantSubscriptionsFollowCurrentEntitlementPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	scope, user := packagelinefixture.Tenant(t, pool)
	lines := packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: scope, User: user})
	packagelinefixture.Exec(t, pool, `UPDATE package_subscriptions SET site_limit=5 WHERE id=$1`, lines.Subscription)
	packagelinefixture.Exec(t, pool, `UPDATE package_subscription_entitlement_versions SET site_limit=5
		WHERE subscription_id=$1 AND revision=1`, lines.Subscription)
	expect := func(step string, line uuid.UUID, sites SubscriptionLimit) {
		t.Helper()
		var stats TenantSubscriptionStats
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			var err error
			stats, err = readTenantSubscriptions(t.Context(), tx, scope, time.Now().Add(time.Second))
			return err
		}); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		if len(stats.Items) != 1 || stats.Items[0].Name != "pkgline-"+line.String()[:8] || stats.Items[0].SiteLimit != sites {
			t.Fatalf("%s: items=%+v, want package of line %s with %d sites", step, stats.Items, line, sites)
		}
	}
	expect("package A", lines.LineA, 5)
	lines.Change(lines.LineB)
	expect("package B (purchase snapshot still A)", lines.LineB, 100)
}
