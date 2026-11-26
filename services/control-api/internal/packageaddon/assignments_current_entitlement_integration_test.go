//go:build integration

package packageaddon_test

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
)

// 附加包分配列表的套餐名按当前生效的权益显示。
// 初购 A、改到 B 后显示 B 的名称（初购快照仍是 A）。
func TestAssignmentsSubscriptionNameFollowsCurrentEntitlementPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	scope, user := packagelinefixture.Tenant(t, pool)
	lines := packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: scope, User: user})
	addon := uuid.New()
	packagelinefixture.Exec(t, pool, `INSERT INTO package_addon_products(id,name,kind,quantity,monthly_price_minor,created_at,updated_at)
		VALUES($1,'current-name','domains',1,0,now(),now())`, addon)
	packagelinefixture.Exec(t, pool, `INSERT INTO package_addon_assignments(id,addon_id,tenant_scope_id,owner_user_id,subscription_id,
		kind,amount,snapshot,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'domains',1,'{"quantity":1}',now(),now())`,
		uuid.New(), addon, scope, user, lines.Subscription)
	store := packageaddon.Store{Pool: pool, Now: func() time.Time { return time.Now().Add(time.Second) }}
	expect := func(step string, line uuid.UUID) {
		t.Helper()
		page, err := store.Assignments(t.Context(), 1, 10, "", addon)
		if err != nil || len(page.Items) != 1 || page.Items[0].SubscriptionName != "pkgline-"+line.String()[:8] {
			t.Fatalf("%s: page=%+v err=%v, want package of line %s", step, page, err, line)
		}
	}
	expect("package A", lines.LineA)
	lines.Change(lines.LineB)
	expect("package B (purchase snapshot still A)", lines.LineB)
}
