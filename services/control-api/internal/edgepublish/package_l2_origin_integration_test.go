//go:build integration

package edgepublish_test

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 套餐 limits.l2_origin=false 的租户站点发布后不带 L2 回源，true 时带。
// 判据同 TestAutomaticPublicationKeepsSiteOnItsL2Members：站点的 L2 成员节点 M 不在站点的线路组里，
// 只有站点走 L2 时 M 才收到这个站点。
func TestPackageL2OriginSwitchDecidesWhetherSiteUsesL2(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	scope.DeleteSite(t, scope.SiteID)
	nodeL, nodeM := scope.AddNode(t, 12), scope.AddNode(t, 12)
	for _, node := range []uuid.UUID{nodeL, nodeM} {
		scope.DeclareSiteSelectionL2(t, node)
		scope.SetPresence(t, node, true, 1)
	}
	groupS := scope.AddStreamLineGroup(t, "198.51.100.77", nodeL)
	groupT := scope.AddStreamLineGroup(t, "198.51.100.78", nodeM)
	site := scope.AddSiteOn(t, "pkg-l2origin.example.com", 18188, groupS)
	other := scope.AddSiteOn(t, "pkg-l2origin-other.example.com", 18189, groupT)
	custom, _ := scope.AddL2Config(t, "pkg l2_origin custom", nodeM)
	scope.SetSiteL2(t, site, "custom", &custom)
	enablePackagePolicy(t, scope)
	worker := withdrawWorker(t, scope)

	setL2Origin := func(value string) {
		t.Helper()
		// 订阅快照有不可变触发器，夹具与 CRS 用例一样在本事务内关掉触发器改写。
		if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			for _, statement := range []string{
				`SET LOCAL session_replication_role = replica`,
				`UPDATE package_subscriptions SET product_snapshot=jsonb_set(product_snapshot,'{spec,limits,l2_origin}',$2::jsonb) WHERE id=$1`,
				`UPDATE package_subscription_entitlement_versions SET product_snapshot=jsonb_set(product_snapshot,'{spec,limits,l2_origin}',$2::jsonb) WHERE subscription_id=$1`,
			} {
				args := []any{}
				if statement[:3] != "SET" {
					args = []any{scope.SubscriptionID, value}
				}
				if _, err := tx.Exec(t.Context(), statement, args...); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	memberServes := func(label string) []string {
		t.Helper()
		state, code := publishLineGroupChange(t, scope, worker)
		requireReconciling(t, label, state, code)
		got := scope.LatestNodeRelease(t, nodeM).Sites
		scope.SettleDeployments(t)
		return got
	}

	setL2Origin("false")
	if got := memberServes("l2_origin=false"); !slices.Equal(got, sortedIDs(other)) {
		t.Fatalf("package without l2_origin: L2 member M serves %v, want only its own website (the site must not use L2)", got)
	}
	setL2Origin("true")
	if got := memberServes("l2_origin=true"); !slices.Equal(got, sortedIDs(site, other)) {
		t.Fatalf("package with l2_origin: L2 member M serves %v, want the website it is the L2 of and its own", got)
	}
}
