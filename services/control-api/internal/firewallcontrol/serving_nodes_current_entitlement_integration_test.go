//go:build integration

package firewallcontrol

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 主机防火墙按节点分发（siteServingNodes）按当前生效权益的套餐线路。
// 站点跟随套餐，初购 A（线路只含甲）、改到 B（只含乙）后按乙，回切 A 又按甲。
func TestSiteServingNodesFollowCurrentEntitlementPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	scope, user := packagelinefixture.Tenant(t, pool)
	lines := packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: scope, User: user})
	site := lines.Site("firewallcontrol-current.example.test")
	inTx := func(fn func(tx pgx.Tx) error) {
		t.Helper()
		if err := pgx.BeginFunc(t.Context(), pool, fn); err != nil {
			t.Fatal(err)
		}
	}
	expect := func(step string, line uuid.UUID) {
		t.Helper()
		want := lines.Node(line)
		inTx(func(tx pgx.Tx) error {
			nodes, err := siteServingNodes(t.Context(), tx, scope, []uuid.UUID{site})
			_, ok := nodes[site][want]
			if err != nil || len(nodes[site]) != 1 || !ok {
				t.Fatalf("%s: serving nodes=%v err=%v, want [%s]", step, nodes[site], err, want)
			}
			return nil
		})
	}
	expect("package A", lines.LineA)
	lines.Change(lines.LineB)
	expect("package B (purchase snapshot still A)", lines.LineB)
	lines.Change(lines.LineA)
	expect("back to package A", lines.LineA)
}
