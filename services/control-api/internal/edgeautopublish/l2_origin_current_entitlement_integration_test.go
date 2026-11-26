//go:build integration

package edgeautopublish

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 自动发布目标节点的 L2 分支与编译（edgepublish siteServingNodes）一致：套餐 limits.l2_origin 为 false 时
// 站点的 L2 成员不算目标节点，并按当前生效权益判断。站点自有线路 A（节点甲）、自定义 L2 只含节点丙；套餐 A
// 允许 L2，目标为甲+丙；改到 l2_origin=false 的套餐 B 后只剩甲，回切 A 又是甲+丙。
func TestTargetNodesL2OriginFollowsCurrentEntitlementPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	scope, user := packagelinefixture.Tenant(t, pool)
	var lines *packagelinefixture.Fixture
	lines = packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: scope, User: user,
		Spec: func(line uuid.UUID) map[string]any {
			return map[string]any{"limits": map[string]any{"l2_origin": lines == nil || line != lines.LineB}}
		}})
	site := lines.Site("l2-origin-target.example.test")
	exec := func(query string, args ...any) { t.Helper(); packagelinefixture.Exec(t, pool, query, args...) }
	exec(`UPDATE sites SET node_group_id=$2 WHERE id=$1`, site, lines.LineA)
	config, member := uuid.New(), uuid.New()
	exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4)
		VALUES($1,$2,'l2-丙','active',$3,(SELECT COALESCE(max(display_id),0)+1 FROM nodes),'198.51.100.75')`, member, scope, user)
	exec(`INSERT INTO l2_topology_configs(id,tenant_scope_id,name,region,mode,load_method,created_by_user_id,updated_by_user_id,
		created_at,updated_at) VALUES($1,$2,'l2-target','hk','global','rr',$3,$3,now(),now())`, config, scope, user)
	exec(`INSERT INTO l2_topology_nodes(id,tenant_scope_id,config_id,node_id,enabled,created_by_user_id,updated_by_user_id,
		created_at,updated_at) VALUES($1,$2,$3,$4,true,$5,$5,now(),now())`, uuid.New(), scope, config, member, user)
	exec(`INSERT INTO site_origin_pools(site_id,l2_mode,l2_config_id) VALUES($1,'custom',$2)`, site, config)
	expect := func(step string, want ...uuid.UUID) {
		t.Helper()
		slices.SortFunc(want, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			bySite, err := SitesTargetNodeIDsTx(t.Context(), tx, scope, []uuid.UUID{site})
			if err != nil || !slices.Equal(bySite[site], want) {
				t.Fatalf("%s: sites target nodes=%v err=%v, want %v", step, bySite[site], err, want)
			}
			nodes, err := lineGroupNodeIDs(t.Context(), tx, scope, &site, nil)
			if err != nil || !slices.Equal(nodes, want) {
				t.Fatalf("%s: line group nodes=%v err=%v, want %v", step, nodes, err, want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	expect("package A allows L2", lines.NodeJia, member)
	lines.Change(lines.LineB)
	expect("package B l2_origin=false", lines.NodeJia)
	lines.Change(lines.LineA)
	expect("back to package A", lines.NodeJia, member)
}
