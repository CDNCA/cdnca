//go:build integration

package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 社区版网站没有套餐、没有自选线路组，由平台默认线路组承担；L2 跟随线路组
// （l2_mode package）时用平台默认线路组的 L2 配置：发布现算 L2 取到该线路组
// 与配置，站点对象也交给配置成员（L2 节点）。
func TestSiteL2PlatformDefaultForCommunitySitePostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	platform := packagelinefixture.Platform(t, pool)
	scope, user := packagelinefixture.Tenant(t, pool)
	lines := packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: scope, User: user, NodeScope: platform, LineScope: platform})
	community := lines.CommunitySite("l2-community.example.test", lines.LineA)
	config := lines.L2(lines.LineA, community, lines.NodeYi)
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		groups, err := loadSiteL2LineGroups(t.Context(), tx, scope, []uuid.UUID{community})
		if err != nil {
			return err
		}
		group, ok := groups[community]
		if !ok || group.ID != lines.LineA || group.ScopeID != platform || group.ConfigID == nil || *group.ConfigID != config {
			t.Errorf("L2 line group=%+v found=%v, want the platform default %s with configuration %s", group, ok, lines.LineA, config)
		}
		nodes, err := siteServingNodes(t.Context(), tx, scope, []string{community.String()})
		if err != nil {
			return err
		}
		served := nodes[community.String()]
		_, jia := served[lines.NodeJia]
		_, yi := served[lines.NodeYi]
		if !jia || !yi || len(served) != 2 {
			t.Errorf("site object serving nodes=%v, want the line group node %s and the L2 member %s", served, lines.NodeJia, lines.NodeYi)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
