//go:build integration

package edgepublish

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 社区版网站没有套餐、没有自选线路组，由平台默认线路组承担（与
// edgeautopublish.lineGroupNodeIDs 同一集合）：站点对象只交给平台默认线路组
// 的节点，不再因为解析不到线路组而交给作用域里所有目标节点；跟随套餐的网站
// 仍只按套餐线路。
func TestSiteObjectServingNodesPlatformDefaultForCommunitySitePostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	platform := packagelinefixture.Platform(t, pool)
	scope, user := packagelinefixture.Tenant(t, pool)
	lines := packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: scope, User: user, NodeScope: platform, LineScope: platform})
	community := lines.CommunitySite("site-objects-community.example.test", lines.LineA)
	lines.Change(lines.LineB)
	packaged := lines.Site("site-objects-packaged.example.test")
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		nodes, err := siteServingNodes(t.Context(), tx, scope, []string{community.String(), packaged.String()})
		if err != nil {
			return err
		}
		for site, want := range map[uuid.UUID]uuid.UUID{community: lines.NodeJia, packaged: lines.NodeYi} {
			served, resolved := nodes[site.String()]
			if _, ok := served[want]; !resolved || !ok || len(served) != 1 {
				t.Fatalf("site %s serving nodes=%v resolved=%v, want [%s]", site, served, resolved, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
