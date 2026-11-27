//go:build integration

package firewallcontrol

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 社区版网站没有套餐、没有自选线路组，由平台默认线路组承担：主机防火墙按节点
// 分发找到平台默认线路组的节点；跟随套餐的网站仍只按套餐线路，不带平台默认。
func TestSiteServingNodesPlatformDefaultForCommunitySitePostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	platform := packagelinefixture.Platform(t, pool)
	scope, user := packagelinefixture.Tenant(t, pool)
	lines := packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: scope, User: user, NodeScope: platform, LineScope: platform})
	community := lines.CommunitySite("firewallcontrol-community.example.test", lines.LineA)
	lines.Change(lines.LineB)
	packaged := lines.Site("firewallcontrol-packaged.example.test")
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		nodes, err := siteServingNodes(t.Context(), tx, scope, []uuid.UUID{community, packaged})
		if err != nil {
			return err
		}
		for site, want := range map[uuid.UUID]uuid.UUID{community: lines.NodeJia, packaged: lines.NodeYi} {
			if _, ok := nodes[site][want]; !ok || len(nodes[site]) != 1 {
				t.Fatalf("site %s serving nodes=%v, want [%s]", site, nodes[site], want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
