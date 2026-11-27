//go:build integration

package securityban

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 社区版网站没有套餐、没有自选线路组，由平台默认线路组承担：封禁下发找到平台
// 默认线路组的节点；跟随套餐的网站仍只按套餐线路，不带平台默认。
func TestServingNodesPlatformDefaultForCommunitySitePostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	platform := packagelinefixture.Platform(t, pool)
	scope, user := packagelinefixture.Tenant(t, pool)
	lines := packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: scope, User: user, NodeScope: platform, LineScope: platform})
	community := lines.CommunitySite("securityban-community.example.test", lines.LineA)
	lines.Change(lines.LineB)
	packaged := lines.Site("securityban-packaged.example.test")
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		nodes, err := servingNodes(t.Context(), tx, []uuid.UUID{community, packaged})
		if err != nil {
			return err
		}
		for site, want := range map[uuid.UUID]uuid.UUID{community: lines.NodeJia, packaged: lines.NodeYi} {
			var got []uuid.UUID
			for node, sites := range nodes {
				if slices.Contains(sites, site) {
					got = append(got, node)
				}
			}
			if !slices.Equal(got, []uuid.UUID{want}) {
				t.Fatalf("site %s serving nodes=%v, want [%s]", site, got, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
