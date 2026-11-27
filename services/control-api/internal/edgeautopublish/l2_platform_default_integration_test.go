//go:build integration

package edgeautopublish_test

import (
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 社区版网站没有套餐、没有自选线路组，由平台默认线路组承担；L2 跟随线路组
// （l2_mode package）时平台默认线路组 L2 配置的成员也是本站的发布目标。
func TestSiteTargetNodesL2PlatformDefaultForCommunitySitePostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	platform := packagelinefixture.Platform(t, pool)
	scope, user := packagelinefixture.Tenant(t, pool)
	lines := packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: scope, User: user, NodeScope: platform, LineScope: platform})
	community := lines.CommunitySite("l2-targets-community.example.test", lines.LineA)
	lines.L2(lines.LineA, community, lines.NodeYi)
	want := []uuid.UUID{lines.NodeJia, lines.NodeYi}
	slices.SortFunc(want, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		single, err := edgeautopublish.SiteTargetNodeIDsTx(t.Context(), tx, scope, community)
		if err != nil {
			return err
		}
		batch, err := edgeautopublish.SitesTargetNodeIDsTx(t.Context(), tx, scope, []uuid.UUID{community})
		if err != nil {
			return err
		}
		if !slices.Equal(single, want) || !slices.Equal(batch[community], want) {
			t.Errorf("targets single=%v batch=%v, want the line group node and the L2 member %v", single, batch[community], want)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
