//go:build integration

package securityanalytics

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 社区版网站没有套餐、没有自选线路组，由平台默认线路组承担：平台默认线路组
// 的节点上报的安全事件归属该网站（不当作越界丢弃），别的线路组节点不归属；
// 跟随套餐的网站仍只按套餐线路。
func TestNodeServesSitePlatformDefaultForCommunitySitePostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	platform := packagelinefixture.Platform(t, pool)
	scope, user := packagelinefixture.Tenant(t, pool)
	lines := packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: scope, User: user, NodeScope: platform, LineScope: platform})
	community := lines.CommunitySite("securityanalytics-community.example.test", lines.LineA)
	lines.Change(lines.LineB)
	packaged := lines.Site("securityanalytics-packaged.example.test")
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, check := range []struct {
			site, node uuid.UUID
			want       bool
		}{{community, lines.NodeJia, true}, {community, lines.NodeYi, false}, {packaged, lines.NodeYi, true}, {packaged, lines.NodeJia, false}} {
			served, err := nodeServesSite(t.Context(), tx, check.node, scope, check.site)
			if err != nil {
				return err
			}
			if served != check.want {
				t.Errorf("site %s node %s served=%v, want %v", check.site, check.node, served, check.want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
