//go:build integration

package sched302table

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
)

// 302 调度表（LoadSites）对跟随套餐的站点按当前生效权益的套餐
// 主线取端点。初购 A（只含甲）、改到 B（只含乙）后为乙，回切 A 又是甲。
func TestLoadSitesFollowsCurrentEntitlementPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	scope, user := packagelinefixture.Tenant(t, pool)
	lines := packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: scope, User: user})
	site := lines.Site("sched302-current.example.test")
	packagelinefixture.Exec(t, pool, `INSERT INTO site_schedule302_settings(scope_id,site_id,target,keep_path,keep_query,
		signature_ttl_seconds,https_to_http,extensions,path_prefixes,min_size_bytes,sign_key,updated_by_user_id,updated_at)
		VALUES($1,$2,$3,true,true,60,false,'{}','{}',0,$4,$5,now())`, scope, site, sched302.TargetAddress, make([]byte, 32), user)
	expect := func(step string, line uuid.UUID) {
		t.Helper()
		sites, err := LoadSites(t.Context(), pool, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		for _, loaded := range sites {
			if loaded.ID == site {
				if len(loaded.Endpoints) != 1 || loaded.Endpoints[0].NodeID != lines.Node(line) {
					t.Fatalf("%s: endpoints=%+v, want node %s", step, loaded.Endpoints, lines.Node(line))
				}
				return
			}
		}
		t.Fatalf("%s: site not loaded", step)
	}
	expect("package A", lines.LineA)
	lines.Change(lines.LineB)
	expect("package B (purchase snapshot still A)", lines.LineB)
	lines.Change(lines.LineA)
	expect("back to package A", lines.LineA)
}
