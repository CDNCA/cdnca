//go:build integration

package l4forward

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
)

// 跟随套餐的四层转发按当前生效权益取套餐的主/备线、CNAME 与
// 套餐名（详情 forwardSelect / effectiveLineColumns），自身 CNAME 意图缺省的域名/模式（streamCNAMESQL）同样取
// 当前套餐。套餐 A：主线 A、备线 B、共享 CNAME a.cdn.test；套餐 B：主线 B、备线 A、按站点 CNAME b.cdn.test。
// 初购 A、改到 B、回切 A，每步都按当前套餐。
func TestForwardFollowsCurrentEntitlementPostgres(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	scope, user := packagelinefixture.Tenant(t, pool)
	var lines *packagelinefixture.Fixture
	lines = packagelinefixture.New(t, pool, packagelinefixture.Options{Scope: scope, User: user,
		Spec: func(line uuid.UUID) map[string]any {
			spec := map[string]any{"node_group_id": line.String(),
				"cname": map[string]any{"mode": "shared", "domain": "a.cdn.test"}}
			if lines != nil && line == lines.LineB {
				spec["backup_node_group_id"] = lines.LineA.String()
				spec["cname"] = map[string]any{"mode": "per_site", "domain": "b.cdn.test"}
			} else if lines != nil {
				spec["backup_node_group_id"] = lines.LineB.String()
			}
			return spec
		}})
	lines.Change(lines.LineA) // revision 2: A with its backup B (New ran before lines was set)
	forward := lines.Forward(18443)
	// The read under test joins the latest intent; its runtime spec is not what is checked here, so this throwaway
	// database drops the runtime spec check rather than building a full v12 spec.
	packagelinefixture.Exec(t, pool, `ALTER TABLE l4_publish_intents DROP CONSTRAINT l4_publish_intents_runtime_spec_506`)
	packagelinefixture.Exec(t, pool, `INSERT INTO l4_publish_intents(id,scope_id,stream_id,version,operation,desired_state,
		resource_revision,configuration_source_revision,runtime_spec,created_by_user_id)
		VALUES(gen_random_uuid(),$1,$2,1,'create','enabled',1,1,'{}',$3)`, scope, forward, user)
	store := NewStore(pool)
	expect := func(step string, line uuid.UUID) {
		t.Helper()
		backup, mode, domain := lines.LineB, "package", "a.cdn.test"
		if line == lines.LineB {
			backup, mode, domain = lines.LineA, "site", "b.cdn.test"
		}
		item, err := store.Get(t.Context(), Actor{UserID: user, ScopeID: scope, ScopeKind: "platform"}, forward)
		if err != nil {
			t.Fatalf("%s: get: %v", step, err)
		}
		if item.Line.NodeGroupID == nil || *item.Line.NodeGroupID != line ||
			item.Line.BackupNodeGroupID == nil || *item.Line.BackupNodeGroupID != backup {
			t.Fatalf("%s: line=%v backup=%v, want %s / %s", step, item.Line.NodeGroupID, item.Line.BackupNodeGroupID, line, backup)
		}
		if item.PackageName == nil || *item.PackageName != "pkgline-"+line.String()[:8] {
			t.Fatalf("%s: package name=%v", step, item.PackageName)
		}
		if item.CNAMEDomain == nil || *item.CNAMEDomain != domain {
			t.Fatalf("%s: cname domain=%v, want %s", step, item.CNAMEDomain, domain)
		}
		var gotDomain, gotMode string
		if err := pool.QueryRow(t.Context(), streamCNAMESQL, scope, lines.Subscription, nil, nil).
			Scan(&gotDomain, &gotMode); err != nil || gotDomain != domain || gotMode != mode {
			t.Fatalf("%s: stream cname=%q/%q err=%v, want %q/%q", step, gotDomain, gotMode, err, domain, mode)
		}
	}
	expect("package A", lines.LineA)
	lines.Change(lines.LineB)
	expect("package B (purchase snapshot still A)", lines.LineB)
	lines.Change(lines.LineA)
	expect("back to package A", lines.LineA)
}
