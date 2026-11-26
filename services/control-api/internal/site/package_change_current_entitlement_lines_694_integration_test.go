//go:build integration

package site

import (
	"context"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/packagelinefixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// （迁移 694）：平台线路 A 只含平台节点甲、B 只含乙，套餐主/备线都指向
// 该线路；站点跟随套餐，初购 A、改到 B 后：承载判定 tenant_carries_node_287、 候选节点、有效供给绑定的
// 套餐备线都按 B（乙），回切 A 后又按 A。
func TestPackageChangeCurrentEntitlementLines694Postgres(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	scope, platform := f.a.scopeID, f.admin.scopeID
	lines := packagelinefixture.New(t, f.pool, packagelinefixture.Options{Scope: scope, User: f.a.userID,
		NodeScope: platform, LineScope: platform, Spec: func(line uuid.UUID) map[string]any {
			return map[string]any{"node_group_id": line.String(), "backup_node_group_id": line.String()}
		}})
	site := lines.Site("lines-694.example.test")

	expect := func(step string, line uuid.UUID) {
		t.Helper()
		in, out := lines.Node(line), lines.NodeJia
		if line == lines.LineA {
			out = lines.NodeYi
		}
		var carriesIn, carriesOut bool
		if err := f.pool.QueryRow(ctx, `SELECT tenant_carries_node_287($1,$2), tenant_carries_node_287($1,$3)`,
			scope, in, out).Scan(&carriesIn, &carriesOut); err != nil || !carriesIn || carriesOut {
			t.Fatalf("%s: carries current=%v other=%v err=%v", step, carriesIn, carriesOut, err)
		}
		rows, err := f.pool.Query(ctx, `SELECT acme_http01_site_candidate_nodes($1,$2)`, scope, site)
		if err != nil {
			t.Fatal(err)
		}
		candidates, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil || !slices.Equal(candidates, []uuid.UUID{in}) {
			t.Fatalf("%s: http-01 candidates=%v err=%v, want [%s]", step, candidates, err, in)
		}
		var backup uuid.UUID
		if err := f.pool.QueryRow(ctx, `SELECT node_group_id FROM site_supply_bindings_effective
			WHERE site_id=$1 AND kind='local_node_group' AND role='backup'`, site).Scan(&backup); err != nil || backup != line {
			t.Fatalf("%s: effective backup binding=%s err=%v, want %s", step, backup, err, line)
		}
	}
	expect("package A", lines.LineA)
	lines.Change(lines.LineB)
	expect("package B (purchase snapshot still A)", lines.LineB)
	lines.Change(lines.LineA)
	expect("back to package A", lines.LineA)
}

// 694：618 / 663 的 L2 分支与编译一致——套餐 limits.l2_origin 为 false 时 L2 成员不算承担本站的节点。
// 站点自定义 L2 只含节点丙；最新发布在线路节点甲健康、在丙失败：套餐允许 L2 时同步失败，改到 l2_origin=false
// 的套餐 B 后丙不再承担本站，已同步。
func TestSitePublicationL2OriginOff694Postgres(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	scope, user := f.a.scopeID, f.a.userID
	var lines *packagelinefixture.Fixture
	lines = packagelinefixture.New(t, f.pool, packagelinefixture.Options{Scope: scope, User: user,
		Spec: func(line uuid.UUID) map[string]any {
			// The site keeps its own line (A); package B turns L2 origin off.
			return map[string]any{"limits": map[string]any{"l2_origin": lines == nil || line != lines.LineB}}
		}})
	site := lines.Site("l2-origin-694.example.test")
	exec := func(query string, args ...any) { t.Helper(); packagelinefixture.Exec(t, f.pool, query, args...) }
	exec(`UPDATE sites SET node_group_id=$2 WHERE id=$1`, site, lines.LineA)
	config, member := uuid.New(), uuid.New()
	exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4)
		VALUES($1,$2,'l2-丙',$3,$4,(SELECT COALESCE(max(display_id),0)+1 FROM nodes),'198.51.100.74')`, member, scope, "active", user)
	exec(`INSERT INTO l2_topology_configs(id,tenant_scope_id,name,region,mode,load_method,created_by_user_id,updated_by_user_id,
		created_at,updated_at) VALUES($1,$2,'l2-694','hk','global','rr',$3,$3,now(),now())`, config, scope, user)
	exec(`INSERT INTO l2_topology_nodes(id,tenant_scope_id,config_id,node_id,enabled,created_by_user_id,updated_by_user_id,
		created_at,updated_at) VALUES($1,$2,$3,$4,true,$5,$5,now(),now())`, uuid.New(), scope, config, member, user)
	exec(`INSERT INTO site_origin_pools(site_id,l2_mode,l2_config_id) VALUES($1,'custom',$2)`, site, config)

	digest := make([]byte, 32)
	version, rollout := uuid.New(), uuid.New()
	exec(`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
		generator_version,status,idempotency_key,request_digest,created_at,published_at)
		VALUES($1,$2,'\x01',$3,'l2-origin','1','releasable',$4,$3,now(),now())`, version, scope, digest, "l2-origin-"+version.String())
	exec(`INSERT INTO edge_config_publications(id,configuration_scope_id,source_revision,idempotency_key,request_digest,request_id,
		correlation_id,canonical_snapshot_sha256,artifact_sha256,config_version_id,rollout_id,node_count,created_at,
		expected_source_revision,target_kind,target_snapshot_sha256,contract_version,actor_user_id,actor_scope_id)
		VALUES(gen_random_uuid(),$1,1,$2,$3,gen_random_uuid(),gen_random_uuid(),$3,$3,$4,$5,2,now(),1,'explicit',$3,1,$6,$1)`,
		scope, "l2-origin-"+rollout.String(), digest, version, rollout, user)
	for node, state := range map[uuid.UUID]string{lines.NodeJia: "healthy", member: "failed"} {
		exec(`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,
			command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
			VALUES(gen_random_uuid(),$1,$2,1,$3,'apply',$4,gen_random_uuid(),'\x01',$5,now()+interval '1 hour',now(),now(),$6)`,
			rollout, node, version, state, digest, scope)
	}
	exec(`INSERT INTO config_version_telemetry_site_bindings(config_version_id,site_id) VALUES($1,$2)`, version, site)

	expect := func(step, want string) {
		t.Helper()
		var detail, batch string
		if err := f.pool.QueryRow(ctx, `SELECT site_sync_status_503($1,$2)`, scope, site).Scan(&detail); err != nil {
			t.Fatal(err)
		}
		if err := f.pool.QueryRow(ctx, `SELECT sync_status FROM site_sync_status_batch_663($1::uuid[]) WHERE out_site_id=$2`,
			[]uuid.UUID{scope}, site).Scan(&batch); err != nil {
			t.Fatal(err)
		}
		if detail != want || batch != want {
			t.Fatalf("%s: detail=%q batch=%q, want %q", step, detail, batch, want)
		}
	}
	expect("package A allows L2: 丙 failed", SyncStatusFailed)
	lines.Change(lines.LineB)
	expect("package B l2_origin=false: 丙 not serving", SyncStatusSynced)
	lines.Change(lines.LineA)
	expect("back to package A", SyncStatusFailed)
}
