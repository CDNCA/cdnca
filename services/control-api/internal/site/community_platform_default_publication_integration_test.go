//go:build integration

package site

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 社区版：网站不绑套餐、不选线路组，由平台默认线路组承担。节点上的发布已经 healthy，
// 接入状态「已发布到节点」与同步状态却一直是发布中/待同步：判定承担本站的节点时不认平台默认线路组。
// 发布前（还没有任何发布）网站应在发布里，同步状态是待同步而不是已同步。
func TestCommunitySiteOnPlatformDefaultLineGroupPublishedPostgres(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	// 手动作用域：本用例只看发布结果的判定，不让建站排出的自动发布请求参与。
	f.manualPublication(f.a)
	created, err := f.createSite(f.a, f.a, "ce-default.example.test")
	if err != nil {
		t.Fatal(err)
	}
	siteID, scope, platform, admin := created.Site.ID, f.a.scopeID, f.admin.scopeID, f.admin.userID
	group, node := uuid.New(), uuid.New()
	digest := make([]byte, 32)
	replica := func(queries ...string) func(args ...[]any) {
		return func(args ...[]any) {
			t.Helper()
			if err := pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
					return err
				}
				for index, query := range queries {
					if _, err := tx.Exec(ctx, query, args[index]...); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	// 平台节点 + 平台默认线路组（平台作用域，r1 只有该节点）。
	replica(
		`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4) VALUES($1,$2,'ce-node','active',$3,921,'192.0.2.71')`,
		`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,
			updated_at,display_id,resolved_value,ipv4_resolved_value,is_platform_default) VALUES($1,$2,'ce-default',1,$3,$3,now(),now(),
			(SELECT COALESCE(max(display_id),0)+1 FROM node_line_groups),'lg-'||replace($1::uuid::text,'-',''),'v4-'||replace($1::uuid::text,'-',''),true)`,
		`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,ipv4_resolved_value,
			probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,
			configuration_digest,created_by_user_id,created_at,sealed_at) VALUES($1,$2,1,'ce-default','lg-'||replace($1::uuid::text,'-',''),
			'v4-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$3,$4,now(),now())`,
		`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,
			port,region,carrier,priority,weight,enabled) VALUES(gen_random_uuid(),$1,$2,$3,1,'192.0.2.71',4,80,'hk','bgp',0,1,true)`,
	)([]any{node, platform, admin}, []any{group, platform, admin}, []any{group, platform, digest, admin}, []any{node, platform, group})

	status := func() (AccessCheck, string, string) {
		t.Helper()
		detail, err := f.sites.Get(ctx, f.a.siteActor(), siteID)
		if err != nil || detail.AccessReadiness == nil {
			t.Fatalf("detail readiness=%v err=%v", detail.AccessReadiness, err)
		}
		// 总览的同步失败计数用批量形式（663），逐站结果须与 503 相同。
		var batched string
		if err := f.pool.QueryRow(ctx, `SELECT sync_status FROM site_sync_status_batch_663(ARRAY[$1]::uuid[])
			WHERE out_site_id=$2`, scope, siteID).Scan(&batched); err != nil {
			t.Fatal(err)
		}
		return detail.AccessReadiness.Checks[5], detail.SyncStatus, batched
	}
	if published, sync, batched := status(); published.OK || sync != SyncStatusPending || batched != SyncStatusPending {
		t.Errorf("before any publication: published=%+v sync=%q batch=%q, want not published / pending", published, sync, batched)
	}

	// 作用域发布带上本站，部署到平台默认线路组的节点并 healthy。
	version, rollout := uuid.New(), uuid.New()
	replica(
		`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
			generator_version,status,idempotency_key,request_digest,created_at,published_at)
			VALUES($1,$2,'\x01',$3,'ce-default','1','releasable',$4,$3,now(),now())`,
		`INSERT INTO edge_config_publications(id,configuration_scope_id,source_revision,idempotency_key,request_digest,request_id,
			correlation_id,canonical_snapshot_sha256,artifact_sha256,config_version_id,rollout_id,node_count,created_at,
			expected_source_revision,target_kind,target_snapshot_sha256,contract_version,actor_user_id,actor_scope_id)
			VALUES(gen_random_uuid(),$1,1,$2,$3,gen_random_uuid(),gen_random_uuid(),$3,$3,$4,$5,1,now(),1,'explicit',$3,1,$6,$7)`,
		`INSERT INTO config_version_telemetry_site_bindings(config_version_id,site_id) VALUES($1,$2)`,
		`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,
			command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
			VALUES(gen_random_uuid(),$1,$2,1,$3,'apply','healthy',gen_random_uuid(),'\x01',$4,now()+interval '1 hour',now(),now(),$5)`,
	)([]any{version, scope, digest, "ce-default-" + version.String()},
		[]any{scope, "ce-default-" + rollout.String(), digest, version, rollout, admin, platform},
		[]any{version, siteID}, []any{rollout, node, version, digest, scope})
	f.now = f.now.Add(time.Second)
	if published, sync, batched := status(); !published.OK || sync != SyncStatusSynced || batched != SyncStatusSynced {
		t.Fatalf("healthy on the platform default line group: published=%+v sync=%q batch=%q, want ok / synced",
			published, sync, batched)
	}
}
