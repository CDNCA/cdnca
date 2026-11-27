//go:build integration

package site

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 社区版：网站不绑套餐、不选线路组，由平台默认线路组承担，L2 跟随线路组（l2_mode package）。
// 平台默认线路组 L2 配置的成员也承担本站：线路组节点 healthy、L2 节点部署失败时，
// 发布结果（618）与批量同步状态（663）都是失败，而不是只看线路组节点得出已同步。
func TestCommunitySiteL2OnPlatformDefaultLineGroupPublicationPostgres(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	f.manualPublication(f.a)
	created, err := f.createSite(f.a, f.a, "ce-default-l2.example.test")
	if err != nil {
		t.Fatal(err)
	}
	siteID, scope, platform, admin := created.Site.ID, f.a.scopeID, f.admin.scopeID, f.admin.userID
	group, node, l2Node, config := uuid.New(), uuid.New(), uuid.New(), uuid.New()
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
	// 平台默认线路组（只有 node）挂 L2 配置（只有 l2Node），网站回源池跟随线路组 L2。
	replica(
		`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4) VALUES($1,$2,'ce-l1','active',$3,931,'192.0.2.81'),
			($4,$2,'ce-l2','active',$3,932,'192.0.2.82')`,
		`INSERT INTO l2_topology_configs(id,tenant_scope_id,name,region,mode,load_method,created_by_user_id,updated_by_user_id,
			created_at,updated_at) VALUES($1,$2,'ce-default-l2','hk','global','rr',$3,$3,now(),now())`,
		`INSERT INTO l2_topology_nodes(id,tenant_scope_id,config_id,node_id,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES(gen_random_uuid(),$1,$2,$3,$4,$4,now(),now())`,
		`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,
			updated_at,display_id,resolved_value,ipv4_resolved_value,is_platform_default,l2_config_id) VALUES($1,$2,'ce-default-l2',1,$3,$3,now(),now(),
			(SELECT COALESCE(max(display_id),0)+1 FROM node_line_groups),'lg-'||replace($1::uuid::text,'-',''),'v4-'||replace($1::uuid::text,'-',''),true,$4)`,
		`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,ipv4_resolved_value,
			probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,
			configuration_digest,created_by_user_id,created_at,sealed_at,l2_config_id) VALUES($1,$2,1,'ce-default-l2','lg-'||replace($1::uuid::text,'-',''),
			'v4-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$3,$4,now(),now(),$5)`,
		`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,
			port,region,carrier,priority,weight,enabled) VALUES(gen_random_uuid(),$1,$2,$3,1,'192.0.2.81',4,80,'hk','bgp',0,1,true)`,
		`UPDATE site_origin_pools SET l2_mode='package',l2_config_id=NULL WHERE site_id=$1`,
	)([]any{node, platform, admin, l2Node}, []any{config, platform, admin}, []any{platform, config, l2Node, admin},
		[]any{group, platform, admin, config}, []any{group, platform, digest, admin, config}, []any{node, platform, group}, []any{siteID})

	// 作用域发布带上本站：线路组节点 healthy，L2 节点失败。
	version, rollout := uuid.New(), uuid.New()
	replica(
		`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
			generator_version,status,idempotency_key,request_digest,created_at,published_at)
			VALUES($1,$2,'\x01',$3,'ce-default-l2','1','releasable',$4,$3,now(),now())`,
		`INSERT INTO edge_config_publications(id,configuration_scope_id,source_revision,idempotency_key,request_digest,request_id,
			correlation_id,canonical_snapshot_sha256,artifact_sha256,config_version_id,rollout_id,node_count,created_at,
			expected_source_revision,target_kind,target_snapshot_sha256,contract_version,actor_user_id,actor_scope_id)
			VALUES(gen_random_uuid(),$1,1,$2,$3,gen_random_uuid(),gen_random_uuid(),$3,$3,$4,$5,2,now(),1,'explicit',$3,1,$6,$7)`,
		`INSERT INTO config_version_telemetry_site_bindings(config_version_id,site_id) VALUES($1,$2)`,
		`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,
			command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
			VALUES(gen_random_uuid(),$1,$2,1,$3,'apply','healthy',gen_random_uuid(),'\x01',$4,now()+interval '1 hour',now(),now(),$5),
			(gen_random_uuid(),$1,$6,1,$3,'apply','failed',gen_random_uuid(),'\x01',$4,now()+interval '1 hour',now(),now(),$5)`,
	)([]any{version, scope, digest, "ce-default-l2-" + version.String()},
		[]any{scope, "ce-default-l2-" + rollout.String(), digest, version, rollout, admin, platform},
		[]any{version, siteID}, []any{rollout, node, version, digest, scope, l2Node})
	f.now = f.now.Add(time.Second)
	var outcome, batched string
	if err := f.pool.QueryRow(ctx, `SELECT state FROM site_publication_outcome_618($1,$2)`, scope, siteID).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT sync_status FROM site_sync_status_batch_663(ARRAY[$1]::uuid[])
		WHERE out_site_id=$2`, scope, siteID).Scan(&batched); err != nil {
		t.Fatal(err)
	}
	if outcome != "failed" || batched != SyncStatusFailed {
		t.Fatalf("L2 member failed: outcome=%q batch=%q, want failed / %q", outcome, batched, SyncStatusFailed)
	}
}
