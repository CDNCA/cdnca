//go:build integration

package site

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// （迁移 692）：详情（site_sync_status_503，列表与 API 筛选同源）、
// 批量（site_sync_status_batch_663，管理员与租户两种形式）与接入检查 published 三处对同一事实给同一口径：
//
//	从未发布 / 最新发布不含本站（应下发的站点）→ pending 待同步（not_published / site_not_in_publication）；
//	恢复在途（作用域级自动请求 source_resource_id 为空，或系统通道 package_suspension）→ pending 发布中（publishing）；
//	发布健康 → synced（通过）；部署失败 → failed（publish_failed）；
//	主动停用 → synced（site_disabled）；暂停中 → synced（package_suspended，作用域有在途请求也不变）。
func TestSitePublicationRestoreInFlightPostgres(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	created, err := f.createSite(f.a, f.a, "restore.example.test")
	if err != nil {
		t.Fatal(err)
	}
	siteID, scope, user := created.Site.ID, f.a.scopeID, f.a.userID
	exec := func(query string, args ...any) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, query, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	digest := make([]byte, 32)

	// 有效套餐（应下发）与一个承担本站的 active 节点。
	subscription, product, node, group := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,site_limit,
		domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,tcp_factor_numerator,
		tcp_factor_denominator,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,$5,1,'{"revision":1,"name":"restore","spec":{}}',1,1,1,0,$3,$3::timestamptz+interval '30 days',
		'UTC','monthly',1,1,$4,$4,$3,$3)`, subscription, scope, f.now, f.admin.userID, product)
	exec(`UPDATE sites SET package_subscription_id=$2, package_id=$3 WHERE id=$1`, siteID, subscription, product)
	exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4) VALUES($1,$2,'restore','active',$3,951,'192.0.2.81')`,
		node, scope, user)
	exec(`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,
		updated_at,display_id,resolved_value,ipv4_resolved_value) VALUES($1,$2,'restore',1,$3,$3,now(),now(),
		(SELECT COALESCE(max(display_id),0)+1 FROM node_line_groups),'lg-'||replace($1::uuid::text,'-',''),'v4-'||replace($1::uuid::text,'-',''))`,
		group, scope, user)
	exec(`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,ipv4_resolved_value,
		probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,
		configuration_digest,created_by_user_id,created_at,sealed_at) VALUES($1,$2,1,'restore','lg-'||replace($1::uuid::text,'-',''),
		'v4-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$3,$4,now(),now())`, group, scope, digest, user)
	exec(`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,
		port,region,carrier,priority,weight,enabled) VALUES(gen_random_uuid(),$1,$2,$3,1,'192.0.2.81',4,80,'hk','bgp',0,1,true)`,
		node, scope, group)
	exec(`UPDATE sites SET node_group_id=$2 WHERE id=$1`, siteID, group)

	revision := 0
	publish := func(carries bool, state string) {
		t.Helper()
		revision++
		version, rollout := uuid.New(), uuid.New()
		exec(`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
			generator_version,status,idempotency_key,request_digest,created_at,published_at)
			VALUES($1,$2,'\x01',$3,'restore','1','releasable',$4,$3,$5,$5)`, version, scope, digest, "restore-"+version.String(), f.now)
		exec(`INSERT INTO edge_config_publications(id,configuration_scope_id,source_revision,idempotency_key,request_digest,request_id,
			correlation_id,canonical_snapshot_sha256,artifact_sha256,config_version_id,rollout_id,node_count,created_at,
			expected_source_revision,target_kind,target_snapshot_sha256,contract_version,actor_user_id,actor_scope_id)
			VALUES(gen_random_uuid(),$1,$8,$2,$3,gen_random_uuid(),gen_random_uuid(),$3,$3,$4,$5,1,$6,$8,'explicit',$3,1,$7,$1)`,
			scope, "restore-"+rollout.String(), digest, version, rollout, f.now, user, revision)
		// 同一节点同一作用域只允许一条在途部署（288）：先收掉旧的在途部署。
		exec(`UPDATE node_deployments SET state='cancelled' WHERE node_id=$1 AND configuration_scope_id=$2
			AND state <> ALL (ARRAY['healthy','failed','reverted','rollback_failed','cancelled'])`, node, scope)
		exec(`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,
			command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
			VALUES(gen_random_uuid(),$1,$2,1,$3,'apply',$4,gen_random_uuid(),'\x01',$5,$6::timestamptz+interval '1 hour',$6,$6,$7)`,
			rollout, node, version, state, digest, f.now, scope)
		if carries {
			exec(`INSERT INTO config_version_telemetry_site_bindings(config_version_id,site_id) VALUES($1,$2)`, version, siteID)
		}
		f.now = f.now.Add(time.Second)
	}
	// 恢复的自动发布请求：自动模式下 source_kind='site'、source_resource_id 为空（作用域级）。
	scopeRequest := func() {
		t.Helper()
		revision++
		id := uuid.New()
		exec(`INSERT INTO edge_automatic_publication_requests(id,target_scope_id,actor_scope_id,actor_user_id,actor_scope_kind,
			source_kind,source_resource_id,source_revision,operation,reason,permission_name,source_request_id,idempotency_key,
			correlation_id,request_digest,policy_revision,created_at) VALUES($1,$2,$2,$3,'tenant','site',NULL,$4,'site.batch.enable',
			'resource_mutation','sites.manage','package-suspension:restore',$5,gen_random_uuid(),$6,1,$7)`,
			id, scope, user, revision, "edgeauto."+id.String(), digest, f.now)
		exec(`INSERT INTO edge_automatic_publication_request_state_facts(request_id,sequence,state,attempt,occurred_at)
			VALUES($1,1,'pending',0,$2)`, id, f.now)
		f.now = f.now.Add(time.Second)
	}
	clearScopeRequests := func() {
		t.Helper()
		exec(`DELETE FROM edge_automatic_publication_request_state_facts WHERE request_id IN (
			SELECT id FROM edge_automatic_publication_requests WHERE target_scope_id=$1)`, scope)
		exec(`DELETE FROM edge_automatic_publication_requests WHERE target_scope_id=$1`, scope)
	}
	// 手动作用域的系统通道（edgepublish.RequestSystemRepublicationTx）。
	systemHead := func(state, trigger string) {
		t.Helper()
		exec(`INSERT INTO edge_system_republication_heads(scope_id,generation,state,triggers,due_at,attempt,created_at,updated_at)
			VALUES($1,1,$2,ARRAY[$3::text],$4,0,$4,$4)
			ON CONFLICT (scope_id) DO UPDATE SET generation=edge_system_republication_heads.generation+1,
			  state=EXCLUDED.state, triggers=EXCLUDED.triggers, updated_at=EXCLUDED.updated_at`, scope, state, trigger, f.now)
	}

	expect := func(step, sync, published string, ok bool) {
		t.Helper()
		detail, err := f.sites.Get(ctx, f.a.siteActor(), siteID)
		if err != nil || detail.AccessReadiness == nil {
			t.Fatalf("%s: detail err=%v readiness=%v", step, err, detail.AccessReadiness)
		}
		check := detail.AccessReadiness.Checks[5]
		if detail.SyncStatus != sync || check.Code != AccessCheckPublished || check.Detail != published || check.OK != ok {
			t.Fatalf("%s: sync_status=%q published=%+v, want %q / %q ok=%v", step, detail.SyncStatus, check, sync, published, ok)
		}
		for _, form := range []struct {
			name string
			arg  any
		}{{"admin", nil}, {"tenant", []uuid.UUID{scope}}} {
			var batch string
			if err := f.pool.QueryRow(ctx, `SELECT sync_status FROM site_sync_status_batch_663($1::uuid[]) WHERE out_site_id=$2`,
				form.arg, siteID).Scan(&batch); err != nil || batch != sync {
				t.Fatalf("%s: batch (%s) = %q err=%v, want %q", step, form.name, batch, err, sync)
			}
		}
		// API 筛选：按期望状态能筛到，按其他状态筛不到；列表项的接入检查与详情一致。
		for _, status := range []string{SyncStatusSynced, SyncStatusPending, SyncStatusFailed} {
			list, err := f.sites.List(ctx, f.a.siteActor(), ListFilter{Page: 1, Limit: 20, SyncStatus: status})
			if err != nil {
				t.Fatalf("%s: list %s: %v", step, status, err)
			}
			found := false
			for _, item := range list.Items {
				if item.ID != siteID {
					continue
				}
				found = true
				if item.AccessReadiness == nil || item.AccessReadiness.Checks[5].Detail != published {
					t.Fatalf("%s: list item readiness=%+v", step, item.AccessReadiness)
				}
			}
			if found != (status == sync) {
				t.Fatalf("%s: filter sync_status=%s found=%v, want %v", step, status, found, status == sync)
			}
		}
	}

	expect("never published", SyncStatusPending, "not_published", false)
	publish(false, "healthy")
	expect("latest publication lacks the site", SyncStatusPending, "site_not_in_publication", false)

	// 恢复在途：作用域级自动请求。
	scopeRequest()
	expect("scope-level automatic request in flight", SyncStatusPending, "publishing", false)
	clearScopeRequests()
	// 恢复在途：手动作用域的系统通道 package_suspension；非停站/恢复类触发器不算。
	systemHead("pending", "package_suspension")
	expect("package_suspension system republication in flight", SyncStatusPending, "publishing", false)
	systemHead("pending", "line_group")
	expect("line_group system republication", SyncStatusPending, "site_not_in_publication", false)
	systemHead("idle", "package_suspension")
	expect("system republication done", SyncStatusPending, "site_not_in_publication", false)

	publish(true, "healthy")
	expect("healthy publication", SyncStatusSynced, "", true)
	publish(true, "failed")
	expect("failed deployment", SyncStatusFailed, "publish_failed", false)

	// 主动停用：最新发布不含本站即是期望状态。
	exec(`UPDATE sites SET enabled=false, status='disabled' WHERE id=$1`, siteID) // sites_check2 pairs them
	publish(false, "healthy")
	expect("disabled site", SyncStatusSynced, "site_disabled", false)
	exec(`UPDATE sites SET enabled=true, status='active' WHERE id=$1`, siteID)

	// 暂停中：不应下发，作用域有在途请求也仍是 package_suspended。
	exec(`UPDATE package_subscriptions SET suspended_at=$2, suspend_reason='whmcs' WHERE id=$1`, subscription, f.now)
	expect("suspended", SyncStatusSynced, PackageUnavailableSuspended, false)
	scopeRequest()
	expect("suspended with a scope request in flight", SyncStatusSynced, PackageUnavailableSuspended, false)

	// WHMCS 恢复：订阅已恢复、恢复的作用域级请求仍在途，最新发布还不含本站 → 发布中。
	exec(`UPDATE package_subscriptions SET suspended_at=NULL, suspend_reason=NULL WHERE id=$1`, subscription)
	expect("unsuspended, republication in flight", SyncStatusPending, "publishing", false)
	clearScopeRequests()
	publish(true, "healthy")
	expect("unsuspended and republished", SyncStatusSynced, "", true)
}
