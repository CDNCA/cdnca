//go:build integration

package site

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// （迁移 693）：同步状态与接入检查按当前生效权益的套餐线路
// 判断承担本站的节点（与发布编译同一来源），不读初购快照。站点无显式线路，初购 A 线路只含节点甲，
// 改到 B 后只含节点乙，再回切 A；详情（site_sync_status_503）、批量（site_sync_status_batch_663 管理员 /
// 租户两种形式）、列表筛选与接入检查 published 对每一步给同一口径。
func TestSitePublicationCurrentPackageLinePostgres(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	created, err := f.createSite(f.a, f.a, "current-line.example.test")
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

	// 线路 A 只含节点甲，线路 B 只含节点乙；两边节点不重叠。
	lineGroup := func(name, address string, display int) (group, node uuid.UUID) {
		t.Helper()
		group, node = uuid.New(), uuid.New()
		exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4) VALUES($1,$2,$3,'active',$4,$5,$6)`,
			node, scope, name, user, display, address)
		exec(`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,
			updated_at,display_id,resolved_value,ipv4_resolved_value) VALUES($1,$2,$3,1,$4,$4,now(),now(),
			(SELECT COALESCE(max(display_id),0)+1 FROM node_line_groups),'lg-'||replace($1::uuid::text,'-',''),'v4-'||replace($1::uuid::text,'-',''))`,
			group, scope, name, user)
		exec(`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,ipv4_resolved_value,
			probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,
			configuration_digest,created_by_user_id,created_at,sealed_at) VALUES($1,$2,1,$3,'lg-'||replace($1::uuid::text,'-',''),
			'v4-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$4,$5,now(),now())`, group, scope, name, digest, user)
		exec(`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,
			port,region,carrier,priority,weight,enabled) VALUES(gen_random_uuid(),$1,$2,$3,1,$4::inet,4,80,'hk','bgp',0,1,true)`,
			node, scope, group, address)
		return group, node
	}
	lineA, nodeJia := lineGroup("line-a", "192.0.2.91", 9531)
	lineB, nodeYi := lineGroup("line-b", "192.0.2.92", 9532)
	snapshot := func(line uuid.UUID) string {
		return `{"revision":1,"name":"current-line","spec":{"node_group_id":"` + line.String() + `"}}`
	}

	// 订阅初购快照为 A（package_subscriptions.product_snapshot 是不可变的初购事实），权益 rev1 同为 A；站点无显式线路。
	subscription, product := uuid.New(), uuid.New()
	exec(`INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,site_limit,
		domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,tcp_factor_numerator,
		tcp_factor_denominator,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,$5,1,$6::jsonb,1,1,1,0,$3,$3::timestamptz+interval '30 days',
		'UTC','monthly',1,1,$4,$4,$3,$3)`, subscription, scope, f.now, f.admin.userID, product, snapshot(lineA))
	exec(`UPDATE sites SET package_subscription_id=$2, package_id=$3, node_group_id=NULL WHERE id=$1`, siteID, subscription, product)
	entitlement := 0
	change := func(line uuid.UUID) {
		t.Helper()
		entitlement++
		operation, supersedes := "manual_open", any(nil)
		effective := "now() - interval '1 hour'"
		if entitlement > 1 {
			operation, supersedes, effective = "admin_edit", entitlement-1, "clock_timestamp()"
		}
		exec(`INSERT INTO package_subscription_entitlement_versions(subscription_id,revision,supersedes_subscription_id,
			supersedes_revision,tenant_scope_id,effective_at,effective_until,product_id,product_revision,product_snapshot,
			site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,tcp_factor_numerator,tcp_factor_denominator,
			currency,entitlement_status,source_order_id,operation,created_by_user_id,created_at,commit_sequence)
			VALUES($1::uuid,$2,CASE WHEN $3::bigint IS NULL THEN NULL ELSE $1::uuid END,$3,$4,`+effective+`,NULL,$5,1,$6::jsonb,
			1,1,1,0,'UTC','monthly',1,1,'CNY','active',NULL,$7,$8,clock_timestamp(),$2)`,
			subscription, entitlement, supersedes, scope, product, snapshot(line), operation, f.admin.userID)
	}
	change(lineA)

	revision := 0
	// publish: a publication carrying the site whose rollout deployed to the
	// given nodes in the given states (no entry: never deployed there).
	publish := func(states map[uuid.UUID]string) {
		t.Helper()
		revision++
		version, rollout := uuid.New(), uuid.New()
		exec(`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
			generator_version,status,idempotency_key,request_digest,created_at,published_at)
			VALUES($1,$2,'\x01',$3,'current-line','1','releasable',$4,$3,$5,$5)`, version, scope, digest, "current-line-"+version.String(), f.now)
		exec(`INSERT INTO edge_config_publications(id,configuration_scope_id,source_revision,idempotency_key,request_digest,request_id,
			correlation_id,canonical_snapshot_sha256,artifact_sha256,config_version_id,rollout_id,node_count,created_at,
			expected_source_revision,target_kind,target_snapshot_sha256,contract_version,actor_user_id,actor_scope_id)
			VALUES(gen_random_uuid(),$1,$8,$2,$3,gen_random_uuid(),gen_random_uuid(),$3,$3,$4,$5,$9,$6,$8,'explicit',$3,1,$7,$1)`,
			scope, "current-line-"+rollout.String(), digest, version, rollout, f.now, user, revision, len(states))
		for node, state := range states {
			// 同一节点同一作用域只允许一条在途部署（288）：先收掉旧的在途部署。
			exec(`UPDATE node_deployments SET state='cancelled' WHERE node_id=$1 AND configuration_scope_id=$2
				AND state <> ALL (ARRAY['healthy','failed','reverted','rollback_failed','cancelled'])`, node, scope)
			exec(`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,
				command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
				VALUES(gen_random_uuid(),$1,$2,1,$3,'apply',$4,gen_random_uuid(),'\x01',$5,$6::timestamptz+interval '1 hour',$6,$6,$7)`,
				rollout, node, version, state, digest, f.now, scope)
		}
		exec(`INSERT INTO config_version_telemetry_site_bindings(config_version_id,site_id) VALUES($1,$2)`, version, siteID)
		f.now = f.now.Add(time.Second)
	}

	expect := func(step, sync, published, failureCode string, ok bool) {
		t.Helper()
		detail, err := f.sites.Get(ctx, f.a.siteActor(), siteID)
		if err != nil || detail.AccessReadiness == nil {
			t.Fatalf("%s: detail err=%v readiness=%v", step, err, detail.AccessReadiness)
		}
		check := detail.AccessReadiness.Checks[5]
		if detail.SyncStatus != sync || check.Code != AccessCheckPublished || check.Detail != published || check.OK != ok ||
			check.FailureCode != failureCode {
			t.Fatalf("%s: sync_status=%q published=%+v, want %q / %q ok=%v failure_code=%q",
				step, detail.SyncStatus, check, sync, published, ok, failureCode)
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
	const undelivered = "serving_nodes_undelivered"

	// 套餐 A：甲健康即已同步。
	publish(map[uuid.UUID]string{nodeJia: "healthy"})
	expect("package A, node 甲 healthy", SyncStatusSynced, "", "", true)

	// 改到 B（初购快照仍是 A）：甲健康而乙未部署 → 承担本站的乙从未收到 → 失败。
	change(lineB)
	expect("package B, 甲 healthy, 乙 never deployed", SyncStatusFailed, "publish_failed", undelivered, false)

	// 乙无 ACK（甲仍健康）→ 发布中。
	publish(map[uuid.UUID]string{nodeJia: "healthy", nodeYi: "queued"})
	expect("package B, 乙 not acknowledged", SyncStatusPending, "publishing", "", false)

	// 乙健康 → 已同步（甲不再承担本站，无部署也不影响）。
	publish(map[uuid.UUID]string{nodeYi: "healthy"})
	expect("package B, 乙 healthy", SyncStatusSynced, "", "", true)

	// 回切 A：最新发布只到了乙 → 甲从未收到 → 失败；甲健康后已同步。
	change(lineA)
	expect("back to package A, 甲 never deployed", SyncStatusFailed, "publish_failed", undelivered, false)
	publish(map[uuid.UUID]string{nodeJia: "healthy"})
	expect("back to package A, 甲 healthy", SyncStatusSynced, "", "", true)
}
