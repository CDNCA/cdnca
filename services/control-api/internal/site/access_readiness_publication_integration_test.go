//go:build integration

package site

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 节点 IP 记错导致本站自动发布请求失败，改正后作用域的系统重新发布已在
// 当前节点上成功，网站能访问，但“已发布到节点=发布失败”“同步失败”一直不变。判定只看当前生效发布在当前
// 承担本站的节点上的结果：失败请求被之后的发布覆盖即不再算；已退役/移出线路组节点的失败部署不计入。
func TestSitePublicationOutcomeFollowsServingNodesPostgres(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	created, err := f.createSite(f.a, f.a, "stalled.example.test")
	if err != nil {
		t.Fatal(err)
	}
	siteID, scope, user := created.Site.ID, f.a.scopeID, f.a.userID
	group, oldNode, newNode := uuid.New(), uuid.New(), uuid.New()
	digest := make([]byte, 32)
	replica := func(statements ...func(tx pgx.Tx) error) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			for _, statement := range statements {
				if err := statement(tx); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	sql := func(query string, args ...any) func(tx pgx.Tx) error {
		return func(tx pgx.Tx) error { _, err := tx.Exec(ctx, query, args...); return err }
	}
	endpoint := func(revision int, node uuid.UUID, address string) func(tx pgx.Tx) error {
		return sql(`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,
			port,region,carrier,priority,weight,enabled) VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,4,80,'hk','bgp',0,1,true)`,
			node, scope, group, revision, address)
	}
	lineRevision := func(revision int) func(tx pgx.Tx) error {
		return sql(`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,ipv4_resolved_value,
			probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,
			configuration_digest,created_by_user_id,created_at,sealed_at) VALUES($1,$2,$3,'stalled','lg-'||replace($1::uuid::text,'-',''),
			'v4-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$4,$5,now(),now())`, group, scope, revision, digest, user)
	}
	// 原节点 IP 记成了 CF 边缘地址 104.16.0.1；线路组 r1 只有它。
	replica(
		sql(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4) VALUES
			($1,$2,'hk-old','active',$3,911,'104.16.0.1'),($4,$5,'hk-new','active',$6,912,'192.0.2.61')`,
			oldNode, scope, user, newNode, scope, user),
		sql(`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,
			updated_at,display_id,resolved_value,ipv4_resolved_value) VALUES($1,$2,'stalled',1,$3,$4,now(),now(),
			(SELECT COALESCE(max(display_id),0)+1 FROM node_line_groups),'lg-'||replace($5::uuid::text,'-',''),'v4-'||replace($6::uuid::text,'-',''))`,
			group, scope, user, user, group, group),
		lineRevision(1), endpoint(1, oldNode, "104.16.0.1"),
		sql(`UPDATE sites SET node_group_id=$1 WHERE id=$2`, group, siteID),
	)

	sourceRevision := 0
	// request: the site's own automatic request at the next source revision ending in state.
	request := func(state, terminal string) {
		t.Helper()
		sourceRevision++
		id := uuid.New()
		replica(
			sql(`INSERT INTO edge_automatic_publication_requests(id,target_scope_id,actor_scope_id,actor_user_id,actor_scope_kind,
				source_kind,source_resource_id,source_revision,operation,reason,permission_name,source_request_id,idempotency_key,
				correlation_id,request_digest,policy_revision,created_at) VALUES($1,$2,$3,$4,'tenant','site',$5,$6,'site.update',
				'resource_mutation','sites.manage','req-618',$7,gen_random_uuid(),$9,1,$8)`,
				id, scope, scope, user, siteID, sourceRevision, "edgeauto."+id.String(), f.now, digest),
			sql(`INSERT INTO edge_automatic_publication_request_state_facts(request_id,sequence,state,attempt,terminal_code,occurred_at)
				VALUES($1,1,$2,1,$3,$4)`, id, state, terminal, f.now),
		)
		f.now = f.now.Add(time.Second)
	}
	// publish: a scope publication at the next source revision carrying the site, one deployment per node.
	publish := func(deployments map[uuid.UUID]string) (version uuid.UUID, ids map[uuid.UUID]uuid.UUID) {
		t.Helper()
		sourceRevision++
		version, rollout := uuid.New(), uuid.New()
		statements := []func(tx pgx.Tx) error{
			sql(`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
				generator_version,status,idempotency_key,request_digest,created_at,published_at)
				VALUES($1,$2,'\x01',$3,'stalled','1','releasable',$4,$3,$5,$5)`, version, scope, digest, "stalled-"+version.String(), f.now),
			sql(`INSERT INTO edge_config_publications(id,configuration_scope_id,source_revision,idempotency_key,request_digest,request_id,
				correlation_id,canonical_snapshot_sha256,artifact_sha256,config_version_id,rollout_id,node_count,created_at,
				expected_source_revision,target_kind,target_snapshot_sha256,contract_version,actor_user_id,actor_scope_id)
				VALUES(gen_random_uuid(),$1,$8,$2,$3,gen_random_uuid(),gen_random_uuid(),$3,$3,$4,$5,1,$6,$8,'explicit',$3,1,$7,$1)`,
				scope, "stalled-"+rollout.String(), digest, version, rollout, f.now, user, sourceRevision),
			sql(`INSERT INTO config_version_telemetry_site_bindings(config_version_id,site_id) VALUES($1,$2)`, version, siteID),
		}
		ids = map[uuid.UUID]uuid.UUID{}
		for node, state := range deployments {
			id := uuid.New()
			ids[node] = id
			statements = append(statements, sql(`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,
				command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
				VALUES($1,$2,$3,1,$4,'apply',$5,gen_random_uuid(),'\x01',$6,$7::timestamptz+interval '1 hour',$7,$7,$8)`,
				id, rollout, node, version, state, digest, f.now, scope))
		}
		replica(statements...)
		f.now = f.now.Add(time.Second)
		return version, ids
	}
	readinessAs := func(actor trustActor) (AccessCheck, string) {
		t.Helper()
		detail, err := f.sites.Get(ctx, actor.siteActor(), siteID)
		if err != nil || detail.AccessReadiness == nil {
			t.Fatalf("detail readiness=%v err=%v", detail.AccessReadiness, err)
		}
		return detail.AccessReadiness.Checks[5], detail.SyncStatus
	}
	// 平台节点名不给用户看：失败节点明细只给平台身份。
	readiness := func() (AccessCheck, string) { t.Helper(); return readinessAs(f.admin) }

	// ① 本站请求的发布在记错 IP 的节点上失败：发布失败、同步失败，带出失败节点名与原因。
	request("failed", "deployment_failed")
	_, failedIDs := publish(map[uuid.UUID]string{oldNode: "failed"})
	replica(sql(`INSERT INTO deployment_status_events(id,deployment_id,event_id,attempt,transition_sequence,state,payload,payload_sha256,
		occurred_at,received_at,error_code) VALUES(gen_random_uuid(),$1,gen_random_uuid(),1,1,'failed','\x01',
		$3,$2,$2,'ERROR_CODE_PRECHECK_FAILED')`,
		failedIDs[oldNode], f.now, digest))
	if published, sync := readiness(); published.Detail != "publish_failed" || sync != SyncStatusFailed ||
		len(published.FailedNodes) != 1 || published.FailedNodes[0].NodeName != "hk-old" ||
		published.FailedNodes[0].ErrorCode == nil || *published.FailedNodes[0].ErrorCode != "ERROR_CODE_PRECHECK_FAILED" {
		t.Fatalf("failed on the mis-addressed node: published=%+v sync=%q", published, sync)
	}
	// 租户（站点所有者）的详情与列表：只有失败节点数与归一化原因，响应里没有节点名、节点 ID、节点 IP。
	if published, _ := readinessAs(f.a); published.Detail != "publish_failed" || len(published.FailedNodes) != 0 ||
		published.FailedNodeCount != 1 || !slices.Equal(published.FailedNodeReasons, []string{"precheck_failed"}) {
		t.Fatalf("tenant readiness: published=%+v, want count 1 / [precheck_failed] without nodes", published)
	}
	tenantDetail, err := f.sites.Get(ctx, f.a.siteActor(), siteID)
	if err != nil {
		t.Fatal(err)
	}
	tenantList, err := f.sites.List(ctx, f.a.siteActor(), ListFilter{Page: 1, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]any{"detail": tenantDetail, "list": tenantList} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, leak := range []string{"hk-old", "hk-new", oldNode.String(), newNode.String(), "104.16.0.1", "192.0.2.61", "node_name", "node_id"} {
			if strings.Contains(string(encoded), leak) {
				t.Fatalf("tenant %s response leaks %q", name, leak)
			}
		}
	}

	// ② 节点改正：旧节点退役，线路组 r2 换成新节点；系统重新发布（不是本站请求）在新节点上成功。
	replica(lineRevision(2), endpoint(2, newNode, "192.0.2.61"),
		sql(`UPDATE node_line_groups SET current_revision=2 WHERE id=$1`, group),
		sql(`UPDATE nodes SET admin_state='retired' WHERE id=$1`, oldNode))
	publish(map[uuid.UUID]string{newNode: "healthy", oldNode: "failed"})
	if published, sync := readiness(); !published.OK || sync != SyncStatusSynced {
		t.Fatalf("after the healthy republication on the serving node: published=%+v sync=%q, want ok/synced", published, sync)
	}

	// ③ 当前承担本站的节点失败仍是失败，只列它；退役节点不列。
	publish(map[uuid.UUID]string{newNode: "failed", oldNode: "failed"})
	if published, sync := readiness(); published.Detail != "publish_failed" || sync != SyncStatusFailed ||
		len(published.FailedNodes) != 1 || published.FailedNodes[0].NodeName != "hk-new" {
		t.Fatalf("serving node failed: published=%+v sync=%q", published, sync)
	}
	// ④ 节点上该作用域的当前配置已是本次发布版本（如同步重试送达）：已发布。
	version, _ := publish(map[uuid.UUID]string{newNode: "failed"})
	replica(sql(`INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,updated_at)
		VALUES($1,$2,$3,now()) ON CONFLICT (node_id,configuration_scope_id) DO UPDATE SET current_config_version_id=EXCLUDED.current_config_version_id`,
		newNode, scope, version))
	if published, sync := readiness(); !published.OK || sync != SyncStatusSynced {
		t.Fatalf("node already runs the current version: published=%+v sync=%q", published, sync)
	}

	// ⑤ 本站新请求在发布前就失败（没有覆盖它的发布）：发布失败，带请求终态码，不列节点。
	request("failed", "no_target_nodes")
	if published, sync := readiness(); published.Detail != "publish_failed" || sync != SyncStatusFailed ||
		published.FailureCode != "no_target_nodes" || len(published.FailedNodes) != 0 {
		t.Fatalf("request failed before publishing: published=%+v sync=%q", published, sync)
	}
}

// 重新发布：手动发布作用域经系统通道排一次立即的重新发布并记审计；他人站点 404；
// 网站停用拒绝；在途时 409 publish_in_flight。
func TestSiteRepublishPostgres(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	created, err := f.createSite(f.a, f.a, "republish.example.test")
	if err != nil {
		t.Fatal(err)
	}
	siteID := created.Site.ID
	if _, err := f.sites.Republish(ctx, f.b.siteActor(), siteID, "req-other"); err != ErrNotFound {
		t.Fatalf("other tenant republish err=%v, want not found", err)
	}
	if _, err := f.sites.Republish(ctx, f.a.siteActor(), siteID, "req-618-a"); err != nil {
		t.Fatalf("republish: %v", err)
	}
	var heads, audits int
	if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1),
		(SELECT count(*) FROM audit_events WHERE action='site.republish' AND resource_id=$2::text)`, f.a.scopeID, siteID).
		Scan(&heads, &audits); err != nil || heads != 1 || audits != 1 {
		t.Fatalf("manual scope republication heads=%d audits=%d err=%v", heads, audits, err)
	}
	// In flight: the site's own automatic request still pending.
	id := uuid.New()
	if err := pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO edge_automatic_publication_requests(id,target_scope_id,actor_scope_id,actor_user_id,
			actor_scope_kind,source_kind,source_resource_id,source_revision,operation,reason,permission_name,source_request_id,
			idempotency_key,correlation_id,request_digest,policy_revision,created_at) VALUES($1,$2,$2,$3,'tenant','site',$4,999,
			'site.update','resource_mutation','sites.manage','req-618-p',$5,gen_random_uuid(),$6,1,now())`,
			id, f.a.scopeID, f.a.userID, siteID, "edgeauto."+id.String(), make([]byte, 32)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO edge_automatic_publication_request_state_facts(request_id,sequence,state,attempt,occurred_at)
			VALUES($1,1,'pending',0,now())`, id)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sites.Republish(ctx, f.a.siteActor(), siteID, "req-618-b"); err != ErrPublishInFlight {
		t.Fatalf("in-flight republish err=%v, want ErrPublishInFlight", err)
	}
}
