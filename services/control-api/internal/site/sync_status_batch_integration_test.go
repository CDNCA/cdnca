//go:build integration

package site

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 迁移 663：site_sync_status_batch_663 对站点集合一次计算，必须与逐站的
// site_sync_status_503(scope_id, site_id) 逐站相等。随机构造：本站/他站的自动发布请求（各种终态与在途）、
// 各种部署状态的发布（带/不带本站）、节点已运行当前版本、节点退役、站点没有线路组（无承担节点）。
// 每一步之后逐站比较；管理员形式 (NULL) 与租户形式 (ARRAY[scope]) 都比。
func TestSiteSyncStatusBatchMatchesPerSitePostgres(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	scope, user := f.a.scopeID, f.a.userID
	const siteCount = 8
	sites := make([]uuid.UUID, 0, siteCount)
	for i := 0; i < siteCount; i++ {
		created, err := f.createSite(f.a, f.a, fmt.Sprintf("batch-%d.example.test", i))
		if err != nil {
			t.Fatal(err)
		}
		sites = append(sites, created.Site.ID)
	}
	digest := make([]byte, 32)
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

	// 两个线路组、三个节点：组 g1 承担站点 0..3，组 g2 承担 4..5，6..7 没有线路组（无承担节点）。
	nodes := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	groups := []uuid.UUID{uuid.New(), uuid.New()}
	for i, node := range nodes {
		exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4) VALUES($1,$2,$3,'active',$4,$5,$6)`,
			node, scope, fmt.Sprintf("batch-node-%d", i), user, 940+i, fmt.Sprintf("192.0.2.%d", 70+i))
	}
	for i, group := range groups {
		exec(`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,
			updated_at,display_id,resolved_value,ipv4_resolved_value) VALUES($1,$2,$3,1,$4,$4,now(),now(),
			(SELECT COALESCE(max(display_id),0)+1 FROM node_line_groups),'lg-'||replace($1::uuid::text,'-',''),'v4-'||replace($1::uuid::text,'-',''))`,
			group, scope, fmt.Sprintf("batch-%d", i), user)
		exec(`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,ipv4_resolved_value,
			probe_interval_ms,probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,
			configuration_digest,created_by_user_id,created_at,sealed_at) VALUES($1,$2,1,'batch','lg-'||replace($1::uuid::text,'-',''),
			'v4-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$3,$4,now(),now())`, group, scope, digest, user)
	}
	endpoint := func(node, group uuid.UUID, address string) {
		exec(`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,
			port,region,carrier,priority,weight,enabled) VALUES(gen_random_uuid(),$1,$2,$3,1,$4,4,80,'hk','bgp',0,1,true)`,
			node, scope, group, address)
	}
	endpoint(nodes[0], groups[0], "192.0.2.70")
	endpoint(nodes[1], groups[0], "192.0.2.71")
	endpoint(nodes[2], groups[1], "192.0.2.72")
	for i, site := range sites {
		switch {
		case i < 4:
			exec(`UPDATE sites SET node_group_id=$1 WHERE id=$2`, groups[0], site)
		case i < 6:
			exec(`UPDATE sites SET node_group_id=$1 WHERE id=$2`, groups[1], site)
		}
	}

	rng := rand.New(rand.NewSource(663))
	clock := f.now
	tick := func() time.Time { clock = clock.Add(time.Second); return clock }
	revision := 0
	requestStates := []string{"pending", "leased", "retry_wait", "reconciling", "failed", "succeeded"}
	deploymentStates := []string{"healthy", "failed", "reverted", "rollback_failed", "cancelled", "started", "delivered"}

	request := func() {
		revision++
		id, site := uuid.New(), sites[rng.Intn(len(sites))]
		state := requestStates[rng.Intn(len(requestStates))]
		at := tick()
		var terminalCode *string // 非终态必须为 NULL，failed / succeeded 必须有码（086 约束）
		switch state {
		case "failed":
			code := "deployment_failed"
			terminalCode = &code
		case "succeeded":
			code := "published"
			terminalCode = &code
		}
		exec(`INSERT INTO edge_automatic_publication_requests(id,target_scope_id,actor_scope_id,actor_user_id,actor_scope_kind,
			source_kind,source_resource_id,source_revision,operation,reason,permission_name,source_request_id,idempotency_key,
			correlation_id,request_digest,policy_revision,created_at) VALUES($1,$2,$2,$3,'tenant','site',$4,$5,'site.update',
			'resource_mutation','sites.manage','req-663',$6,gen_random_uuid(),$7,1,$8)`,
			id, scope, user, site, revision, "edgeauto."+id.String(), digest, at)
		// 086 的行级约束：各状态要求的附属列不同（租约、重试时间与错误类、发布与 rollout、终态码、尝试次数）。
		exec(`INSERT INTO edge_automatic_publication_request_state_facts(request_id,sequence,state,attempt,lease_owner,lease_token,
			lease_expires_at,publication_id,rollout_id,available_at,terminal_code,error_class,occurred_at)
			VALUES($1,1,$2::text,CASE WHEN $2::text='pending' THEN 0 ELSE 1 END,
			CASE WHEN $2::text='leased' THEN 'batch-test' END,
			CASE WHEN $2::text='leased' THEN gen_random_uuid() END,
			CASE WHEN $2::text='leased' THEN $4::timestamptz + interval '1 hour' END,
			CASE WHEN $2::text IN ('reconciling','succeeded') THEN gen_random_uuid() END,
			CASE WHEN $2::text IN ('reconciling','succeeded') THEN gen_random_uuid() END,
			CASE WHEN $2::text='retry_wait' THEN $4::timestamptz + interval '1 minute' END,
			$3::text,
			CASE WHEN $2::text='retry_wait' THEN 'publish_outcome_unknown' END,
			$4)`, id, state, terminalCode, at)
	}
	publish := func() {
		revision++
		version, rollout := uuid.New(), uuid.New()
		at := tick()
		exec(`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
			generator_version,status,idempotency_key,request_digest,created_at,published_at)
			VALUES($1,$2,'\x01',$3,'batch','1','releasable',$4,$3,$5,$5)`, version, scope, digest, "batch-"+version.String(), at)
		exec(`INSERT INTO edge_config_publications(id,configuration_scope_id,source_revision,idempotency_key,request_digest,request_id,
			correlation_id,canonical_snapshot_sha256,artifact_sha256,config_version_id,rollout_id,node_count,created_at,
			expected_source_revision,target_kind,target_snapshot_sha256,contract_version,actor_user_id,actor_scope_id)
			VALUES(gen_random_uuid(),$1,$8,$2,$3,gen_random_uuid(),gen_random_uuid(),$3,$3,$4,$5,1,$6,$8,'explicit',$3,1,$7,$1)`,
			scope, "batch-"+rollout.String(), digest, version, rollout, at, user, revision)
		for _, site := range sites {
			if rng.Intn(4) != 0 { // 四分之一的站点不在本次发布里（excluded）
				exec(`INSERT INTO config_version_telemetry_site_bindings(config_version_id,site_id) VALUES($1,$2)`, version, site)
			}
		}
		for _, node := range nodes {
			if rng.Intn(5) == 0 { // 有的节点这次没有部署（undelivered / pending 的来源）
				continue
			}
			// 同一节点同一作用域只允许一条在途部署（288 唯一索引）：新部署前先收掉旧的在途部署。
			exec(`UPDATE node_deployments SET state='cancelled' WHERE node_id=$1 AND configuration_scope_id=$2
				AND state <> ALL (ARRAY['healthy','failed','reverted','rollback_failed','cancelled'])`, node, scope)
			exec(`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,
				command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
				VALUES(gen_random_uuid(),$1,$2,1,$3,'apply',$4,gen_random_uuid(),'\x01',$5,$6::timestamptz+interval '1 hour',$6,$6,$7)`,
				rollout, node, version, deploymentStates[rng.Intn(len(deploymentStates))], digest, at, scope)
		}
	}
	nodeRuns := func() {
		node := nodes[rng.Intn(len(nodes))]
		exec(`INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,updated_at)
			VALUES($1,$2,(SELECT config_version_id FROM edge_config_publications WHERE configuration_scope_id=$2
				ORDER BY created_at DESC, id DESC LIMIT 1),now())
			ON CONFLICT (node_id,configuration_scope_id) DO UPDATE SET current_config_version_id=EXCLUDED.current_config_version_id`,
			node, scope)
	}
	toggleNode := func() {
		node := nodes[rng.Intn(len(nodes))]
		exec(`UPDATE nodes SET admin_state=CASE WHEN admin_state='active' THEN 'retired' ELSE 'active' END WHERE id=$1`, node)
	}

	compare := func(step int) {
		t.Helper()
		for _, form := range []struct {
			name string
			arg  any
		}{{"admin", nil}, {"tenant", []uuid.UUID{scope}}} {
			rows, err := f.pool.Query(ctx, `SELECT b.out_site_id, b.sync_status, site_sync_status_503(b.out_scope_id, b.out_site_id)
				FROM site_sync_status_batch_663($1::uuid[]) b JOIN sites s ON s.id=b.out_site_id WHERE s.scope_id=$2`, form.arg, scope)
			if err != nil {
				t.Fatal(err)
			}
			seen := map[uuid.UUID]bool{}
			for rows.Next() {
				var site uuid.UUID
				var batch, single string
				if err := rows.Scan(&site, &batch, &single); err != nil {
					t.Fatal(err)
				}
				seen[site] = true
				if batch != single {
					rows.Close()
					t.Fatalf("step %d (%s): site %s batch=%q per-site=%q", step, form.name, site, batch, single)
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if len(seen) != len(sites) {
				t.Fatalf("step %d (%s): batch covered %d of %d sites", step, form.name, len(seen), len(sites))
			}
		}
	}

	compare(0) // 没有任何请求和发布：全部 synced
	counts := map[string]int{}
	for step := 1; step <= 60; step++ {
		switch rng.Intn(5) {
		case 0, 1:
			request()
		case 2:
			publish()
		case 3:
			nodeRuns()
		default:
			toggleNode()
		}
		compare(step)
		rows, err := f.pool.Query(ctx, `SELECT sync_status, count(*) FROM site_sync_status_batch_663(ARRAY[$1]::uuid[]) GROUP BY 1`, scope)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var status string
			var n int
			if err := rows.Scan(&status, &n); err != nil {
				t.Fatal(err)
			}
			counts[status] += n
		}
		rows.Close()
	}
	// 随机序列要真的覆盖到三种结果，否则等价性比较没有意义。
	for _, status := range []string{"synced", "failed", "pending"} {
		if counts[status] == 0 {
			t.Fatalf("random sequence never produced %q (counts=%v); change the seed", status, counts)
		}
	}
}
