//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestCommunityL2PlatformDefault706: a site bound to no package and no line group, its L2 following the line
// group (l2_mode package), is served by the platform default line group and that group's L2 members. With the
// line group node healthy and the L2 node failed, 706 reports the publication failed (618 and 663); down restores
// the 705 reading (the L2 node not counted: succeeded / synced); up again reports it failed.
func TestCommunityL2PlatformDefault706(t *testing.T) {
	const version = 706
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	var platform uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL LIMIT 1`).
		Scan(&platform); err != nil {
		platform = uuid.New()
		mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	}
	tenantID, scope, user := uuid.New(), uuid.New(), uuid.New()
	site, group, node, l2Node, config := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	configVersion, rollout := uuid.New(), uuid.New()
	digest := make([]byte, 32)
	steps := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'ce706')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scope, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'ce706','ce706','unused')`, []any{user}},
		{`INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
			VALUES($1,$2,1,$3,'ce706.example.test',ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3)`, []any{site, scope, user}},
		{`INSERT INTO site_origin_pools(site_id,l2_mode) VALUES($1,'package')`, []any{site}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4) VALUES($1,$2,'ce706-l1','active',$3,1,'192.0.2.91'),
			($4,$2,'ce706-l2','active',$3,2,'192.0.2.92')`, []any{node, platform, user, l2Node}},
		{`INSERT INTO l2_topology_configs(id,tenant_scope_id,name,region,mode,load_method,created_by_user_id,updated_by_user_id,
			created_at,updated_at) VALUES($1,$2,'ce706','hk','global','rr',$3,$3,now(),now())`, []any{config, platform, user}},
		{`INSERT INTO l2_topology_nodes(id,tenant_scope_id,config_id,node_id,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES(gen_random_uuid(),$1,$2,$3,$4,$4,now(),now())`, []any{platform, config, l2Node, user}},
		{`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,
			updated_at,display_id,resolved_value,ipv4_resolved_value,is_platform_default,l2_config_id) VALUES($1,$2,'ce706',1,$3,$3,now(),now(),
			1,'lg-'||replace($1::uuid::text,'-',''),'v4-'||replace($1::uuid::text,'-',''),true,$4)`, []any{group, platform, user, config}},
		{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,
			port,region,carrier,priority,weight,enabled) VALUES(gen_random_uuid(),$1,$2,$3,1,'192.0.2.91',4,80,'hk','bgp',0,1,true)`,
			[]any{node, platform, group}},
		{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
			generator_version,status,idempotency_key,request_digest,created_at,published_at)
			VALUES($1,$2,'\x01',$3,'ce706','1','releasable','ce706-version',$3,now(),now())`, []any{configVersion, scope, digest}},
		{`INSERT INTO edge_config_publications(id,configuration_scope_id,source_revision,idempotency_key,request_digest,request_id,
			correlation_id,canonical_snapshot_sha256,artifact_sha256,config_version_id,rollout_id,node_count,created_at,
			expected_source_revision,target_kind,target_snapshot_sha256,contract_version,actor_user_id,actor_scope_id)
			VALUES(gen_random_uuid(),$1,1,'ce706-publication',$2,gen_random_uuid(),gen_random_uuid(),$2,$2,$3,$4,2,now(),1,'explicit',$2,1,$5,$6)`,
			[]any{scope, digest, configVersion, rollout, user, platform}},
		{`INSERT INTO config_version_telemetry_site_bindings(config_version_id,site_id) VALUES($1,$2)`, []any{configVersion, site}},
		{`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,
			command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at,configuration_scope_id)
			VALUES(gen_random_uuid(),$1,$2,1,$3,'apply','healthy',gen_random_uuid(),'\x01',$4,now()+interval '1 hour',now(),now(),$5),
			(gen_random_uuid(),$1,$6,1,$3,'apply','failed',gen_random_uuid(),'\x01',$4,now()+interval '1 hour',now(),now(),$5)`,
			[]any{rollout, node, configVersion, digest, scope, l2Node}},
	}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		for _, step := range steps {
			if _, err := tx.Exec(ctx, step.query, step.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	read := func() (outcome, batched string) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT state FROM site_publication_outcome_618($1,$2)`, scope, site).Scan(&outcome); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(ctx, `SELECT sync_status FROM site_sync_status_batch_663(ARRAY[$1]::uuid[]) WHERE out_site_id=$2`,
			scope, site).Scan(&batched); err != nil {
			t.Fatal(err)
		}
		return outcome, batched
	}
	if outcome, batched := read(); outcome != "succeeded" || batched != "synced" {
		t.Fatalf("at 705: outcome=%q batch=%q, want the L2 node not counted (succeeded / synced)", outcome, batched)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		want, wantBatch := "failed", "failed"
		if step == "down" {
			want, wantBatch = "succeeded", "synced"
		}
		if outcome, batched := read(); outcome != want || batched != wantBatch {
			t.Fatalf("after %s: outcome=%q batch=%q, want %q / %q", step, outcome, batched, want, wantBatch)
		}
	}
}
