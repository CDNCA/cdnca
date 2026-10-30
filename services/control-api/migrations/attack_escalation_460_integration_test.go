//go:build integration

package migrations_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestAttackEscalation460 rolls 460 up, down and up, then checks the DB
// guards: a grant needs an owner or a regrantable upstream grant (P4603),
// B needs a usable high defense group (P4604), C an unlimited one (P4605).
func TestAttackEscalation460(t *testing.T) {
	const version = 460
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	user := uuid.New()
	platform, agent, leaf := uuid.New(), uuid.New(), uuid.New()
	high, unlimited, normal := uuid.New(), uuid.New(), uuid.New()
	product := uuid.New()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(tx pgx.Tx, sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(tx, `SET LOCAL session_replication_role = replica`)
	exec(tx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'esc','hash')`, user, "esc-460-"+user.String())
	exec(tx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	for _, scope := range []uuid.UUID{agent, leaf} {
		tenant := uuid.New()
		exec(tx, `INSERT INTO tenants(id,display_name) VALUES($1,'esc 460')`, tenant)
		exec(tx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scope, tenant)
	}
	for index, group := range []uuid.UUID{high, unlimited, normal} {
		exec(tx, `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,
			created_at,updated_at,display_id,resolved_value,ipv4_resolved_value)
			VALUES($1::uuid,$2,$3,1,$4,$4,$5,$5,$6,'lg-'||replace($1::uuid::text,'-',''),'v4-'||replace($1::uuid::text,'-',''))`,
			group, platform, "esc-460-"+group.String()[:8], user, now, 46000+index)
	}
	exec(tx, `INSERT INTO package_products(id,name,enabled,sort_order,spec,revision,created_by_user_id,updated_by_user_id,
		created_at,updated_at) VALUES($1,$2,true,1,'{}',1,$3,$3,$4,$4)`, product, "esc-460-"+product.String()[:8], user, now)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, `INSERT INTO node_line_group_tiers(tenant_scope_id,line_group_id,tier,updated_by_user_id,updated_at)
		VALUES($1,$2,'high_defense',$4,$5),($1,$3,'unlimited',$4,$5)`, platform, high, unlimited, user, now)

	grant := func(grantor, grantee uuid.UUID, regrant bool) error {
		_, err := pool.Exec(ctx, `INSERT INTO node_line_group_grants(id,owner_scope_id,line_group_id,grantor_scope_id,
			grantee_scope_id,may_regrant,created_by_user_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
			uuid.New(), platform, high, grantor, grantee, regrant, user, now)
		return err
	}
	if err := grant(agent, leaf, false); sqlState(err) != "P4603" {
		t.Fatalf("grant by a scope without a grant: %v, want P4603", err)
	}
	if err := grant(platform, agent, false); err != nil {
		t.Fatalf("owner grant: %v", err)
	}
	if err := grant(agent, leaf, false); sqlState(err) != "P4603" {
		t.Fatalf("regrant without may_regrant: %v, want P4603", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_line_group_grants SET may_regrant=true WHERE grantee_scope_id=$1`, agent); sqlState(err) != "P4602" {
		t.Fatalf("grant mutation: %v, want P4602", err)
	}

	policy := func(owner uuid.UUID, b, c *uuid.UUID) error {
		bOwner, cOwner := any(nil), any(nil)
		if b != nil {
			bOwner = platform
		}
		if c != nil {
			cOwner = platform
		}
		_, err := pool.Exec(ctx, `INSERT INTO escalate_package_policies(product_id,owner_scope_id,b_owner_scope_id,
			b_line_group_id,c_owner_scope_id,c_line_group_id,thresholds,sustain_seconds,recover_permille,min_dwell_seconds,
			revision,updated_by_user_id,updated_at) VALUES($1,$2,$3,$4,$5,$6,'{}',30,500,1800,1,$7,$8)
			ON CONFLICT (product_id) DO UPDATE SET owner_scope_id=EXCLUDED.owner_scope_id,
			b_owner_scope_id=EXCLUDED.b_owner_scope_id,b_line_group_id=EXCLUDED.b_line_group_id,
			c_owner_scope_id=EXCLUDED.c_owner_scope_id,c_line_group_id=EXCLUDED.c_line_group_id`,
			product, owner, bOwner, b, cOwner, c, user, now)
		return err
	}
	if err := policy(platform, &normal, nil); sqlState(err) != "P4604" {
		t.Fatalf("B on a normal group: %v, want P4604", err)
	}
	if err := policy(platform, &unlimited, nil); sqlState(err) != "P4604" {
		t.Fatalf("B on an unlimited group: %v, want P4604", err)
	}
	if err := policy(platform, nil, &high); sqlState(err) != "P4605" {
		t.Fatalf("C on a high defense group: %v, want P4605", err)
	}
	if err := policy(leaf, &high, nil); sqlState(err) != "P4604" {
		t.Fatalf("B on a group not granted to the owner: %v, want P4604", err)
	}
	if err := policy(agent, &high, nil); err != nil {
		t.Fatalf("B on a granted high defense group: %v", err)
	}
	if err := policy(platform, &high, &unlimited); err != nil {
		t.Fatalf("own B and C: %v", err)
	}
	// Site state: a lock needs who locked it.
	site := uuid.New()
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exec(tx, `SET LOCAL session_replication_role = replica`)
	exec(tx, `INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,46100,$3,'esc-460.example.test',ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3)`, site, leaf, user)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	state := func(locked any, by any) error {
		_, err := pool.Exec(ctx, `INSERT INTO escalate_site_states(tenant_scope_id,site_id,level,applied_level,entered_at,
			locked_level,locked_by_user_id,revision,updated_at) VALUES($1,$2,'D','D',$3,$4,$5,1,$3)
			ON CONFLICT (tenant_scope_id,site_id) DO UPDATE SET locked_level=EXCLUDED.locked_level`, leaf, site, now, locked, by)
		return err
	}
	if err := state("D", nil); sqlState(err) != "23514" {
		t.Fatalf("lock without actor: %v, want 23514", err)
	}
	if err := state("D", user); err != nil {
		t.Fatalf("lock: %v", err)
	}
	mustExec(t, pool, `INSERT INTO escalate_events(id,tenant_scope_id,site_id,from_level,to_level,reason,occurred_at)
		VALUES($1,$2,$3,'C','D','escalate',$4)`, uuid.New(), leaf, site, now)
	// S3 route: blackhole needs its since, a line group target needs a group.
	route := func(target string, group, since any) error {
		_, err := pool.Exec(ctx, `INSERT INTO escalate_site_routes(tenant_scope_id,site_id,line_owner_scope_id,line_group_id,
			dns_target,dns_changed_at,blackhole_since,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$6)
			ON CONFLICT (tenant_scope_id,site_id) DO UPDATE SET dns_target=EXCLUDED.dns_target,
			line_owner_scope_id=EXCLUDED.line_owner_scope_id,line_group_id=EXCLUDED.line_group_id,
			blackhole_since=EXCLUDED.blackhole_since`, leaf, site, func() any {
			if group == nil {
				return nil
			}
			return platform
		}(), group, target, now, since)
		return err
	}
	if err := route("blackhole", nil, nil); sqlState(err) != "23514" {
		t.Fatalf("blackhole without since: %v, want 23514", err)
	}
	if err := route("line_group", nil, nil); sqlState(err) != "23514" {
		t.Fatalf("line_group without a group: %v, want 23514", err)
	}
	if err := route("line_group", high, nil); err != nil {
		t.Fatalf("line group route: %v", err)
	}
	// The attack escalation reason and trigger are accepted.
	var constraints int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint WHERE conname IN ('aggregated_edge_switch_events_reason_460_check',
		'dns_cname_retargets_ttl_460_check','dns_cname_retargets_node_group_460_fkey')`).Scan(&constraints); err != nil || constraints != 3 {
		t.Fatalf("460 constraints = %d %v", constraints, err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down with rows: %v", err)
	}
}
