//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestCommunityDefaultPublication705: 705 gives every tenant scope that has a live site but no automatic
// publication policy a community_default automatic policy acting as the earliest active platform administrator
// (a manual scope and a scope without sites are left alone), and counts a site bound to no package as belonging in
// the publication. Down restores the 701/692 functions and keeps the policies; up again adds no second policy.
func TestCommunityDefaultPublication705(t *testing.T) {
	const version = 705
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	var platform uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL LIMIT 1`).
		Scan(&platform); err != nil {
		platform = uuid.New()
		mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	}
	// A platform member without platform.admin joined first: not the policy's actor.
	viewer, admin, role := uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash,created_at) VALUES
		($1,'ce705-viewer','viewer','unused',now()-interval '2 days'),($2,'ce705-admin','admin','unused',now()-interval '1 day')`,
		viewer, admin)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($1,$3)`, platform, viewer, admin)
	mustExec(t, pool, `INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'ce705_admin',true)`, role, platform)
	mustExec(t, pool, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'platform.admin')`, role)
	mustExec(t, pool, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, platform, admin, role)

	type tenant struct{ scope, user, site uuid.UUID }
	seed := func(name string, withSite bool) tenant {
		t.Helper()
		item := tenant{scope: uuid.New(), user: uuid.New()}
		tenantID := uuid.New()
		mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, name)
		mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, item.scope, tenantID)
		mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'unused')`, item.user, name)
		mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, item.scope, item.user)
		if !withSite {
			return item
		}
		item.site = uuid.New()
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,
				created_by_user_id,updated_by_user_id) VALUES($1,$2,1,$3,$4,ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3)`,
				item.site, item.scope, item.user, name+".example.test"); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, item.site); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, item.site)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return item
	}
	plain, manual, empty := seed("ce705-plain", true), seed("ce705-manual", true), seed("ce705-empty", false)
	mustExec(t, pool, `INSERT INTO edge_automatic_publication_policy_facts(target_scope_id,revision,mode,node_ids,
		activation_timeout_ms,observation_window_ms,required_consecutive_successes,max_attempts,deadline_window_seconds,
		actor_scope_id,actor_user_id,reason,created_at) VALUES($1,1,'manual','{}',30000,15000,2,3,600,$1,$2,'operator',now())`,
		manual.scope, manual.user)

	type policy struct {
		count                   int
		mode, reason            string
		actorScope, actorUser   uuid.UUID
		activation, observation int64
		successes, attempts     int
		deadline                int
	}
	policyOf := func(scope uuid.UUID) policy {
		t.Helper()
		var item policy
		if err := pool.QueryRow(ctx, `SELECT count(*) OVER (),mode,reason,actor_scope_id,actor_user_id,activation_timeout_ms,
			observation_window_ms,required_consecutive_successes,max_attempts,deadline_window_seconds
			FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1 ORDER BY revision DESC LIMIT 1`, scope).
			Scan(&item.count, &item.mode, &item.reason, &item.actorScope, &item.actorUser, &item.activation, &item.observation,
				&item.successes, &item.attempts, &item.deadline); err != nil && err != pgx.ErrNoRows {
			t.Fatal(err)
		}
		return item
	}
	expected := func(item tenant) bool {
		t.Helper()
		var value bool
		if err := pool.QueryRow(ctx, `SELECT site_publication_expected_692($1,$2)`, item.scope, item.site).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	community := policy{count: 1, mode: "automatic", reason: "community_default", actorScope: platform, actorUser: admin,
		activation: 60000, observation: 30000, successes: 3, attempts: 3, deadline: 1800}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		if got := policyOf(plain.scope); got != community {
			t.Fatalf("after %s: scope with a site got %+v, want %+v", step, got, community)
		}
		if got := policyOf(manual.scope); got.count != 1 || got.mode != "manual" {
			t.Fatalf("after %s: manual scope policy %+v, want its own manual one only", step, got)
		}
		if got := policyOf(empty.scope); got.count != 0 {
			t.Fatalf("after %s: scope without sites got %+v", step, got)
		}
		if got := expected(plain); got != (step == "up") {
			t.Fatalf("after %s: site without a package expected in the publication=%v", step, got)
		}
	}
}
