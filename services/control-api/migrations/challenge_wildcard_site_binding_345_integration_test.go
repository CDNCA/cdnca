//go:build integration

package migrations_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestChallengeWildcardSiteBinding345: before 345 a wildcard site's JS
// challenge (its policy names one host under the wildcard, 053) cannot be
// bound (138: binding.host = sites.domain). After it the binding names a host
// the wildcard covers, moves with the active revision's host, and exact sites
// keep 138's rule; down refuses while a wildcard binding exists.
func TestChallengeWildcardSiteBinding345(t *testing.T) {
	const version = 345
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	wildcardSite, exactSite := uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'345 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'challenge-345','Challenge 345','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	for index, site := range []struct {
		id     uuid.UUID
		domain string
	}{{wildcardSite, "*.x345.example"}, {exactSite, "exact345.example"}} {
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,
				created_by_user_id,updated_by_user_id) VALUES($1,$2,$3,$4,$5,ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$4,$4)`,
				site.id, scopeID, index+1, userID, site.domain); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, site.id); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, site.id)
			return err
		}); err != nil {
			t.Fatalf("seed site %s: %v", site.domain, err)
		}
	}
	bind := func(siteID uuid.UUID, host string) error {
		_, err := pool.Exec(ctx, `INSERT INTO challenge_site_bindings_138(
			tenant_scope_id,tenant_id,site_id,host,created_at,updated_at) VALUES($1,$2,$3,$4,now(),now())`,
			scopeID, tenantID, siteID, host)
		return err
	}
	if err := bind(wildcardSite, "www.x345.example"); sqlState(err) != "P1386" {
		t.Fatalf("344 wildcard site binding: %v, want P1386 (the defect)", err)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	for site, hosts := range map[uuid.UUID][]string{
		wildcardSite: {"x345.example", "www.other345.example", "wwwx345.example"},
		exactSite:    {"www.exact345.example"},
	} {
		for _, host := range hosts {
			if err := bind(site, host); sqlState(err) != "P1386" {
				t.Fatalf("binding %s: %v, want P1386", host, err)
			}
		}
	}
	// The wildcard itself never names a binding (138's host CHECK).
	if err := bind(wildcardSite, "*.x345.example"); sqlState(err) != "23514" {
		t.Fatalf("binding the wildcard: %v, want 23514", err)
	}
	if err := bind(wildcardSite, "www.x345.example"); err != nil {
		t.Fatalf("wildcard site binding: %v", err)
	}
	if err := bind(exactSite, "exact345.example"); err != nil {
		t.Fatalf("exact site binding: %v", err)
	}

	// The binding host follows its active revision (another host's policy).
	challengeBindingRevision345(ctx, t, pool, scopeID, tenantID, userID, wildcardSite, "www.x345.example", 1)
	mustExec(t, pool, `UPDATE challenge_site_bindings_138 SET active_binding_revision=1 WHERE site_id=$1`, wildcardSite)
	challengeBindingRevision345(ctx, t, pool, scopeID, tenantID, userID, wildcardSite, "api.x345.example", 2)
	challengeBindingRevision345(ctx, t, pool, scopeID, tenantID, userID, wildcardSite, "www.x345.example", 3)
	if _, err := pool.Exec(ctx, `UPDATE challenge_site_bindings_138 SET host='api.x345.example',
		lkg_binding_revision=1,active_binding_revision=2 WHERE site_id=$1`, wildcardSite); err != nil {
		t.Fatalf("move wildcard binding to its active revision's host: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE challenge_site_bindings_138 SET host='cdn.x345.example',
		lkg_binding_revision=2,active_binding_revision=3 WHERE site_id=$1`, wildcardSite); sqlState(err) != "P3452" {
		t.Fatalf("host other than the active revision's: %v, want P3452", err)
	}
	challengeBindingRevision345(ctx, t, pool, scopeID, tenantID, userID, exactSite, "exact345.example", 1)
	if _, err := pool.Exec(ctx, `UPDATE challenge_site_bindings_138 SET host='www.exact345.example',
		active_binding_revision=1 WHERE site_id=$1`, exactSite); sqlState(err) != "P1386" {
		t.Fatalf("exact site host change: %v, want P1386", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM challenge_site_bindings_138 WHERE site_id=$1`, exactSite); sqlState(err) != "P1385" {
		t.Fatalf("delete: %v, want P1385", err)
	}

	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("down orphaned a wildcard site binding")
	}
}

// challengeBindingRevision345 records a binding revision of site for host (as the binding
// publisher does after the policy and secret facts, which this test skips).
func challengeBindingRevision345(ctx context.Context, t *testing.T, pool *pgxpool.Pool, scopeID, tenantID, userID, siteID uuid.UUID,
	host string, number int64) {
	t.Helper()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO challenge_site_binding_revisions_138(tenant_scope_id,tenant_id,site_id,host,
			binding_revision,policy_id,policy_revision,secret_rollout_id,secret_config_version_id,secret_revision,state,
			idempotency_key,request_digest,request_id,correlation_id,actor_scope_id,actor_user_id,created_at)
			VALUES($1,$2,$3,$4,$5,$6,1,$7,$8,1,'candidate',$9,decode(repeat('00',32),'hex'),$9,'challenge-345',$1,$10,now())`,
			scopeID, tenantID, siteID, host, number, uuid.New(), uuid.New(), uuid.New(),
			"challenge-345-"+siteID.String()[:8]+"-"+string(rune('0'+number)), userID)
		return err
	}); err != nil {
		t.Fatalf("binding revision %d: %v", number, err)
	}
}
