//go:build integration

package migrations_test

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestDomainTrustMigration rolls 303 up, down and up on a 302 schema with
// existing site domains, then checks the new overlap guard, the claim
// suspension exemption and release, the enable guard and the rollback refusal.
func TestDomainTrustMigration(t *testing.T) {
	const version = 303
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	now := time.Date(2026, 10, 17, 1, 0, 0, 0, time.UTC)
	tenantA, tenantB := uuid.New(), uuid.New()
	scopeA, scopeB := uuid.New(), uuid.New()
	userA, userB := uuid.New(), uuid.New()
	siteA, siteB := uuid.New(), uuid.New()
	for _, seed := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Trust A'),($2,'Trust B')`, []any{tenantA, tenantB}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2),($3,'tenant',$4)`,
			[]any{scopeA, tenantA, scopeB, tenantB}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES
			($1,'trust-299-a','Trust A','unused'),($2,'trust-299-b','Trust B','unused')`, []any{userA, userB}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($3,$4)`, []any{scopeA, userA, scopeB, userB}},
		{`INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,
			created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES
			($1,$2,1,$3,'www.a.example.test',ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3,$7,$7),
			($4,$5,1,$6,'b.example.test',ARRAY['192.0.2.11:80'],ARRAY['192.0.2.11'],$6,$6,$7,$7)`,
			[]any{siteA, scopeA, userA, siteB, scopeB, userB, now}},
	} {
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, seed.sql, seed.args...); err != nil {
				return err
			}
			if !regexpSites.MatchString(seed.sql) {
				return nil
			}
			if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id,updated_at) VALUES($1,$3),($2,$3)`,
				siteA, siteB, now); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port,weight,enabled) VALUES
				($1,1,'192.0.2.10',80,1,true),($2,1,'192.0.2.11',80,1,true)`, siteA, siteB)
			return err
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	fact := func(scope, site, user uuid.UUID, action, domain string) error {
		_, err := pool.Exec(ctx, `INSERT INTO site_domain_facts(scope_id,site_id,site_revision,action,
			canonical_domain,actor_scope_id,actor_user_id,request_id,occurred_at)
			VALUES($1,$2,1,$3,$4,$1,$5,'req-299',$6)`, scope, site, action, domain, user, now)
		return err
	}
	for _, domain := range []string{"www.a.example.test", "*.w.example.test", "gone.example.test"} {
		if err := fact(scopeA, siteA, userA, "activate", domain); err != nil {
			t.Fatalf("seed fact %s: %v", domain, err)
		}
	}
	if err := fact(scopeA, siteA, userA, "deactivate", "gone.example.test"); err != nil {
		t.Fatal(err)
	}
	guardSource := func() string {
		var source string
		if err := pool.QueryRow(ctx, `SELECT prosrc FROM pg_proc WHERE proname='guard_site_domain_fact_148'`).Scan(&source); err != nil {
			t.Fatal(err)
		}
		return source
	}
	original := guardSource()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		if step == "down" && guardSource() != original {
			t.Fatal("rollback did not restore the 148 guard body")
		}
	}
	var active []string
	if err := pool.QueryRow(ctx, `SELECT array_agg(canonical_domain ORDER BY canonical_domain) FROM site_domain_active
		WHERE scope_id=$1`, scopeA).Scan(&active); err != nil || len(active) != 2 ||
		active[0] != "*.w.example.test" || active[1] != "www.a.example.test" {
		t.Fatalf("backfilled active domains = %v (%v)", active, err)
	}
	var granted bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('cdnca_control_app','domain_ownerships','UPDATE') AND
		has_table_privilege('cdnca_control_runtime','site_domain_active','INSERT') AND
		has_function_privilege('cdnca_control_app','lock_site_domains_299(text[])','EXECUTE') AND
		NOT has_table_privilege('cdnca_control_app','domain_ownerships','DELETE')`).Scan(&granted); err != nil || !granted {
		t.Fatalf("runtime grants = %v (%v)", granted, err)
	}

	for _, domain := range []string{"www.a.example.test", "*.a.example.test", "k.w.example.test", "*.w.example.test"} {
		if err := fact(scopeB, siteB, userB, "activate", domain); !overlap(err) {
			t.Fatalf("B activate %s = %v, want overlap", domain, err)
		}
	}
	for _, domain := range []string{"x.www.a.example.test", "*.www.a.example.test", "a.example.test", "gone.example.test"} {
		if err := fact(scopeB, siteB, userB, "activate", domain); err != nil {
			t.Fatalf("B activate %s: %v", domain, err)
		}
	}

	ownership := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO domain_ownerships(id,scope_id,apex,method,token,status,verified_at,
		last_checked_at,next_check_at,created_by_user_id,created_at,updated_at)
		VALUES($1,$2,'example.test','dns_txt',repeat('a',48),'verified',$3,$3,$3,$4,$3,$3)`,
		ownership, scopeB, now, userB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO domain_ownerships(id,scope_id,apex,method,token,status,verified_at,
		last_checked_at,next_check_at,created_by_user_id,created_at,updated_at)
		VALUES($1,$2,'example.test','dns_txt',repeat('b',48),'verified',$3,$3,$3,$4,$3,$3)`,
		uuid.New(), scopeA, now, userA); err == nil {
		t.Fatal("a second scope verified the same apex")
	}
	if _, err := pool.Exec(ctx, `UPDATE sites SET enabled=false,status='disabled' WHERE id=$1`, siteA); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO domain_claim_suspensions(id,scope_id,site_id,canonical_domain,
		claimant_scope_id,claimant_user_id,ownership_id,request_id,created_at)
		VALUES($1,$2,$3,'www.a.example.test',$4,$5,$6,'claim-299',$7)`,
		uuid.New(), scopeA, siteA, scopeB, userB, ownership, now); err != nil {
		t.Fatal(err)
	}
	if err := fact(scopeB, siteB, userB, "activate", "www.a.example.test"); err != nil {
		t.Fatalf("claimant activate after suspension: %v", err)
	}
	if err := fact(scopeB, siteB, userB, "activate", "k.w.example.test"); !overlap(err) {
		t.Fatalf("unsuspended wildcard holder lost protection: %v", err)
	}
	if err := enableSite(ctx, pool, siteA); sqlState(err) != "P3032" {
		t.Fatalf("enable suspended site = %v, want P3032", err)
	}
	// One write drops the claimed domain and re-enables the site.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE sites SET enabled=true,status='active' WHERE id=$1`, siteA); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO site_domain_facts(scope_id,site_id,site_revision,action,canonical_domain,
		actor_scope_id,actor_user_id,request_id,occurred_at) VALUES($1,$2,2,'deactivate','www.a.example.test',$1,$3,'drop-299',$4)`,
		scopeA, siteA, userA, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("drop claimed domain and re-enable: %v", err)
	}
	var reason string
	if err := pool.QueryRow(ctx, `SELECT release_reason FROM domain_claim_suspensions WHERE site_id=$1`, siteA).Scan(&reason); err != nil || reason != "domain_removed" {
		t.Fatalf("release reason = %q (%v)", reason, err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("rollback discarded ownership and claim records")
	}
}

func overlap(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "site_domain_facts_overlap_148"
}

func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func enableSite(ctx context.Context, pool *pgxpool.Pool, siteID uuid.UUID) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE sites SET enabled=true,status='active' WHERE id=$1`, siteID)
		return err
	})
}

var regexpSites = regexp.MustCompile(`^INSERT INTO sites\(`)
