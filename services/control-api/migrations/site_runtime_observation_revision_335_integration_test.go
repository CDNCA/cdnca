//go:build integration

package migrations_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestSiteRuntimeObservationRevision335 covers the defect: the site IPv6
// projection (edgedeployment/site_ipv6_projection.go) writes the observed
// ipv6_runtime_state / ipv6_runtime_source_revision (and updated_at) when a
// rollout ends, and migration 021's sites trigger advanced the scope's
// source_revision for it, so a security activation candidate (source_revision
// = candidate - 1 CAS) could never promote under real node reports. After 335
// only observation-only updates leave source_revision alone; every other
// change of sites still advances it, and down restores 021's behaviour.
func TestSiteRuntimeObservationRevision335(t *testing.T) {
	const version = 335
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	tenantID, scopeID, userID, siteID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,'335 tenant')`, tenantID)
	mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'site-335','Site 335','unused')`, userID)
	mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	seedSite335(ctx, t, pool, scopeID, userID, siteID, 1)

	observe := `UPDATE sites SET ipv6_runtime_state=$2,ipv6_runtime_source_revision=ipv6_runtime_source_revision+1,
		updated_at=updated_at+interval '1 second' WHERE id=$1`
	// Before 335 (the defect): an observation-only update advances it.
	before := scopeSourceRevision(ctx, t, pool, scopeID)
	mustExec(t, pool, observe, siteID, "failed")
	if got := scopeSourceRevision(ctx, t, pool, scopeID); got != before+1 {
		t.Fatalf("334 observation update source_revision = %d, want %d (021 behaviour)", got, before+1)
	}

	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		if step == "down" {
			revision := scopeSourceRevision(ctx, t, pool, scopeID)
			mustExec(t, pool, observe, siteID, "active")
			if got := scopeSourceRevision(ctx, t, pool, scopeID); got != revision+1 {
				t.Fatalf("down observation update source_revision = %d, want %d", got, revision+1)
			}
		}
	}

	for _, change := range []struct {
		name    string
		sql     string
		advance int64
	}{
		{"ipv6 runtime projection", observe, 0},
		{"no-op update", `UPDATE sites SET updated_at=updated_at WHERE id=$1`, 0},
		{"updated_at only", `UPDATE sites SET updated_at=updated_at+interval '1 second' WHERE id=$1`, 0},
		{"ipv6 desired state", `UPDATE sites SET ipv6_enabled=NOT ipv6_enabled,ipv6_runtime_state='pending',
			revision=revision+1,updated_at=updated_at+interval '1 second' WHERE id=$1`, 1},
		{"configuration column", `UPDATE sites SET http_ports=ARRAY[8080],revision=revision+1 WHERE id=$1`, 1},
		{"revision only", `UPDATE sites SET revision=revision+1 WHERE id=$1`, 1},
		{"site status", `UPDATE sites SET status='disabled',enabled=false,revision=revision+1 WHERE id=$1`, 1},
	} {
		revision := scopeSourceRevision(ctx, t, pool, scopeID)
		if change.sql == observe {
			mustExec(t, pool, change.sql, siteID, "disabled")
		} else {
			mustExec(t, pool, change.sql, siteID)
		}
		if got := scopeSourceRevision(ctx, t, pool, scopeID); got != revision+change.advance {
			t.Errorf("%s: source_revision = %d, want %d", change.name, got, revision+change.advance)
		}
	}

	// Insert and (soft) delete still advance it. The seed transaction also
	// writes the site's origin pool and origin, whose 021 child triggers
	// advance it too, so only "advanced" is asserted for the insert.
	otherSiteID := uuid.New()
	revision := scopeSourceRevision(ctx, t, pool, scopeID)
	seedSite335(ctx, t, pool, scopeID, userID, otherSiteID, 2)
	inserted := scopeSourceRevision(ctx, t, pool, scopeID)
	if inserted <= revision {
		t.Fatalf("insert source_revision = %d, want > %d", inserted, revision)
	}
	mustExec(t, pool, `UPDATE sites SET deleted_at=updated_at,revision=revision+1 WHERE id=$1`, otherSiteID)
	if got := scopeSourceRevision(ctx, t, pool, scopeID); got != inserted+1 {
		t.Fatalf("delete source_revision = %d, want %d", got, inserted+1)
	}

	// l4_forwards keeps 021's shared trigger function.
	var sitesFunction, l4Function string
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT tgfoid::regproc::text FROM pg_trigger WHERE tgrelid='sites'::regclass
		  AND tgname='sites_bump_edge_configuration_revision'),
		(SELECT tgfoid::regproc::text FROM pg_trigger WHERE tgrelid='l4_forwards'::regclass
		  AND tgname='l4_forwards_bump_edge_configuration_revision')`).Scan(&sitesFunction, &l4Function); err != nil {
		t.Fatal(err)
	}
	if sitesFunction != "bump_edge_configuration_site_revision_335" || l4Function != "bump_edge_configuration_scope_revision" {
		t.Fatalf("trigger functions = sites %s, l4_forwards %s", sitesFunction, l4Function)
	}
}

func seedSite335(ctx context.Context, t *testing.T, pool *pgxpool.Pool, scopeID, userID, siteID uuid.UUID, displayID int) {
	t.Helper()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO sites(id,scope_id,display_id,owner_user_id,domain,origins,origin_hosts,
			created_by_user_id,updated_by_user_id) VALUES($1,$2,$3,$4,$5,ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$4,$4)`,
			siteID, scopeID, displayID, userID, fmt.Sprintf("site-335-%d.example.test", displayID)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, siteID)
		return err
	}); err != nil {
		t.Fatalf("seed site: %v", err)
	}
}

func scopeSourceRevision(ctx context.Context, t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) int64 {
	t.Helper()
	var revision int64
	if err := pool.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`,
		scopeID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}
