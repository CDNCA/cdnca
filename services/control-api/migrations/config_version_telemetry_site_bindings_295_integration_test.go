//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestConfigVersionTelemetrySiteBindingsMigration checks that 295 records a
// version's sites immutably, rolls up, down and up again while empty, and
// refuses to roll back once a version has bindings.
func TestConfigVersionTelemetrySiteBindingsMigration(t *testing.T) {
	const version = 295
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var pgErr *pgconn.PgError
	if _, err := pool.Exec(ctx, `INSERT INTO config_version_telemetry_site_bindings(config_version_id,site_id)
		VALUES($1,$2)`, uuid.New(), uuid.New()); !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("binding of an unknown config version err=%v", err)
	}
	tenantID, scopeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,'migration 295')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	configID, siteID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO config_versions
		(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,generator_version,
		 status,idempotency_key,request_digest,created_at,published_at)
		VALUES($1,$2,'{}',sha256('{}'),'migration-295','1','releasable',$3,sha256('x'),now(),now())`,
		configID, scopeID, "migration-295-"+configID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO config_version_telemetry_site_bindings(config_version_id,site_id)
		VALUES($1,$2)`, configID, siteID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE config_version_telemetry_site_bindings SET package_subscription_id=$2
		WHERE config_version_id=$1`, configID, uuid.New()); !errors.As(err, &pgErr) || pgErr.Code != "P2951" {
		t.Fatalf("binding update err=%v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM config_version_telemetry_site_bindings WHERE config_version_id=$1`,
		configID); !errors.As(err, &pgErr) || pgErr.Code != "P2951" {
		t.Fatalf("binding delete err=%v", err)
	}
	// A v2 version still depends on its bindings, so the rollback refuses.
	if err := migrateVersionIsolated(ctx, pool, "down", version); !errors.As(err, &pgErr) || pgErr.Code != "P2953" {
		t.Fatalf("rollback with bindings err=%v", err)
	}
}
