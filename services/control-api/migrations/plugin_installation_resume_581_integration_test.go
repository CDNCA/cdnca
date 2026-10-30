//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration 581 (report B): a disabled head may move back to enabled only as the mirror of disable (same
// verified authorization, identity generation +1); resume receipts carry no reason; down refuses resume facts.
// fix-plugresume placeholder 601, renumbered to 581 on merge-p22 (predecessor 580).
func TestPluginInstallationResume581(t *testing.T) {
	pool := databasetest.FreshSchemaPool(t, "mig581", nil, func(ctx context.Context, pool *pgxpool.Pool) error {
		return databasetest.MigrateThrough(ctx, pool, "up", 580)
	})
	ctx := t.Context()
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	expectCode := func(err error, code string) {
		t.Helper()
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != code {
			t.Fatalf("expected %s, got %v", code, err)
		}
	}
	tenant := uuid.New()
	must(`INSERT INTO tenants(id,display_name) VALUES($1,'迁移581租户')`, tenant)
	must(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, tenant)
	digest := sha256.Sum256([]byte("581"))
	authorization, verification := uuid.New(), uuid.New()
	must(`INSERT INTO plugin_installation_heads(tenant_scope_id,authorization_id,installation_id,
		verification_id,plugin_id,plugin_version,manifest_sha256,configuration_schema_sha256,manifest_scopes,approved_scopes,
		sensitive_scopes,status,revision,identity_generation,lkg_verification_id,lkg_version,created_at,updated_at)
		VALUES($1,$2,$3,$4,'acme.cache','1.0.0',$5,$5,'{}','{}','{}','disabled',2,2,$4,'1.0.0',now(),now())`,
		tenant, authorization, uuid.New(), verification, digest[:])
	// Before 581 the paused head cannot come back.
	_, err := pool.Exec(ctx, `UPDATE plugin_installation_heads SET status='enabled',revision=3,identity_generation=3
		WHERE authorization_id=$1`, authorization)
	expectCode(err, "P1451")
	if err := databasetest.MigrateThrough(ctx, pool, "up", 581); err != nil {
		t.Fatal(err)
	}
	// A resume that swaps the authorization's version is refused.
	_, err = pool.Exec(ctx, `UPDATE plugin_installation_heads SET status='enabled',revision=3,identity_generation=3,
		plugin_version='1.0.1' WHERE authorization_id=$1`, authorization)
	expectCode(err, "P5811")
	_, err = pool.Exec(ctx, `UPDATE plugin_installation_heads SET status='enabled',revision=3,identity_generation=2
		WHERE authorization_id=$1`, authorization)
	expectCode(err, "P5811")
	must(`UPDATE plugin_installation_heads SET status='enabled',revision=3,identity_generation=3 WHERE authorization_id=$1`,
		authorization)
	// The resume/resumed pairing and the missing reason are enforced on receipts.
	var check string
	if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conname='plugin_installation_receipts_resume_581_check'`).Scan(&check); err != nil ||
		check != "CHECK ((((action = 'resume'::text) = (result = 'resumed'::text)) AND ((action <> 'resume'::text) OR (reason IS NULL))))" {
		t.Fatalf("resume receipt check=%q err=%v", check, err)
	}
	// Rolling back is allowed while no resume receipt exists, and re-applies cleanly.
	if err := databasetest.MigrateThrough(ctx, pool, "down", 581); err != nil {
		t.Fatalf("581 down: %v", err)
	}
	if err := databasetest.MigrateThrough(ctx, pool, "up", 581); err != nil {
		t.Fatalf("581 re-up: %v", err)
	}
}
