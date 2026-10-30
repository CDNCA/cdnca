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

// Migration 586: entrypoint_type must agree with resource_scope and never changes; one authorization has one
// local target (a second tenant head for the same authorization is refused); a tenant head written before 586
// is backfilled from its materialized ui_page.
func TestPluginInstallationTargetBinding586(t *testing.T) {
	pool := databasetest.FreshSchemaPool(t, "mig586", nil, func(ctx context.Context, pool *pgxpool.Pool) error {
		return databasetest.MigrateThrough(ctx, pool, "up", 585)
	})
	ctx := t.Context()
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	tenantA, tenantB := uuid.New(), uuid.New()
	for _, tenant := range []uuid.UUID{tenantA, tenantB} {
		must(`INSERT INTO tenants(id,display_name) VALUES($1,'迁移586租户')`, tenant)
		must(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, tenant)
	}
	digest := sha256.Sum256([]byte("586"))
	head := func(scope, authorization uuid.UUID, pluginID string, entrypoint string) error {
		columns, values, args := "", "", []any{scope, authorization, uuid.New(), uuid.New(), pluginID, digest[:]}
		if entrypoint != "" {
			columns, values = ",entrypoint_type", ",$7"
			args = append(args, entrypoint)
		}
		_, err := pool.Exec(ctx, `INSERT INTO plugin_installation_heads(tenant_scope_id,authorization_id,installation_id,
			verification_id,plugin_id,plugin_version,manifest_sha256,configuration_schema_sha256,manifest_scopes,approved_scopes,
			sensitive_scopes,status,revision,identity_generation,lkg_verification_id,lkg_version,created_at,updated_at`+columns+`)
			VALUES($1,$2,$3,$4,$5,'1.0.0',$6,$6,'{}','{}','{}','enabled',1,1,$4,'1.0.0',now(),now()`+values+`)`, args...)
		return err
	}
	// Before 586: a tenant head whose plugin materialized a ui_page.
	existing := uuid.New()
	if err := head(tenantA, existing, "acme.page", ""); err != nil {
		t.Fatal(err)
	}
	must(`INSERT INTO plugin_ui_pages(plugin_id,version,origin,api_base_url,declaration,declaration_sha256,status,
		tenant_scope_id,authorization_id,materialized_at,updated_at) VALUES('acme.page','1.0.0','https://page.example.test','',
		'{"plugin_id":"acme.page","origin":"https://page.example.test"}',$1,'active',$2,$3,now(),now())`,
		"0000000000000000000000000000000000000000000000000000000000000000", tenantA, existing)
	if err := databasetest.MigrateThrough(ctx, pool, "up", 586); err != nil {
		t.Fatal(err)
	}
	var backfilled string
	if err := pool.QueryRow(ctx, `SELECT entrypoint_type FROM plugin_installation_heads WHERE authorization_id=$1`, existing).
		Scan(&backfilled); err != nil || backfilled != "ui_page" {
		t.Fatalf("backfilled entrypoint_type=%q err=%v", backfilled, err)
	}
	expectCode := func(err error, code string) {
		t.Helper()
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != code {
			t.Fatalf("expected %s, got %v", code, err)
		}
	}
	expectCode(head(tenantA, uuid.New(), "acme.theme", "theme"), "23514")
	expectCode(head(tenantA, uuid.New(), "acme.missing", ""), "23502")
	bound := uuid.New()
	if err := head(tenantA, bound, "acme.ext", "external_https"); err != nil {
		t.Fatal(err)
	}
	// The same authorization cannot get a second local target.
	expectCode(head(tenantB, bound, "acme.ext", "external_https"), "23505")
	_, err := pool.Exec(ctx, `UPDATE plugin_installation_heads SET entrypoint_type='ui_page',revision=revision+1
		WHERE authorization_id=$1`, bound)
	expectCode(err, "P5862")
	if err := databasetest.MigrateThrough(ctx, pool, "down", 586); err != nil {
		t.Fatal(err)
	}
}
