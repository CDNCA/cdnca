//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration 585: a head's resource_scope must equal the kind of its access scope and never changes;
// platform_owner (and no tenant role) gets plugin_installations.platform.*; down refuses platform heads.
func TestPluginInstallationResourceScope585(t *testing.T) {
	pool := databasetest.FreshSchemaPool(t, "mig585", nil, func(ctx context.Context, pool *pgxpool.Pool) error {
		return databasetest.MigrateThrough(ctx, pool, "up", 584)
	})
	ctx := t.Context()
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	var platformScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScope); err != nil {
		platformScope = uuid.New()
		must(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope)
	}
	tenant := uuid.New()
	must(`INSERT INTO tenants(id,display_name) VALUES($1,'迁移585租户')`, tenant)
	must(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, tenant)
	digest := sha256.Sum256([]byte("585"))
	head := func(scope uuid.UUID, resourceScope string) error {
		args := []any{scope, uuid.New(), uuid.New(), uuid.New(), "acme.theme-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:6], digest[:]}
		columns, values := "", ""
		if resourceScope != "" {
			columns, values = ",resource_scope", ",$7"
			args = append(args, resourceScope)
		}
		_, err := pool.Exec(ctx, `INSERT INTO plugin_installation_heads(tenant_scope_id,authorization_id,installation_id,
			verification_id,plugin_id,plugin_version,manifest_sha256,configuration_schema_sha256,manifest_scopes,approved_scopes,
			sensitive_scopes,status,revision,identity_generation,lkg_verification_id,lkg_version,created_at,updated_at`+columns+`)
			VALUES($1,$2,$3,$4,$5,'1.0.0',$6,$6,'{}','{}','{}','enabled',1,1,$4,'1.0.0',now(),now()`+values+`)`, args...)
		return err
	}
	// A tenant head written before 585 is backfilled from its access scope.
	if err := head(tenant, ""); err != nil {
		t.Fatal(err)
	}
	if err := databasetest.MigrateThrough(ctx, pool, "up", 585); err != nil {
		t.Fatal(err)
	}
	var backfilled string
	if err := pool.QueryRow(ctx, `SELECT resource_scope FROM plugin_installation_heads WHERE tenant_scope_id=$1`, tenant).
		Scan(&backfilled); err != nil || backfilled != "tenant" {
		t.Fatalf("backfilled resource_scope=%q err=%v", backfilled, err)
	}
	expectCode := func(err error, code string) {
		t.Helper()
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != code {
			t.Fatalf("expected %s, got %v", code, err)
		}
	}
	expectCode(head(tenant, "platform"), "P5852")
	expectCode(head(platformScope, "tenant"), "P5852")
	if err := head(platformScope, "platform"); err != nil {
		t.Fatalf("platform head: %v", err)
	}
	_, err := pool.Exec(ctx, `UPDATE plugin_installation_heads SET resource_scope='tenant',revision=revision+1
		WHERE tenant_scope_id=$1`, platformScope)
	expectCode(err, "P5851")

	var platformGrants, tenantGrants int
	if err := pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE scope.kind='platform' AND role.name='platform_owner'),
		count(*) FILTER (WHERE scope.kind='tenant')
		FROM role_permissions grant_row JOIN roles role ON role.id=grant_row.role_id
		JOIN access_scopes scope ON scope.id=role.scope_id
		WHERE grant_row.permission_name LIKE 'plugin_installations.platform.%'`).Scan(&platformGrants, &tenantGrants); err != nil {
		t.Fatal(err)
	}
	if tenantGrants != 0 {
		t.Fatalf("tenant roles hold platform plugin installation permissions: %d", tenantGrants)
	}
	var owners int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM roles role JOIN access_scopes scope ON scope.id=role.scope_id
		WHERE scope.kind='platform' AND role.system_role AND role.name='platform_owner'`).Scan(&owners); err != nil {
		t.Fatal(err)
	}
	if platformGrants != owners*2 {
		t.Fatalf("platform_owner grants=%d owners=%d", platformGrants, owners)
	}
	expectCode(databasetest.MigrateThrough(ctx, pool, "down", 585), "P5854")
}
