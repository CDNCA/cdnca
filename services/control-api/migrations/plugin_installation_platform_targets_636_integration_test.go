//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type targets636 struct {
	t        *testing.T
	pool     *pgxpool.Pool
	platform uuid.UUID
	user     uuid.UUID
}

func newTargets636(t *testing.T) targets636 {
	pool := databasetest.MigratedPool(t, nil)
	fixture := targets636{t: t, pool: pool, user: uuid.New()}
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&fixture.platform); err != nil {
		fixture.platform = uuid.New()
		fixture.exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, fixture.platform)
	}
	fixture.exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'平台','unused')`,
		fixture.user, "t636-"+strings.ReplaceAll(fixture.user.String(), "-", "")[:10])
	return fixture
}

func (f targets636) exec(query string, args ...any) error {
	f.t.Helper()
	_, err := f.pool.Exec(f.t.Context(), query, args...)
	return err
}

func (f targets636) must(query string, args ...any) {
	f.t.Helper()
	if err := f.exec(query, args...); err != nil {
		f.t.Fatalf("%v\n%s", err, query)
	}
}

func (f targets636) tenant(name string) uuid.UUID {
	id := uuid.New()
	f.must(`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, id, name)
	f.must(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$1)`, id)
	return id
}

const head636 = `INSERT INTO plugin_installation_heads(tenant_scope_id,authorization_id,installation_id,verification_id,
	plugin_id,plugin_version,manifest_sha256,configuration_schema_sha256,manifest_scopes,approved_scopes,sensitive_scopes,
	status,revision,identity_generation,created_at,updated_at,resource_scope,entrypoint_type)
	VALUES($1,$2,$3,$4,'acme.page','1.0.0',$5,$5,'{}','{}','{}','enabled',1,1,now(),now(),$6,$7)`

func (f targets636) head(scope, authorization uuid.UUID, resourceScope, entrypoint string) error {
	digest := sha256.Sum256(authorization[:])
	return f.exec(head636, scope, authorization, uuid.New(), uuid.New(), digest[:], resourceScope, entrypoint)
}

func (f targets636) covers(authorization, tenant uuid.UUID) bool {
	f.t.Helper()
	var covered bool
	if err := f.pool.QueryRow(f.t.Context(), `SELECT plugin_installation_covers_tenant_636($1,$2)`, authorization, tenant).
		Scan(&covered); err != nil {
		f.t.Fatal(err)
	}
	return covered
}

func sqlState636(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

// 636: a platform-held tenant plugin needs targets (commit-time check), covers listed tenants or all tenants,
// a tenant-held head covers only its own tenant, a platform resource is never a tenant plugin's holder in a tenant
// scope, and targets only attach to platform-held tenant plugins.
func TestPluginInstallationPlatformTargets636Coverage(t *testing.T) {
	f := newTargets636(t)
	tenantA, tenantB := f.tenant("甲"), f.tenant("乙")

	// Without targets the platform-held tenant head is refused at commit.
	lonely := uuid.New()
	if err := f.head(f.platform, lonely, "tenant", "ui_page"); sqlState636(err) != "P6362" {
		t.Fatalf("platform-held tenant head without targets err=%v", err)
	}
	// Head + targets in one transaction.
	listed := uuid.New()
	tx, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(listed[:])
	if _, err := tx.Exec(t.Context(), head636, f.platform, listed, uuid.New(), uuid.New(), digest[:], "tenant", "ui_page"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_installation_targets(authorization_id,all_tenants,revision,
		last_idempotency_key,last_request_sha256,updated_by_user_id,created_at,updated_at) VALUES($1,false,1,'k',$2,$3,now(),now())`,
		listed, digest[:], f.user); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_installation_target_tenants VALUES($1,$2)`, listed, tenantA); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatalf("head with targets: %v", err)
	}
	if !f.covers(listed, tenantA) || f.covers(listed, tenantB) || f.covers(listed, f.platform) {
		t.Fatal("listed targets must cover exactly the listed tenant")
	}
	f.must(`UPDATE plugin_installation_targets SET all_tenants=true,revision=2 WHERE authorization_id=$1`, listed)
	tenantC := f.tenant("丙") // created after the confirmation
	if !f.covers(listed, tenantB) || !f.covers(listed, tenantC) || f.covers(listed, f.platform) {
		t.Fatal("all tenants must cover every tenant scope, including new ones, and never the platform scope")
	}
	// A listed target is a tenant scope; targets need a platform-held tenant plugin.
	if err := f.exec(`INSERT INTO plugin_installation_target_tenants VALUES($1,$2)`, listed, f.platform); sqlState636(err) != "P6361" {
		t.Fatalf("platform scope as target err=%v", err)
	}
	own := uuid.New()
	if err := f.head(tenantA, own, "tenant", "external_https"); err != nil {
		t.Fatalf("tenant-held head: %v", err)
	}
	if !f.covers(own, tenantA) || f.covers(own, tenantB) {
		t.Fatal("a tenant-held head covers only its tenant")
	}
	if err := f.exec(`INSERT INTO plugin_installation_targets(authorization_id,all_tenants,revision,last_idempotency_key,
		last_request_sha256,updated_by_user_id,created_at,updated_at) VALUES($1,true,1,'k',$2,$3,now(),now())`,
		own, digest[:], f.user); sqlState636(err) != "P6361" {
		t.Fatalf("targets on a tenant-held head err=%v", err)
	}
	// 585 still refuses a platform resource in a tenant scope.
	if err := f.head(tenantA, uuid.New(), "platform", "theme"); sqlState636(err) != "P5852" {
		t.Fatalf("platform resource in a tenant scope err=%v", err)
	}
}

// 636 rolls back to the 188/368/585/604 keys and triggers when no platform-held tenant plugin exists, refuses
// otherwise, and applies again.
func TestPluginInstallationPlatformTargets636UpDownUp(t *testing.T) {
	const version = 636
	pool := migrationPoolAt(t, version)
	state := func() (bool, bool) {
		t.Helper()
		var table, covers bool
		if err := pool.QueryRow(t.Context(), `SELECT to_regclass('plugin_installation_targets') IS NOT NULL,
			to_regprocedure('plugin_installation_covers_tenant_636(uuid,uuid)') IS NOT NULL`).Scan(&table, &covers); err != nil {
			t.Fatal(err)
		}
		return table, covers
	}
	if table, covers := state(); !table || !covers {
		t.Fatalf("at head: table=%v covers=%v", table, covers)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	if table, covers := state(); table || covers {
		t.Fatalf("after down: table=%v covers=%v", table, covers)
	}
	var fk int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_constraint WHERE conname IN
		('api_keys_plugin_installation_604_fk','plugin_webhook_subscriptions_installation_binding_188_fk')`).Scan(&fk); err != nil || fk != 2 {
		t.Fatalf("restored composite keys=%d err=%v", fk, err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if table, covers := state(); !table || !covers {
		t.Fatalf("after up: table=%v covers=%v", table, covers)
	}

	// With a platform-held tenant plugin the rollback is refused.
	f := targets636{t: t, pool: pool, user: uuid.New()}
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&f.platform); err != nil {
		f.platform = uuid.New()
		f.must(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, f.platform)
	}
	f.must(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'平台','unused')`, f.user,
		"t636d-"+strings.ReplaceAll(f.user.String(), "-", "")[:10])
	authorization := uuid.New()
	digest := sha256.Sum256(authorization[:])
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), head636, f.platform, authorization, uuid.New(), uuid.New(), digest[:], "tenant", "ui_page"); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `INSERT INTO plugin_installation_targets(authorization_id,all_tenants,revision,
		last_idempotency_key,last_request_sha256,updated_by_user_id,created_at,updated_at) VALUES($1,true,1,'k',$2,$3,$4,$4)`,
		authorization, digest[:], f.user, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", version); err == nil || !strings.Contains(err.Error(), "P6365") {
		t.Fatalf("down with a platform-held tenant plugin err=%v", err)
	}
}
