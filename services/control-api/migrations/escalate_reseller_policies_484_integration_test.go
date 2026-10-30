//go:build integration

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestEscalateResellerPolicies484 rolls 484 up, down and up, then checks the
// ADR 0018 §7 guard: an escalation policy's owner is its package's owner
// (P4842) — a reseller cannot hold the policy of the platform's package, nor
// the platform the policy of a reseller's package. Before 484 both inserts
// were accepted.
func TestEscalateResellerPolicies484(t *testing.T) {
	const version = 484
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	user, agent, platformProduct, resellerProduct := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	var platform uuid.UUID
	exec := func(tx pgx.Tx, sql string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatalf("%s: %v", sql, err)
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exec(tx, `SET LOCAL session_replication_role = replica`)
	exec(tx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'rs','hash')`, user, "rs-484-"+user.String())
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); errors.Is(err, pgx.ErrNoRows) {
		platform = uuid.New()
		exec(tx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	} else if err != nil {
		t.Fatal(err)
	}
	tenant := uuid.New()
	exec(tx, `INSERT INTO tenants(id,display_name) VALUES($1,'rs 484')`, tenant)
	exec(tx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, agent, tenant)
	exec(tx, `INSERT INTO reseller_profiles(scope_id,status,revision,created_by_user_id,created_at,updated_by_user_id,updated_at,prepaid_account_id)
		VALUES($1,'active',1,$2,$3,$2,$3,$1)`, agent, user, now)
	for _, product := range []struct {
		id    uuid.UUID
		owner uuid.UUID
	}{{platformProduct, platform}, {resellerProduct, agent}} {
		exec(tx, `INSERT INTO package_products(id,owner_scope_id,name,enabled,sort_order,spec,revision,created_by_user_id,
			updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,false,1,'{"group_ids":[]}'::jsonb,1,$4,$4,$5,$5)`,
			product.id, product.owner, "rs484-"+product.id.String()[:8], user, now)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	code := func(err error) string {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return pgErr.Code
		}
		return ""
	}
	put := func(product, owner uuid.UUID) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		_, err = tx.Exec(ctx, `INSERT INTO escalate_package_policies(product_id,owner_scope_id,thresholds,sustain_seconds,
			recover_permille,min_dwell_seconds,revision,updated_by_user_id,updated_at)
			VALUES($1,$2,'{}'::jsonb,30,500,1800,1,$3,$4)`, product, owner, user, now)
		return err
	}
	for _, refused := range []struct {
		name           string
		product, owner uuid.UUID
	}{{"reseller on the platform's package", platformProduct, agent}, {"platform on a reseller's package", resellerProduct, platform}} {
		if err := put(refused.product, refused.owner); code(err) != "P4842" {
			t.Fatalf("%s = %v", refused.name, err)
		}
	}
	for _, own := range []struct{ product, owner uuid.UUID }{{platformProduct, platform}, {resellerProduct, agent}} {
		if err := put(own.product, own.owner); err != nil {
			t.Fatalf("owner's own policy: %v", err)
		}
	}
}
