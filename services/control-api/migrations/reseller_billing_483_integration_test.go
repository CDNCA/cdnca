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

// TestResellerBilling483 rolls 483 up over an existing reseller (its prepaid
// account is created and bound), down and up; checks the wholesale cost
// function (main + backup, NULL without a main price) and that down refuses
// once a reseller ledger row exists.
func TestResellerBilling483(t *testing.T) {
	const version = 483
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	user, agent, main, backup := uuid.New(), uuid.New(), uuid.New(), uuid.New()
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
	exec(tx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'rs','hash')`, user, "rs-483-"+user.String())
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platform); errors.Is(err, pgx.ErrNoRows) {
		platform = uuid.New()
		exec(tx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	} else if err != nil {
		t.Fatal(err)
	}
	tenant := uuid.New()
	exec(tx, `INSERT INTO tenants(id,display_name) VALUES($1,'rs 483')`, tenant)
	exec(tx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, agent, tenant)
	exec(tx, `INSERT INTO reseller_profiles(scope_id,status,revision,created_by_user_id,created_at,updated_by_user_id,updated_at)
		VALUES($1,'active',1,$2,$3,$2,$3)`, agent, user, now)
	for index, line := range []uuid.UUID{main, backup} {
		exec(tx, `INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,
			created_at,updated_at,display_id,resolved_value,ipv4_resolved_value)
			VALUES($1::uuid,$2,$3,1,$4,$4,$5,$5,$6,'lg-'||replace($1::uuid::text,'-',''),'v4-'||replace($1::uuid::text,'-',''))`,
			line, platform, "rs483-"+line.String()[:8], user, now, 48310+index)
	}
	exec(tx, `INSERT INTO reseller_wholesale_prices(price_list,platform_scope_id,line_group_id,period,price_minor,updated_by_user_id,updated_at)
		VALUES('standard',$1,$2,'month',300,$4,$5),('standard',$1,$3,'month',100,$4,$5),('standard',$1,$3,'year',900,$4,$5)`,
		platform, main, backup, user, now)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var account uuid.UUID
	var kind string
	if err := pool.QueryRow(ctx, `SELECT profile.prepaid_account_id,account.kind FROM reseller_profiles profile
		JOIN billing_accounts account ON account.id=profile.prepaid_account_id WHERE profile.scope_id=$1`, agent).
		Scan(&account, &kind); err != nil || account != agent || kind != "tenant_liability" {
		t.Fatalf("prepaid account = %s %s, %v", account, kind, err)
	}
	spec := `{"node_group_id":"` + main.String() + `","backup_node_group_id":"` + backup.String() + `"}`
	for _, check := range []struct {
		spec, period string
		want         *int64
	}{
		{spec, "month", minor483(400)},
		{`{"node_group_id":"` + main.String() + `","backup_node_group_id":null}`, "month", minor483(300)},
		{spec, "year", nil}, // the main line group has no yearly price
		{spec, "quarter", nil},
	} {
		var got *int64
		if err := pool.QueryRow(ctx, `SELECT reseller_wholesale_minor_483($1,$2::jsonb,$3)`, agent, check.spec, check.period).
			Scan(&got); err != nil || (got == nil) != (check.want == nil) || got != nil && *got != *check.want {
			t.Fatalf("wholesale %s %s = %v, want %v (%v)", check.spec, check.period, got, check.want, err)
		}
	}
	code := func(err error) string {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return pgErr.Code
		}
		return ""
	}
	// A reseller ledger row (written in replica mode: its order/posting chain is not under test here).
	tx, err = pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exec(tx, `SET LOCAL session_replication_role = replica`)
	exec(tx, `INSERT INTO billing_transactions(id,target_scope_id,operation,direction,amount_minor,currency,reason,
		created_by_user_id,created_at,commercial_order_id) VALUES($1,$2,'reseller_wholesale','debit',400,'CNY','rs483',$3,$4,$5)`,
		uuid.New(), agent, user, now, uuid.New())
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); code(err) != "P4837" && code(errors.Unwrap(err)) != "P4837" {
		t.Fatalf("down with reseller ledger rows = %v", err)
	}
}

func minor483(value int64) *int64 { return &value }
