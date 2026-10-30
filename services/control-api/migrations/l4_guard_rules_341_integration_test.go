//go:build integration

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestL4GuardRulesMigration: 341 leaves streams without rules, keeps rules off
// v1 streams, checks the stored rule shape, and refuses to roll back once
// rules or their history exist.
func TestL4GuardRulesMigration(t *testing.T) {
	const version = 341
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	now := time.Now().UTC()
	scope, user, subscription := seedL4DisplayIdentity214(t, pool, "guard-rules-341", now)
	legacy := uuid.New()
	seedL4Forward214(t, pool, legacy, scope, subscription, user, "Legacy plain", 19496, now)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var rules *string
	if err := pool.QueryRow(ctx, `SELECT guard_rules::text FROM l4_forwards WHERE id=$1`, legacy).Scan(&rules); err != nil || rules != nil {
		t.Fatalf("existing stream after 341: %v err=%v", rules, err)
	}
	var pgErr *pgconn.PgError
	valid := `[{"id":"66666666-6666-4666-8666-666666666661","action":"drop","client_ip":{"cidrs":["192.0.2.0/24"]}}]`
	if _, err := pool.Exec(ctx, `UPDATE l4_forwards SET guard_rules=$2::jsonb WHERE id=$1`, legacy, valid); !errors.As(err, &pgErr) ||
		pgErr.Code != "23514" || pgErr.ConstraintName != "l4_forwards_guard_rules_341" {
		t.Fatalf("guard rules on a v1 stream: err=%v", err)
	}
	const rule = `"id":"66666666-6666-4666-8666-666666666661","client_ip":{"cidrs":["192.0.2.0/24"]}`
	for _, check := range []struct {
		rules string
		valid bool
	}{
		{valid, true},
		{`[{` + rule + `,"action":"ban","ban_seconds":600,"threshold":5,"window_seconds":60}]`, true},
		{`[{` + rule + `,"action":"ban","ban_seconds":600,"threshold":1}]`, true},
		{`[]`, false}, {`{}`, false}, {`[1]`, false},
		{`[{` + rule + `,"action":"reject"}]`, false},
		{`[{"id":"66666666-6666-4666-8666-666666666661","action":"drop"}]`, false},
		{`[{` + rule + `,"action":"drop","extra":1}]`, false},
		{`[{` + rule + `,"action":"drop","ban_seconds":60}]`, false},
		{`[{` + rule + `,"action":"ban","ban_seconds":600,"threshold":5}]`, false},
		{`[{` + rule + `,"action":"ban","ban_seconds":600,"threshold":1,"window_seconds":60}]`, false},
		{`[{` + rule + `,"action":"ban","ban_seconds":86401,"threshold":1}]`, false},
		{`[{` + rule + `,"action":"drop"},{` + rule + `,"action":"allow"}]`, false},
		{`[{"id":"rule-1","action":"drop","client_ip":{"cidrs":["192.0.2.0/24"]}}]`, false},
	} {
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT valid_l4_guard_rules_341($1::jsonb)`, check.rules).Scan(&ok); err != nil || ok != check.valid {
			t.Fatalf("%s valid=%v err=%v, want %v", check.rules, ok, err, check.valid)
		}
	}
	seedL4WriteReceipt214(t, pool, legacy, scope, user, "stream.update", "guard-rules-341-receipt", now)
	if _, err := pool.Exec(ctx, `UPDATE l4_write_requests SET response_body=response_body||jsonb_build_object('guard_rules',$1::jsonb)
		WHERE idempotency_key='guard-rules-341-receipt'`, valid); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); !errors.As(err, &pgErr) || pgErr.Code != "P3412" {
		t.Fatalf("down with guard rule history err=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE l4_write_requests SET response_body=response_body||'{"guard_rules":[]}'
		WHERE idempotency_key='guard-rules-341-receipt'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down with only empty rule lists: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatal(err)
	}
}
