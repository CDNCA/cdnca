//go:build integration

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestL4PortRangeMigration: 334 leaves streams single-port, keeps ranges and
// follow-port off v1 streams, bounds ranges, and refuses to roll back once a
// range or its history exists.
func TestL4PortRangeMigration(t *testing.T) {
	const version = 334
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	now := time.Now().UTC()
	scope, user, subscription := seedL4DisplayIdentity214(t, pool, "port-range-334", now)
	legacy := uuid.New()
	seedL4Forward214(t, pool, legacy, scope, subscription, user, "Legacy plain", 19497, now)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var end *int
	var follow bool
	if err := pool.QueryRow(ctx, `SELECT listen_port_end, upstream_follow_port FROM l4_forwards WHERE id=$1`, legacy).Scan(&end, &follow); err != nil || end != nil || follow {
		t.Fatalf("existing stream after 334: %v %v err=%v", end, follow, err)
	}
	var pgErr *pgconn.PgError
	for _, statement := range []string{
		`UPDATE l4_forwards SET listen_port_end=listen_port+10 WHERE id=$1`,
		`UPDATE l4_forwards SET upstream_follow_port=true WHERE id=$1`,
	} {
		if _, err := pool.Exec(ctx, statement, legacy); !errors.As(err, &pgErr) || pgErr.Code != "23514" || pgErr.ConstraintName != "l4_forwards_port_range_334" {
			t.Fatalf("%s on a v1 stream: err=%v", statement, err)
		}
	}
	for _, check := range []struct {
		port, end int
		valid     bool
	}{{20000, 20999, true}, {20000, 21000, false}, {20000, 20000, false}, {65000, 65536, false},
		{400, 500, false}, {18000, 18100, false}, {18440, 18450, false}, {1, 79, true}} {
		var valid bool
		if err := pool.QueryRow(ctx, `SELECT valid_l4_port_range_334($1,$2)`, check.port, check.end).Scan(&valid); err != nil || valid != check.valid {
			t.Fatalf("range %d-%d valid=%v err=%v, want %v", check.port, check.end, valid, err, check.valid)
		}
	}
	seedL4WriteReceipt214(t, pool, legacy, scope, user, "stream.update", "port-range-334-receipt", now)
	if _, err := pool.Exec(ctx, `UPDATE l4_write_requests SET response_body=response_body||'{"listen_port_end":20010}'
		WHERE idempotency_key='port-range-334-receipt'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); !errors.As(err, &pgErr) || pgErr.Code != "P3342" {
		t.Fatalf("down with port range history err=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE l4_write_requests SET response_body=response_body-'listen_port_end'
		WHERE idempotency_key='port-range-334-receipt'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down without ranges: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatal(err)
	}
}
