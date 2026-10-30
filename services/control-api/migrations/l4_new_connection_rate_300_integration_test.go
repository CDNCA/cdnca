//go:build integration

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestL4NewConnectionRateMigration checks that 300 leaves existing streams
// unlimited, bounds the rate as edgeconfig does, keeps it off v1 streams, and
// refuses to roll back once a rate or its history exists.
func TestL4NewConnectionRateMigration(t *testing.T) {
	const version = 300
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	now := time.Now().UTC()
	scope, user, subscription := seedL4DisplayIdentity214(t, pool, "new-conn-rate-300", now)
	legacy := uuid.New()
	seedL4Forward214(t, pool, legacy, scope, subscription, user, "Legacy plain", 19499, now)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var rate, burst, ban int
	if err := pool.QueryRow(ctx, `SELECT max_new_connections_per_client_per_second,new_connection_burst,new_connection_ban_seconds
		FROM l4_forwards WHERE id=$1`, legacy).Scan(&rate, &burst, &ban); err != nil || rate != 0 || burst != 0 || ban != 0 {
		t.Fatalf("existing stream after 300: %d/%d/%d err=%v", rate, burst, ban, err)
	}
	var pgErr *pgconn.PgError
	for name, update := range map[string]string{
		"rate on a v1 stream":  `max_new_connections_per_client_per_second=10`,
		"burst without a rate": `new_connection_burst=5`,
		"ban without a rate":   `new_connection_ban_seconds=60`,
		"negative rate":        `max_new_connections_per_client_per_second=-1`,
		"rate over the bound":  `max_new_connections_per_client_per_second=100001`,
		"ban over the bound":   `new_connection_ban_seconds=86401`,
	} {
		if _, err := pool.Exec(ctx, `UPDATE l4_forwards SET `+update+` WHERE id=$1`, legacy); !errors.As(err, &pgErr) ||
			pgErr.Code != "23514" || pgErr.ConstraintName != "l4_forwards_new_connection_rate_300" {
			t.Errorf("%s: err=%v", name, err)
		}
	}

	// History with a rate blocks the rollback; a zero rate does not.
	seedL4WriteReceipt214(t, pool, legacy, scope, user, "stream.update", "new-conn-rate-300-receipt", now)
	if _, err := pool.Exec(ctx, `UPDATE l4_write_requests SET response_body=response_body||'{"max_new_connections_per_client_per_second":20}'
		WHERE idempotency_key='new-conn-rate-300-receipt'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); !errors.As(err, &pgErr) || pgErr.Code != "P3002" {
		t.Fatalf("down with rate history err=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE l4_write_requests SET response_body=response_body||'{"max_new_connections_per_client_per_second":0}'
		WHERE idempotency_key='new-conn-rate-300-receipt'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down with only unlimited responses: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatal(err)
	}
}
