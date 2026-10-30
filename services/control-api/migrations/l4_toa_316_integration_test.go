//go:build integration

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestL4TOAMigration checks that 316 leaves existing streams without TOA,
// keeps TOA to v2 TCP streams without PROXY protocol, and refuses to roll
// back once TOA or its history exists.
func TestL4TOAMigration(t *testing.T) {
	const version = 316
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	now := time.Now().UTC()
	scope, user, subscription := seedL4DisplayIdentity214(t, pool, "toa-316", now)
	legacy := uuid.New()
	seedL4Forward214(t, pool, legacy, scope, subscription, user, "Legacy plain", 19503, now)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	var toa bool
	if err := pool.QueryRow(ctx, `SELECT toa FROM l4_forwards WHERE id=$1`, legacy).Scan(&toa); err != nil || toa {
		t.Fatalf("existing stream after 316: toa=%t err=%v", toa, err)
	}
	var pgErr *pgconn.PgError
	for name, update := range map[string]string{
		"toa on a v1 stream":      `toa=true`,
		"toa with outbound PROXY": `toa=true, proxy_protocol_v1=true`,
		"toa on a UDP v1 stream":  `toa=true, protocol='udp'`,
	} {
		if _, err := pool.Exec(ctx, `UPDATE l4_forwards SET `+update+` WHERE id=$1`, legacy); !errors.As(err, &pgErr) ||
			pgErr.Code != "23514" || pgErr.ConstraintName != "l4_forwards_toa_316" {
			t.Errorf("%s: err=%v", name, err)
		}
	}

	// The intent validator is exercised with real intents in
	// edgepublish.CheckL4TOAPublication.

	// TOA history blocks the rollback; toa=false responses do not.
	seedL4WriteReceipt214(t, pool, legacy, scope, user, "stream.update", "toa-316-receipt", now)
	if _, err := pool.Exec(ctx, `UPDATE l4_write_requests SET response_body=response_body||'{"toa":true}'
		WHERE idempotency_key='toa-316-receipt'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); !errors.As(err, &pgErr) || pgErr.Code != "P3162" {
		t.Fatalf("down with TOA history err=%v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE l4_write_requests SET response_body=response_body||'{"toa":false}'
		WHERE idempotency_key='toa-316-receipt'`); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down with only toa=false responses: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatal(err)
	}
}
