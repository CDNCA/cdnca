//go:build integration

package migrations_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestRealtimeEmptySourceRosterMigration278(t *testing.T) {
	pool := packageCommerceRBAC079Pool(t, 277)
	insert := `INSERT INTO analytics_realtime_source_rosters_247(window_start,sources,evidence_sha256,captured_at)
		VALUES($1,$2::jsonb,sha256(convert_to(($2::jsonb)::text,'UTF8')),$1)`
	hour := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var pgError *pgconn.PgError
	if _, err := pool.Exec(t.Context(), insert, hour, `[]`); !errors.As(err, &pgError) || pgError.Code != "23514" {
		t.Fatalf("247 must reject empty roster: %v", err)
	}
	if _, err := pool.Exec(t.Context(), insert, hour, `[{"scope_id":"x"}]`); err != nil {
		t.Fatalf("nonempty roster before 278: %v", err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 278); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "down", 278); err != nil {
		t.Fatalf("rollback without empty rosters: %v", err)
	}
	if err := migrateVersionIsolated(t.Context(), pool, "up", 278); err != nil {
		t.Fatalf("reapply: %v", err)
	}
	if _, err := pool.Exec(t.Context(), insert, hour.Add(time.Hour), `[]`); err != nil {
		t.Fatalf("278 must record empty roster: %v", err)
	}
	if _, err := pool.Exec(t.Context(), insert, hour.Add(2*time.Hour), `{}`); !errors.As(err, &pgError) || pgError.Code != "23514" {
		t.Fatalf("non-array roster accepted: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM analytics_realtime_source_rosters_247`); !errors.As(err, &pgError) || pgError.Code != "P2472" {
		t.Fatalf("roster immutability lost: %v", err)
	}
	err := migrateVersionIsolated(t.Context(), pool, "down", 278)
	if !errors.As(err, &pgError) || pgError.Code != "P2782" {
		t.Fatalf("empty roster rollback must fail with P2782: %v", err)
	}
	var head int
	if err := pool.QueryRow(t.Context(), `SELECT max(version) FROM schema_migrations`).Scan(&head); err != nil || head != 278 {
		t.Fatalf("rollback failure changed head: %d %v", head, err)
	}
}
