//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestCNAMELineAreaScopes679: 678 -> 679 -> 678 -> 679. The area scopes are refused
// before 679 and accepted after; down refuses while an area line record exists (P6792).
func TestCNAMELineAreaScopes679(t *testing.T) {
	const version = 679
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	// Whether the line scope CHECK in force names the scope.
	accepts := func(scope string) bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT pg_get_constraintdef(oid) LIKE '%'||$1||'%' FROM pg_constraint
			WHERE conrelid='cname_carrier_line_records'::regclass AND contype='c' AND conname LIKE 'cname_carrier_line_records_line_scope%'`,
			"'"+scope+"'").Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if accepts("east_asia") || !accepts("overseas") {
		t.Fatal("678 head already accepts area scopes")
	}
	for _, step := range []struct {
		direction string
		accepts   bool
	}{{"up", true}, {"down", false}, {"up", true}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		for _, scope := range []string{"asia", "east_asia", "southeast_asia", "south_asia", "west_asia", "central_asia",
			"europe", "north_america", "south_america", "africa"} {
			if accepts(scope) != step.accepts {
				t.Fatalf("after %s: %s accepted = %v", step.direction, scope, !step.accepts)
			}
		}
		if !accepts("overseas") || !accepts("telecom") {
			t.Fatalf("after %s: carrier scopes lost", step.direction)
		}
	}
	// Real rows (FK skipped as in 609; the CHECK still applies): an area scope
	// and a province scope are stored; global, an unknown code, a mistyped one
	// and an area with a carrier are not; down refuses the area records.
	siteID := uuid.New()
	insert := func(scope string) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cname_carrier_line_records(site_id,line_scope,desired_digest,next_attempt_at,updated_at)
			VALUES($1,$2,$3,now(),now())`, siteID, scope, zeros); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	for _, scope := range []string{"europe", "asia", "广东:telecom"} {
		if err := insert(scope); err != nil {
			t.Fatalf("%s refused: %v", scope, err)
		}
	}
	for _, scope := range []string{"global", "oceania", "Europe", "east_asia:telecom"} {
		if err := insert(scope); err == nil {
			t.Fatalf("%s accepted", scope)
		}
	}
	err := migrateVersionIsolated(ctx, pool, "down", version)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P6792" {
		t.Fatalf("down with area records = %v", err)
	}
	mustExec(t, pool, `DELETE FROM cname_carrier_line_records WHERE site_id=$1 AND line_scope IN ('europe','asia')`, siteID)
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down after retiring area records: %v", err)
	}
	if accepts("europe") {
		t.Fatal("down kept the area scopes")
	}
}
