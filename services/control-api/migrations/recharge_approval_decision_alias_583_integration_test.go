//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestRechargeApprovalDecisionAlias583: the upgrade path (a 582 schema rolled
// up to 583) and the fresh-install path (all migrations from scratch / the
// template at head) end with the same validate_recharge_payment_approval_171()
// definition, which no longer reads the ambiguous decision column; down
// restores the 435 definition and up again re-applies the fix.
func TestRechargeApprovalDecisionAlias583(t *testing.T) {
	matches, err := fs.Glob(controlmigrations.FS, "*_recharge_approval_decision_alias.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("decision alias migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(matches[0][:3], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	definition := func(pool *pgxpool.Pool) string {
		t.Helper()
		var body string
		if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef('validate_recharge_payment_approval_171()'::regprocedure)`).
			Scan(&body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	fresh := migrationPoolAt(t, version)
	freshBody := definition(fresh)
	if strings.Contains(freshBody, "AND decision='approved'") ||
		!strings.Contains(freshBody, "approved_row.decision='approved'") {
		t.Fatalf("fresh install keeps the ambiguous decision query")
	}

	upgraded := migrationPoolAt(t, version-1)
	if before := definition(upgraded); !strings.Contains(before, "AND decision='approved'") {
		t.Fatalf("pre-583 schema does not carry the released 435 definition")
	}
	if err := migrateVersionIsolated(ctx, upgraded, "up", version); err != nil {
		t.Fatalf("up: %v", err)
	}
	if got := definition(upgraded); got != freshBody {
		t.Fatalf("upgrade and fresh install differ:\nupgrade:\n%s\nfresh:\n%s", got, freshBody)
	}
	if err := migrateVersionIsolated(ctx, upgraded, "down", version); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := definition(upgraded); !strings.Contains(got, "AND decision='approved'") {
		t.Fatalf("down did not restore the 435 definition")
	}
	if err := migrateVersionIsolated(ctx, upgraded, "up", version); err != nil {
		t.Fatalf("up again: %v", err)
	}
	if got := definition(upgraded); got != freshBody {
		t.Fatalf("up again differs from fresh install")
	}
}
