//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// TestSitePublicationOutcome618: 617→618 adds site_publication_outcome_618
// and site_sync_status_503 reads it (a site with no request and no
// publication stays synced); the guard refuses a second apply; down drops the
// function and restores 503's body; up again.
func TestSitePublicationOutcome618(t *testing.T) {
	const version = 618
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	exists := func() bool {
		t.Helper()
		var found bool
		if err := pool.QueryRow(ctx, `SELECT to_regprocedure('site_publication_outcome_618(uuid,uuid)') IS NOT NULL`).Scan(&found); err != nil {
			t.Fatal(err)
		}
		return found
	}
	syncStatus := func() string {
		t.Helper()
		var status string
		if err := pool.QueryRow(ctx, `SELECT site_sync_status_503($1, $2)`, uuid.New(), uuid.New()).Scan(&status); err != nil {
			t.Fatal(err)
		}
		return status
	}
	if exists() || syncStatus() != "synced" {
		t.Fatal("617 head already has the 618 function or a non-synced default")
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d: %v", version, err)
	}
	var state string
	var failed string
	if err := pool.QueryRow(ctx, `SELECT state, failed_nodes::text FROM site_publication_outcome_618($1, $2)`,
		uuid.New(), uuid.New()).Scan(&state, &failed); err != nil || state != "" || failed != "[]" {
		t.Fatalf("never published outcome state=%q failed=%s err=%v", state, failed, err)
	}
	if !exists() || syncStatus() != "synced" {
		t.Fatal("618 up did not add the function or changed the never-published default")
	}
	up, err := controlmigrations.FS.ReadFile("618_site_publication_outcome.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(up)); err == nil || !strings.Contains(err.Error(), "P6180") {
		t.Fatalf("618 re-applied on the head: %v", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
		t.Fatalf("down %d: %v", version, err)
	}
	if exists() || syncStatus() != "synced" {
		t.Fatal("618 down left the function or broke site_sync_status_503")
	}
	if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
		t.Fatalf("up %d again: %v", version, err)
	}
}
