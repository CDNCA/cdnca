//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestEdgePublicationServingNodes702UpDownUp rolls the
// serving nodes table up, down and up again on the 701 head; a recorded row
// cannot be changed or deleted (P7021). (Its writers and readers run in the
// edgepublish stop overlay and node settings redelivery integration tests.)
func TestEdgePublicationServingNodes702UpDownUp(t *testing.T) {
	const version = 702
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	present := func() bool {
		t.Helper()
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass(current_schema() || '.edge_publication_serving_nodes') IS NOT NULL`).
			Scan(&exists); err != nil {
			t.Fatal(err)
		}
		return exists
	}
	for _, step := range []struct {
		direction string
		present   bool
	}{{"up", true}, {"down", false}, {"up", true}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if got := present(); got != step.present {
			t.Fatalf("after %s: table present=%v", step.direction, got)
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// The FKs are not what this checks: insert with them off, then mutate.
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO edge_publication_serving_nodes(config_version_id,configuration_scope_id,serving,created_at)
		VALUES(gen_random_uuid(),gen_random_uuid(),'{"node_sets":[],"sites":{},"streams":{}}',now())`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
	var databaseError *pgconn.PgError
	if _, err := tx.Exec(ctx, `UPDATE edge_publication_serving_nodes SET created_at=now()`); !errors.As(err, &databaseError) ||
		databaseError.Code != "P7021" {
		t.Fatalf("update serving nodes: %v, want P7021", err)
	}
}
