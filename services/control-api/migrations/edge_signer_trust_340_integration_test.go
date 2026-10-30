//go:build integration

package migrations_test

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestEdgeSignerTrustMigration rolls 340 up, down and up, then checks that
// accepted documents are append-only and block the down migration.
func TestEdgeSignerTrustMigration(t *testing.T) {
	const version = 340
	pool := migrationPoolAt(t, version-1)
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		var documents, events, state bool
		if err := pool.QueryRow(t.Context(), `SELECT
			to_regclass(current_schema()||'.edge_signer_trust_documents') IS NOT NULL,
			to_regclass(current_schema()||'.edge_signer_trust_events') IS NOT NULL,
			to_regclass(current_schema()||'.edge_signer_trust_node_state') IS NOT NULL`).Scan(&documents, &events, &state); err != nil {
			t.Fatal(err)
		}
		if want := step == "up"; documents != want || events != want || state != want {
			t.Fatalf("after %s: documents=%v events=%v state=%v", step, documents, events, state)
		}
	}
	digest := make([]byte, 32)
	_, _ = rand.Read(digest)
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_signer_trust_documents(revision,document,document_sha256,
		root_key_id,root_generation,revoked_keys,source,accepted_at) VALUES(1,'{}',$1,'root',1,0,'import',$2)`,
		digest, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_signer_trust_events(id,event,reason,occurred_at)
		VALUES($1,'accepted','document_accepted',now())`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`UPDATE edge_signer_trust_documents SET revoked_keys=1`,
		`DELETE FROM edge_signer_trust_documents`, `TRUNCATE edge_signer_trust_documents`,
		`DELETE FROM edge_signer_trust_events`} {
		var pgErr *pgconn.PgError
		if _, err := pool.Exec(t.Context(), statement); !errors.As(err, &pgErr) || pgErr.Code != "P3402" {
			t.Fatalf("%s: error = %v", statement, err)
		}
	}
	var pgErr *pgconn.PgError
	if err := migrateVersionIsolated(t.Context(), pool, "down", version); !errors.As(err, &pgErr) || pgErr.Code != "P3403" {
		t.Fatalf("down with accepted documents: %v", err)
	}
}
