//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestACMEHTTP01EpochDriftAlertsMigration rolls 347 up, down and up: down
// removes the policy and templates (with the immutable trigger enabled again)
// and refuses once an outbox row references the template.
func TestACMEHTTP01EpochDriftAlertsMigration(t *testing.T) {
	const version = 347
	pool := migrationPoolAt(t, version-1)
	counts := func() (templates, policies int) {
		t.Helper()
		if err := pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM notification_templates WHERE template_id='acme.http01.epoch_drift.zh-cn'),
			(SELECT count(*) FROM notification_event_policies WHERE event_type='acme.http01.epoch_drift')`).Scan(&templates, &policies); err != nil {
			t.Fatal(err)
		}
		return templates, policies
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(t.Context(), pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
		templates, policies := counts()
		if step == "up" && (templates != 2 || policies != 1) || step == "down" && (templates != 0 || policies != 0) {
			t.Fatalf("after %s templates=%d policies=%d", step, templates, policies)
		}
		var enabled bool
		if err := pool.QueryRow(t.Context(), `SELECT tgenabled='O' FROM pg_trigger
			WHERE tgrelid='notification_templates'::regclass AND tgname='notification_templates_immutable'`).Scan(&enabled); err != nil || !enabled {
			t.Fatalf("after %s immutable trigger enabled=%v %v", step, enabled, err)
		}
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO notification_outbox(id,scope_id,event_id,channel,template_id,template_version,
			subject,body,dedup_key,status,attempt_count,available_at,created_at,updated_at,generation)
			VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'email','acme.http01.epoch_drift.zh-cn',1,
			's','b','notification-v1-'||encode(sha256('drift-347'),'hex'),'pending',0,now(),now(),now(),1)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	err := migrateVersionIsolated(t.Context(), pool, "down", version)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P3479" {
		t.Fatalf("down with drift alert history: %v", err)
	}
}
