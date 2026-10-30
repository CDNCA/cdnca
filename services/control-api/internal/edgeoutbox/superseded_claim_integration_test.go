//go:build integration

package edgeoutbox

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fix-cfgflow2 §3 (PG): a command whose deployment already ended (here: it
// timed out while the command was retrying) is claimed as superseded and
// closed without being published.
func TestPostgresClaimClosesCommandOfEndedDeployment(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	fixture := newIntegrationFixture(t, databaseURL)
	defer fixture.close(t)
	deployment := fixture.seedDeployment(t, uuid.New())
	ctx := context.Background()
	// The deadline passed while the command was retrying: 348 records the
	// timeout and fails the deployment; the retrying command is left behind.
	// The seeded deadline is an hour ahead, so 348's guards (overdue, not
	// ahead of the clock) are off while that timeout fact is seeded.
	if _, err := fixture.pool.Exec(ctx, `UPDATE edge_command_outbox SET status='publishing',updated_at=CURRENT_TIMESTAMP
		WHERE id=$1`, deployment.outboxID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE edge_command_outbox SET status='failed',available_at=CURRENT_TIMESTAMP,
		updated_at=CURRENT_TIMESTAMP WHERE id=$1`, deployment.outboxID); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(ctx, fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO node_deployment_timeouts(deployment_id,attempt,previous_state,deadline_at,timed_out_at)
			SELECT id,attempt,state,deadline_at,deadline_at+interval '1 minute' FROM node_deployments WHERE id=$1`,
			deployment.deploymentID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE node_deployments SET state='failed',updated_at=clock_timestamp() WHERE id=$1`,
			deployment.deploymentID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	store := &postgresStore{pool: fixture.pool}
	claimed, err := store.claim(ctx, 10, time.Minute)
	if err != nil || len(claimed) != 1 || !claimed[0].superseded {
		t.Fatalf("claimed = %+v, %v; want one superseded command", claimed, err)
	}
	if err := store.markSuperseded(ctx, claimed[0].outboxID, claimed[0].claimToken); err != nil {
		t.Fatal(err)
	}
	assertOutboxState(t, fixture.pool, deployment.outboxID, "cancelled", 1, false, "superseded:newer_deployment")
}
