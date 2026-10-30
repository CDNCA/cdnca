//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestNodeDeploymentStatusRefusals477: before 477 a running
// deployment whose status was refused cannot fail without a node status
// event. After it a recorded refusal is that fact (queued included); without
// one the triggers still refuse, a refusal must name the deployment's current
// state, is immutable, and down refuses while one is recorded. 348's
// timeouts still end deployments.
func TestNodeDeploymentStatusRefusals477(t *testing.T) {
	const version = 477
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	seed := seedTimeout348(t, pool)
	fail := func(id uuid.UUID) error {
		_, err := pool.Exec(ctx, `UPDATE node_deployments SET state='failed',updated_at=now() WHERE id=$1`, id)
		return err
	}
	if err := fail(seed.staged); sqlState(err) != "P0001" {
		t.Fatalf("476 staged -> failed without a fact: %v, want P0001", err)
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	if err := fail(seed.staged); sqlState(err) != "P0001" {
		t.Fatalf("staged -> failed without a refusal: %v, want P0001", err)
	}
	refuse := func(id uuid.UUID, previous string) error {
		_, err := pool.Exec(ctx, `INSERT INTO node_deployment_status_refusals(deployment_id,attempt,previous_state,reason_code,
			status_event_id,transition_sequence,refused_at)
			SELECT id,attempt,$2,'status_binding_conflict',$3,3,clock_timestamp() FROM node_deployments WHERE id=$1`,
			id, previous, uuid.New())
		return err
	}
	if err := refuse(seed.activated, "activated"); sqlState(err) != "23514" {
		t.Fatalf("refusal of an activated deployment: %v, want 23514", err)
	}
	if err := refuse(seed.staged, "queued"); sqlState(err) != "P4773" {
		t.Fatalf("refusal naming another state: %v, want P4773", err)
	}
	if err := refuse(seed.staged, "staged"); err != nil {
		t.Fatal(err)
	}
	if err := fail(seed.otherStaged); sqlState(err) != "P0001" {
		t.Fatalf("staged -> failed on another deployment's refusal: %v, want P0001", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4772" {
		t.Fatalf("down with a recorded refusal: %v, want P4772", err)
	}
	if err := fail(seed.staged); err != nil {
		t.Fatalf("refused staged -> failed: %v", err)
	}
	if err := seed.next(); sqlState(err) != "23505" {
		t.Fatalf("next deployment while the queued one runs: %v, want 23505", err)
	}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO node_deployment_status_refusals(deployment_id,attempt,previous_state,reason_code,
			status_event_id,transition_sequence,refused_at)
			SELECT id,attempt,'queued','status_invalid_transition',$2,2,clock_timestamp() FROM node_deployments WHERE id=$1`,
			seed.queued, uuid.New()); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE node_deployments SET state='failed',updated_at=now() WHERE id=$1`, seed.queued)
		return err
	}); err != nil {
		t.Fatalf("refused queued -> failed: %v", err)
	}
	if err := seed.next(); err != nil {
		t.Fatalf("next deployment after the refusal: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE node_deployment_status_refusals SET reason_code='status_invalid_transition'
		WHERE deployment_id=$1`, seed.staged); sqlState(err) != "P4774" {
		t.Fatalf("update of a refusal: %v, want P4774", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM node_deployment_status_refusals WHERE deployment_id=$1`, seed.staged); sqlState(err) != "P4774" {
		t.Fatalf("delete of a refusal: %v, want P4774", err)
	}
	// 348's timeout path is unchanged.
	if _, err := pool.Exec(ctx, `INSERT INTO node_deployment_timeouts(deployment_id,attempt,previous_state,deadline_at,timed_out_at)
		SELECT id,attempt,'staged',deadline_at,clock_timestamp() FROM node_deployments WHERE id=$1`, seed.otherStaged); err != nil {
		t.Fatal(err)
	}
	if err := fail(seed.otherStaged); err != nil {
		t.Fatalf("timed-out staged -> failed after 477: %v", err)
	}
}
