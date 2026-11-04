//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestNodeDeploymentHostReplacements627UpDown: the 046 triggers run the 627
// functions after up and the 046 functions again after down; once a
// deployment failed for a host replacement the rollback is refused (P6272).
func TestNodeDeploymentHostReplacements627UpDown(t *testing.T) {
	const version = 627
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	triggerFunctions := func() string {
		t.Helper()
		var functions string
		if err := pool.QueryRow(ctx, `SELECT string_agg(tgname||'='||tgfoid::regproc::text,',' ORDER BY tgname)
			FROM pg_trigger WHERE tgrelid='node_deployments'::regclass
			AND tgname IN ('node_deployments_state_046','node_deployments_fact_046')`).Scan(&functions); err != nil {
			t.Fatal(err)
		}
		return functions
	}
	const before = "node_deployments_fact_046=assert_node_deployment_fact_046,node_deployments_state_046=enforce_node_deployment_state_046"
	const after = "node_deployments_fact_046=assert_node_deployment_fact_627,node_deployments_state_046=enforce_node_deployment_state_627"
	if got := triggerFunctions(); got != before {
		t.Fatalf("triggers at 626 = %s", got)
	}
	for _, step := range []struct {
		direction, want string
	}{{"up", after}, {"down", before}, {"up", after}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if got := triggerFunctions(); got != step.want {
			t.Fatalf("triggers after %s = %s", step.direction, got)
		}
	}
	// A recorded host replacement (written as a replica: no node, deployment
	// or certificate is needed to block the rollback).
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO node_deployment_host_replacements(deployment_id,attempt,previous_state,
			reason_code,node_id,certificate_id,replaced_at) VALUES($1,1,'activated','host_replaced',$2,$3,now())`,
			uuid.New(), uuid.New(), uuid.New())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); !pgCode(err, "P6272") {
		t.Fatalf("down %d with a host replacement = %v, want P6272", version, err)
	}
	if got := triggerFunctions(); got != after {
		t.Fatalf("triggers after the refused rollback = %s", got)
	}
}
