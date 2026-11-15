//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 669: 668 -> 669 -> 668 -> 669. Up lets recovery rollouts name platform scope nodes,
// takes the source revision of in-flight candidates (scope at N or already collided at N+1 moves one step,
// terminal candidates do not) and creates the republication dedup table; down restores the tenant-only check
// and drops the table without lowering any revision.
func TestSecurityActivationRecoveryPlatformNodes669UpDownUp(t *testing.T) {
	const version = 669
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	// Only the rows migration 669 reads: FKs and triggers are off (session_replication_role=replica), so the
	// candidates need no site, binding, publication or node behind them.
	seed := func(scopeRevision int64, status string) uuid.UUID {
		t.Helper()
		scopeID := uuid.New()
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role=replica`); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`,
				scopeID, uuid.New()); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO edge_configuration_scopes(scope_id,source_revision,updated_at)
				VALUES($1,$2,now())`, scopeID, scopeRevision); err != nil {
				return err
			}
			digest := make([]byte, 32)
			_, err := tx.Exec(ctx, `INSERT INTO security_policy_activation_candidates(id,tenant_scope_id,site_id,
				binding_id,binding_revision,last_bundle_id,last_claimed_policy_version,expected_active_policy_version,
				candidate_source_revision,candidate_config_version_id,candidate_artifact_sha256,target_snapshot_sha256,
				required_capabilities,candidate_status,canary_node_ids,idempotency_key,request_digest,request_id,
				actor_scope_id,actor_user_id,expires_at,created_at,updated_at,promoted_at)
				VALUES($1,$2,$3,$4,1,$5,1,0,2,$6,$7,$7,'["waf.v1"]'::jsonb,$8,ARRAY[$9]::uuid[],$10,$7,$10,$2,$11,
				now()+interval '1 hour',now(),now(),CASE WHEN $8='promoted' THEN now() END)`,
				uuid.New(), scopeID, uuid.New(), uuid.New(), uuid.New(), uuid.New(), digest, status, uuid.New(),
				"m669-"+scopeID.String(), uuid.New())
			return err
		})
		if err != nil {
			t.Fatalf("seed 669 candidate: %v", err)
		}
		return scopeID
	}
	revision := func(scopeID uuid.UUID) int64 {
		t.Helper()
		var value int64
		if err := pool.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`,
			scopeID).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	// every seeded candidate holds source revision 2
	open := seed(1, "healthy")      // scope at N=1: takes 2
	collided := seed(2, "claimed")  // scope already at N+1=2 (an edit took it): moves to 3
	promoted := seed(2, "promoted") // terminal: untouched
	state := func() (bool, bool) {
		t.Helper()
		var platformCheck, table bool
		if err := pool.QueryRow(ctx, `SELECT
			strpos(pg_get_functiondef('validate_security_policy_activation_recovery_rollout_088()'::regprocedure),
			       'node_scope.kind')>0,
			to_regclass('security_activation_recovery_republications_669') IS NOT NULL`).
			Scan(&platformCheck, &table); err != nil {
			t.Fatal(err)
		}
		return platformCheck, table
	}
	if check, table := state(); check || table {
		t.Fatalf("before 669: platform check %v table %v", check, table)
	}
	want := []struct {
		direction                string
		present                  bool
		open, collided, promoted int64
	}{{"up", true, 2, 3, 2}, {"down", false, 2, 3, 2}, {"up", true, 3, 3, 2}}
	for _, step := range want {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if check, table := state(); check != step.present || table != step.present {
			t.Fatalf("after %s: platform check %v table %v want %v", step.direction, check, table, step.present)
		}
		if got := [3]int64{revision(open), revision(collided), revision(promoted)}; got !=
			[3]int64{step.open, step.collided, step.promoted} {
			t.Fatalf("after %s: scope revisions %v want %v", step.direction, got, [3]int64{step.open, step.collided, step.promoted})
		}
	}
	// the dedup table holds one row per candidate
	insert := `INSERT INTO security_activation_recovery_republications_669(candidate_id,tenant_scope_id,source_revision,created_at)
		VALUES($1,$2,3,now())`
	var candidateID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM security_policy_activation_candidates WHERE tenant_scope_id=$1`,
		open).Scan(&candidateID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, insert, candidateID, open); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, insert, candidateID, open); err == nil {
		t.Fatal("669 accepted a second republication for one candidate")
	}
}
