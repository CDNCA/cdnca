//go:build integration

package migrations_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// 675: 674 -> 675 -> 674 -> 675. Before 675 a paused plan cannot become cancelled
// (P9302); after it paused -> cancelled is accepted while no node command has a status past accepted
// (or an unexpired accepted one). The node predicate and the down refusal for plans cancelled while
// paused run on real commands in controlupgrade (TestCancelPausedRolloutPostgres).
func TestUpgradePausedCancel675UpDownUp(t *testing.T) {
	const version = 675
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	identity := seedUpgradePlan672Identity(t, pool)
	present := func() bool {
		t.Helper()
		var text string
		if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef('validate_control_upgrade_plan_093()'::regprocedure)`).
			Scan(&text); err != nil {
			t.Fatal(err)
		}
		return strings.Contains(text, "OLD.state NOT IN ('queued','paused')") && strings.Contains(text, "P6753")
	}
	// transition inserts a v1 plan in insertState and applies steps in a rolled-back transaction.
	transition := func(t *testing.T, insertState string, steps []string, want []string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		plan := upgradePlan672V1(identity)
		plan.snapshot["State"] = insertState
		resume := ""
		if insertState == "paused" {
			resume = "canary"
		}
		plan.snapshot["ResumeState"] = resume
		snapshot, _ := json.Marshal(plan.snapshot)
		sum := sha256.Sum256(snapshot)
		_, err = tx.Exec(ctx, `INSERT INTO control_upgrade_rollout_plans(id,actor_scope_id,actor_user_id,
			installation_id,schema_version,revision,state,resume_state,completion,active_batch,
			canonical_snapshot_bytes,canonical_snapshot_sha256,created_at,updated_at)
			VALUES($1,$2,$3,$4,1,1,$5,$6,'',-1,$7,$8,now(),now())`, plan.id, identity.scopeID,
			identity.userID, identity.installationID, insertState, resume, snapshot, sum[:])
		results := []error{err}
		for index, state := range steps {
			if err != nil {
				break
			}
			plan.snapshot["State"], plan.snapshot["Revision"], plan.snapshot["ResumeState"] = state, index+2, ""
			snapshot, _ = json.Marshal(plan.snapshot)
			sum = sha256.Sum256(snapshot)
			_, err = tx.Exec(ctx, `UPDATE control_upgrade_rollout_plans SET state=$2,revision=$3,resume_state='',
				canonical_snapshot_bytes=$4,canonical_snapshot_sha256=$5 WHERE id=$1`,
				plan.id, state, index+2, snapshot, sum[:])
			results = append(results, err)
		}
		if len(results) != len(want) {
			t.Fatalf("ran %d steps, want %d: %v", len(results), len(want), results)
		}
		for index, code := range want {
			var pgErr *pgconn.PgError
			if code == "" && results[index] != nil ||
				code != "" && (!errors.As(results[index], &pgErr) || pgErr.Code != code) {
				t.Fatalf("step %d error = %v, want %q", index, results[index], code)
			}
		}
	}

	if present() {
		t.Fatal("674 already has the 675 plan trigger")
	}
	// Reproduces the refusal the console hit: before 675 a paused plan cannot be cancelled.
	transition(t, "paused", []string{"cancelled"}, []string{"", "P9302"})
	for _, step := range []struct {
		direction string
		present   bool
	}{{"up", true}, {"down", false}, {"up", true}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if present() != step.present {
			t.Fatalf("after %s: 675 present = %v", step.direction, !step.present)
		}
	}

	t.Run("queued or paused to cancelled only", func(t *testing.T) {
		transition(t, "paused", []string{"cancelled"}, []string{"", ""})
		transition(t, "queued", []string{"cancelled"}, []string{"", ""})
		transition(t, "canary", []string{"cancelled"}, []string{"", "P9302"})
		transition(t, "running", []string{"cancelled"}, []string{"", "P9302"})
		transition(t, "paused", []string{"cancelled", "paused"}, []string{"", "", "P9302"})
	})
}
