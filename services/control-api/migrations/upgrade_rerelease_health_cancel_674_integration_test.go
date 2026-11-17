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

// 674: 673 -> 674 -> 673 -> 674. Before 674 a queued plan cannot become cancelled
// (P9302) and the status semantics require a same-version re-release's healthy evidence to name the empty
// RollbackSHA256Digest; after it queued -> cancelled is the only way into the terminal cancelled state, and
// down refuses while a re-release or cancelled plan exists. Healthy receipts themselves are exercised by
// controlupgrade (rollout persistence and the two-process acceptance).
func TestUpgradeRereleaseHealthCancel674UpDownUp(t *testing.T) {
	const version = 674
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	identity := seedUpgradePlan672Identity(t, pool)
	definition := func(function string) string {
		t.Helper()
		var text string
		if err := pool.QueryRow(ctx, `SELECT pg_get_functiondef($1::regprocedure)`, function).Scan(&text); err != nil {
			t.Fatal(err)
		}
		return text
	}
	present := func() bool {
		t.Helper()
		var constraint int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_constraint
			WHERE conrelid='control_upgrade_write_receipts_096'::regclass
			  AND conname='control_upgrade_write_receipts_096_operation_674'`).Scan(&constraint); err != nil {
			t.Fatal(err)
		}
		plan := strings.Contains(definition("validate_control_upgrade_plan_093()"), "'cancelled'")
		semantics := strings.Contains(definition("validate_control_upgrade_status_semantics_105()"),
			"? 'CurrentReleaseSequence'")
		if plan != semantics || plan != (constraint == 1) {
			t.Fatalf("partial 674: plan=%v semantics=%v constraint=%d", plan, semantics, constraint)
		}
		return plan
	}
	// cancel runs steps on one queued v1 plan in a rolled-back transaction (the event history check is
	// deferred to commit); step "" is the plan insert itself.
	cancel := func(t *testing.T, insertState string, steps []string, want []string) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		plan := upgradePlan672V1(identity)
		plan.snapshot["State"] = insertState
		snapshot, _ := json.Marshal(plan.snapshot)
		sum := sha256.Sum256(snapshot)
		_, err = tx.Exec(ctx, `INSERT INTO control_upgrade_rollout_plans(id,actor_scope_id,actor_user_id,
			installation_id,schema_version,revision,state,resume_state,completion,active_batch,
			canonical_snapshot_bytes,canonical_snapshot_sha256,created_at,updated_at)
			VALUES($1,$2,$3,$4,1,1,$5,'','',-1,$6,$7,now(),now())`, plan.id, identity.scopeID,
			identity.userID, identity.installationID, insertState, snapshot, sum[:])
		results := []error{err}
		for index, state := range steps {
			if err != nil {
				break
			}
			plan.snapshot["State"], plan.snapshot["Revision"] = state, index+2
			snapshot, _ = json.Marshal(plan.snapshot)
			sum = sha256.Sum256(snapshot)
			_, err = tx.Exec(ctx, `UPDATE control_upgrade_rollout_plans SET state=$2,revision=$3,
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
		t.Fatal("673 already has the 674 functions")
	}
	// Reproduces the missing state: before 674 a queued plan cannot be cancelled.
	cancel(t, "queued", []string{"cancelled"}, []string{"", "P9302"})
	for _, step := range []struct {
		direction string
		present   bool
	}{{"up", true}, {"down", false}, {"up", true}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if present() != step.present {
			t.Fatalf("after %s: 674 present = %v", step.direction, !step.present)
		}
	}

	t.Run("queued to cancelled only", func(t *testing.T) {
		cancel(t, "queued", []string{"cancelled"}, []string{"", ""})
		cancel(t, "cancelled", nil, []string{"P9302"})
		cancel(t, "queued", []string{"cancelled", "queued"}, []string{"", "", "P9302"})
		cancel(t, "queued", []string{"cancelled", "cancelled"}, []string{"", "", "P9302"})
	})
	t.Run("cross-version and re-release plans still insert", func(t *testing.T) {
		assertUpgradePlan672Code(t, pool, identity, upgradePlan672V3(identity, false), "")
		assertUpgradePlan672Code(t, pool, identity, upgradePlan672V3(identity, true), "")
	})
	t.Run("down refuses a re-release plan", func(t *testing.T) {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := insertUpgradePlan672(ctx, tx, identity, upgradePlan672V3(identity, true)); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		err = migrateVersionIsolated(ctx, pool, "down", version)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P6742" {
			t.Fatalf("down with a re-release plan: %v", err)
		}
		if !present() {
			t.Fatal("refused down still restored the 673 functions")
		}
	})
}
