//go:build integration

package securityactivation

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// moveActivationNodesToPlatform puts the fixture's nodes in the platform scope, as on every shared
// production node since multi-tenant node sharing (287); the fixture keeps their per-tenant
// node_config_state rows.
func moveActivationNodesToPlatform(t *testing.T, fixture activationFixture) {
	t.Helper()
	var platformScopeID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform' LIMIT 1`).
		Scan(&platformScopeID); errors.Is(err, pgx.ErrNoRows) {
		platformScopeID = uuid.New()
		if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`,
			platformScopeID); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	// Production enrolls shared nodes in the platform scope; the fixture moves them with their
	// certificates (publication requires owner scope = node scope). The certificate lifecycle guard
	// refuses such a move, so triggers and foreign keys are off for this fixture transaction only.
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role=replica`); err != nil {
			return err
		}
		nodes := []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}
		if _, err := tx.Exec(t.Context(), `UPDATE node_certificates SET owner_scope_id=$1 WHERE node_id=ANY($2)`,
			platformScopeID, nodes); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE nodes SET scope_id=$1 WHERE id=ANY($2)`, platformScopeID, nodes)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func assertRecoveryRollouts(t *testing.T, fixture activationFixture, candidateID uuid.UUID, wantRollouts, wantNodes int) {
	t.Helper()
	var rollouts, nodes int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*),COALESCE(sum(cardinality(node_ids)),0)
		FROM security_policy_activation_recovery_rollouts WHERE candidate_id=$1`, candidateID).
		Scan(&rollouts, &nodes); err != nil {
		t.Fatal(err)
	}
	if rollouts != wantRollouts || nodes != wantNodes {
		t.Fatalf("recovery rollouts/nodes = %d/%d, want %d/%d", rollouts, nodes, wantRollouts, wantNodes)
	}
}

// An expired candidate on platform-scope nodes could not write its recovery rollout
// (P8802, node.scope_id<>tenant scope) and the worker stopped the control plane. Migration 669.
func TestExpiredCandidateRecoversOnPlatformNodes(t *testing.T) {
	fixture := newActivationFixture(t)
	moveActivationNodesToPlatform(t, fixture)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "platform-node-expire",
		[]uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 2)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	loadedNode := started.Candidate.CanaryNodeIDs[0]
	if err := markPartialCandidateLoaded(t, fixture, started.Candidate, loadedNode); err != nil {
		t.Fatal(err)
	}
	fixture.now = input.ExpiresAt.Add(time.Second)
	store.clock = func() time.Time { return fixture.now }
	expired, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(started.Candidate, "platform-node-expire-reconcile"))
	if err != nil || expired.Action != string(actionExpire) || expired.Candidate.Status != StatusExpired {
		t.Fatalf("expire Reconcile on platform nodes = (%+v, %v)", expired, err)
	}
	assertRecoveryRollouts(t, fixture, started.Candidate.ID, 1, 1)
	assertRecoveryPendingFacts(t, fixture.pool, started.Candidate.ID, 1, 0)
	if err := markProductionRecoveryReverted(t, fixture, started.Candidate.ID, loadedNode); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(started.Candidate, "platform-node-expire-proof"))
	if err != nil || recovered.Action != string(actionRecover) || recovered.Candidate.RecoveredAt == nil {
		t.Fatalf("proof Reconcile on platform nodes = (%+v, %v)", recovered, err)
	}
}

// The scope's source revision moved after the claim (a quick block
// edit), Promote failed every pass, failPromotion's recovery was refused and the joined error read
// as contention, so the candidate stayed healthy until it expired. With the recovery refused
// (pre-669 guard, injected here) Reconcile reports the refusal itself; once recovery is possible
// the same stuck, expired candidate recovers on the next pass without manual repair.
func TestStuckHealthyCandidateFailsPromotionAndSelfHeals(t *testing.T) {
	fixture := newActivationFixture(t)
	moveActivationNodesToPlatform(t, fixture)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "platform-node-source-conflict",
		[]uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 1)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	candidate := started.Candidate
	markProductionPhaseHealthy(t, fixture, candidate, "canary")
	if result, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(candidate, "source-conflict-expand")); err != nil || result.Action != string(actionExpand) {
		t.Fatalf("expand Reconcile = (%+v, %v)", result, err)
	}
	markProductionPhaseHealthy(t, fixture, candidate, "expand")
	// The nodes remember the configuration they ran before the candidate (rollback target).
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE node_config_state SET
		previous_config_version_id=$2,previous_config_identity_schema=1,previous_config_artifact_sha256=$3
		WHERE node_id=ANY($1) AND configuration_scope_id=$4`, []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID},
		fixture.previousConfigID, fixture.previousArtifactDigest[:], fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE edge_configuration_scopes
		SET source_revision=source_revision+1,updated_at=$2 WHERE scope_id=$1`, fixture.scopeID, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `CREATE FUNCTION refuse_recovery_rollout_test()
		RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
			RAISE EXCEPTION 'invalid security policy activation recovery rollout identity' USING ERRCODE='P8802';
		END $$;
		CREATE TRIGGER aaa_refuse_recovery_rollout_test BEFORE INSERT ON security_policy_activation_recovery_rollouts
		FOR EACH ROW EXECUTE FUNCTION refuse_recovery_rollout_test()`); err != nil {
		t.Fatal(err)
	}
	_, err = store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "source-conflict-refused"))
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "P8802" || ignorableWorkerError(err) || !candidateLocalError(err) {
		t.Fatalf("refused promotion failure = %v, want a candidate-local P8802 the worker does not ignore", err)
	}
	assertCandidateStatus(t, fixture.pool, candidate.ID, StatusHealthy, false)
	assertRecoveryRollouts(t, fixture, candidate.ID, 0, 0)

	if _, err := fixture.pool.Exec(t.Context(), `DROP TRIGGER aaa_refuse_recovery_rollout_test
		ON security_policy_activation_recovery_rollouts; DROP FUNCTION refuse_recovery_rollout_test()`); err != nil {
		t.Fatal(err)
	}
	fixture.now = input.ExpiresAt.Add(time.Second)
	store.clock = func() time.Time { return fixture.now }
	expired, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(candidate, "source-conflict-heal"))
	if err != nil || expired.Action != string(actionExpire) || expired.Candidate.Status != StatusExpired {
		t.Fatalf("stuck candidate Reconcile after expiry = (%+v, %v)", expired, err)
	}
	assertRecoveryRollouts(t, fixture, candidate.ID, 1, 2)
}

// Before expiry the same conflict now fails the candidate at once (failPromotion succeeds).
func TestSourceConflictFailsCandidateOnPlatformNodes(t *testing.T) {
	fixture := newActivationFixture(t)
	moveActivationNodesToPlatform(t, fixture)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "platform-node-promotion-failed",
		[]uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 1)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	candidate := started.Candidate
	markProductionPhaseHealthy(t, fixture, candidate, "canary")
	if _, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(candidate, "promotion-failed-expand")); err != nil {
		t.Fatal(err)
	}
	markProductionPhaseHealthy(t, fixture, candidate, "expand")
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE node_config_state SET
		previous_config_version_id=$2,previous_config_identity_schema=1,previous_config_artifact_sha256=$3
		WHERE node_id=ANY($1) AND configuration_scope_id=$4`, []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID},
		fixture.previousConfigID, fixture.previousArtifactDigest[:], fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE edge_configuration_scopes
		SET source_revision=source_revision+1,updated_at=$2 WHERE scope_id=$1`, fixture.scopeID, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(candidate, "promotion-failed-promote")); !errors.Is(err, ErrSourceRevisionConflict) {
		t.Fatalf("promotion after source conflict error = %v, want ErrSourceRevisionConflict", err)
	}
	assertCandidateStatus(t, fixture.pool, candidate.ID, StatusFailed, false)
	assertRecoveryRollouts(t, fixture, candidate.ID, 1, 2)
}
