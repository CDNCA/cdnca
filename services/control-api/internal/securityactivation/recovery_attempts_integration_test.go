//go:build integration

package securityactivation

import (
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
)

func assertRecoveryFailed(t *testing.T, fixture activationFixture, candidateID uuid.UUID, want bool) {
	t.Helper()
	var failed bool
	if err := fixture.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM security_activation_recovery_failures_670
		WHERE candidate_id=$1)`, candidateID).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != want {
		t.Fatalf("recovery failed = %v, want %v", failed, want)
	}
}

func expireForRecovery(t *testing.T, fixture *activationFixture, store *Store, key string) (Candidate, uuid.UUID) {
	t.Helper()
	moveActivationNodesToPlatform(t, *fixture)
	input := prepareProductionStart(t, *fixture, store, key, []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 2)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	loadedNode := started.Candidate.CanaryNodeIDs[0]
	if err := markPartialCandidateLoaded(t, *fixture, started.Candidate, loadedNode); err != nil {
		t.Fatal(err)
	}
	fixture.now = input.ExpiresAt.Add(time.Second)
	store.clock = func() time.Time { return fixture.now }
	expired, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(started.Candidate, key+"-expire"))
	if err != nil || expired.Action != string(actionExpire) {
		t.Fatalf("expire Reconcile = (%+v, %v)", expired, err)
	}
	assertRecoveryRollouts(t, *fixture, started.Candidate.ID, 1, 1)
	return started.Candidate, loadedNode
}

// Every recovery rollback failed and each reconcile pass used to create
// another, without end. Now one is in flight at a
// time, a failed one is retried after 1, 2, 4, 8 minutes, and after the fifth
// failure the candidate is marked recovery failed, administrators are told and
// the worker leaves it alone.
func TestRecoveryRetryBacksOffAndGivesUp(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	admin := platformActivationAdmin(t, fixture, "platform.admin")
	candidate, node := expireForRecovery(t, &fixture, store, "recovery-backoff")

	pass := 0
	reconcile := func() ReconcileResult {
		t.Helper()
		pass++
		result, err := store.Reconcile(t.Context(), fixture.actor,
			productionReconcileInput(candidate, "recovery-backoff-pass-"+strconv.Itoa(pass)))
		if err != nil {
			t.Fatalf("Reconcile pass %d: %v", pass, err)
		}
		return result
	}
	// In flight: no second rollout.
	reconcile()
	assertRecoveryRollouts(t, fixture, candidate.ID, 1, 1)
	for attempt := 1; attempt < maxRecoveryAttempts; attempt++ {
		if err := markProductionRecoveryFailed(t, fixture, candidate.ID, node); err != nil {
			t.Fatal(err)
		}
		// The failure lands at now+2s; just before its backoff ends nothing is sent.
		fixture.now = fixture.now.Add(recoveryRetryDelay(attempt))
		reconcile()
		assertRecoveryRollouts(t, fixture, candidate.ID, attempt, attempt)
		fixture.now = fixture.now.Add(3 * time.Second)
		if result := reconcile(); result.Action != string(actionWait) {
			t.Fatalf("retry %d action = %q, want wait", attempt+1, result.Action)
		}
		assertRecoveryRollouts(t, fixture, candidate.ID, attempt+1, attempt+1)
		assertRecoveryFailed(t, fixture, candidate.ID, false)
	}
	if err := markProductionRecoveryFailed(t, fixture, candidate.ID, node); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Hour)
	reconcile()
	reconcile()
	assertRecoveryRollouts(t, fixture, candidate.ID, maxRecoveryAttempts, maxRecoveryAttempts)
	assertRecoveryFailed(t, fixture, candidate.ID, true)
	var messages int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM admin_inbox_messages
		WHERE recipient_user_id=$1 AND event_type='security_activation.recovery_failed' AND source_event_id=$2`,
		admin.UserID, "security-activation-recovery-failed/"+candidate.ID.String()).Scan(&messages); err != nil {
		t.Fatal(err)
	}
	if messages != 1 {
		t.Fatalf("administrator inbox messages = %d, want 1", messages)
	}
	items, err := store.loadWorkerItems(t.Context(), reconcileWorkerBatchSize, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if item.input.CandidateID == candidate.ID {
			t.Fatal("worker still reconciles a candidate whose recovery gave up")
		}
	}
}

// Recovery rollouts written before 670 (failed ones may pile up) have no
// attempt row: they neither count toward the limit nor delay the first
// counted attempt, and a retry that reverts the node recovers the candidate.
func TestLegacyFailedRecoveriesDoNotCountAndRetryRecovers(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	candidate, node := expireForRecovery(t, &fixture, store, "recovery-legacy")
	if err := markProductionRecoveryFailed(t, fixture, candidate.ID, node); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM security_activation_recovery_attempts_670
		WHERE candidate_id=$1`, candidate.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(candidate, "recovery-legacy-retry")); err != nil {
		t.Fatal(err)
	}
	assertRecoveryRollouts(t, fixture, candidate.ID, 2, 2)
	var attempt int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT max(attempt) FROM security_activation_recovery_attempts_670
		WHERE candidate_id=$1`, candidate.ID).Scan(&attempt); err != nil || attempt != 1 {
		t.Fatalf("first counted attempt = %d (%v), want 1", attempt, err)
	}
	if err := markProductionRecoveryReverted(t, fixture, candidate.ID, node); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(10 * time.Second)
	recovered, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(candidate, "recovery-legacy-proof"))
	if err != nil || recovered.Action != string(actionRecover) || recovered.Candidate.RecoveredAt == nil {
		t.Fatalf("proof Reconcile after retry = (%+v, %v)", recovered, err)
	}
	assertRecoveryFailed(t, fixture, candidate.ID, false)
}
