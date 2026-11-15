//go:build integration

package securityactivation

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func scopeSourceRevision(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) int64 {
	t.Helper()
	var revision int64
	if err := pool.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1`,
		scopeID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}

// The claim used to leave the scope at N while the candidate's release went out as N+1; a quick
// block edit then took N+1 too and the nodes refused it. The claim now takes N+1: an edit during the
// activation gets N+2, and a promotion without edits does not advance the scope a second time.
func TestClaimReservesCandidateRevision(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "reserve-revision",
		[]uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 1)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	reserved := started.Candidate.CandidateSourceRevision
	if got := scopeSourceRevision(t, fixture.pool, fixture.scopeID); got != reserved || reserved != fixture.sourceRevision+1 {
		t.Fatalf("scope revision after claim = %d, candidate %d, want both %d", got, reserved, fixture.sourceRevision+1)
	}
	completeProductionActivation(t, fixture, store, started.Candidate)
	if got := scopeSourceRevision(t, fixture.pool, fixture.scopeID); got != reserved {
		t.Fatalf("scope revision after promotion = %d, want the reserved %d", got, reserved)
	}

	// A second activation while an edit lands: the edit takes the revision after the reserved one.
	next := prepareProductionStart(t, fixture, store, "reserve-revision-edit",
		[]uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 1)
	next.ExpectedBindingRevision, next.ExpectedActivePolicyVersion = started.Candidate.BindingRevision+1, input.PolicyVersion
	second, err := store.Start(t.Context(), fixture.actor, next)
	if err != nil {
		t.Fatal(err)
	}
	if second.Candidate.CandidateSourceRevision != reserved+1 {
		t.Fatalf("second candidate revision = %d, want %d", second.Candidate.CandidateSourceRevision, reserved+1)
	}
	if _, err := fixture.pool.Exec(t.Context(), `SELECT advance_edge_configuration_scope_revision($1)`, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	if edited := scopeSourceRevision(t, fixture.pool, fixture.scopeID); edited == second.Candidate.CandidateSourceRevision {
		t.Fatalf("an edit during the activation took the candidate's revision %d", edited)
	}
}

// The pre-669 state: a claim did not take its revision and an edit published
// it. Once the candidate expired and its nodes went back, the scope goes out once more through the
// system republication channel, at a revision of its own; later passes and the start-up scan do not
// queue it again.
func TestCollidedCandidateRecoversAndRepublishesOnce(t *testing.T) {
	fixture := newActivationFixture(t)
	moveActivationNodesToPlatform(t, fixture)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "collided-revision",
		[]uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 2)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	candidate := started.Candidate
	// Pre-669: the scope stayed at N, an edit advanced it to the candidate's N+1.
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE edge_configuration_scopes SET source_revision=source_revision-1
		WHERE scope_id=$1`, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `SELECT advance_edge_configuration_scope_revision($1)`, fixture.scopeID); err != nil {
		t.Fatal(err)
	}
	loadedNode := candidate.CanaryNodeIDs[0]
	if err := markPartialCandidateLoaded(t, fixture, candidate, loadedNode); err != nil {
		t.Fatal(err)
	}
	fixture.now = input.ExpiresAt.Add(time.Second)
	store.clock = func() time.Time { return fixture.now }
	if expired, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(candidate, "collided-expire")); err != nil || expired.Action != string(actionExpire) {
		t.Fatalf("expire Reconcile = (%+v, %v)", expired, err)
	}
	if err := markProductionRecoveryReverted(t, fixture, candidate.ID, loadedNode); err != nil {
		t.Fatal(err)
	}
	if recovered, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(candidate, "collided-recovered")); err != nil || recovered.Action != string(actionRecover) {
		t.Fatalf("recovery Reconcile = (%+v, %v)", recovered, err)
	}
	assertRecoveredRepublication(t, fixture, candidate)

	if _, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(candidate, "collided-after")); err != nil {
		t.Fatal(err)
	}
	store.republishCollidedScopes(t.Context())
	assertRecoveredRepublication(t, fixture, candidate)
}

func assertRecoveredRepublication(t *testing.T, fixture activationFixture, candidate Candidate) {
	t.Helper()
	var marks int
	var markedRevision int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*),COALESCE(max(source_revision),0)
		FROM security_activation_recovery_republications_669 WHERE candidate_id=$1`, candidate.ID).
		Scan(&marks, &markedRevision); err != nil {
		t.Fatal(err)
	}
	if marks != 1 || markedRevision != candidate.CandidateSourceRevision {
		t.Fatalf("recovery republication marks = %d at %d, want 1 at %d", marks, markedRevision, candidate.CandidateSourceRevision)
	}
	if got := scopeSourceRevision(t, fixture.pool, fixture.scopeID); got != candidate.CandidateSourceRevision+1 {
		t.Fatalf("scope revision = %d, want one advance past %d", got, candidate.CandidateSourceRevision)
	}
	var queued bool
	if err := fixture.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM edge_system_republication_heads
		WHERE scope_id=$1 AND state='pending' AND 'node_sync'=ANY(triggers))`, fixture.scopeID).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	if !queued {
		t.Fatal("no node_sync system republication queued for the recovered scope")
	}
}
