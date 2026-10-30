//go:build integration

package securityactivation

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// sec-rebind (live-waf CC 恢复段): a site bound to library A could not move
// to library B (400 then 409), could not withdraw the kind, and a deleted A
// left the kind unbindable. These cases run on the full production store.

// rebindLibraryB adds a second WAF library to the fixture's scope (v1, the
// fixture's v2 rules) and releases the fixture's open claim targets so the
// nodes can take a new claim.
func rebindLibraryB(t *testing.T, fixture activationFixture) uuid.UUID {
	t.Helper()
	policyID := uuid.New()
	var document []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT document FROM security_policy_versions
		WHERE policy_id=$1 AND revision=2`, fixture.policyID).Scan(&document); err != nil {
		t.Fatal(err)
	}
	var policy securitypolicy.Policy
	if err := json.Unmarshal(document, &policy); err != nil {
		t.Fatal(err)
	}
	policy.ID, policy.Name, policy.Revision = policyID, "library-b", 1
	encoded, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := json.Marshal(policy.Rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `UPDATE security_policy_publication_targets
			SET released_at=$2,release_reason='completed' WHERE publication_id=$1 AND released_at IS NULL`,
			fixture.bundleID, fixture.now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO security_policies(id,scope_id,tenant_id,owner_user_id,kind,name,
			enabled,default_action,rules,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,$3,$4,'waf','library-b',true,'allow',$5,1,$4,$4,$6,$6)`,
			policyID, fixture.scopeID, fixture.tenantID, fixture.actor.UserID, rules, fixture.now); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at)
			VALUES($1,1,$2,$3,$4)`, policyID, encoded, fixture.actor.UserID, fixture.now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return policyID
}

func rebindStart(fixture activationFixture, key string, policyID uuid.UUID, version, bindingRevision, active int64) StartInput {
	return StartInput{
		TenantScopeID: fixture.scopeID, SiteID: fixture.siteID, PolicyID: policyID, PolicyVersion: version,
		ExpectedBindingRevision: bindingRevision, ExpectedActivePolicyVersion: active,
		TargetNodeIDs: []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, CanarySize: 1,
		IdempotencyKey: key, RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
		Traceparent: "00-11111111111111111111111111111111-2222222222222222-01",
		ExpiresAt:   fixture.now.Add(10 * time.Minute),
	}
}

func assertBindingPolicy(t *testing.T, fixture activationFixture, wantPolicy uuid.UUID, wantActive *int64) {
	t.Helper()
	var policyID uuid.UUID
	var active *int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT policy_id,active_policy_version FROM security_policy_site_bindings
		WHERE id=$1`, fixture.bindingID).Scan(&policyID, &active); err != nil {
		t.Fatal(err)
	}
	if policyID != wantPolicy || (active == nil) != (wantActive == nil) || (active != nil && *active != *wantActive) {
		t.Fatalf("binding = (%s, %v), want (%s, %v)", policyID, active, wantPolicy, wantActive)
	}
}

func bindingRevision(t *testing.T, fixture activationFixture) int64 {
	t.Helper()
	var revision int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT revision FROM security_policy_site_bindings WHERE id=$1`,
		fixture.bindingID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}

func deletePolicy(t *testing.T, fixture activationFixture, policyID uuid.UUID, key string) error {
	t.Helper()
	var revision int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT revision FROM security_policies WHERE id=$1`, policyID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	service := securitypolicy.NewService(securitypolicy.NewStoreWithClock(fixture.pool, func() time.Time { return fixture.now }))
	_, err := service.Delete(t.Context(), fixture.actor, securitypolicy.DeleteRequest{
		ID: policyID, ExpectedRevision: revision, IdempotencyKey: key, RequestID: key})
	return err
}

func int64Pointer(value int64) *int64 { return &value }

// A (v1 active) → B v1: the live 400 (B v1 not above A's v1) and 409
// (binding pointed at A) are gone; the binding points at B once promoted,
// and A, no longer referenced, can be deleted (D3).
func TestRebindAToBPromotesAndReleasesA(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	// A is published through an activation first (A v3), so the rebind has
	// a promoted candidate of A to roll back to.
	first, err := store.Start(t.Context(), fixture.actor,
		prepareProductionStart(t, fixture, store, "publish-a", []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 1))
	if err != nil {
		t.Fatalf("publish A: %v", err)
	}
	completeProductionActivation(t, fixture, store, first.Candidate)
	activeA := first.Candidate.LastClaimedPolicyVersion
	libraryB := rebindLibraryB(t, fixture)
	started, err := store.Start(t.Context(), fixture.actor,
		rebindStart(fixture, "rebind-a-to-b", libraryB, 1, bindingRevision(t, fixture), activeA))
	if err != nil {
		t.Fatalf("rebind Start: %v", err)
	}
	assertBindingPolicy(t, fixture, fixture.policyID, int64Pointer(activeA))
	var inUse *securitypolicy.InUseError
	if err := deletePolicy(t, fixture, libraryB, "delete-b-in-flight"); !errors.As(err, &inUse) {
		t.Fatalf("delete B while the rebind is in flight = %v, want ErrInUse", err)
	}
	completeProductionActivation(t, fixture, store, started.Candidate)
	assertBindingPolicy(t, fixture, libraryB, int64Pointer(1))
	status, err := store.Status(t.Context(), fixture.actor, fixture.siteID, securitypolicy.KindWAF)
	if err != nil || status.Binding == nil || status.Binding.PolicyID != libraryB || status.Rollback == nil ||
		!status.Rollback.Available || status.Rollback.PolicyID == nil || *status.Rollback.PolicyID != fixture.policyID ||
		status.Rollback.SourcePolicyVersion != activeA || status.Rollback.CandidateID == nil ||
		*status.Rollback.CandidateID != first.Candidate.ID {
		t.Fatalf("status after rebind = (%+v, %v)", status, err)
	}
	if err := deletePolicy(t, fixture, fixture.policyID, "delete-a-after-rebind"); err != nil {
		t.Fatalf("delete A after the rebind: %v", err)
	}
	// A is deleted: rolling back to it is refused, with the reason.
	status, err = store.Status(t.Context(), fixture.actor, fixture.siteID, securitypolicy.KindWAF)
	if err != nil || status.Rollback == nil || status.Rollback.Available || status.Rollback.Reason != RollbackReasonPolicyDeleted {
		t.Fatalf("rollback after deleting A = (%+v, %v)", status.Rollback, err)
	}
}

// Rolling a rebind back restores A (a new version of A cloned from the one
// active before), through the panel's status facts.
func TestRebindRollbackRestoresA(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	first, err := store.Start(t.Context(), fixture.actor,
		prepareProductionStart(t, fixture, store, "publish-a-rollback", []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 1))
	if err != nil {
		t.Fatalf("publish A: %v", err)
	}
	completeProductionActivation(t, fixture, store, first.Candidate)
	activeA := first.Candidate.LastClaimedPolicyVersion
	libraryB := rebindLibraryB(t, fixture)
	rebound, err := store.Start(t.Context(), fixture.actor,
		rebindStart(fixture, "rebind-for-rollback", libraryB, 1, bindingRevision(t, fixture), activeA))
	if err != nil {
		t.Fatalf("rebind Start: %v", err)
	}
	completeProductionActivation(t, fixture, store, rebound.Candidate)
	status, err := store.Status(t.Context(), fixture.actor, fixture.siteID, securitypolicy.KindWAF)
	if err != nil || status.Rollback == nil || !status.Rollback.Available {
		t.Fatalf("status before rollback = (%+v, %v)", status, err)
	}
	rolled, err := store.Rollback(t.Context(), fixture.actor, RollbackInput{
		CandidateID: *status.Rollback.CandidateID, SourcePolicyVersion: status.Rollback.SourcePolicyVersion,
		ExpectedBindingRevision: status.Binding.BindingRevision, ExpectedActivePolicyVersion: status.Binding.ActivePolicyVersion,
		TargetNodeIDs: []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, CanarySize: 1,
		IdempotencyKey: "rollback-rebind", RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
		Traceparent: "00-11111111111111111111111111111111-2222222222222222-01",
		ExpiresAt:   fixture.now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("rollback to A: %v", err)
	}
	completeProductionActivation(t, fixture, store, rolled.Candidate)
	assertBindingPolicy(t, fixture, fixture.policyID, int64Pointer(rolled.Candidate.LastClaimedPolicyVersion))
}

// A failed rebind leaves A active and bound; A can then be published again.
func TestRebindFailureKeepsA(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	libraryB := rebindLibraryB(t, fixture)
	input := rebindStart(fixture, "rebind-a-to-b-fails", libraryB, 1, 2, 1)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatalf("rebind Start: %v", err)
	}
	fixture.now = input.ExpiresAt.Add(time.Second)
	store.clock = func() time.Time { return fixture.now }
	expired, err := store.Reconcile(t.Context(), fixture.actor, productionReconcileInput(started.Candidate, "rebind-expire"))
	if err != nil || expired.Candidate.Status != StatusExpired {
		t.Fatalf("expire Reconcile = (%+v, %v)", expired, err)
	}
	assertBindingPolicy(t, fixture, fixture.policyID, int64Pointer(1))
	if err := deletePolicy(t, fixture, libraryB, "delete-b-after-failure"); err != nil {
		t.Fatalf("delete B after the failed rebind: %v", err)
	}
	var inUse *securitypolicy.InUseError
	if err := deletePolicy(t, fixture, fixture.policyID, "delete-a-still-active"); !errors.As(err, &inUse) {
		t.Fatalf("delete A still active = %v, want ErrInUse", err)
	}
}

// Detaching withdraws the kind (no active version); the detached library
// can then be deleted, and a deleted library cannot be bound again.
func TestDetachThenDeleteAndDeletedCannotBind(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	rebindLibraryB(t, fixture)
	detach := rebindStart(fixture, "detach-a", fixture.policyID, 1, 2, 1)
	detach.Detach = true
	started, err := store.Start(t.Context(), fixture.actor, detach)
	if err != nil {
		t.Fatalf("detach Start: %v", err)
	}
	completeProductionActivation(t, fixture, store, started.Candidate)
	assertBindingPolicy(t, fixture, fixture.policyID, nil)
	status, err := store.Status(t.Context(), fixture.actor, fixture.siteID, securitypolicy.KindWAF)
	// A v1 was active without an activation of it (fixture): nothing to roll back to.
	if err != nil || !status.LatestDetach || status.Rollback == nil || status.Rollback.Reason != RollbackReasonNoPrevious {
		t.Fatalf("status after detach = (%+v, %v)", status, err)
	}
	if err := deletePolicy(t, fixture, fixture.policyID, "delete-a-after-detach"); err != nil {
		t.Fatalf("delete A after the detach: %v", err)
	}
	var revision int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT revision FROM security_policies WHERE id=$1`, fixture.policyID).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Start(t.Context(), fixture.actor,
		rebindStart(fixture, "bind-deleted-a", fixture.policyID, revision, bindingRevision(t, fixture), 0)); !errors.Is(err, ErrPolicyDeleted) {
		t.Fatalf("bind deleted A = %v, want ErrPolicyDeleted", err)
	}
}

// A deleted library still active on a site (the live D3 leftover, before
// sec-policy-fix) can be detached, and the kind bound to a new library.
func TestDetachDeletedActiveLibraryThenBindNew(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	libraryB := rebindLibraryB(t, fixture)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE security_policies SET deleted_at=$2 WHERE id=$1`,
		fixture.policyID, fixture.now); err != nil {
		t.Fatal(err)
	}
	detach := rebindStart(fixture, "detach-deleted-a", fixture.policyID, 1, 2, 1)
	detach.Detach = true
	started, err := store.Start(t.Context(), fixture.actor, detach)
	if err != nil {
		t.Fatalf("detach deleted A: %v", err)
	}
	completeProductionActivation(t, fixture, store, started.Candidate)
	assertBindingPolicy(t, fixture, fixture.policyID, nil)
	bound, err := store.Start(t.Context(), fixture.actor,
		rebindStart(fixture, "bind-b-after-detach", libraryB, 1, bindingRevision(t, fixture), 0))
	if err != nil {
		t.Fatalf("bind B after detaching deleted A: %v", err)
	}
	completeProductionActivation(t, fixture, store, bound.Candidate)
	assertBindingPolicy(t, fixture, libraryB, int64Pointer(1))
}
