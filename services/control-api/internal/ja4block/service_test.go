package ja4block

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func TestSubmitWorkerUsesExactSnapshotAndRecoversResponseLoss(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	tenantID, siteID, userID := uuid.New(), uuid.New(), uuid.New()
	targetNodes := []uuid.UUID{uuid.New(), uuid.New()}
	authority := &authorityStub{snapshot: AuthoritySnapshot{
		TenantScopeID: tenantID, SiteID: siteID, JA4: "t13d1516h2_8daaf6152771_02713d6af862",
		FilterFrom: now.Add(-6 * time.Hour), FilterTo: now, FilterTimezone: "UTC",
		SnapshotAt: now.Add(-time.Minute), SnapshotExpiresAt: now.Add(time.Minute),
		Consistency: "latest_event_id_at_snapshot", RequestCount: 41, ResponseBytes: 8192,
		ExpectedBindingRevision: 0, ExpectedActiveVersion: 0,
		TargetSnapshotID: uuid.New(), TargetSnapshotRevision: 1,
		TargetSnapshotSHA256: nodescheduler.CanonicalNodeSetDigest(targetNodes),
		TargetNodeIDs:        targetNodes, RolloutID: uuid.New(),
	}}
	store := newMemoryWorkflowStore()
	policies := &policyStub{result: securitypolicy.WriteResult{Policy: securitypolicy.Policy{
		ID: uuid.New(), ScopeID: tenantID, Kind: securitypolicy.KindWAF, Revision: 1,
	}}}
	publications := &publicationStub{}
	service, err := NewService(store, authority, policies, publications, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	input := SubmitInput{TenantScopeID: tenantID, SiteID: siteID, JA4: authority.snapshot.JA4,
		SnapshotAt: authority.snapshot.SnapshotAt, Duration: time.Hour, Reason: "credential_stuffing",
		ExpectedRevision: 0, IdempotencyKey: "ja4-block-1", RequestID: "request-1",
		SessionID: uuid.New(), StepUpEvidenceID: uuid.New(), StepUpVerifiedAt: now.Add(-time.Second)}
	actor := Actor{UserID: userID, ScopeID: tenantID, ScopeKind: "tenant", SessionID: input.SessionID}
	created, err := service.Submit(t.Context(), actor, input)
	if err != nil || created.Phase != PhaseQueued || created.Revision != 1 {
		t.Fatalf("Submit() = (%#v, %v)", created, err)
	}
	replayed, err := service.Submit(t.Context(), actor, input)
	if err != nil || !replayed.Replayed || replayed.ID != created.ID {
		t.Fatalf("Submit(replay) = (%#v, %v)", replayed, err)
	}
	conflict := input
	conflict.Duration += time.Second
	if _, err := service.Submit(t.Context(), actor, conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Submit(conflict) error = %v", err)
	}

	store.failPolicySettlement = true
	if _, err := service.RunOne(t.Context(), "worker-1"); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("RunOne(response loss) error = %v", err)
	}
	if policies.calls != 1 || store.items[created.ID].Phase != PhaseQueued {
		t.Fatalf("response loss mutated durable phase: calls=%d workflow=%#v", policies.calls, store.items[created.ID])
	}
	if _, err := service.RunOne(t.Context(), "worker-1"); err != nil {
		t.Fatal(err)
	}
	if policies.calls != 2 || policies.lastCreate.TargetScopeID != tenantID ||
		len(policies.lastCreate.Fields.Rules) != 1 ||
		policies.lastCreate.Fields.Rules[0].Conditions[0].Values[0] != input.JA4 {
		t.Fatalf("policy adapter input is not exact/replay-safe: %#v", policies.lastCreate)
	}
	publications.result = securitybinding.Publication{
		BundleID: uuid.New(), BindingID: uuid.New(), BindingRevision: 1, TenantScopeID: tenantID,
		SiteID: siteID, PolicyID: policies.result.Policy.ID, PolicyKind: securitypolicy.KindWAF,
		PolicyVersion: 1, ExpectedActiveVersion: 0, RolloutID: authority.snapshot.RolloutID,
		TargetNodeIDs: authority.snapshot.TargetNodeIDs,
	}
	if _, err := service.RunOne(t.Context(), "worker-1"); err != nil {
		t.Fatal(err)
	}
	if publications.calls != 1 || publications.last.TenantScopeID != tenantID ||
		publications.last.SiteID != siteID || publications.last.PolicyID != policies.result.Policy.ID ||
		publications.last.PolicyVersion != 1 || publications.last.ExpectedBindingRevision != 0 {
		t.Fatalf("publication adapter input is not exact: %#v", publications.last)
	}
	got, err := service.Get(t.Context(), actor, tenantID, created.ID)
	if err != nil || got.Phase != PhaseEdgePending || got.PolicyRevision != 1 || got.BindingRevision != 1 {
		t.Fatalf("Get() = (%#v, %v)", got, err)
	}
}

func TestSubmitFailsClosedForScopeStaleAndExpiredRanking(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	tenantID, siteID := uuid.New(), uuid.New()
	targetNodes := []uuid.UUID{uuid.New()}
	base := AuthoritySnapshot{TenantScopeID: tenantID, SiteID: siteID, JA4: "t13d1516h2_8daaf6152771_e5627efa2ab1",
		FilterFrom: now.Add(-6 * time.Hour), FilterTo: now, FilterTimezone: "UTC",
		SnapshotAt: now.Add(-time.Minute), SnapshotExpiresAt: now.Add(time.Minute),
		Consistency: "latest_event_id_at_snapshot", RequestCount: 1,
		TargetSnapshotID: uuid.New(), TargetSnapshotRevision: 1,
		TargetSnapshotSHA256: nodescheduler.CanonicalNodeSetDigest(targetNodes),
		TargetNodeIDs:        targetNodes, RolloutID: uuid.New()}
	input := SubmitInput{TenantScopeID: tenantID, SiteID: siteID, JA4: base.JA4, SnapshotAt: base.SnapshotAt,
		Duration: time.Hour, Reason: "abusive_automation", IdempotencyKey: "scope-test", RequestID: "request-scope",
		SessionID: uuid.New(), StepUpEvidenceID: uuid.New(), StepUpVerifiedAt: now.Add(-time.Second)}
	actor := Actor{UserID: uuid.New(), ScopeID: tenantID, ScopeKind: "tenant", SessionID: input.SessionID}
	for name, mutate := range map[string]func(*AuthoritySnapshot){
		"cross tenant":        func(value *AuthoritySnapshot) { value.TenantScopeID = uuid.New() },
		"cross site":          func(value *AuthoritySnapshot) { value.SiteID = uuid.New() },
		"wrong JA4":           func(value *AuthoritySnapshot) { value.JA4 += "x" },
		"stale":               func(value *AuthoritySnapshot) { value.SnapshotAt = value.SnapshotAt.Add(-time.Second) },
		"expired":             func(value *AuthoritySnapshot) { value.SnapshotExpiresAt = now },
		"unknown consistency": func(value *AuthoritySnapshot) { value.Consistency = "eventually_consistent" },
	} {
		t.Run(name, func(t *testing.T) {
			snapshot := base
			mutate(&snapshot)
			service, err := NewService(newMemoryWorkflowStore(), &authorityStub{snapshot: snapshot},
				&policyStub{}, &publicationStub{}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := service.Submit(t.Context(), actor, input); err == nil {
				t.Fatal("Submit() accepted unauthoritative ranking")
			}
		})
	}
}

func TestRecordEdgeReceiptRequiresExactPublicationAndPreservesLKG(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	tenantID, siteID, actorUserID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	nodeA, nodeB := uuid.New(), uuid.New()
	item := Workflow{ID: uuid.New(), TenantScopeID: tenantID, SiteID: siteID, Phase: PhaseEdgePending, Revision: 3,
		ActorUserID: actorUserID, ActorScopeID: tenantID, ActorScopeKind: "tenant", SessionID: sessionID,
		PolicyID: uuid.New(), PolicyRevision: 8, BindingID: uuid.New(), BindingRevision: 5,
		PublicationID: uuid.New(), RolloutID: uuid.New(), ExpectedActiveVersion: 7,
		TargetNodeIDs: []uuid.UUID{nodeA, nodeB},
		CreatedAt:     now.Add(-time.Minute), UpdatedAt: now.Add(-time.Second)}
	store := newMemoryWorkflowStore()
	store.items[item.ID] = item
	service, err := NewService(store, &authorityStub{}, &policyStub{}, &publicationStub{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: actorUserID, ScopeID: tenantID, ScopeKind: "tenant", SessionID: sessionID}
	active := EdgeReceiptInput{ReceiptID: uuid.New(), TenantScopeID: tenantID, SiteID: siteID, WorkflowID: item.ID,
		PolicyID: item.PolicyID, PolicyRevision: item.PolicyRevision, BindingID: item.BindingID,
		BindingRevision: item.BindingRevision, PublicationID: item.PublicationID, RolloutID: item.RolloutID,
		NodeID: nodeA, ConfigSHA256: [32]byte{1}, ReceiptSHA256: [32]byte{2},
		ExpectedRevision: item.Revision, ActivePolicyRevision: item.PolicyRevision,
		State: "active", ReasonCode: "edge_applied", ObservedAt: now}
	pending, err := service.RecordEdgeReceipt(t.Context(), actor, active)
	if err != nil || pending.Phase != PhaseEdgePending || pending.Revision != item.Revision {
		t.Fatalf("RecordEdgeReceipt(first node) = (%#v,%v)", pending, err)
	}
	second := active
	second.ReceiptID, second.NodeID, second.ConfigSHA256, second.ReceiptSHA256 = uuid.New(), nodeB, [32]byte{3}, [32]byte{4}
	completed, err := service.RecordEdgeReceipt(t.Context(), actor, second)
	if err != nil || completed.Phase != PhaseActive || completed.EdgeState != "active" || !store.promoted[item.ID] {
		t.Fatalf("RecordEdgeReceipt(all active) = (%#v,%v), promoted=%v", completed, err, store.promoted[item.ID])
	}
	replayed, err := service.RecordEdgeReceipt(t.Context(), actor, second)
	if err != nil || !replayed.Replayed || replayed.ID != item.ID {
		t.Fatalf("RecordEdgeReceipt(replay) = (%#v,%v)", replayed, err)
	}
	conflict := second
	conflict.PublicationID = uuid.New()
	if _, err := service.RecordEdgeReceipt(t.Context(), actor, conflict); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("RecordEdgeReceipt(conflict) error = %v", err)
	}
	wrongActor := actor
	wrongActor.SessionID = uuid.New()
	if _, err := service.RecordEdgeReceipt(t.Context(), wrongActor, second); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("RecordEdgeReceipt(wrong session) error = %v", err)
	}

	failedItem := item
	failedItem.ID, failedItem.RolloutID, failedItem.PublicationID = uuid.New(), uuid.New(), uuid.New()
	store.items[failedItem.ID] = failedItem
	partial := EdgeReceiptInput{ReceiptID: uuid.New(), TenantScopeID: tenantID, SiteID: siteID, WorkflowID: failedItem.ID,
		PolicyID: failedItem.PolicyID, PolicyRevision: failedItem.PolicyRevision, BindingID: failedItem.BindingID,
		BindingRevision: failedItem.BindingRevision, PublicationID: failedItem.PublicationID, RolloutID: failedItem.RolloutID,
		NodeID: nodeA, ConfigSHA256: [32]byte{5}, ReceiptSHA256: [32]byte{6},
		ExpectedRevision: failedItem.Revision, ActivePolicyRevision: failedItem.PolicyRevision,
		State: "active", ReasonCode: "edge_applied", ObservedAt: now}
	if pending, err := service.RecordEdgeReceipt(t.Context(), actor, partial); err != nil || pending.Phase != PhaseEdgePending {
		t.Fatalf("RecordEdgeReceipt(partial active) = (%#v,%v)", pending, err)
	}
	failed := partial
	failed.ReceiptID, failed.NodeID, failed.ConfigSHA256, failed.ReceiptSHA256 = uuid.New(), nodeB, [32]byte{7}, [32]byte{8}
	failed.ActivePolicyRevision = failedItem.ExpectedActiveVersion
	failed.State, failed.ReasonCode = "rolled_back", "edge_rollback_confirmed"
	rolledBack, err := service.RecordEdgeReceipt(t.Context(), actor, failed)
	if err != nil || rolledBack.Phase != PhaseFailed || rolledBack.EdgeState != "rolled_back" ||
		failed.ActivePolicyRevision != failedItem.ExpectedActiveVersion || store.promoted[failedItem.ID] {
		t.Fatalf("RecordEdgeReceipt(rollback) = (%#v,%v)", rolledBack, err)
	}
}

type authorityStub struct{ snapshot AuthoritySnapshot }

func (stub *authorityStub) Resolve(_ context.Context, _ AuthorityRequest) (AuthoritySnapshot, error) {
	return stub.snapshot, nil
}

type policyStub struct {
	calls      int
	lastCreate securitypolicy.CreateRequest
	result     securitypolicy.WriteResult
}

func (stub *policyStub) Create(_ context.Context, _ securitypolicy.Actor, request securitypolicy.CreateRequest) (securitypolicy.WriteResult, error) {
	stub.calls++
	stub.lastCreate = request
	if stub.calls > 1 {
		stub.result.Replayed = true
	}
	return stub.result, nil
}

func (stub *policyStub) Update(context.Context, securitypolicy.Actor, securitypolicy.UpdateRequest) (securitypolicy.WriteResult, error) {
	return securitypolicy.WriteResult{}, errors.New("unexpected update")
}

type publicationStub struct {
	calls  int
	last   securitybinding.PublishRequest
	result securitybinding.Publication
}

func (stub *publicationStub) Publish(_ context.Context, _ securitypolicy.Actor, request securitybinding.PublishRequest) (securitybinding.Publication, error) {
	stub.calls++
	stub.last = request
	return stub.result, nil
}

type memoryWorkflowStore struct {
	items                map[uuid.UUID]Workflow
	keys                 map[string]uuid.UUID
	claimed              map[uuid.UUID]uuid.UUID
	receipts             map[uuid.UUID][]byte
	nodeReceipts         map[uuid.UUID]map[uuid.UUID][]byte
	promoted             map[uuid.UUID]bool
	failPolicySettlement bool
}

func newMemoryWorkflowStore() *memoryWorkflowStore {
	return &memoryWorkflowStore{items: map[uuid.UUID]Workflow{}, keys: map[string]uuid.UUID{}, claimed: map[uuid.UUID]uuid.UUID{},
		receipts: map[uuid.UUID][]byte{}, nodeReceipts: map[uuid.UUID]map[uuid.UUID][]byte{}, promoted: map[uuid.UUID]bool{}}
}

func (store *memoryWorkflowStore) Create(_ context.Context, item Workflow) (Workflow, error) {
	key := item.TenantScopeID.String() + "/" + item.IdempotencyKey
	if id, ok := store.keys[key]; ok {
		existing := store.items[id]
		if existing.RequestSHA256 != item.RequestSHA256 {
			return Workflow{}, ErrIdempotencyConflict
		}
		existing.Replayed = true
		return existing, nil
	}
	store.items[item.ID] = item
	store.keys[key] = item.ID
	return item, nil
}
func (store *memoryWorkflowStore) Claim(_ context.Context, _ string, _ time.Time, _ time.Duration) (Claim, bool, error) {
	for id, item := range store.items {
		if _, busy := store.claimed[id]; busy {
			continue
		}
		action := ""
		if item.Phase == PhaseQueued {
			action = ActionApplyPolicy
		}
		if item.Phase == PhasePolicyReady {
			action = ActionPublishBinding
		}
		if action == "" {
			continue
		}
		token := uuid.New()
		store.claimed[id] = token
		return Claim{Workflow: item, Token: token, Action: action}, true, nil
	}
	return Claim{}, false, nil
}
func (store *memoryWorkflowStore) SetPolicy(_ context.Context, claim Claim, result securitypolicy.WriteResult) (Workflow, error) {
	if store.claimed[claim.Workflow.ID] != claim.Token {
		return Workflow{}, ErrClaimLost
	}
	delete(store.claimed, claim.Workflow.ID)
	if store.failPolicySettlement {
		store.failPolicySettlement = false
		return Workflow{}, ErrStoreUnavailable
	}
	item := claim.Workflow
	item.PolicyID = result.Policy.ID
	item.PolicyRevision = result.Policy.Revision
	item.Phase = PhasePolicyReady
	item.Revision++
	store.items[item.ID] = item
	return item, nil
}
func (store *memoryWorkflowStore) SetPublication(_ context.Context, claim Claim, result securitybinding.Publication) (Workflow, error) {
	if store.claimed[claim.Workflow.ID] != claim.Token {
		return Workflow{}, ErrClaimLost
	}
	delete(store.claimed, claim.Workflow.ID)
	item := claim.Workflow
	item.BindingID = result.BindingID
	item.BindingRevision = result.BindingRevision
	item.PublicationID = result.BundleID
	item.EdgeState = "pending"
	item.Phase = PhaseEdgePending
	item.Revision++
	store.items[item.ID] = item
	return item, nil
}
func (store *memoryWorkflowStore) Retry(_ context.Context, claim Claim, code string, available time.Time) error {
	delete(store.claimed, claim.Workflow.ID)
	item := store.items[claim.Workflow.ID]
	item.AttemptCount++
	item.LastErrorCode = code
	item.AvailableAt = available
	store.items[item.ID] = item
	return nil
}
func (store *memoryWorkflowStore) Get(_ context.Context, tenantID, id uuid.UUID) (Workflow, error) {
	item, ok := store.items[id]
	if !ok || item.TenantScopeID != tenantID {
		return Workflow{}, ErrNotFound
	}
	return item, nil
}
func (store *memoryWorkflowStore) SetEdgeReceipt(_ context.Context, input EdgeReceiptInput) (Workflow, error) {
	item, ok := store.items[input.WorkflowID]
	if !ok || item.TenantScopeID != input.TenantScopeID {
		return Workflow{}, ErrNotFound
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return Workflow{}, ErrInvalidInput
	}
	if item.Phase == PhaseActive || item.Phase == PhaseFailed {
		if item.Revision == input.ExpectedRevision+1 && bytes.Equal(store.nodeReceipts[item.ID][input.NodeID], encoded) {
			item.Replayed = true
			return item, nil
		}
		return Workflow{}, ErrRevisionConflict
	}
	if item.Revision != input.ExpectedRevision || item.RolloutID != input.RolloutID || item.SiteID != input.SiteID ||
		item.PolicyID != input.PolicyID || item.PolicyRevision != input.PolicyRevision || item.BindingID != input.BindingID ||
		item.BindingRevision != input.BindingRevision || item.PublicationID != input.PublicationID {
		return Workflow{}, ErrRevisionConflict
	}
	if store.nodeReceipts[item.ID] == nil {
		store.nodeReceipts[item.ID] = map[uuid.UUID][]byte{}
	}
	if existing := store.nodeReceipts[item.ID][input.NodeID]; existing != nil {
		if !bytes.Equal(existing, encoded) {
			return Workflow{}, ErrRevisionConflict
		}
		item.Replayed = true
		return item, nil
	}
	store.nodeReceipts[item.ID][input.NodeID] = encoded
	if len(store.nodeReceipts[item.ID]) < len(item.TargetNodeIDs) {
		return item, nil
	}
	allActive := true
	allRolledBack := true
	for _, payload := range store.nodeReceipts[item.ID] {
		var receipt EdgeReceiptInput
		_ = json.Unmarshal(payload, &receipt)
		allActive = allActive && receipt.State == "active"
		allRolledBack = allRolledBack && receipt.State == "rolled_back"
	}
	item.Revision++
	if allActive {
		item.Phase, item.EdgeState = PhaseActive, "active"
		store.promoted[item.ID] = true
	} else {
		item.Phase, item.EdgeState = PhaseFailed, "failed"
		if allRolledBack || input.State == "rolled_back" {
			item.EdgeState = "rolled_back"
		}
	}
	item.LastErrorCode, item.UpdatedAt = input.ReasonCode, input.ObservedAt.UTC()
	store.items[item.ID] = item
	store.receipts[item.ID] = encoded
	return item, nil
}

var _ WorkflowStore = (*memoryWorkflowStore)(nil)
