package nodeisolation

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

type memoryRepository struct {
	mu       sync.Mutex
	states   map[uuid.UUID]State
	reports  map[uuid.UUID]storedReport
	applyErr error
	listErr  error
}

type storedReport struct {
	digest [32]byte
	result ApplyResult
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{states: make(map[uuid.UUID]State), reports: make(map[uuid.UUID]storedReport)}
}

func (repository *memoryRepository) Apply(_ context.Context, command ApplyCommand) (ApplyResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.applyErr != nil {
		return ApplyResult{}, repository.applyErr
	}
	if existing, ok := repository.reports[command.Result.ReportID]; ok {
		if existing.digest != command.Digest {
			return ApplyResult{}, ErrConflict
		}
		replayed := existing.result
		replayed.Replay = true
		replayed.Effects = nil
		return replayed, nil
	}
	previous := repository.states[command.Result.NodeID]
	result := evolveIsolationState(previous, command)
	repository.states[command.Result.NodeID] = result.State
	repository.reports[command.Result.ReportID] = storedReport{digest: command.Digest, result: result}
	return result, nil
}

func (repository *memoryRepository) List(_ context.Context, scopeID uuid.UUID, nodeIDs []uuid.UUID) (map[uuid.UUID]State, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.listErr != nil {
		return nil, repository.listErr
	}
	result := make(map[uuid.UUID]State, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		if state, ok := repository.states[nodeID]; ok && state.ScopeID == scopeID {
			result[nodeID] = state
		}
	}
	return result, nil
}

func TestConsecutiveFailuresIsolateOnlyTheFaultingNode(t *testing.T) {
	now := time.Date(2026, 8, 9, 8, 0, 0, 0, time.UTC)
	repository := newMemoryRepository()
	service := newTestService(t, repository, &now, Policy{FailureThreshold: 3, RecoveryThreshold: 2, MaxEvidenceAge: time.Minute})
	scopeID, failedNodeID, healthyNodeID := uuid.New(), uuid.New(), uuid.New()
	desired := testIdentity("11111111-1111-4111-8111-111111111111", 1, 1)

	for attempt := 1; attempt <= 3; attempt++ {
		result, err := service.RecordSyncResult(context.Background(), SyncResult{
			ScopeID: scopeID, NodeID: failedNodeID, ReportID: uuid.New(), Desired: desired,
			Outcome: OutcomeFailed, ErrorCode: "agent_apply_failed",
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.PublicationAllowed != (attempt < 3) {
			t.Fatalf("attempt %d publication allowed = %t", attempt, result.PublicationAllowed)
		}
	}

	plan, err := service.PlanPublication(context.Background(), scopeID, []uuid.UUID{failedNodeID, healthyNodeID})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.EligibleNodeIDs, []uuid.UUID{healthyNodeID}) ||
		!slices.Equal(plan.IsolatedNodeIDs, []uuid.UUID{failedNodeID}) {
		t.Fatalf("publication plan = %#v", plan)
	}
	state := repository.states[failedNodeID]
	if state.Status != StatusIsolated || state.ConsecutiveFailures != 3 || state.ReasonCode != ReasonFailureThreshold {
		t.Fatalf("isolated state = %#v", state)
	}
	afterIsolation := recordResult(t, service, SyncResult{
		ScopeID: scopeID, NodeID: failedNodeID, ReportID: uuid.New(), Desired: desired,
		Outcome: OutcomeFailed, ErrorCode: "agent_apply_failed",
	})
	if afterIsolation.State.ConsecutiveFailures != 3 || len(afterIsolation.Effects) != 1 ||
		afterIsolation.Effects[0].Code != AuditSyncResultRecorded {
		t.Fatalf("post-isolation failure = %#v", afterIsolation)
	}
}

func TestRecoveryRequiresConsecutiveFreshCurrentIdentityEvidence(t *testing.T) {
	now := time.Date(2026, 8, 9, 8, 0, 0, 0, time.UTC)
	repository := newMemoryRepository()
	service := newTestService(t, repository, &now, Policy{FailureThreshold: 1, RecoveryThreshold: 2, MaxEvidenceAge: time.Minute})
	scopeID, nodeID := uuid.New(), uuid.New()
	desiredV1 := testIdentity("11111111-1111-4111-8111-111111111111", 1, 1)
	desiredV2 := testIdentity("22222222-2222-4222-8222-222222222222", 2, 1)

	recordResult(t, service, SyncResult{ScopeID: scopeID, NodeID: nodeID, ReportID: uuid.New(), Desired: desiredV1, Outcome: OutcomeFailed, ErrorCode: "precheck_failed"})
	mismatch := HealthEvidence{SessionEpoch: 1, Sequence: 1, ObservedAt: now, Active: testIdentity(desiredV1.ConfigVersionID.String(), 9, 1)}
	result := recordResult(t, service, SyncResult{ScopeID: scopeID, NodeID: nodeID, ReportID: uuid.New(), Desired: desiredV1, Outcome: OutcomeSucceeded, Health: &mismatch})
	if result.PublicationAllowed || result.State.ConsecutiveHealthy != 0 || result.ReasonCode != ReasonIdentityMismatch {
		t.Fatalf("mismatched recovery = %#v", result)
	}

	firstV1 := HealthEvidence{SessionEpoch: 1, Sequence: 2, ObservedAt: now, Active: desiredV1}
	result = recordResult(t, service, SyncResult{ScopeID: scopeID, NodeID: nodeID, ReportID: uuid.New(), Desired: desiredV1, Outcome: OutcomeSucceeded, Health: &firstV1})
	if result.PublicationAllowed || result.State.ConsecutiveHealthy != 1 || result.ReasonCode != ReasonRecoveryPending {
		t.Fatalf("first recovery confirmation = %#v", result)
	}

	firstV2 := HealthEvidence{SessionEpoch: 1, Sequence: 3, ObservedAt: now, Active: desiredV2}
	result = recordResult(t, service, SyncResult{ScopeID: scopeID, NodeID: nodeID, ReportID: uuid.New(), Desired: desiredV2, Outcome: OutcomeSucceeded, Health: &firstV2})
	if result.PublicationAllowed || result.State.ConsecutiveHealthy != 1 {
		t.Fatalf("new desired identity did not restart confirmation = %#v", result)
	}

	staleV2 := HealthEvidence{SessionEpoch: 1, Sequence: 3, ObservedAt: now, Active: desiredV2}
	result = recordResult(t, service, SyncResult{ScopeID: scopeID, NodeID: nodeID, ReportID: uuid.New(), Desired: desiredV2, Outcome: OutcomeSucceeded, Health: &staleV2})
	if result.PublicationAllowed || result.State.ConsecutiveHealthy != 0 || result.ReasonCode != ReasonEvidenceStale {
		t.Fatalf("stale confirmation = %#v", result)
	}

	secondV2 := HealthEvidence{SessionEpoch: 2, Sequence: 1, ObservedAt: now.Add(time.Second), Active: desiredV2}
	now = now.Add(time.Second)
	recordResult(t, service, SyncResult{ScopeID: scopeID, NodeID: nodeID, ReportID: uuid.New(), Desired: desiredV2, Outcome: OutcomeSucceeded, Health: &secondV2})
	thirdV2 := HealthEvidence{SessionEpoch: 2, Sequence: 2, ObservedAt: now.Add(time.Second), Active: desiredV2}
	now = now.Add(time.Second)
	result = recordResult(t, service, SyncResult{ScopeID: scopeID, NodeID: nodeID, ReportID: uuid.New(), Desired: desiredV2, Outcome: OutcomeSucceeded, Health: &thirdV2})
	if !result.PublicationAllowed || result.State.Status != StatusActive || result.ReasonCode != ReasonRecovered {
		t.Fatalf("recovered result = %#v", result)
	}
	assertEffect(t, result.Effects, EffectAlertResolved, AuditNodeRecovered)
	assertEffect(t, result.Effects, EffectAudit, AuditNodeRecovered)
}

func TestUnknownOutcomeFailsClosedAndSurvivesServiceRestart(t *testing.T) {
	now := time.Date(2026, 8, 9, 8, 0, 0, 0, time.UTC)
	repository := newMemoryRepository()
	policy := Policy{FailureThreshold: 5, RecoveryThreshold: 2, MaxEvidenceAge: time.Minute}
	service := newTestService(t, repository, &now, policy)
	scopeID, nodeID := uuid.New(), uuid.New()
	desired := testIdentity("11111111-1111-4111-8111-111111111111", 1, 1)
	reportID := uuid.New()

	result := recordResult(t, service, SyncResult{
		ScopeID: scopeID, NodeID: nodeID, ReportID: reportID, Desired: desired,
		Outcome: OutcomeUnknown, ErrorCode: "gateway_receipt_timeout",
	})
	if result.PublicationAllowed || result.State.Status != StatusIsolated || result.ReasonCode != ReasonOutcomeUnknown {
		t.Fatalf("unknown result = %#v", result)
	}
	assertEffect(t, result.Effects, EffectAlertOpened, AuditNodeIsolated)
	assertEffect(t, result.Effects, EffectAudit, AuditNodeIsolated)

	restarted := newTestService(t, repository, &now, policy)
	plan, err := restarted.PlanPublication(context.Background(), scopeID, []uuid.UUID{nodeID})
	if err != nil || len(plan.EligibleNodeIDs) != 0 || !slices.Equal(plan.IsolatedNodeIDs, []uuid.UUID{nodeID}) {
		t.Fatalf("restart plan = %#v, error = %v", plan, err)
	}
	replay := recordResult(t, restarted, SyncResult{
		ScopeID: scopeID, NodeID: nodeID, ReportID: reportID, Desired: desired,
		Outcome: OutcomeUnknown, ErrorCode: "gateway_receipt_timeout",
	})
	if !replay.Replay || len(replay.Effects) != 0 || replay.State.Revision != result.State.Revision {
		t.Fatalf("idempotent replay = %#v", replay)
	}
}

func TestConflictingReplayAndRepositoryUncertaintyRemainFailClosed(t *testing.T) {
	now := time.Date(2026, 8, 9, 8, 0, 0, 0, time.UTC)
	repository := newMemoryRepository()
	service := newTestService(t, repository, &now, Policy{FailureThreshold: 3, RecoveryThreshold: 2, MaxEvidenceAge: time.Minute})
	scopeID, nodeID := uuid.New(), uuid.New()
	desired := testIdentity("11111111-1111-4111-8111-111111111111", 1, 1)
	reportID := uuid.New()
	recordResult(t, service, SyncResult{ScopeID: scopeID, NodeID: nodeID, ReportID: reportID, Desired: desired, Outcome: OutcomeFailed, ErrorCode: "apply_failed"})

	conflict, err := service.RecordSyncResult(context.Background(), SyncResult{
		ScopeID: scopeID, NodeID: nodeID, ReportID: reportID, Desired: desired,
		Outcome: OutcomeFailed, ErrorCode: "different_failure",
	})
	if !errors.Is(err, ErrConflict) || conflict.PublicationAllowed {
		t.Fatalf("conflicting replay result = %#v, error = %v", conflict, err)
	}

	repository.applyErr = ErrNotFound
	notFound, err := service.RecordSyncResult(context.Background(), SyncResult{
		ScopeID: scopeID, NodeID: uuid.New(), ReportID: uuid.New(), Desired: desired,
		Outcome: OutcomeFailed, ErrorCode: "apply_failed",
	})
	if !errors.Is(err, ErrNotFound) || notFound.PublicationAllowed || notFound.ReasonCode != ReasonOutcomeUncertain {
		t.Fatalf("missing node result = %#v, error = %v", notFound, err)
	}

	repository.applyErr = errors.New("commit outcome unavailable")
	uncertain, err := service.RecordSyncResult(context.Background(), SyncResult{
		ScopeID: scopeID, NodeID: uuid.New(), ReportID: uuid.New(), Desired: desired,
		Outcome: OutcomeFailed, ErrorCode: "apply_failed",
	})
	if !errors.Is(err, ErrOutcomeUncertain) || uncertain.PublicationAllowed || uncertain.ReasonCode != ReasonOutcomeUncertain {
		t.Fatalf("uncertain apply result = %#v, error = %v", uncertain, err)
	}

	repository.listErr = errors.New("read outcome unavailable")
	plan, err := service.PlanPublication(context.Background(), scopeID, []uuid.UUID{nodeID, uuid.New()})
	if !errors.Is(err, ErrOutcomeUncertain) || len(plan.EligibleNodeIDs) != 0 || len(plan.IsolatedNodeIDs) != 2 {
		t.Fatalf("uncertain plan = %#v, error = %v", plan, err)
	}
}

func newTestService(t *testing.T, repository Repository, now *time.Time, policy Policy) *Service {
	t.Helper()
	service, err := NewIsolationService(repository, policy, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func recordResult(t *testing.T, service *Service, value SyncResult) Result {
	t.Helper()
	result, err := service.RecordSyncResult(context.Background(), value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testIdentity(configVersionID string, fill byte, schema uint32) ConfigIdentity {
	var digest [32]byte
	for index := range digest {
		digest[index] = fill
	}
	return ConfigIdentity{Schema: schema, ConfigVersionID: uuid.MustParse(configVersionID), ArtifactSHA256: digest}
}

func assertEffect(t *testing.T, effects []Effect, kind EffectKind, code string) {
	t.Helper()
	for _, effect := range effects {
		if effect.Kind == kind && effect.Code == code && effect.DedupeKey != "" {
			return
		}
	}
	t.Fatalf("effect kind=%q code=%q missing from %#v", kind, code, effects)
}
