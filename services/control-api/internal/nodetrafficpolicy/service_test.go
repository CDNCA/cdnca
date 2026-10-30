package nodetrafficpolicy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type serviceRepositoryStub struct {
	policy  Policy
	state   PolicyState
	applied ApplyEvaluationRequest
	result  EvaluationRecord
}

func (stub *serviceRepositoryStub) Get(_ context.Context, scopeID, nodeID uuid.UUID) (PolicyState, error) {
	if scopeID != stub.policy.ScopeID || nodeID != stub.policy.NodeID {
		return PolicyState{}, ErrNotFound
	}
	state := stub.state
	state.Policy = stub.policy
	return state, nil
}

func (stub *serviceRepositoryStub) Put(_ context.Context, _ Actor, request PutRequest) (WriteResult, error) {
	stub.policy = request.Policy
	stub.policy.Revision = request.ExpectedRevision + 1
	return WriteResult{State: PolicyState{Policy: stub.policy}}, nil
}

func (stub *serviceRepositoryStub) ApplyEvaluation(_ context.Context, request ApplyEvaluationRequest) (EvaluationRecord, error) {
	stub.applied = request
	if stub.result.ID == uuid.Nil {
		stub.result = EvaluationRecord{
			ID: uuid.New(), ScopeID: request.ScopeID, NodeID: request.NodeID,
			Decision: request.Decision, SyncTask: request.SyncTask,
		}
	}
	return stub.result, nil
}

type usageReaderStub struct {
	query UsageQuery
	value UsageEvidence
	err   error
}

func (stub *usageReaderStub) Read(_ context.Context, query UsageQuery) (UsageEvidence, error) {
	stub.query = query
	return stub.value, stub.err
}

func TestServiceEvaluateBindsScopeNodePeriodClockAndCreatesQueryableSyncTask(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	policy := validPolicy()
	policy.MonthlyLimitBytes = 100
	repository := &serviceRepositoryStub{
		policy: policy,
		state: PolicyState{
			AdminState:             NodeStateActive,
			LastEvaluation:         &EvaluationSnapshot{PeriodKey: "2026-08", Suppressed: true, ReasonCode: ReasonMonthlyLimitReached},
			CurrentConfigVersionID: uuidPointer(uuid.MustParse("44444444-4444-4444-8444-444444444444")),
		},
	}
	usageValue := usageEvidence(0)
	usageValue.SnapshotAt = now
	usageValue.FinalizedThrough = now
	usage := &usageReaderStub{value: usageValue}
	service, err := NewService(repository, usage, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: uuid.New(), ScopeID: policy.ScopeID, ScopeKind: ScopeKindPlatform, Permissions: []string{PermissionManage}}

	record, err := service.Evaluate(context.Background(), actor, EvaluateRequest{
		ScopeID: policy.ScopeID, NodeID: policy.NodeID, IdempotencyKey: "node-policy-evaluate-1", RequestID: "request-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if usage.query.ScopeID != policy.ScopeID || usage.query.NodeID != policy.NodeID ||
		!usage.query.Period.Start.Equal(repository.applied.Decision.PeriodStart) || usage.query.SnapshotAt != now {
		t.Fatalf("usage query = %#v, applied = %#v", usage.query, repository.applied)
	}
	if !repository.applied.Decision.SyncRequired || repository.applied.SyncTask == nil ||
		repository.applied.SyncTask.ConfigVersionID != *repository.state.CurrentConfigVersionID ||
		repository.applied.SyncTask.Status != SyncTaskQueued || record.SyncTask == nil {
		t.Fatalf("sync task = %#v; record = %#v", repository.applied.SyncTask, record)
	}
}

func uuidPointer(value uuid.UUID) *uuid.UUID { return &value }

func TestServiceFailClosedOnUsageDependencyAndAuthorization(t *testing.T) {
	policy := validPolicy()
	repository := &serviceRepositoryStub{policy: policy, state: PolicyState{AdminState: NodeStateActive}}
	usage := &usageReaderStub{err: errors.New("clickhouse unavailable")}
	service, err := NewService(repository, usage, func() time.Time { return time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.Evaluate(context.Background(), Actor{
		UserID: uuid.New(), ScopeID: policy.ScopeID, ScopeKind: ScopeKindPlatform, Permissions: []string{PermissionRead},
	}, EvaluateRequest{ScopeID: policy.ScopeID, NodeID: policy.NodeID, IdempotencyKey: "evaluate-2", RequestID: "request-2"})
	if !errors.Is(err, ErrPermissionDenied) || repository.applied.NodeID != uuid.Nil {
		t.Fatalf("permission result = %v, mutation = %#v", err, repository.applied)
	}

	_, err = service.Evaluate(context.Background(), Actor{
		UserID: uuid.New(), ScopeID: policy.ScopeID, ScopeKind: ScopeKindPlatform, Permissions: []string{PermissionManage},
	}, EvaluateRequest{ScopeID: policy.ScopeID, NodeID: policy.NodeID, IdempotencyKey: "evaluate-3", RequestID: "request-3"})
	if !errors.Is(err, ErrUsageUnavailable) || repository.applied.NodeID != uuid.Nil {
		t.Fatalf("dependency result = %v, mutation = %#v", err, repository.applied)
	}
}

func TestServiceRejectsScopeConfusionBeforeRepositoryAccess(t *testing.T) {
	policy := validPolicy()
	repository := &serviceRepositoryStub{policy: policy}
	service, err := NewService(repository, &usageReaderStub{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Get(context.Background(), Actor{
		UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: ScopeKindTenant, Permissions: []string{PermissionRead},
	}, policy.ScopeID, policy.NodeID)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("error = %v, want unauthenticated", err)
	}
}
