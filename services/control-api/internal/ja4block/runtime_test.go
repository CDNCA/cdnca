package ja4block

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRuntimeProcessesPolicyAndDurableReceiptAcrossSettlementLoss(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	tenantID := uuid.New()
	receipt := exactReceiptFixture(now, tenantID)
	actor := Actor{UserID: uuid.New(), ScopeID: tenantID, ScopeKind: "tenant", SessionID: uuid.New()}
	service := &runtimeServiceStub{runResult: RunResult{Claimed: true}, recordResults: []Workflow{
		{ID: receipt.WorkflowID, TenantScopeID: tenantID, Phase: PhaseActive},
		{ID: receipt.WorkflowID, TenantScopeID: tenantID, Phase: PhaseActive, Replayed: true},
	}}
	queue := &receiptQueueStub{claim: EdgeReceiptClaim{Token: uuid.New(), Actor: actor, Receipt: receipt}, failComplete: true}
	runtime, err := NewRuntime(service, queue,
		RuntimeConfig{WorkerID: "ja4-worker-1", PollInterval: time.Second, ErrorBackoff: 2 * time.Second,
			OperationTimeout: 5 * time.Second, ReceiptLease: 10 * time.Second}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first, err := runtime.RunOnce(t.Context())
	if err == nil || !first.PolicyClaimed || !first.ReceiptClaimed || queue.completed != 0 || service.recordCalls != 1 {
		t.Fatalf("first RunOnce = (%#v,%v), completed=%d records=%d", first, err, queue.completed, service.recordCalls)
	}
	queue.failComplete = false
	second, err := runtime.RunOnce(t.Context())
	if err != nil || !second.ReceiptReplayed || queue.completed != 1 || service.recordCalls != 2 {
		t.Fatalf("second RunOnce = (%#v,%v), completed=%d records=%d", second, err, queue.completed, service.recordCalls)
	}
	if queue.lastWorker != "ja4-worker-1" || queue.lastLease != 10*time.Second || queue.lastClaim.Token != queue.claim.Token {
		t.Fatalf("receipt claim/settlement identity = %#v", queue)
	}
	if service.lastActor != actor {
		t.Fatalf("runtime actor=%#v, want request actor %#v", service.lastActor, actor)
	}
}

func TestRuntimeRetriesTransientReceiptAndRejectsConflictingTerminalReceipt(t *testing.T) {
	now := time.Date(2026, 8, 8, 10, 0, 0, 0, time.UTC)
	receipt := exactReceiptFixture(now, uuid.New())
	actor := Actor{UserID: uuid.New(), ScopeID: receipt.TenantScopeID, ScopeKind: "tenant", SessionID: uuid.New()}
	for name, test := range map[string]struct {
		err        error
		wantRetry  int
		wantReject int
	}{
		"store unavailable": {ErrStoreUnavailable, 1, 0},
		"identity conflict": {ErrRevisionConflict, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			service := &runtimeServiceStub{recordErr: test.err}
			queue := &receiptQueueStub{claim: EdgeReceiptClaim{Token: uuid.New(), Actor: actor, Receipt: receipt}}
			runtime, err := NewRuntime(service, queue,
				RuntimeConfig{WorkerID: "ja4-worker-2", PollInterval: time.Second, ErrorBackoff: 2 * time.Second,
					OperationTimeout: 5 * time.Second, ReceiptLease: 10 * time.Second}, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			result, err := runtime.RunOnce(t.Context())
			if !errors.Is(err, test.err) || !result.ReceiptClaimed || queue.retried != test.wantRetry || queue.rejected != test.wantReject {
				t.Fatalf("RunOnce = (%#v,%v), retry=%d reject=%d", result, err, queue.retried, queue.rejected)
			}
		})
	}
}

func TestRuntimeRunStopsOnCancellationWithoutCompletingUnverifiedReceipt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service := &runtimeServiceStub{}
	queue := &receiptQueueStub{}
	runtime, err := NewRuntime(service, queue,
		RuntimeConfig{WorkerID: "ja4-worker-3", PollInterval: time.Second, ErrorBackoff: 2 * time.Second,
			OperationTimeout: 5 * time.Second, ReceiptLease: 10 * time.Second}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(ctx); !errors.Is(err, context.Canceled) || queue.completed != 0 {
		t.Fatalf("Run() error=%v completed=%d", err, queue.completed)
	}
}

type runtimeServiceStub struct {
	runResult     RunResult
	runErr        error
	recordResults []Workflow
	recordErr     error
	recordCalls   int
	lastActor     Actor
}

func (stub *runtimeServiceStub) RunOne(context.Context, string) (RunResult, error) {
	return stub.runResult, stub.runErr
}

func (stub *runtimeServiceStub) RecordEdgeReceipt(_ context.Context, actor Actor, _ EdgeReceiptInput) (Workflow, error) {
	stub.recordCalls++
	stub.lastActor = actor
	if stub.recordErr != nil {
		return Workflow{}, stub.recordErr
	}
	if len(stub.recordResults) == 0 {
		return Workflow{}, nil
	}
	index := stub.recordCalls - 1
	if index >= len(stub.recordResults) {
		index = len(stub.recordResults) - 1
	}
	return stub.recordResults[index], nil
}

type receiptQueueStub struct {
	claim        EdgeReceiptClaim
	failComplete bool
	completed    int
	retried      int
	rejected     int
	lastWorker   string
	lastLease    time.Duration
	lastClaim    EdgeReceiptClaim
}

func (stub *receiptQueueStub) Claim(_ context.Context, worker string, _ time.Time, lease time.Duration) (EdgeReceiptClaim, bool, error) {
	stub.lastWorker, stub.lastLease = worker, lease
	return stub.claim, stub.claim.Token != uuid.Nil, nil
}

func (stub *receiptQueueStub) Complete(_ context.Context, claim EdgeReceiptClaim) error {
	stub.lastClaim = claim
	if stub.failComplete {
		return ErrStoreUnavailable
	}
	stub.completed++
	return nil
}

func (stub *receiptQueueStub) Retry(_ context.Context, claim EdgeReceiptClaim, _ string, _ time.Time) error {
	stub.lastClaim = claim
	stub.retried++
	return nil
}

func (stub *receiptQueueStub) Reject(_ context.Context, claim EdgeReceiptClaim, _ string) error {
	stub.lastClaim = claim
	stub.rejected++
	return nil
}

func exactReceiptFixture(now time.Time, tenantID uuid.UUID) EdgeReceiptInput {
	return EdgeReceiptInput{ReceiptID: uuid.New(), TenantScopeID: tenantID, SiteID: uuid.New(), WorkflowID: uuid.New(),
		PolicyID: uuid.New(), PolicyRevision: 8, BindingID: uuid.New(), BindingRevision: 5,
		PublicationID: uuid.New(), RolloutID: uuid.New(), NodeID: uuid.New(), ConfigSHA256: [32]byte{1}, ReceiptSHA256: [32]byte{2},
		ExpectedRevision: 3, ActivePolicyRevision: 8,
		State: "active", ReasonCode: "edge_applied", ObservedAt: now}
}
