package edgeautopublish

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

type workerRepositoryStub struct {
	mu              sync.Mutex
	references      []edgepublish.AutomaticClaimReference
	retries         []string
	failures        []string
	claimInProgress bool
}

func (stub *workerRepositoryStub) ClaimAutomaticPublication(
	_ context.Context,
	_ string,
	_ time.Duration,
) (edgepublish.AutomaticClaimReference, bool, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	if stub.claimInProgress || len(stub.references) == 0 {
		return edgepublish.AutomaticClaimReference{}, false, nil
	}
	stub.claimInProgress = true
	reference := stub.references[0]
	stub.references = stub.references[1:]
	return reference, true, nil
}

func (stub *workerRepositoryStub) RetryAutomaticPublication(
	_ context.Context,
	_ edgepublish.AutomaticClaimReference,
	reason string,
	_ time.Duration,
) error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.retries = append(stub.retries, reason)
	stub.claimInProgress = false
	return nil
}

func (stub *workerRepositoryStub) FailAutomaticPublication(
	_ context.Context,
	_ edgepublish.AutomaticClaimReference,
	reason string,
) error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.failures = append(stub.failures, reason)
	stub.claimInProgress = false
	return nil
}

type publisherStub struct {
	mu         sync.Mutex
	references []edgepublish.AutomaticClaimReference
	results    []edgepublish.PublishResult
	errors     []error
}

func (stub *publisherStub) PublishAutomatic(
	_ context.Context,
	reference edgepublish.AutomaticClaimReference,
) (edgepublish.PublishResult, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.references = append(stub.references, reference)
	index := len(stub.references) - 1
	var result edgepublish.PublishResult
	if index < len(stub.results) {
		result = stub.results[index]
	}
	if index < len(stub.errors) {
		return result, stub.errors[index]
	}
	return result, nil
}

func TestWorkerPublishesOnlyOpaqueClaimReference(t *testing.T) {
	reference := automaticReference(t)
	repository := &workerRepositoryStub{references: []edgepublish.AutomaticClaimReference{reference}}
	want := edgepublish.PublishResult{
		PublicationID: uuid.New(), ConfigurationScopeID: uuid.New(), SourceRevision: 41, RolloutID: uuid.New(),
	}
	publisher := &publisherStub{results: []edgepublish.PublishResult{want}}
	worker, err := NewWorker(repository, publisher,
		WorkerConfig{WorkerID: "worker-a", LeaseDuration: time.Minute, RetryDelay: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	worked, err := worker.RunOnce(t.Context())
	if err != nil || !worked {
		t.Fatalf("RunOnce() = %t, %v", worked, err)
	}
	if len(publisher.references) != 1 || publisher.references[0] != reference {
		t.Fatalf("published references=%+v want=%+v", publisher.references, reference)
	}
}

func TestWorkerRBACRevocationFailsClosedBeforePublish(t *testing.T) {
	reference := automaticReference(t)
	repository := &workerRepositoryStub{references: []edgepublish.AutomaticClaimReference{reference}}
	publisher := &publisherStub{errors: []error{ErrPermissionDenied}}
	worker, err := NewWorker(repository, publisher,
		WorkerConfig{WorkerID: "worker-rbac", LeaseDuration: time.Minute, RetryDelay: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	worked, err := worker.RunOnce(t.Context())
	if err != nil || !worked {
		t.Fatalf("RunOnce() = %t, %v", worked, err)
	}
	if len(publisher.references) != 1 || len(repository.failures) != 1 || repository.failures[0] != FailureRBACRevoked {
		t.Fatalf("publish calls=%d failures=%v", len(publisher.references), repository.failures)
	}
}

// A publication no retry can complete ends with a reason the publication
// page shows: no node serves the scope, or every node lacks what the
// release needs (a node upgrade or line group change republishes).
func TestWorkerFailsUnpublishableAutomaticPublication(t *testing.T) {
	for publishErr, want := range map[error]string{
		ErrNoTargetNodes: FailureNoTargetNodes,
		fmt.Errorf("publish: %w", &edgepublish.TargetCapabilityError{NodeID: uuid.New()}):          FailureNodeCapability,
		&edgepublish.ChallengePolicyUnavailableError{NodeID: uuid.New(), SiteID: uuid.NewString()}: FailureNodeCapability,
		// O2 (live-site2 10-22): rule packs or the IP library still on their
		// way to the node are a node artifact sync, not a missing capability.
		&edgepublish.RulePackUnavailableError{NodeID: uuid.New()}: FailureNodeArtifactsSyncing,
		fmt.Errorf("publish: %w", &edgepublish.TargetCapabilityError{NodeID: uuid.New(),
			Capability: agentv1.CapabilityName_CAPABILITY_NAME_IP_INTEL, Required: 2, Advertised: 2}): FailureNodeArtifactsSyncing,
		// adm-fix-a2 (73, 10-24): a cross-scope refusal was retried 350 times
		// as publish_outcome_unknown until the deadline.
		fmt.Errorf("publish: %w", &edgepublish.CrossScopeConflictError{NodeID: uuid.New(),
			Reason: "domain a.example is already served by another tenant"}): FailureNodeScopeConflict,
	} {
		reference := automaticReference(t)
		repository := &workerRepositoryStub{references: []edgepublish.AutomaticClaimReference{reference}}
		publisher := &publisherStub{errors: []error{publishErr}}
		worker, err := NewWorker(repository, publisher,
			WorkerConfig{WorkerID: "worker-unpublishable", LeaseDuration: time.Minute, RetryDelay: time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
			t.Fatalf("RunOnce() = %t, %v", worked, err)
		}
		if len(repository.retries) != 0 || len(repository.failures) != 1 || repository.failures[0] != want {
			t.Fatalf("publish error=%v retries=%v failures=%v, want failure %s", publishErr, repository.retries, repository.failures, want)
		}
	}
}

func TestWorkerRetriesAutomaticPublicationFailure(t *testing.T) {
	for _, publishErr := range []error{edgepublish.ErrPersistence, edgepublish.ErrEntitlementDenied} {
		reference := automaticReference(t)
		repository := &workerRepositoryStub{references: []edgepublish.AutomaticClaimReference{reference}}
		publisher := &publisherStub{errors: []error{publishErr}}
		worker, err := NewWorker(repository, publisher,
			WorkerConfig{WorkerID: "worker-retry", LeaseDuration: time.Minute, RetryDelay: time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
			t.Fatalf("RunOnce() = %t, %v", worked, err)
		}
		if len(repository.retries) != 1 || repository.retries[0] != FailurePublishUnknown {
			t.Fatalf("publish error=%v retries=%v", publishErr, repository.retries)
		}
	}
}

func TestWorkerDoesNotRetryTerminalAutomaticRequestExpiration(t *testing.T) {
	reference := automaticReference(t)
	repository := &workerRepositoryStub{references: []edgepublish.AutomaticClaimReference{reference}}
	publisher := &publisherStub{errors: []error{edgepublish.ErrAutomaticRequestExpired}}
	worker, err := NewWorker(repository, publisher,
		WorkerConfig{WorkerID: "worker-expired-request", LeaseDuration: time.Minute, RetryDelay: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if worked, err := worker.RunOnce(t.Context()); err != nil || !worked {
		t.Fatalf("RunOnce() = %t, %v", worked, err)
	}
	if len(repository.retries) != 0 || len(repository.failures) != 0 {
		t.Fatalf("terminal expiration retries/failures=%v/%v", repository.retries, repository.failures)
	}
}

func TestWorkerTwoConcurrentClaimsPublishOnce(t *testing.T) {
	reference := automaticReference(t)
	repository := &workerRepositoryStub{references: []edgepublish.AutomaticClaimReference{reference}}
	publisher := &publisherStub{results: []edgepublish.PublishResult{{
		PublicationID: uuid.New(), ConfigurationScopeID: uuid.New(), SourceRevision: 72, RolloutID: uuid.New(),
	}}}
	newWorker := func(id string) *Worker {
		worker, err := NewWorker(repository, publisher,
			WorkerConfig{WorkerID: id, LeaseDuration: time.Minute, RetryDelay: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		return worker
	}
	workers := []*Worker{newWorker("worker-one"), newWorker("worker-two")}
	start := make(chan struct{})
	results := make(chan error, len(workers))
	for _, worker := range workers {
		go func(worker *Worker) {
			<-start
			_, err := worker.RunOnce(t.Context())
			results <- err
		}(worker)
	}
	close(start)
	for range workers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if len(publisher.references) != 1 {
		t.Fatalf("publish calls=%d", len(publisher.references))
	}
}

func TestClassifyRolloutUsesWholeRolloutAndActionSemantics(t *testing.T) {
	tests := []struct {
		name     string
		action   string
		states   []string
		terminal bool
		outcome  string
		reason   string
	}{
		{name: "apply healthy", action: "apply", states: []string{"healthy", "healthy"}, terminal: true, outcome: StateSucceeded, reason: SuccessApplyHealthy},
		{name: "apply reverted fails", action: "apply", states: []string{"healthy", "reverted"}, terminal: true, outcome: StateFailed, reason: FailureApplyReverted},
		{name: "rollback reverted succeeds", action: "rollback", states: []string{"reverted", "reverted"}, terminal: true, outcome: StateSucceeded, reason: SuccessRollbackReverted},
		{name: "rollback healthy not success", action: "rollback", states: []string{"reverted", "healthy"}, terminal: true, outcome: StateFailed, reason: FailureRollbackUnexpected},
		{name: "failed", action: "apply", states: []string{"healthy", "failed"}, terminal: true, outcome: StateFailed, reason: FailureDeploymentFailed},
		{name: "rollback failed", action: "rollback", states: []string{"reverted", "rollback_failed"}, terminal: true, outcome: StateFailed, reason: FailureRollbackFailed},
		{name: "cancelled", action: "apply", states: []string{"healthy", "cancelled"}, terminal: true, outcome: StateFailed, reason: FailureCancelled},
		{name: "single healthy does not decide", action: "apply", states: []string{"healthy", "activated"}, terminal: false},
		// fix-cfgflow2 §1: a node that ignored this old release runs a newer one.
		{name: "apply healthy with ignored old release", action: "apply", states: []string{"healthy", "superseded"}, terminal: true, outcome: StateSucceeded, reason: SuccessApplyHealthy},
		{name: "apply only ignored old release", action: "apply", states: []string{"superseded"}, terminal: true, outcome: StateSucceeded, reason: SuccessApplyHealthy},
		{name: "ignored old release with a failure fails", action: "apply", states: []string{"superseded", "failed"}, terminal: true, outcome: StateFailed, reason: FailureDeploymentFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			terminal, outcome, reason := classifyRollout(test.action, test.states)
			if terminal != test.terminal || outcome != test.outcome || reason != test.reason {
				t.Fatalf("classifyRollout() = %t/%q/%q, want %t/%q/%q",
					terminal, outcome, reason, test.terminal, test.outcome, test.reason)
			}
		})
	}
}

func TestClassifyPersistedRolloutRequiresAggregateTerminalState(t *testing.T) {
	tests := []struct {
		name     string
		contract int16
		action   string
		status   string
		states   []string
		terminal bool
		outcome  string
		reason   string
	}{
		// adm-fix-a (73, 10-25): v0/v1 rollouts never leave queued, so the
		// deployments decide; before the fix these stayed reconciling forever
		// and the CRS republication banner never cleared.
		{name: "v0 queued all healthy", contract: 0, action: "apply", status: "queued", states: []string{"healthy", "healthy"}, terminal: true, outcome: StateSucceeded, reason: SuccessApplyHealthy},
		{name: "v1 queued all healthy", contract: 1, action: "apply", status: "queued", states: []string{"healthy", "healthy"}, terminal: true, outcome: StateSucceeded, reason: SuccessApplyHealthy},
		{name: "v1 queued one failed", contract: 1, action: "apply", status: "queued", states: []string{"healthy", "failed"}, terminal: true, outcome: StateFailed, reason: FailureDeploymentFailed},
		{name: "v1 queued still activating", contract: 1, action: "apply", status: "queued", states: []string{"healthy", "activated"}},
		{name: "v1 cancelled", contract: 1, action: "apply", status: "cancelled", states: []string{"healthy", "cancelled"}, terminal: true, outcome: StateFailed, reason: FailureCancelled},
		{name: "v2 queued all healthy", contract: 2, action: "apply", status: "queued", states: []string{"healthy", "healthy"}},
		{name: "v2 paused all healthy", contract: 2, action: "apply", status: "paused", states: []string{"healthy", "healthy"}},
		{name: "v2 cancelled healthy", contract: 2, action: "apply", status: "cancelled", states: []string{"healthy"}, terminal: true, outcome: StateFailed, reason: FailureCancelled},
		{name: "v2 failed healthy", contract: 2, action: "apply", status: "failed", states: []string{"healthy"}, terminal: true, outcome: StateFailed, reason: FailureDeploymentFailed},
		{name: "v2 failed rollback failed", contract: 2, action: "rollback", status: "failed", states: []string{"rollback_failed"}, terminal: true, outcome: StateFailed, reason: FailureRollbackFailed},
		{name: "v2 completed apply", contract: 2, action: "apply", status: "completed", states: []string{"healthy", "healthy"}, terminal: true, outcome: StateSucceeded, reason: SuccessApplyHealthy},
		{name: "v2 completed inconsistent", contract: 2, action: "apply", status: "completed", states: []string{"activated"}, terminal: true, outcome: StateFailed, reason: FailureDeploymentFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			terminal, outcome, reason := classifyPersistedRollout(test.contract, test.action, test.status, test.states)
			if terminal != test.terminal || outcome != test.outcome || reason != test.reason {
				t.Fatalf("classifyPersistedRollout() = %t/%q/%q, want %t/%q/%q",
					terminal, outcome, reason, test.terminal, test.outcome, test.reason)
			}
		})
	}
}

func TestWorkerRejectsInvalidDependencies(t *testing.T) {
	repository := &workerRepositoryStub{references: []edgepublish.AutomaticClaimReference{automaticReference(t)}}
	publisher := &publisherStub{}
	valid := WorkerConfig{WorkerID: "worker-valid", LeaseDuration: time.Minute, RetryDelay: time.Second}
	if _, err := NewWorker(nil, publisher, valid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil repository error=%v", err)
	}
	if _, err := NewWorker(repository, nil, valid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil publisher error=%v", err)
	}
}

func automaticReference(t *testing.T) edgepublish.AutomaticClaimReference {
	t.Helper()
	requestID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return edgepublish.AutomaticClaimReference{
		RequestID: requestID, LeaseToken: uuid.New(), StateSequence: 2,
	}
}

func automaticClaim(t *testing.T, operation string, sourceRevision int64) Claim {
	t.Helper()
	nodes := []uuid.UUID{uuid.New(), uuid.New()}
	if nodes[0].String() > nodes[1].String() {
		nodes[0], nodes[1] = nodes[1], nodes[0]
	}
	requestID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	correlationID, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	sourceKind, permission := SourceSite, PermissionSitesManage
	if len(operation) >= len("stream.") && operation[:len("stream.")] == "stream." {
		sourceKind, permission = SourceL4, PermissionStreamsManage
	}
	return Claim{
		Request: Request{
			ID: requestID, CorrelationID: correlationID, TargetScopeID: uuid.New(),
			ActorScopeID: uuid.New(), ActorUserID: uuid.New(), ActorScopeKind: ScopeKindTenant,
			SourceKind: sourceKind, SourceResourceID: uuid.New(), SourceRevision: sourceRevision,
			Operation: operation, Reason: ReasonResourceMutation, Permission: permission,
			SourceRequestID: "source-request", IdempotencyKey: "edgeauto." + requestID.String(),
			CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
		},
		Policy: Policy{
			TargetScopeID: uuid.New(), Revision: 3, Mode: ModeAutomatic, NodeIDs: nodes,
			ActivationTimeout: 30 * time.Second, ObservationWindow: 15 * time.Second,
			RequiredConsecutiveSuccesses: 2, MaxAttempts: 3, DeadlineWindow: 10 * time.Minute,
		},
		LeaseToken: uuid.New(), StateSequence: 2,
	}
}
