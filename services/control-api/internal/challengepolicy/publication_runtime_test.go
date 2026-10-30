package challengepolicy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type publicationPolicySourceStub struct {
	snapshot PublicationSnapshot
}

func (stub *publicationPolicySourceStub) UsePublicationSnapshot(ctx context.Context, _ Actor, scopeID, policyID uuid.UUID,
	revision int64, consume PublicationConsumer) error {
	if scopeID != stub.snapshot.TenantScopeID || policyID != stub.snapshot.PolicyID || revision != stub.snapshot.Revision {
		return ErrRevisionConflict
	}
	return consume(ctx, nil, stub.snapshot)
}

func (stub *publicationPolicySourceStub) ReadPublicationSnapshot(ctx context.Context, _ Actor, scopeID, policyID uuid.UUID,
	consume PublicationConsumer) error {
	if scopeID != stub.snapshot.TenantScopeID || policyID != stub.snapshot.PolicyID {
		return ErrNotFound
	}
	return consume(ctx, nil, stub.snapshot)
}

type publicationRuntimeStub struct {
	secret       challengepublication.SecretPublication
	status       challengepublication.RolloutStatus
	promotion    challengepublication.PromotionStatus
	promoted     challengepublication.PromoteRequest
	publishCalls int
	statusCalls  int
	promoteCalls int
}

func (stub *publicationRuntimeStub) Publish(context.Context, challengepublication.PublishRequest) (challengepublication.SecretPublication, error) {
	stub.publishCalls++
	return stub.secret, nil
}

func (stub *publicationRuntimeStub) Status(context.Context, challengepublication.StatusRequest) (challengepublication.RolloutStatus, error) {
	stub.statusCalls++
	return stub.status, nil
}

func (stub *publicationRuntimeStub) Promote(_ context.Context, request challengepublication.PromoteRequest) (challengepublication.PromotionStatus, error) {
	stub.promoteCalls++
	stub.promoted = request
	return stub.promotion, nil
}

type publicationPlannerStub struct{ plan PublicationPlan }

func (stub *publicationPlannerStub) Plan(context.Context, pgx.Tx, PublicationSnapshot) (PublicationPlan, error) {
	return stub.plan, nil
}

type publicationVerifierStub struct {
	nodes     []uuid.UUID
	err       error
	calls     int
	readiness challengepublication.NodeReadiness
	planned   []uuid.UUID
}

func (stub *publicationVerifierStub) Verify(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, int64) ([]uuid.UUID, error) {
	stub.calls++
	return stub.nodes, stub.err
}

func (stub *publicationVerifierStub) Readiness(_ context.Context, _ pgx.Tx, _, _ uuid.UUID,
	planned []uuid.UUID) (challengepublication.NodeReadiness, error) {
	stub.planned = planned
	if stub.readiness.Ready == nil && stub.readiness.Deferred == nil {
		return challengepublication.NodeReadiness{Ready: planned}, nil
	}
	return stub.readiness, nil
}

func TestPublicationCoordinatorBindsStatusAndPromotionToExactDurableArtifact(t *testing.T) {
	snapshot := testPublicationSnapshot()
	rolloutID, configVersionID := uuid.New(), uuid.New()
	nodes := []uuid.UUID{uuid.New(), uuid.New()}
	status := challengepublication.RolloutStatus{RolloutID: rolloutID, ConfigVersionID: configVersionID,
		Revision: 1, State: challengepublication.StateHealthy, Total: 2, Healthy: 2}
	runtime := &publicationRuntimeStub{
		secret: challengepublication.SecretPublication{RolloutID: rolloutID, ConfigVersionID: configVersionID, Revision: 1},
		status: status,
		promotion: challengepublication.PromotionStatus{RolloutStatus: status,
			ConfigPublication: &challengepublication.ConfigPublication{PublicationID: uuid.New(), Revision: 9}},
	}
	planner := &publicationPlannerStub{plan: PublicationPlan{NodeIDs: nodes,
		HealthCheck: edgedeployment.HealthCheckPolicy{ActivationTimeout: time.Second,
			ObservationWindow: time.Second, RequiredConsecutiveSuccesses: 1}, Deadline: time.Now().Add(time.Minute)}}
	verifier := &publicationVerifierStub{nodes: nodes}
	coordinator, err := NewPublicationCoordinator(&publicationPolicySourceStub{snapshot: snapshot}, runtime, planner, verifier)
	if err != nil {
		t.Fatal(err)
	}
	request := testPublicationCommand(snapshot)
	published, err := coordinator.Publish(context.Background(), request)
	if err != nil || published.PolicyID != snapshot.PolicyID || published.State != challengepublication.StateHealthy ||
		runtime.publishCalls != 1 || verifier.calls != 1 {
		t.Fatalf("Publish() = (%+v, %v), calls=%d verifier=%d", published, err, runtime.publishCalls, verifier.calls)
	}
	request.RolloutID = rolloutID
	promoted, err := coordinator.Promote(context.Background(), request)
	if err != nil || promoted.State != challengepublication.StateHealthy || promoted.ConfigPublication == nil ||
		runtime.promoteCalls != 1 || verifier.calls != 2 {
		t.Fatalf("Promote() = (%+v, %v), calls=%d verifier=%d", promoted, err, runtime.promoteCalls, verifier.calls)
	}
}

func TestPublicationCoordinatorRejectsCrossPolicyRolloutAndNodeDriftWithoutPromotion(t *testing.T) {
	snapshot := testPublicationSnapshot()
	rolloutID, configVersionID := uuid.New(), uuid.New()
	nodeID := uuid.New()
	runtime := &publicationRuntimeStub{status: challengepublication.RolloutStatus{
		RolloutID: rolloutID, ConfigVersionID: configVersionID, Revision: 1,
		State: challengepublication.StateHealthy, Total: 1, Healthy: 1,
	}}
	planner := &publicationPlannerStub{plan: PublicationPlan{NodeIDs: []uuid.UUID{nodeID},
		HealthCheck: edgedeployment.HealthCheckPolicy{ActivationTimeout: time.Second,
			ObservationWindow: time.Second, RequiredConsecutiveSuccesses: 1}, Deadline: time.Now().Add(time.Minute)}}
	verifier := &publicationVerifierStub{err: ErrNotFound}
	coordinator, err := NewPublicationCoordinator(&publicationPolicySourceStub{snapshot: snapshot}, runtime, planner, verifier)
	if err != nil {
		t.Fatal(err)
	}
	request := testPublicationCommand(snapshot)
	request.RolloutID = rolloutID
	if _, err := coordinator.Promote(context.Background(), request); !errors.Is(err, ErrNotFound) || runtime.promoteCalls != 0 {
		t.Fatalf("cross-policy Promote() error=%v calls=%d", err, runtime.promoteCalls)
	}
	verifier.err = nil
	verifier.nodes = []uuid.UUID{uuid.New()}
	if _, err := coordinator.Promote(context.Background(), request); !errors.Is(err, ErrConflict) || runtime.promoteCalls != 0 {
		t.Fatalf("node-drift Promote() error=%v calls=%d", err, runtime.promoteCalls)
	}
}

// A rollout node the scope no longer plans (disabled
// since) does not conflict; the readiness of the rollout's nodes, against the
// planned set, goes to the runtime with every rollout node as the target.
func TestPublicationCoordinatorPromotesWithRolloutNodesOutsideThePlan(t *testing.T) {
	snapshot := testPublicationSnapshot()
	rolloutID, configVersionID := uuid.New(), uuid.New()
	planned, disabled := uuid.New(), uuid.New()
	status := challengepublication.RolloutStatus{RolloutID: rolloutID, ConfigVersionID: configVersionID, Revision: 1,
		State: challengepublication.StateRunning, Reason: challengepublication.ReasonWaitingForNodes, Total: 2,
		Healthy: 1, Pending: 1}
	runtime := &publicationRuntimeStub{status: status, promotion: challengepublication.PromotionStatus{RolloutStatus: status,
		ConfigPublication: &challengepublication.ConfigPublication{PublicationID: uuid.New(), Revision: 4}}}
	planner := &publicationPlannerStub{plan: PublicationPlan{NodeIDs: []uuid.UUID{planned},
		HealthCheck: edgedeployment.HealthCheckPolicy{ActivationTimeout: time.Second,
			ObservationWindow: time.Second, RequiredConsecutiveSuccesses: 1}, Deadline: time.Now().Add(time.Minute)}}
	readiness := challengepublication.NodeReadiness{Ready: []uuid.UUID{planned}, Deferred: []uuid.UUID{disabled}}
	verifier := &publicationVerifierStub{nodes: []uuid.UUID{planned, disabled}, readiness: readiness}
	coordinator, err := NewPublicationCoordinator(&publicationPolicySourceStub{snapshot: snapshot}, runtime, planner, verifier)
	if err != nil {
		t.Fatal(err)
	}
	request := testPublicationCommand(snapshot)
	request.RolloutID = rolloutID
	if _, err := coordinator.Promote(context.Background(), request); err != nil || runtime.promoteCalls != 1 {
		t.Fatalf("Promote() error=%v calls=%d", err, runtime.promoteCalls)
	}
	if !equalPublicationNodes(runtime.promoted.NodeIDs, []uuid.UUID{planned, disabled}) ||
		!equalPublicationNodes(verifier.planned, []uuid.UUID{planned}) ||
		!equalPublicationNodes(runtime.promoted.Readiness.Ready, readiness.Ready) ||
		!equalPublicationNodes(runtime.promoted.Readiness.Deferred, readiness.Deferred) {
		t.Fatalf("promoted %v readiness %+v (planned %v)", runtime.promoted.NodeIDs, runtime.promoted.Readiness, verifier.planned)
	}
}

func testPublicationSnapshot() PublicationSnapshot {
	return PublicationSnapshot{PolicyID: uuid.New(), TenantScopeID: uuid.New(), TenantID: uuid.New(), SiteID: uuid.New(),
		Host: "challenge.example.test", Revision: 7, Priority: 10, Mode: ModeClick,
		ChallengeTTLSeconds: 60, PassTTLSeconds: 300, AttemptsPerNonce: 1,
		FailureWindowSeconds: 60, MaxFailuresPerWindow: 3, IPBinding: IPBindingExact,
		KeyReference: "keyref:challenge-primary"}
}

func testPublicationCommand(snapshot PublicationSnapshot) PublicationRequest {
	actor := Actor{UserID: uuid.New(), ScopeID: snapshot.TenantScopeID, ScopeKind: "tenant",
		Credential: CredentialReference{Kind: CredentialKindSession, ID: uuid.New()}, rawCredential: "challenge-session"}
	return PublicationRequest{Actor: actor, TenantScopeID: snapshot.TenantScopeID, PolicyID: snapshot.PolicyID,
		ExpectedRevision: snapshot.Revision, Metadata: WriteMetadata{IdempotencyKey: "challenge-publication-test",
			RequestID: uuid.NewString(), TraceID: uuid.NewString()}}
}

// Nodes that ignored the secret as an old release are returned
// apart (superseded) and do not make the status invalid or failed.
func TestPublicationStatusCarriesIgnoredOldRelease(t *testing.T) {
	snapshot := testPublicationSnapshot()
	view := publicationStatusView(snapshot, challengepublication.RolloutStatus{RolloutID: uuid.New(),
		ConfigVersionID: uuid.New(), Revision: 1, State: challengepublication.StateHealthy,
		Total: 3, Healthy: 2, Superseded: 1}, nil)
	if view.Superseded != 1 || view.Failed != 0 || !validPublicationStatus(view) {
		t.Fatalf("publicationStatusView() = %+v valid=%v", view, validPublicationStatus(view))
	}
}
