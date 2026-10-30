//go:build integration

package edgepublish_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/challengepolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A JS challenge promotion no longer needs every
// node of the scope healthy. Nodes A and B are online, C is offline; the
// challenge secret rollout reached A and B, C's deployment waits in its queue.

type promoteRolloutReader struct {
	status challengepublication.RolloutStatus
}

func (reader promoteRolloutReader) ChallengeRolloutStatus(context.Context, challengepublication.StatusRequest,
) (challengepublication.RolloutStatus, error) {
	return reader.status, nil
}

type promoteSecretPublisher struct{}

func (promoteSecretPublisher) PublishChallengeSecret(context.Context, challengepublication.PublishRequest,
	challengepublication.ArtifactMaterial) (challengepublication.SecretPublication, error) {
	return challengepublication.SecretPublication{}, errors.New("not used")
}

type promoteCase struct {
	scope            *edgepublish.SystemRepublishScope
	nodeA, nodeB     uuid.UUID
	nodeC, policyID  uuid.UUID
	rolloutID        uuid.UUID
	promotions       int
	bindingPublished []uuid.UUID
}

func newPromoteCase(t *testing.T, states func(a, b, c uuid.UUID) map[uuid.UUID]string) *promoteCase {
	t.Helper()
	scope := edgepublish.NewSystemRepublishScope(t)
	value := &promoteCase{scope: scope, nodeA: scope.AddNode(t, 6), nodeB: scope.AddNode(t, 6), nodeC: scope.AddNode(t, 6),
		policyID: uuid.New()}
	scope.SetPresence(t, value.nodeA, true, 1)
	scope.SetPresence(t, value.nodeB, true, 1)
	if err := scope.PublishManually(t, "promote-baseline", value.nodeA, value.nodeB, value.nodeC); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	scope.BindChallenge(t, value.policyID, 4)
	value.rolloutID = scope.InstallChallengeRollout(t, value.policyID, 4, states(value.nodeA, value.nodeB, value.nodeC))
	return value
}

func (value *promoteCase) nodes() []uuid.UUID {
	return sortedNodes(value.nodeA, value.nodeB, value.nodeC)
}

// readiness classifies the rollout's nodes as the coordinator does
// (PostgresPublicationIdentityVerifier.Readiness), every node planned.
func (value *promoteCase) readiness(t *testing.T) challengepublication.NodeReadiness {
	t.Helper()
	var readiness challengepublication.NodeReadiness
	if err := pgx.BeginFunc(t.Context(), value.scope.Pool, func(tx pgx.Tx) error {
		var err error
		readiness, err = challengepolicy.PostgresPublicationIdentityVerifier{}.Readiness(t.Context(), tx,
			value.scope.ScopeID, value.rolloutID, value.nodes())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return readiness
}

// promote runs the challenge runtime's promotion gate with the readiness;
// its binding publisher publishes to the ready nodes and defers the rest.
func (value *promoteCase) promote(t *testing.T, readiness challengepublication.NodeReadiness) (challengepublication.PromotionStatus, error) {
	t.Helper()
	configs := challengepublication.ConfigPublisherFunc(func(_ context.Context, request challengepublication.BindingRequest,
	) (challengepublication.ConfigPublication, error) {
		value.promotions++
		value.bindingPublished = slices.Clone(request.NodeIDs)
		result, err := value.scope.PublishChallengeBinding(t, "promote-binding", request.NodeIDs, request.DeferredNodeIDs,
			value.policyID, value.rolloutID, 4)
		if err != nil {
			return challengepublication.ConfigPublication{}, err
		}
		return challengepublication.ConfigPublication{PublicationID: result.PublicationID, Revision: result.SourceRevision}, nil
	})
	status := challengepublication.RolloutStatus{RolloutID: value.rolloutID, ConfigVersionID: uuid.New(), Revision: 1,
		State: challengepublication.StateRunning, Reason: challengepublication.ReasonWaitingForNodes, Total: 3, Healthy: 2,
		Pending: 1}
	keys := challengepublication.KeyResolverFunc(func(context.Context, challengepublication.PublicationSnapshot,
	) (challengepublication.ResolvedKeys, error) {
		return challengepublication.ResolvedKeys{}, challengepublication.ErrKeyUnavailable
	})
	runtime, err := challengepublication.NewRuntime(keys, promoteSecretPublisher{},
		promoteRolloutReader{status: status}, configs)
	if err != nil {
		t.Fatal(err)
	}
	return runtime.Promote(t.Context(), challengepublication.PromoteRequest{
		PublishRequest: challengepublication.PublishRequest{
			Policy: challengepublication.PublicationSnapshot{PolicyID: value.policyID, TenantScopeID: value.scope.ScopeID,
				TenantID: uuid.New(), SiteID: value.scope.SiteID, Host: "system-republish.example.com", Revision: 4,
				Priority: 10, Mode: "click", KeyReference: "keyref:challenge-primary"},
			NodeIDs: value.nodes(), IdempotencyKey: "promote",
		},
		Secret:    challengepublication.SecretPublication{RolloutID: value.rolloutID, ConfigVersionID: status.ConfigVersionID, Revision: 1},
		Readiness: readiness,
	})
}

// One node offline: the others take the challenge at once; the offline node
// is held and its queued secret deployment becomes its redelivery; once it
// comes back and installs the policy, the scope is republished to it too.
func TestChallengePromotionLeavesOfflineNodeToRedelivery(t *testing.T) {
	value := newPromoteCase(t, func(a, b, c uuid.UUID) map[uuid.UUID]string {
		return map[uuid.UUID]string{a: "healthy", b: "healthy", c: "queued"}
	})
	scope := value.scope
	readiness := value.readiness(t)
	if !slices.Equal(readiness.Ready, sortedNodes(value.nodeA, value.nodeB)) ||
		!slices.Equal(readiness.Deferred, []uuid.UUID{value.nodeC}) || len(readiness.Waiting)+len(readiness.Failed) != 0 {
		t.Fatalf("readiness = %+v", readiness)
	}
	status, err := value.promote(t, readiness)
	if err != nil || status.State != challengepublication.StateActive || status.ConfigPublication == nil {
		t.Fatalf("Promote() = (%+v, %v)", status, err)
	}
	if publication := scope.LatestPublication(t); !slices.Equal(publication.NodeIDs, sortedNodes(value.nodeA, value.nodeB)) {
		t.Fatalf("binding published to %v", publication.NodeIDs)
	}
	hold, found := scope.LatestHold(t)
	if !found || hold.SourceRevision != status.ConfigPublication.Revision ||
		!slices.Equal(hold.Requested, value.nodes()) || !slices.Equal(hold.Refused, []uuid.UUID{value.nodeC}) {
		t.Fatalf("hold = %+v (found %v), publication revision %d", hold, found, status.ConfigPublication.Revision)
	}
	rows := scope.ChallengeRedeliveries(t)
	if row, ok := rows[value.nodeC]; len(rows) != 1 || !ok || row.State != edgepublish.ChallengeRedeliveryStateDelivering ||
		row.RolloutID == nil || *row.RolloutID != value.rolloutID || row.Attempt != 1 {
		t.Fatalf("redeliveries = %+v", rows)
	}
	if got := scope.Count(t, `SELECT count(*) FROM audit_events WHERE scope_id=$1
		AND action='edge_publication.capability_hold' AND payload->'challenge'->>'deferred'='true'`); got != 1 {
		t.Fatalf("deferral audits = %d", got)
	}

	redeliverer, fake := newChallengeRedeliverer(t, scope, 0)
	// Offline and in flight: nothing new is started.
	if queued := sweep(t, redeliverer); queued != 0 || dispatch(t, redeliverer) || observe(t, redeliverer) != 0 {
		t.Fatal("offline deferred node redelivered again")
	}
	// C comes back and installs the queued policy: delivered, republished.
	scope.SetPresence(t, value.nodeC, true, 1)
	scope.SetRolloutDeploymentState(t, value.rolloutID, value.nodeC, "healthy")
	if settled := observe(t, redeliverer); settled != 1 || len(fake.calls) != 0 {
		t.Fatalf("settled %d, new rollouts %d", settled, len(fake.calls))
	}
	scope.SettleDeployments(t)
	scope.MakeDue(t)
	scope.Run(t)
	attempt := scope.LatestAttempt(t)
	if attempt.Outcome != edgepublish.SystemOutcomePublished || !slices.Equal(attempt.NodeIDs, value.nodes()) ||
		len(attempt.RefusedNodes) != 0 || !slices.Equal(attempt.Triggers, []string{edgepublish.SystemTriggerChallengeDelivery}) {
		t.Fatalf("republication = %+v", attempt)
	}
	if queued := sweep(t, redeliverer); queued != 0 || len(scope.ChallengeRedeliveries(t)) != 0 {
		t.Fatalf("after the republication queued %d: %+v", queued, scope.ChallengeRedeliveries(t))
	}
}

// An online node that failed (or is past its deadline) refuses the whole
// promotion; one still applying holds it; nothing is published either way.
func TestChallengePromotionRefusedForOnlineNodeFailure(t *testing.T) {
	value := newPromoteCase(t, func(a, b, c uuid.UUID) map[uuid.UUID]string {
		return map[uuid.UUID]string{a: "healthy", b: "failed", c: "queued"}
	})
	scope := value.scope
	before := scope.LatestPublication(t).SourceRevision
	readiness := value.readiness(t)
	if !slices.Equal(readiness.Ready, []uuid.UUID{value.nodeA}) || !slices.Equal(readiness.Failed, []uuid.UUID{value.nodeB}) ||
		!slices.Equal(readiness.Deferred, []uuid.UUID{value.nodeC}) {
		t.Fatalf("readiness = %+v", readiness)
	}
	status, err := value.promote(t, readiness)
	if !errors.Is(err, challengepublication.ErrRolloutFailed) || status.State != challengepublication.StateFailed ||
		value.promotions != 0 {
		t.Fatalf("Promote() = (%+v, %v), bindings %d", status, err, value.promotions)
	}

	// B still staging it (online): wait.
	scope.SetRolloutDeploymentState(t, value.rolloutID, value.nodeB, "staged")
	readiness = value.readiness(t)
	if !slices.Equal(readiness.Waiting, []uuid.UUID{value.nodeB}) || len(readiness.Failed) != 0 {
		t.Fatalf("readiness while B applies = %+v", readiness)
	}
	if _, err := value.promote(t, readiness); !errors.Is(err, challengepublication.ErrRolloutNotHealthy) || value.promotions != 0 {
		t.Fatalf("Promote() while B applies: %v, bindings %d", err, value.promotions)
	}
	// B online past its deadline: failed.
	scope.ExpireRolloutDeployment(t, value.rolloutID, value.nodeB)
	if readiness = value.readiness(t); !slices.Equal(readiness.Failed, []uuid.UUID{value.nodeB}) {
		t.Fatalf("readiness after B's deadline = %+v", readiness)
	}
	// B goes offline: no longer holds the promotion back.
	scope.SetPresence(t, value.nodeB, false, 0)
	if readiness = value.readiness(t); !slices.Equal(readiness.Deferred, sortedNodes(value.nodeB, value.nodeC)) ||
		!slices.Equal(readiness.Ready, []uuid.UUID{value.nodeA}) {
		t.Fatalf("readiness with B offline = %+v", readiness)
	}
	if after := scope.LatestPublication(t).SourceRevision; after != before {
		t.Fatalf("refused promotions published revision %d (was %d)", after, before)
	}
	if _, found := scope.LatestHold(t); found {
		t.Fatal("a refused promotion recorded a hold")
	}
}

// A refused publication followed by one of the same revision to fewer nodes
// is the tenant's choice: the refused node is not a target of the system
// republication (its hold was not written with a publication, 352); a
// deferred promotion's hold is (TestChallengePromotionLeavesOfflineNodeToRedelivery).
func TestRefusedHoldAtPublishedRevisionDoesNotTargetTheNode(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA, nodeB := scope.AddNode(t, 6), scope.AddNode(t, 6)
	if err := scope.PublishManually(t, "stale-baseline", nodeA, nodeB); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	policyID := uuid.New()
	scope.BindChallenge(t, policyID, 4)
	scope.InstallChallengePolicy(t, nodeA, policyID, 4, "healthy")
	var unavailable *edgepublish.ChallengePolicyUnavailableError
	if err := scope.PublishManually(t, "stale-both", nodeA, nodeB); !errors.As(err, &unavailable) || unavailable.NodeID != nodeB {
		t.Fatalf("publish to both: %v", err)
	}
	if err := scope.PublishManually(t, "stale-a", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	hold, found := scope.LatestHold(t)
	if publication := scope.LatestPublication(t); !found || hold.SourceRevision != publication.SourceRevision ||
		!slices.Equal(hold.Refused, []uuid.UUID{nodeB}) {
		t.Fatalf("hold %+v (found %v), publication revision %d", hold, found, publication.SourceRevision)
	}
	scope.Request(t, edgepublish.SystemTriggerNodeSync)
	scope.MakeDue(t)
	scope.Run(t)
	attempt := scope.LatestAttempt(t)
	if attempt.Outcome != edgepublish.SystemOutcomePublished || !slices.Equal(attempt.NodeIDs, []uuid.UUID{nodeA}) ||
		len(attempt.RefusedNodes) != 0 {
		t.Fatalf("republication = %+v", attempt)
	}
}
