//go:build integration

package edgepublish_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

// A manual publication refused because a target
// node lacks the site's JS challenge policy is held like a capability
// refusal, so the node becomes a redelivery target; once it confirms the
// policy the held revision goes out to every node it asked for.
func TestRefusedChallengePublicationIsHeldAndRepublishedAfterRedelivery(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA, nodeB := scope.AddNode(t, 6), scope.AddNode(t, 6)
	scope.SetPresence(t, nodeA, true, 1)
	if err := scope.PublishManually(t, "followup-baseline", nodeA, nodeB); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	// The latest publication goes to A only: B is no target of the scope.
	scope.AdvanceRevision(t)
	if err := scope.PublishManually(t, "followup-a-only", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	policyID := uuid.New()
	scope.BindChallenge(t, policyID, 4)
	scope.InstallChallengePolicy(t, nodeA, policyID, 4, "healthy")

	err := scope.PublishManually(t, "followup-a-and-b", nodeA, nodeB)
	var refusal *edgepublish.ChallengePolicyUnavailableError
	if !errors.As(err, &refusal) || refusal.NodeID != nodeB {
		t.Fatalf("publish to A and B: %v, want B refused for the challenge policy", err)
	}
	hold, held := scope.LatestHold(t)
	if !held || !slices.Equal(hold.Requested, sortedNodes(nodeA, nodeB)) || !slices.Equal(hold.Refused, []uuid.UUID{nodeB}) {
		t.Fatalf("hold = %+v (%v), want requested A,B refused B", hold, held)
	}
	if got := scope.Count(t, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='edge_publication.capability_hold'
		AND payload->'challenge'->>'policy_id'=$2 AND payload->'challenge'->>'site_id'=$3`,
		policyID.String(), scope.SiteID.String()); got != 1 {
		t.Fatalf("challenge hold audits = %d", got)
	}

	// B is a redelivery target now; once it confirms the policy the held
	// revision is published to A and B.
	redeliverer, fake := newChallengeRedeliverer(t, scope, 0)
	scope.SetPresence(t, nodeB, true, 1)
	if queued := sweep(t, redeliverer); queued != 1 || !dispatch(t, redeliverer) || len(fake.calls) != 1 ||
		fake.calls[0].NodeID != nodeB {
		t.Fatalf("redelivery to B: queued %d calls %+v", queued, fake.calls)
	}
	row := scope.ChallengeRedeliveries(t)[nodeB]
	scope.SetRolloutDeploymentState(t, *row.RolloutID, nodeB, "healthy")
	if settled := observe(t, redeliverer); settled != 1 {
		t.Fatalf("settled %d", settled)
	}
	scope.MakeDue(t)
	scope.Run(t)
	attempt := scope.LatestAttempt(t)
	if attempt.Outcome != edgepublish.SystemOutcomePublished || !slices.Equal(attempt.NodeIDs, sortedNodes(nodeA, nodeB)) {
		t.Fatalf("republication = %+v", attempt)
	}
}
