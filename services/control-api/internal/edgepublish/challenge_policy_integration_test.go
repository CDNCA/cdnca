//go:build integration

package edgepublish_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
)

// A release with a JS challenge is refused, naming the node and the site,
// until the challenge secret rollout of that policy version is healthy on
// every target node (nginx -t would accept it there, master start would not).
func TestPublishRefusesJSChallengeUntilEveryTargetHoldsThePolicy(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA, nodeB := scope.AddNode(t, 6), scope.AddNode(t, 6)
	if err := scope.PublishManually(t, "challenge-baseline", nodeA, nodeB); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	policyID := uuid.New()
	scope.BindChallenge(t, policyID, 7)
	publications := `SELECT count(*) FROM edge_config_publications WHERE configuration_scope_id=$1`
	before := scope.Count(t, publications)

	refused := func(key string, want ...uuid.UUID) {
		t.Helper()
		err := scope.PublishManually(t, key, nodeA, nodeB)
		var refusal *edgepublish.ChallengePolicyUnavailableError
		if !errors.As(err, &refusal) || !errors.Is(err, edgepublish.ErrTargetIneligible) {
			t.Fatalf("%s: %v, want a challenge policy refusal", key, err)
		}
		named := append([]uuid.UUID{refusal.NodeID}, refusal.OtherNodeIDs...)
		if !slices.Equal(sortedNodes(named...), sortedNodes(want...)) || refusal.SiteID != scope.SiteID.String() ||
			refusal.PolicyID != policyID.String() || refusal.PolicyVersion != 7 ||
			!strings.Contains(err.Error(), refusal.NodeID.String()) || !strings.Contains(err.Error(), "system-republish.example.com") {
			t.Fatalf("%s: refusal %+v (%v), want nodes %v", key, refusal, err, want)
		}
		if got := scope.Count(t, publications); got != before {
			t.Fatalf("%s: refused release persisted (%d publications, was %d)", key, got, before)
		}
	}
	refused("challenge-none", nodeA, nodeB)
	scope.InstallChallengePolicy(t, nodeA, policyID, 7, "healthy")
	scope.InstallChallengePolicy(t, nodeB, policyID, 7, "failed")
	refused("challenge-failed-on-b", nodeB)
	// Another version of the policy is another file.
	scope.InstallChallengePolicy(t, nodeB, policyID, 6, "healthy")
	refused("challenge-other-version-on-b", nodeB)
	scope.InstallChallengePolicy(t, nodeB, policyID, 7, "healthy")
	if err := scope.PublishManually(t, "challenge-ready", nodeA, nodeB); err != nil {
		t.Fatalf("both nodes hold the policy: %v", err)
	}
	if got := scope.Count(t, publications); got != before+1 {
		t.Fatalf("publications = %d, want %d", got, before+1)
	}
}

// The system and automatic channels leave a node without the policy out
// (listed with the site) and publish the rest.
func TestSystemChannelExcludesNodesWithoutTheChallengePolicy(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA, nodeB := scope.AddNode(t, 6), scope.AddNode(t, 6)
	if err := scope.PublishManually(t, "challenge-baseline", nodeA, nodeB); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	policyID := uuid.New()
	scope.BindChallenge(t, policyID, 3)
	scope.InstallChallengePolicy(t, nodeA, policyID, 3, "healthy")
	published, refused := scope.PublishExcluding(t, "challenge-system", nodeA, nodeB)
	if !slices.Equal(published, []uuid.UUID{nodeA}) || len(refused) != 1 || refused[nodeB] != scope.SiteID.String() {
		t.Fatalf("published %v, refused %v", published, refused)
	}
}

// Site runtime v2 loads the same policy file (listener challenge): the same
// refusal before the rollout, the release once it is healthy.
func TestSiteRuntimeV2PublishRefusesJSChallengeWithoutThePolicy(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := scope.AddNode(t, 6)
	if err := scope.PublishManuallyV2(t, "challenge-v2-baseline", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	policyID := uuid.New()
	scope.BindChallenge(t, policyID, 2)
	err := scope.PublishManuallyV2(t, "challenge-v2-missing", nodeA)
	var refusal *edgepublish.ChallengePolicyUnavailableError
	if !errors.As(err, &refusal) || refusal.NodeID != nodeA || refusal.SiteID != scope.SiteID.String() || refusal.PolicyVersion != 2 {
		t.Fatalf("v2 without the policy: %v", err)
	}
	scope.InstallChallengePolicy(t, nodeA, policyID, 2, "healthy")
	if err := scope.PublishManuallyV2(t, "challenge-v2-ready", nodeA); err != nil {
		t.Fatalf("v2 with the policy: %v", err)
	}
}
