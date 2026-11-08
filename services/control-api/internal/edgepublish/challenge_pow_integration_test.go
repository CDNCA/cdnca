//go:build integration

package edgepublish_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/challengepolicy"
	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// The publication planner requires CHALLENGE_POW only for
// an explicit difficulty, leaves the nodes whose latest session does not
// declare it out of the rollout, and refuses when no node declares it.
func TestChallengePublicationPlannerGatesExplicitDifficultyOnChallengePoW(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA, nodeB := scope.AddNode(t, 6), scope.AddNode(t, 6)
	scope.DeclareChallengePoW(t, nodeA, true)
	scope.DeclareChallengePoW(t, nodeB, false)
	planner, err := challengepolicy.NewPostgresPublicationPlanner(challengepolicy.PublicationPlannerConfig{
		Clock: time.Now, ActivationTimeout: 30 * time.Second, ObservationWindow: 5 * time.Second,
		RequiredConsecutiveSuccesses: 2, Deadline: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	plan := func(difficulty *int) (challengepolicy.PublicationPlan, error) {
		var result challengepolicy.PublicationPlan
		err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
			var err error
			result, err = planner.Plan(t.Context(), tx, challengepolicy.PublicationSnapshot{
				TenantScopeID: scope.ScopeID, PowDifficulty: difficulty})
			return err
		})
		return result, err
	}
	hasPoW := func(capabilities []*agentv1.Capability) bool {
		return slices.ContainsFunc(capabilities, func(capability *agentv1.Capability) bool {
			return capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CHALLENGE_POW && capability.GetApiVersion() == 1
		})
	}

	// Default difficulty: every node, no CHALLENGE_POW (older nodes accept it).
	result, err := plan(nil)
	if err != nil || !slices.Contains(result.NodeIDs, nodeA) || !slices.Contains(result.NodeIDs, nodeB) ||
		len(result.UnsupportedNodeIDs) != 0 || hasPoW(result.RequiredCapabilities) || len(result.RequiredCapabilities) != 2 {
		t.Fatalf("default difficulty: %+v, %v", result, err)
	}
	// Explicit difficulty: nodeB (no CHALLENGE_POW) is left out.
	difficulty := 20
	result, err = plan(&difficulty)
	if err != nil || !slices.Contains(result.NodeIDs, nodeA) || slices.Contains(result.NodeIDs, nodeB) ||
		!slices.Contains(result.UnsupportedNodeIDs, nodeB) || slices.Contains(result.UnsupportedNodeIDs, nodeA) ||
		!hasPoW(result.RequiredCapabilities) {
		t.Fatalf("explicit difficulty: %+v, %v", result, err)
	}
	// A scope node without any session row (the fixture's own node) stays
	// planned: the command's required_capabilities leave it to the agent.
	var sessionless []uuid.UUID
	for _, nodeID := range result.NodeIDs {
		if nodeID == nodeA {
			continue
		}
		if scope.Count(t, `SELECT count(*) FROM node_session_capabilities WHERE node_id=$2 AND $1::uuid IS NOT NULL`, nodeID) != 0 {
			t.Fatalf("planned node %v with a session lacking CHALLENGE_POW", nodeID)
		}
		sessionless = append(sessionless, nodeID)
	}
	// No node declares it: refused, naming the nodes.
	scope.DeclareChallengePoW(t, nodeA, false)
	for _, nodeID := range sessionless {
		scope.DeclareChallengePoW(t, nodeID, false)
	}
	_, err = plan(&difficulty)
	var refusal *edgepublish.TargetCapabilityError
	if !errors.As(err, &refusal) || refusal.Capability != agentv1.CapabilityName_CAPABILITY_NAME_CHALLENGE_POW {
		t.Fatalf("no capable node: %v", err)
	}
	refused := append([]uuid.UUID{refusal.NodeID}, refusal.OtherNodeIDs...)
	if !slices.Contains(refused, nodeA) || !slices.Contains(refused, nodeB) {
		t.Fatalf("refused nodes %v, want %v and %v", refused, nodeA, nodeB)
	}
}

// A policy with an explicit difficulty is not redelivered
// to a node without CHALLENGE_POW (no rollout, the redelivery fails naming the
// capability, the node keeps its policy); once the node declares it on a new
// session the redelivery starts over and its rollout requires CHALLENGE_POW.
func TestChallengeRedeliveryWaitsForChallengePoW(t *testing.T) {
	scope, _, nodeB, policyID := challengeScope(t)
	origin := scope.SeedChallengeOrigin(t, policyID, 4)
	difficulty := 20
	scope.SetChallengePoWDifficulty(t, policyID, 4, difficulty)
	snapshot := challengepublication.PublicationSnapshot{PolicyID: policyID, TenantScopeID: scope.ScopeID,
		TenantID: origin.TenantID, SiteID: scope.SiteID, Host: origin.Host, Revision: 4, Priority: 10, Mode: "click",
		ChallengeTTLSeconds: 60, PassTTLSeconds: 300, ClockSkewSeconds: 5, AttemptsPerNonce: 1, FailureWindowSeconds: 60,
		MaxFailuresPerWindow: 3, IPBinding: "exact", BypassRoutes: []challengepublication.BypassRoute{},
		KeyReference: "keyref:challenge-primary", PowDifficulty: &difficulty}
	keys := challengepublication.ResolvedKeys{Current: challengepublication.ArtifactSecret{KeyID: "challenge-current",
		Secret: bytes.Repeat([]byte{9}, 32)}}
	document, err := challengepublication.PolicyDocument(snapshot, keys)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(document, []byte(`"pow_difficulty":20`)) {
		t.Fatalf("document without the difficulty: %s", document)
	}
	scope.PublishChallengeOrigin(t, document)
	resolver := challengepublication.KeyResolverFunc(func(context.Context, challengepublication.PublicationSnapshot,
	) (challengepublication.ResolvedKeys, error) {
		return keys, nil
	})
	producer, err := challengepublication.NewArtifactProducer(redeliveryTestSigner{
		private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x45}, ed25519.SeedSize))})
	if err != nil {
		t.Fatal(err)
	}
	deliverer, err := challengepublication.NewChallengeSecretRedeliverer(challengepublication.PostgresRedeliveryFactSource{},
		resolver, scope.DeploymentStore(t), producer, challengepublication.RedeliveryPolicy{
			HealthCheck: edgedeployment.HealthCheckPolicy{ActivationTimeout: 30 * time.Second,
				ObservationWindow: 5 * time.Second, RequiredConsecutiveSuccesses: 2}})
	if err != nil {
		t.Fatal(err)
	}
	redeliverer, err := edgepublish.NewChallengeRedeliverer(scope.Pool, deliverer, edgeautopublish.ChallengeDeliveryPublisher{},
		edgepublish.ChallengeRedelivererConfig{})
	if err != nil {
		t.Fatal(err)
	}
	rollouts := `SELECT count(*) FROM rollouts rollout JOIN config_versions version ON version.id=rollout.config_version_id
		JOIN node_deployments deployment ON deployment.rollout_id=rollout.id
		WHERE rollout.configuration_scope_id=$1 AND version.generator_name='cdnca-challengepublication'
		  AND deployment.node_id='` + nodeB.String() + `'`

	scope.DeclareChallengePoW(t, nodeB, false)
	scope.SetPresence(t, nodeB, true, 1)
	if sweep(t, redeliverer) != 1 || !dispatch(t, redeliverer) {
		t.Fatal("redelivery not attempted")
	}
	row := scope.ChallengeRedeliveries(t)[nodeB]
	if row.State != edgepublish.ChallengeRedeliveryStateFailed || row.RolloutID != nil || row.LastError == nil ||
		!strings.Contains(*row.LastError, "CAPABILITY_NAME_CHALLENGE_POW") {
		t.Fatalf("node without CHALLENGE_POW: %+v", row)
	}
	if got := scope.Count(t, rollouts); got != 0 {
		t.Fatalf("challenge rollouts to the node without CHALLENGE_POW = %d", got)
	}
	// The same session: not retried.
	if queued := sweep(t, redeliverer); queued != 0 {
		t.Fatalf("same session requeued %d", queued)
	}

	scope.DeclareChallengePoW(t, nodeB, true)
	scope.SetPresence(t, nodeB, true, 2)
	if sweep(t, redeliverer) != 1 || !dispatch(t, redeliverer) {
		t.Fatal("redelivery not started after the node declared CHALLENGE_POW")
	}
	row = scope.ChallengeRedeliveries(t)[nodeB]
	if row.State != edgepublish.ChallengeRedeliveryStateDelivering || row.RolloutID == nil {
		t.Fatalf("after the upgrade: %+v", row)
	}
	var commandBytes []byte
	if err := scope.Pool.QueryRow(t.Context(), `SELECT command_bytes FROM node_deployments
		WHERE rollout_id=$1 AND node_id=$2`, *row.RolloutID, nodeB).Scan(&commandBytes); err != nil {
		t.Fatal(err)
	}
	var command agentv1.DeploymentCommand
	if err := proto.Unmarshal(commandBytes, &command); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(command.GetRequiredCapabilities(), func(capability *agentv1.Capability) bool {
		return capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CHALLENGE_POW && capability.GetApiVersion() == 1
	}) {
		t.Fatalf("redelivered command capabilities = %v", command.GetRequiredCapabilities())
	}
}
