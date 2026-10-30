//go:build integration

package edgedeployment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The control plane redelivers a secret (a JS challenge policy) by itself,
// without a session: the rollout is the accountable user's but audited as the
// system, replays by idempotency key, and still goes only to active nodes of
// the scope that hold an active artifact recipient key.
func TestCreateSystemSecretRolloutNeedsNoSessionAndKeepsTheNodeBoundary(t *testing.T) {
	fixture, scopeID, userID, _ := newSecretRolloutIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	nodeID, keyless := uuid.New(), uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	seedEdgeNode(t, pool, scopeID, userID, keyless)
	recipientID, _ := seedActiveArtifactKey(t, pool, nodeID, userID, nil)
	otherScopeID, otherUserID := seedEdgeScope(t, pool)
	foreign := uuid.New()
	seedEdgeNode(t, pool, otherScopeID, otherUserID, foreign)
	seedActiveArtifactKey(t, pool, foreign, otherUserID, nil)

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	builder := func(_ context.Context, binding SecretArtifactBinding) (ArtifactInput, error) {
		calls++
		return testSecretArtifact(t, binding, "challenge-redelivery-signer", publicKey, privateKey), nil
	}
	request := func(key string, nodes ...uuid.UUID) SystemSecretRolloutRequest {
		return SystemSecretRolloutRequest{
			ConfigurationScopeID: scopeID, AccountableUserID: userID, NodeIDs: nodes,
			CanonicalSnapshot: []byte(`{"policy_version":3}`), GeneratorName: "cdnca-challengepublication",
			GeneratorVersion: "1.0.0", PayloadDigest: sha256.Sum256([]byte(key)),
			RequiredCapabilities: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1}},
			HealthCheck:          HealthCheckPolicy{ActivationTimeout: time.Minute, ObservationWindow: 5 * time.Second, RequiredConsecutiveSuccesses: 2},
			Deadline:             integrationClock.Add(time.Hour), IdempotencyKey: key,
			RequestID: uuid.NewString(), CorrelationID: uuid.NewString(), Reason: "challenge_redelivery",
		}
	}
	create := func(request SystemSecretRolloutRequest) (CreateRolloutResult, error) {
		var result CreateRolloutResult
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			var err error
			result, err = store.CreateSystemSecretRolloutTx(t.Context(), tx, request, builder)
			return err
		})
		return result, err
	}

	first := request("challenge-redelivery-1", nodeID)
	created, err := create(first)
	if err != nil {
		t.Fatal(err)
	}
	if created.Replayed || len(created.Rollout.Deployments) != 1 || created.Rollout.Deployments[0].NodeID != nodeID ||
		created.Rollout.Deployments[0].Command.Artifacts[0].GetRecipientKeyId() != recipientID || calls != 1 {
		t.Fatalf("created=%+v calls=%d", created, calls)
	}
	assertSecretRolloutRowCounts(t, pool, first.IdempotencyKey, 1, 1, 1, 1, 1, 1)
	var actorUser *uuid.UUID
	var actorKind, reason string
	if err := pool.QueryRow(t.Context(), `SELECT actor_user_id,payload->>'actor_kind',payload->>'reason' FROM audit_events
		WHERE action='edge_secret_rollout.create' AND payload->>'idempotency_key'=$1`, first.IdempotencyKey).
		Scan(&actorUser, &actorKind, &reason); err != nil {
		t.Fatal(err)
	}
	if actorUser != nil || actorKind != "system" || reason != "challenge_redelivery" {
		t.Fatalf("audit actor=%v kind=%q reason=%q, want the system", actorUser, actorKind, reason)
	}

	replayed, err := create(first)
	if err != nil || !replayed.Replayed || replayed.Rollout.ID != created.Rollout.ID || calls != 1 {
		t.Fatalf("replay=%+v err=%v calls=%d", replayed, err, calls)
	}
	if _, err := create(request("challenge-redelivery-foreign", foreign)); !errors.Is(err, ErrConfigurationScopeConflict) {
		t.Fatalf("another tenant's node: %v", err)
	}
	if _, err := create(request("challenge-redelivery-keyless", keyless)); !errors.Is(err, ErrNodeRecipientKeyUnavailable) {
		t.Fatalf("node without an artifact key: %v", err)
	}
	missing := request("challenge-redelivery-unaccountable", nodeID)
	missing.AccountableUserID = uuid.Nil
	if _, err := create(missing); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("no accountable user: %v", err)
	}
}
