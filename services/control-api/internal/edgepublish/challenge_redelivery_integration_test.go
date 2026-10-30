//go:build integration

package edgepublish_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/challengepublication"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fakeChallengeRedeliverer stands in for challengepublication's secret
// rollout: it records the call and, unless told to fail, installs the policy
// on the node as a queued challenge secret rollout in the caller's tx.
type fakeChallengeRedeliverer struct {
	t     *testing.T
	scope *edgepublish.SystemRepublishScope
	fail  error
	calls []edgepublish.ChallengeRedelivery
}

func (fake *fakeChallengeRedeliverer) RedeliverChallengeSecretTx(
	_ context.Context, tx pgx.Tx, item edgepublish.ChallengeRedelivery,
) (uuid.UUID, error) {
	fake.calls = append(fake.calls, item)
	if fake.fail != nil {
		return uuid.Nil, fake.fail
	}
	return fake.scope.InstallChallengePolicyTx(fake.t, tx, item.NodeID, item.PolicyID, item.PolicyVersion, "queued"), nil
}

func newChallengeRedeliverer(t *testing.T, scope *edgepublish.SystemRepublishScope, retryDelay time.Duration,
) (*edgepublish.ChallengeRedeliverer, *fakeChallengeRedeliverer) {
	t.Helper()
	fake := &fakeChallengeRedeliverer{t: t, scope: scope}
	redeliverer, err := edgepublish.NewChallengeRedeliverer(scope.Pool, fake, edgeautopublish.ChallengeDeliveryPublisher{},
		edgepublish.ChallengeRedelivererConfig{RetryDelay: retryDelay})
	if err != nil {
		t.Fatal(err)
	}
	return redeliverer, fake
}

func sweep(t *testing.T, redeliverer *edgepublish.ChallengeRedeliverer) int {
	t.Helper()
	queued, err := redeliverer.SweepOnce(t.Context())
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	return queued
}

func dispatch(t *testing.T, redeliverer *edgepublish.ChallengeRedeliverer) bool {
	t.Helper()
	worked, err := redeliverer.DispatchOnce(t.Context())
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	return worked
}

func observe(t *testing.T, redeliverer *edgepublish.ChallengeRedeliverer) int {
	t.Helper()
	settled, err := redeliverer.ObserveOnce(t.Context())
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	return settled
}

// challengeScope: nodes A and B published once, then the site's JS challenge
// (policy v4) is installed on A and released there only; B joined the
// scope's targets without the policy (a system republication refused it).
func challengeScope(t *testing.T) (*edgepublish.SystemRepublishScope, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA, nodeB := scope.AddNode(t, 6), scope.AddNode(t, 6)
	scope.SetPresence(t, nodeA, true, 1)
	if err := scope.PublishManually(t, "redeliver-baseline", nodeA, nodeB); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	policyID := uuid.New()
	scope.BindChallenge(t, policyID, 4)
	scope.InstallChallengePolicy(t, nodeA, policyID, 4, "healthy")
	if err := scope.PublishManually(t, "redeliver-challenge-a", nodeA); err != nil {
		t.Fatal(err)
	}
	scope.SettleDeployments(t)
	scope.ExcludeFromSystemRepublication(t, nodeB)
	return scope, nodeA, nodeB, policyID
}

// A node that joined the scope's targets without the site's JS challenge
// policy gets it once it is online; attempts are bounded and start over only
// on a new node session; the confirmed delivery republishes the scope with
// trigger challenge_delivery, which now includes the node.
func TestChallengeRedeliveryReachesJoinedNodeAndRepublishes(t *testing.T) {
	scope, nodeA, nodeB, policyID := challengeScope(t)
	redeliverer, fake := newChallengeRedeliverer(t, scope, 0)

	// Offline: nothing to do (an attempt would only wait for its deadline).
	if queued := sweep(t, redeliverer); queued != 0 || len(scope.ChallengeRedeliveries(t)) != 0 {
		t.Fatalf("offline node queued %d: %+v", queued, scope.ChallengeRedeliveries(t))
	}
	// Online: B needs v4; A holds it.
	scope.SetPresence(t, nodeB, true, 1)
	if queued := sweep(t, redeliverer); queued != 1 {
		t.Fatalf("online node queued %d", queued)
	}
	rows := scope.ChallengeRedeliveries(t)
	if len(rows) != 1 || rows[nodeB].State != edgepublish.ChallengeRedeliveryStatePending || rows[nodeB].Epoch != 1 {
		t.Fatalf("rows after B came online: %+v", rows)
	}

	// Failing attempts are bounded.
	fake.fail = errors.New("node recipient key unavailable")
	for attempt := 1; attempt <= edgepublish.SystemRepublicationMaxAttempts; attempt++ {
		if !dispatch(t, redeliverer) {
			t.Fatalf("attempt %d not dispatched", attempt)
		}
	}
	if dispatch(t, redeliverer) || len(fake.calls) != edgepublish.SystemRepublicationMaxAttempts {
		t.Fatalf("attempts = %d, want %d then none", len(fake.calls), edgepublish.SystemRepublicationMaxAttempts)
	}
	if row := scope.ChallengeRedeliveries(t)[nodeB]; row.State != edgepublish.ChallengeRedeliveryStateFailed ||
		row.Attempt != edgepublish.SystemRepublicationMaxAttempts || row.LastError == nil {
		t.Fatalf("after the last attempt: %+v", row)
	}
	// The same session: it stays failed.
	if queued := sweep(t, redeliverer); queued != 0 || dispatch(t, redeliverer) {
		t.Fatalf("failed redelivery restarted in the same session (queued %d)", queued)
	}
	// B reconnects: it starts over.
	scope.SetPresence(t, nodeB, true, 2)
	if queued := sweep(t, redeliverer); queued != 1 {
		t.Fatalf("reconnected node queued %d", queued)
	}
	if row := scope.ChallengeRedeliveries(t)[nodeB]; row.State != edgepublish.ChallengeRedeliveryStatePending ||
		row.Attempt != 0 || row.Epoch != 2 {
		t.Fatalf("after reconnect: %+v", row)
	}

	fake.fail, fake.calls = nil, nil
	if !dispatch(t, redeliverer) || len(fake.calls) != 1 {
		t.Fatalf("redelivery not dispatched: %d calls", len(fake.calls))
	}
	call := fake.calls[0]
	if call.ScopeID != scope.ScopeID || call.NodeID != nodeB || call.PolicyID != policyID || call.PolicyVersion != 4 ||
		call.SiteID != scope.SiteID || call.AccountableUserID != scope.UserID || call.Attempt != 1 ||
		call.IdempotencyKey == "" || !call.Deadline.After(time.Now()) {
		t.Fatalf("redelivery = %+v", call)
	}
	row := scope.ChallengeRedeliveries(t)[nodeB]
	if row.State != edgepublish.ChallengeRedeliveryStateDelivering || row.RolloutID == nil || row.Attempt != 1 {
		t.Fatalf("after dispatch: %+v", row)
	}
	// In flight: no second rollout, no republication yet.
	if queued := sweep(t, redeliverer); queued != 0 || dispatch(t, redeliverer) || observe(t, redeliverer) != 0 {
		t.Fatal("in-flight redelivery dispatched again or settled before the receipt")
	}
	heads := `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1 AND state='pending'
		AND 'challenge_delivery'=ANY(triggers)`
	if got := scope.Count(t, heads); got != 0 {
		t.Fatalf("republication queued before the node confirmed: %d", got)
	}

	// B confirms: delivered, the scope is republished with B.
	scope.SetRolloutDeploymentState(t, *row.RolloutID, nodeB, "healthy")
	if settled := observe(t, redeliverer); settled != 1 {
		t.Fatalf("settled %d", settled)
	}
	if row := scope.ChallengeRedeliveries(t)[nodeB]; row.State != edgepublish.ChallengeRedeliveryStateDelivered {
		t.Fatalf("after the receipt: %+v", row)
	}
	if got := scope.Count(t, heads); got != 1 {
		t.Fatalf("challenge_delivery republications queued = %d", got)
	}
	scope.MakeDue(t)
	scope.Run(t)
	attempt := scope.LatestAttempt(t)
	if attempt.Outcome != edgepublish.SystemOutcomePublished || !slices.Equal(attempt.NodeIDs, sortedNodes(nodeA, nodeB)) ||
		len(attempt.RefusedNodes) != 0 || !slices.Equal(attempt.Triggers, []string{edgepublish.SystemTriggerChallengeDelivery}) {
		t.Fatalf("republication = %+v", attempt)
	}
	// B holds the policy now: the row goes, nothing is queued.
	if queued := sweep(t, redeliverer); queued != 0 || len(scope.ChallengeRedeliveries(t)) != 0 {
		t.Fatalf("after delivery queued %d: %+v", queued, scope.ChallengeRedeliveries(t))
	}
}

// A failed receipt retries after backoff; an unrecoverable redelivery fails
// at once; a node going offline or a binding moving on drops the row.
func TestChallengeRedeliveryRetriesAndDropsWhatIsNoLongerNeeded(t *testing.T) {
	scope, _, nodeB, policyID := challengeScope(t)
	redeliverer, fake := newChallengeRedeliverer(t, scope, 5*time.Minute)
	scope.SetPresence(t, nodeB, true, 1)
	if sweep(t, redeliverer) != 1 || !dispatch(t, redeliverer) {
		t.Fatal("redelivery not started")
	}
	row := scope.ChallengeRedeliveries(t)[nodeB]
	scope.SetRolloutDeploymentState(t, *row.RolloutID, nodeB, "failed")
	if settled := observe(t, redeliverer); settled != 1 {
		t.Fatalf("settled %d", settled)
	}
	row = scope.ChallengeRedeliveries(t)[nodeB]
	if row.State != edgepublish.ChallengeRedeliveryStatePending || row.Attempt != 1 || row.LastError == nil ||
		row.DueInMS < int64(4*time.Minute/time.Millisecond) || row.DueInMS > int64(5*time.Minute/time.Millisecond) {
		t.Fatalf("after a failed receipt: %+v", row)
	}
	if dispatch(t, redeliverer) {
		t.Fatal("retried before its backoff")
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1
		AND 'challenge_delivery'=ANY(triggers)`); got != 0 {
		t.Fatalf("a failed delivery queued %d republications", got)
	}

	// Offline: the row goes.
	scope.SetPresence(t, nodeB, false, 0)
	if sweep(t, redeliverer); len(scope.ChallengeRedeliveries(t)) != 0 {
		t.Fatalf("offline node kept %+v", scope.ChallengeRedeliveries(t))
	}

	// Unrecoverable: failed at the first attempt.
	scope.SetPresence(t, nodeB, true, 2)
	if sweep(t, redeliverer) != 1 {
		t.Fatal("not queued after coming back")
	}
	fake.fail = fmt.Errorf("%w: policy document changed", edgepublish.ErrChallengeRedeliveryUnrecoverable)
	if !dispatch(t, redeliverer) {
		t.Fatal("not dispatched")
	}
	if row := scope.ChallengeRedeliveries(t)[nodeB]; row.State != edgepublish.ChallengeRedeliveryStateFailed || row.Attempt != 1 {
		t.Fatalf("unrecoverable redelivery: %+v", row)
	}

	// The site moves to policy v5: the v4 row goes, v5 is queued for both
	// nodes (A holds only v4).
	scope.BindChallenge(t, policyID, 5)
	if queued := sweep(t, redeliverer); queued != 2 {
		t.Fatalf("queued %d for v5", queued)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_challenge_redeliveries WHERE scope_id=$1 AND policy_version=5
		AND state='pending'`); got != 2 || len(scope.ChallengeRedeliveries(t)) != 2 {
		t.Fatalf("v5 rows = %d, all rows %+v", got, scope.ChallengeRedeliveries(t))
	}
}

// fix-tails1028 §1: a redelivery the node ignored as an old release is
// skipped — the row goes, no attempt is spent, nothing is failed or
// republished — and the next sweep queues it afresh while it is still needed.
func TestChallengeRedeliverySkipsIgnoredOldReleaseWithoutFailing(t *testing.T) {
	scope, _, nodeB, _ := challengeScope(t)
	redeliverer, fake := newChallengeRedeliverer(t, scope, 5*time.Minute)
	scope.SetPresence(t, nodeB, true, 1)
	if sweep(t, redeliverer) != 1 || !dispatch(t, redeliverer) {
		t.Fatal("redelivery not started")
	}
	row := scope.ChallengeRedeliveries(t)[nodeB]
	scope.IgnoreRolloutAsOldRelease(t, *row.RolloutID, nodeB)
	if settled := observe(t, redeliverer); settled != 1 {
		t.Fatalf("settled %d", settled)
	}
	if rows := scope.ChallengeRedeliveries(t); len(rows) != 0 {
		t.Fatalf("ignored old release left %+v (want the row gone, not failed or retried)", rows)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1
		AND 'challenge_delivery'=ANY(triggers)`); got != 0 {
		t.Fatalf("an ignored old release queued %d republications", got)
	}
	// Still needed (the node holds no healthy copy): queued afresh at attempt 0.
	if queued := sweep(t, redeliverer); queued != 1 {
		t.Fatalf("queued %d after the skip", queued)
	}
	if row := scope.ChallengeRedeliveries(t)[nodeB]; row.State != edgepublish.ChallengeRedeliveryStatePending ||
		row.Attempt != 0 || row.LastError != nil {
		t.Fatalf("after the skip: %+v", row)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("deliverer calls = %d, want 1", len(fake.calls))
	}
}

// An automatic scope republishes a confirmed delivery through its own policy
// (source_kind challenge_delivery, the node as the source resource).
func TestChallengeDeliveryRepublishesAutomaticScopeThroughItsPolicy(t *testing.T) {
	scope := edgepublish.NewSystemRepublishScope(t)
	nodeA := scope.AddNode(t, 6)
	scope.EnableAutomaticPolicy(t, nodeA)
	rolloutID := uuid.New()
	if err := pgx.BeginFunc(t.Context(), scope.Pool, func(tx pgx.Tx) error {
		return edgeautopublish.ChallengeDeliveryPublisher{}.RepublishChallengeDeliveryTx(t.Context(), tx, scope.ScopeID, nodeA, rolloutID)
	}); err != nil {
		t.Fatal(err)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_automatic_publication_requests WHERE target_scope_id=$1
		AND source_kind='challenge_delivery' AND operation='node.challenge_delivered' AND reason='challenge_delivered'
		AND source_resource_id=$2`, nodeA); got != 1 {
		t.Fatalf("automatic challenge delivery requests = %d", got)
	}
	if got := scope.Count(t, `SELECT count(*) FROM edge_system_republication_heads WHERE scope_id=$1`); got != 0 {
		t.Fatalf("automatic scope also queued a system republication (%d)", got)
	}
}

type redeliveryTestSigner struct{ private ed25519.PrivateKey }

func (redeliveryTestSigner) ArtifactSigningKeyID() string { return "challenge-redelivery-test" }
func (signer redeliveryTestSigner) ArtifactSigningPublicKey() ed25519.PublicKey {
	return signer.private.Public().(ed25519.PublicKey)
}
func (signer redeliveryTestSigner) SignArtifact(_ context.Context, value []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, value), nil
}

// The real redelivery rebuilds the binding's published document from the
// policy revision and its keys, and sends it to the node alone as a system
// secret rollout (encrypted to the node's artifact key); a document that no
// longer rebuilds fails at once without a rollout.
func TestChallengeRedeliveryRebuildsThePublishedPolicyForTheNode(t *testing.T) {
	scope, _, nodeB, policyID := challengeScope(t)
	origin := scope.SeedChallengeOrigin(t, policyID, 4)
	snapshot := challengepublication.PublicationSnapshot{PolicyID: policyID, TenantScopeID: scope.ScopeID,
		TenantID: origin.TenantID, SiteID: scope.SiteID, Host: origin.Host, Revision: 4, Priority: 10, Mode: "click",
		ChallengeTTLSeconds: 60, PassTTLSeconds: 300, ClockSkewSeconds: 5, AttemptsPerNonce: 1, FailureWindowSeconds: 60,
		MaxFailuresPerWindow: 3, IPBinding: "exact", BypassRoutes: []challengepublication.BypassRoute{},
		KeyReference: "keyref:challenge-primary"}
	keys := challengepublication.ResolvedKeys{Current: challengepublication.ArtifactSecret{KeyID: "challenge-current",
		Secret: bytes.Repeat([]byte{9}, 32)}}
	document, err := challengepublication.PolicyDocument(snapshot, keys)
	if err != nil {
		t.Fatal(err)
	}
	originID := scope.PublishChallengeOrigin(t, document)
	resolved := keys
	resolver := challengepublication.KeyResolverFunc(func(_ context.Context, got challengepublication.PublicationSnapshot,
	) (challengepublication.ResolvedKeys, error) {
		if got.PolicyID != policyID || got.Revision != 4 || got.Host != origin.Host || got.KeyReference != snapshot.KeyReference {
			return challengepublication.ResolvedKeys{}, challengepublication.ErrKeyUnavailable
		}
		return resolved, nil
	})
	producer, err := challengepublication.NewArtifactProducer(redeliveryTestSigner{
		private: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))})
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
	scope.SetPresence(t, nodeB, true, 1)
	if sweep(t, redeliverer) != 1 || !dispatch(t, redeliverer) {
		t.Fatal("redelivery not started")
	}
	row := scope.ChallengeRedeliveries(t)[nodeB]
	if row.State != edgepublish.ChallengeRedeliveryStateDelivering || row.RolloutID == nil {
		t.Fatalf("after dispatch: %+v", row)
	}
	var snapshotOut []byte
	var generator string
	var nodes []uuid.UUID
	var encrypted int
	if err := scope.Pool.QueryRow(t.Context(), `SELECT version.canonical_snapshot,version.generator_name,
		ARRAY(SELECT node_id FROM node_deployments WHERE rollout_id=rollout.id ORDER BY node_id),
		(SELECT count(*) FROM configuration_artifacts WHERE config_version_id=version.id AND kind='node_secret_bundle'
		   AND recipient_key_id IS NOT NULL)
		FROM rollouts rollout JOIN config_versions version ON version.id=rollout.config_version_id
		WHERE rollout.id=$1 AND rollout.configuration_scope_id=$2`, *row.RolloutID, scope.ScopeID).
		Scan(&snapshotOut, &generator, &nodes, &encrypted); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(snapshotOut, document) || generator != edgepublish.ChallengeSecretGeneratorName ||
		!slices.Equal(nodes, []uuid.UUID{nodeB}) || encrypted != 1 || *row.RolloutID == originID {
		t.Fatalf("redelivered rollout: generator=%q nodes=%v encrypted=%d same document=%v", generator, nodes, encrypted,
			bytes.Equal(snapshotOut, document))
	}
	if got := scope.Count(t, `SELECT count(*) FROM audit_events WHERE action='edge_secret_rollout.create'
		AND resource_id=$2::text AND actor_user_id IS NULL AND payload->>'actor_kind'='system'
		AND payload->>'reason'='challenge_redelivery' AND scope_id=$1`, row.RolloutID.String()); got != 1 {
		t.Fatalf("system secret rollout audits = %d", got)
	}

	// The key facts now resolve to another key: the published document
	// cannot be rebuilt, the redelivery fails without a rollout.
	scope.SetRolloutDeploymentState(t, *row.RolloutID, nodeB, "failed")
	observe(t, redeliverer)
	resolved = challengepublication.ResolvedKeys{Current: challengepublication.ArtifactSecret{KeyID: "challenge-rotated",
		Secret: bytes.Repeat([]byte{9}, 32)}}
	rollouts := `SELECT count(*) FROM rollouts rollout JOIN config_versions version ON version.id=rollout.config_version_id
		WHERE rollout.configuration_scope_id=$1 AND version.generator_name='cdnca-challengepublication'`
	before := scope.Count(t, rollouts)
	if !dispatch(t, redeliverer) {
		t.Fatal("retry not dispatched")
	}
	if row := scope.ChallengeRedeliveries(t)[nodeB]; row.State != edgepublish.ChallengeRedeliveryStateFailed ||
		row.Attempt != 2 || row.LastError == nil {
		t.Fatalf("after the key changed: %+v", row)
	}
	if got := scope.Count(t, rollouts); got != before {
		t.Fatalf("a rollout was persisted for a document that does not rebuild (%d, was %d)", got, before)
	}
}
