//go:build integration

package securityactivation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/cdnca/cdnca/services/control-api/internal/edgepublish"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybinding"
	"github.com/cdnca/cdnca/services/control-api/internal/securitybundle"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type activationIntegrationSigner struct {
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func (signer *activationIntegrationSigner) KeyID() string { return "security-activation-integration" }

func (signer *activationIntegrationSigner) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), signer.public...)
}

func (signer *activationIntegrationSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(signer.private, payload), nil
}

type activationIntegrationEntitlement struct{}

func (activationIntegrationEntitlement) AuthorizePublication(
	context.Context,
	pgx.Tx,
	edgepublish.EntitlementRequest,
) (edgepublish.EntitlementDecision, error) {
	return edgepublish.EntitlementDecision{
		Allowed: true, LocallyVerified: true, Status: edgepublish.EntitlementStatusValid,
	}, nil
}

func TestStatusUsesLiveReadPermissionAndReturnsAuthoritativeFacts(t *testing.T) {
	fixture := newActivationFixture(t)
	store, err := NewStore(fixture.pool, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Claim(t.Context(), fixture.actor, fixture.claimInput("status-activation"))
	if err != nil {
		t.Fatal(err)
	}
	reader := fixture.newPermissionActor(t, "security_policies.read")

	result, err := store.Status(t.Context(), reader.actor, fixture.siteID, securitypolicy.KindWAF)
	if err != nil {
		t.Fatal(err)
	}
	if result.Binding == nil || result.Binding.ID != fixture.bindingID || result.Binding.PolicyID != fixture.policyID ||
		result.Binding.BindingRevision != 2 || result.Binding.ActivePolicyVersion != 1 ||
		result.Binding.LastClaimedPolicyVersion != 2 || result.LatestCandidate == nil ||
		result.LatestCandidate.ID != created.Candidate.ID || result.Operation == nil ||
		*result.Operation != OperationActivation {
		t.Fatalf("activation status = %+v", result)
	}
	if candidate, err := store.Get(t.Context(), reader.actor, created.Candidate.ID); err != nil || candidate.ID != created.Candidate.ID {
		t.Fatalf("read-only candidate Get = (%+v, %v)", candidate, err)
	}

	absentSiteID := uuid.New()
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(
			id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
			VALUES($1,2,$2,$3,'activation-absent.example',ARRAY['192.0.2.11:80'],ARRAY['192.0.2.11'],$3,$3)`,
			absentSiteID, fixture.scopeID, fixture.actor.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, absentSiteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
			VALUES($1,1,'192.0.2.11',80,1,true)`, absentSiteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	absent, err := store.Status(t.Context(), reader.actor, absentSiteID, securitypolicy.KindWAF)
	if err != nil || absent.Binding != nil || absent.LatestCandidate != nil || absent.Operation != nil {
		t.Fatalf("absent binding status = (%+v, %v)", absent, err)
	}
	reader.revoke(t, fixture)
	if _, err := store.Status(t.Context(), reader.actor, fixture.siteID, securitypolicy.KindWAF); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked status error = %v, want ErrPermissionDenied", err)
	}
}

func TestRollbackPersistsChildOperationMarkerAndReplaysOriginalEvent(t *testing.T) {
	fixture := newActivationFixture(t)
	base, err := NewStore(fixture.pool, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	created, err := base.Claim(t.Context(), fixture.actor, fixture.claimInput("rollback-source"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.markCandidateHealthy(t, created.Candidate.ID)
	if _, err := base.Promote(t.Context(), fixture.actor, created.Candidate.ID, created.Candidate.PromotionCAS()); err != nil {
		t.Fatal(err)
	}
	store := newProductionActivationStore(t, fixture)
	input := RollbackInput{
		CandidateID: created.Candidate.ID, SourcePolicyVersion: 2,
		ExpectedBindingRevision: 3, ExpectedActivePolicyVersion: 2,
		TargetNodeIDs: []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, CanarySize: 1,
		IdempotencyKey: "rollback-operation-marker", RequestID: uuid.NewString(),
		CorrelationID: uuid.NewString(), Traceparent: "00-11111111111111111111111111111111-2222222222222222-01",
		ExpiresAt: fixture.now.Add(10 * time.Minute),
	}
	first, err := store.Rollback(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	if first.Candidate.Status != StatusClaimed {
		t.Fatalf("rollback candidate status = %s, want %s", first.Candidate.Status, StatusClaimed)
	}
	assertPhaseCounts(t, fixture.pool, first.Candidate.ID, 1, 0)
	status, err := store.Status(t.Context(), fixture.actor, fixture.siteID, securitypolicy.KindWAF)
	if err != nil {
		t.Fatal(err)
	}
	if status.LatestCandidate == nil || status.LatestCandidate.ID != first.Candidate.ID ||
		status.Operation == nil || *status.Operation != OperationRollback {
		t.Fatalf("rollback status = %+v", status)
	}
	var originalMarkers, childMarkers int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE candidate_id=$1 AND action='rollback'),
		count(*) FILTER (WHERE candidate_id=$2 AND action='rollback')
		FROM security_policy_activation_events WHERE candidate_id IN ($1,$2)`,
		created.Candidate.ID, first.Candidate.ID).Scan(&originalMarkers, &childMarkers); err != nil {
		t.Fatal(err)
	}
	if originalMarkers != 1 || childMarkers != 1 {
		t.Fatalf("rollback markers original/child = %d/%d", originalMarkers, childMarkers)
	}
	replayed, err := store.Rollback(t.Context(), fixture.actor, input)
	if err != nil || !replayed.Replayed || replayed.Candidate.ID != first.Candidate.ID {
		t.Fatalf("rollback replay = (%+v, %v)", replayed, err)
	}
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM security_policy_activation_events
		WHERE candidate_id IN ($1,$2) AND action='rollback'`,
		created.Candidate.ID, first.Candidate.ID).Scan(&originalMarkers); err != nil {
		t.Fatal(err)
	}
	if originalMarkers != 2 {
		t.Fatalf("rollback marker count after replay = %d, want 2", originalMarkers)
	}
	completeProductionActivation(t, fixture, store, first.Candidate)
}

func newProductionActivationStore(t *testing.T, fixture activationFixture) *Store {
	t.Helper()
	signer := fixture.signer
	if signer == nil {
		t.Fatal("activation fixture signer is nil")
	}
	bundlePublisher, err := securitybundle.NewPublisher(signer, securitybundle.Config{
		Clock: func() time.Time { return fixture.now }, Validity: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	bindings, err := securitybinding.NewStore(fixture.pool, bundlePublisher, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	deployments, err := edgedeployment.NewStoreWithClock(fixture.pool, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	publishConfig := edgepublish.DefaultConfig()
	publishConfig.Clock = func() time.Time { return fixture.now }
	publishConfig.EntitlementAuthorizer = activationIntegrationEntitlement{}
	publisher, err := edgepublish.NewService(fixture.pool, deployments, signer, publishConfig)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewProductionStore(fixture.pool, func() time.Time { return fixture.now }, bindings,
		publisher, deployments, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestProductionStartDefersIdentityAndResumesDeterministicRollouts(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "production-start-resume",
		[]uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 1)

	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	if started.Candidate.Status != StatusClaimed {
		t.Fatalf("started candidate status = %s, want %s", started.Candidate.Status, StatusClaimed)
	}
	assertPhaseCounts(t, fixture.pool, started.Candidate.ID, 1, 0)

	restarted := newProductionActivationStore(t, fixture)
	replayed, err := restarted.Start(t.Context(), fixture.actor, input)
	if err != nil || !replayed.Replayed || replayed.Candidate.ID != started.Candidate.ID {
		t.Fatalf("Start replay after restart = (%+v, %v)", replayed, err)
	}
	assertPhaseCounts(t, fixture.pool, started.Candidate.ID, 1, 0)

	completeProductionActivation(t, fixture, restarted, started.Candidate)
	assertPhaseCounts(t, fixture.pool, started.Candidate.ID, 2, 2)
}

func TestProductionPendingFactsCoverCanaryExpandAndReplay(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "pending-canary-expand",
		[]uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 1)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	assertProductionPendingFacts(t, fixture, started.Candidate, 1, 1)

	replayed, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil || !replayed.Replayed || replayed.Candidate.ID != started.Candidate.ID {
		t.Fatalf("Start replay = (%+v, %v)", replayed, err)
	}
	assertProductionPendingFacts(t, fixture, started.Candidate, 1, 1)

	markProductionPhaseHealthy(t, fixture, started.Candidate, "canary")
	result, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(started.Candidate, "pending-expand"))
	if err != nil || result.Action != string(actionExpand) || result.Candidate.Status != StatusCanary {
		t.Fatalf("expand Reconcile = (%+v, %v)", result, err)
	}
	assertProductionPendingFacts(t, fixture, started.Candidate, 2, 2)
}

func TestProductionPartialPreHealthyRecoveryRequiresExactProof(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "pending-partial-recovery",
		[]uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 2)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	loadedNode := started.Candidate.CanaryNodeIDs[0]
	if err := markPartialCandidateLoaded(t, fixture, started.Candidate, loadedNode); err != nil {
		t.Fatal(err)
	}
	fixture.now = input.ExpiresAt.Add(time.Second)
	store.clock = func() time.Time { return fixture.now }
	expired, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(started.Candidate, "partial-recovery-expire"))
	if err != nil || expired.Action != string(actionExpire) || expired.Candidate.Status != StatusExpired {
		t.Fatalf("expire Reconcile = (%+v, %v)", expired, err)
	}
	assertRecoveryPendingFacts(t, fixture.pool, started.Candidate.ID, 1, 0)
	if err := markProductionRecoveryReverted(t, fixture, started.Candidate.ID, loadedNode); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(started.Candidate, "partial-recovery-proof"))
	if err != nil || recovered.Action != string(actionRecover) || recovered.Candidate.RecoveredAt == nil {
		t.Fatalf("proof Reconcile = (%+v, %v)", recovered, err)
	}
	assertRecoveryPendingFacts(t, fixture.pool, started.Candidate.ID, 1, 1)
}

func TestProductionRecoveryRetryUsesLatestApplyGeneration(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "pending-recovery-retry",
		[]uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 2)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	loadedNode := started.Candidate.CanaryNodeIDs[0]
	if err := markPartialCandidateLoaded(t, fixture, started.Candidate, loadedNode); err != nil {
		t.Fatal(err)
	}
	fixture.now = input.ExpiresAt.Add(time.Second)
	store.clock = func() time.Time { return fixture.now }
	if _, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(started.Candidate, "recovery-retry-expire")); err != nil {
		t.Fatal(err)
	}
	assertRecoveryPendingFacts(t, fixture.pool, started.Candidate.ID, 1, 0)
	if err := markProductionRecoveryFailed(t, fixture, started.Candidate.ID, loadedNode); err != nil {
		t.Fatal(err)
	}
	retried, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(started.Candidate, "recovery-retry-second-rollout"))
	if err != nil || retried.Action != string(actionWait) || retried.Candidate.RecoveredAt != nil {
		t.Fatalf("retry recovery Reconcile = (%+v, %v)", retried, err)
	}
	var rollouts, pending, maxGeneration int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM security_policy_activation_recovery_rollouts WHERE candidate_id=$1),
		count(*),max(generation) FROM security_policy_activation_recovery_pending_095
		WHERE candidate_id=$1 AND node_id=$2 AND action='rollback'`,
		started.Candidate.ID, loadedNode).Scan(&rollouts, &pending, &maxGeneration); err != nil {
		t.Fatal(err)
	}
	if rollouts != 2 || pending != 2 || maxGeneration != 3 {
		t.Fatalf("recovery retry rollouts/pending/max generation = %d/%d/%d, want 2/2/3",
			rollouts, pending, maxGeneration)
	}
}

func TestProductionPendingFactFailureRollsBackWholeStart(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "pending-atomic-failure",
		[]uuid.UUID{fixture.canaryNodeID}, 1)
	if _, err := fixture.pool.Exec(t.Context(), `CREATE FUNCTION fail_pending_activation_095_test()
		RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
			RAISE EXCEPTION 'injected pending failure' USING ERRCODE='P9502';
		END $$;
		CREATE TRIGGER aaa_fail_pending_activation_095_test
		BEFORE INSERT ON security_policy_activation_recovery_pending_095
		FOR EACH ROW EXECUTE FUNCTION fail_pending_activation_095_test()`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Start(t.Context(), fixture.actor, input); err == nil {
		t.Fatal("Start succeeded despite injected pending fact failure")
	}
	var candidates, rollouts, deployments, outbox int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM security_policy_activation_candidates WHERE idempotency_key=$1),
		(SELECT count(*) FROM rollouts WHERE idempotency_key=$2),
		(SELECT count(*) FROM node_deployments deployment JOIN rollouts rollout ON rollout.id=deployment.rollout_id
		 WHERE rollout.idempotency_key=$2),
		(SELECT count(*) FROM edge_command_outbox outbox JOIN node_deployments deployment
		 ON deployment.id=outbox.deployment_id AND deployment.attempt=outbox.deployment_attempt
		 JOIN rollouts rollout ON rollout.id=deployment.rollout_id WHERE rollout.idempotency_key=$2)`,
		input.IdempotencyKey, derivedKey("canary", uuid.Nil.String())).
		Scan(&candidates, &rollouts, &deployments, &outbox); err != nil {
		t.Fatal(err)
	}
	if candidates != 0 || rollouts != 0 || deployments != 0 || outbox != 0 {
		t.Fatalf("failed Start writes candidates/rollouts/deployments/outbox=%d/%d/%d/%d",
			candidates, rollouts, deployments, outbox)
	}
	if _, err := fixture.pool.Exec(t.Context(), `DROP TRIGGER aaa_fail_pending_activation_095_test
		ON security_policy_activation_recovery_pending_095; DROP FUNCTION fail_pending_activation_095_test()`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Start(t.Context(), fixture.actor, input); err != nil {
		t.Fatalf("Start after removing injection: %v", err)
	}
}

func TestProductionConcurrentStartHasSinglePendingWinner(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "pending-concurrent-winner",
		[]uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID}, 2)
	results := make([]StartResult, 2)
	errs := make([]error, 2)
	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(2)
	done.Add(2)
	for index := range results {
		go func(index int) {
			defer done.Done()
			ready.Done()
			<-start
			results[index], errs[index] = store.Start(t.Context(), fixture.actor, input)
		}(index)
	}
	ready.Wait()
	close(start)
	done.Wait()
	if errs[0] != nil || errs[1] != nil || results[0].Candidate.ID != results[1].Candidate.ID ||
		results[0].Replayed == results[1].Replayed {
		t.Fatalf("concurrent Start results=(%+v,%v)/(%+v,%v)", results[0], errs[0], results[1], errs[1])
	}
	assertProductionPendingFacts(t, fixture, results[0].Candidate, 2, 1)
}

func assertProductionPendingFacts(t *testing.T, fixture activationFixture, candidate Candidate,
	wantNodes, wantRollouts int) {
	t.Helper()
	var nodes, rollouts, invalid int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*),count(DISTINCT rollout_id),
		count(*) FILTER (WHERE action<>'apply' OR tenant_scope_id<>$2 OR candidate_config_version_id<>$3
		 OR candidate_artifact_sha256<>$4 OR candidate_target_snapshot_sha256<>$5
		 OR recovery_target_snapshot_sha256=candidate_target_snapshot_sha256 OR deployment_attempt<>1
		 OR generation<>1 OR request_id IS NULL OR created_at IS NULL OR NOT EXISTS (
		   SELECT 1 FROM node_deployments deployment
		   JOIN edge_command_outbox outbox ON outbox.deployment_id=deployment.id
		    AND outbox.deployment_attempt=deployment.attempt
		   WHERE deployment.id=security_policy_activation_recovery_pending_095.deployment_id
		     AND deployment.attempt=security_policy_activation_recovery_pending_095.deployment_attempt
		     AND deployment.rollout_id=security_policy_activation_recovery_pending_095.rollout_id
		     AND deployment.node_id=security_policy_activation_recovery_pending_095.node_id
		     AND deployment.action='apply' AND outbox.node_id=deployment.node_id
		 ))
		FROM security_policy_activation_recovery_pending_095 WHERE candidate_id=$1`, candidate.ID,
		fixture.scopeID, candidate.CandidateConfigVersionID, candidate.CandidateArtifactSHA256[:],
		candidate.TargetSnapshotSHA256[:]).Scan(&nodes, &rollouts, &invalid); err != nil {
		t.Fatal(err)
	}
	if nodes != wantNodes || rollouts != wantRollouts || invalid != 0 {
		t.Fatalf("pending nodes/rollouts/invalid=%d/%d/%d, want %d/%d/0",
			nodes, rollouts, invalid, wantNodes, wantRollouts)
	}
}

func assertRecoveryPendingFacts(t *testing.T, pool *pgxpool.Pool, candidateID uuid.UUID,
	wantPending, wantProofs int) {
	t.Helper()
	var pending, proofs int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM security_policy_activation_recovery_pending_095
		 WHERE candidate_id=$1 AND action='rollback'),
		(SELECT count(*) FROM security_policy_activation_recovery_proofs_095
		 WHERE candidate_id=$1 AND action='rollback')`, candidateID).Scan(&pending, &proofs); err != nil {
		t.Fatal(err)
	}
	if pending != wantPending || proofs != wantProofs {
		t.Fatalf("recovery pending/proofs=%d/%d, want %d/%d", pending, proofs, wantPending, wantProofs)
	}
}

func markPartialCandidateLoaded(t *testing.T, fixture activationFixture, candidate Candidate,
	nodeID uuid.UUID) error {
	return pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		var deploymentID uuid.UUID
		if err := tx.QueryRow(t.Context(), `SELECT deployment.id FROM node_deployments deployment
			JOIN rollouts rollout ON rollout.id=deployment.rollout_id
			WHERE rollout.idempotency_key=$1 AND deployment.node_id=$2 AND deployment.attempt=1`,
			derivedKey("canary", candidate.ID.String()), nodeID).Scan(&deploymentID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE edge_command_outbox SET status='publishing',updated_at=$2
			WHERE deployment_id=$1 AND deployment_attempt=1 AND status='pending'`, deploymentID, fixture.now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE edge_command_outbox
			SET status='published',published_at=$2,updated_at=$2
			WHERE deployment_id=$1 AND deployment_attempt=1 AND status='publishing'`,
			deploymentID, fixture.now); err != nil {
			return err
		}
		for sequence, state := range []string{"delivered", "staged", "prechecked", "activated"} {
			at := fixture.now.Add(time.Duration(sequence+1) * time.Second)
			payload := []byte("partial candidate " + state + " after load")
			digest := sha256.Sum256(payload)
			if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(id,deployment_id,event_id,
				attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
				VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$8)`, uuid.New(), deploymentID, uuid.New(), sequence+1,
				state, payload, digest[:], at); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state=$2,updated_at=$3
				WHERE id=$1 AND attempt=1`, deploymentID, state, at); err != nil {
				return err
			}
		}
		loadedAt := fixture.now.Add(4 * time.Second)
		// The node runs its own artifact: the candidate's (v1) or its v2 one.
		_, err := tx.Exec(t.Context(), `UPDATE node_config_state SET
			previous_config_version_id=$2,previous_config_identity_schema=1,
			previous_config_artifact_sha256=$3,current_config_version_id=$4,
			current_config_identity_schema=1,current_config_artifact_sha256=
			  security_policy_activation_node_artifact_sha256_333($7,$4,$1,$5),updated_at=$6
			WHERE node_id=$1`, nodeID, fixture.previousConfigID, fixture.previousArtifactDigest[:],
			candidate.CandidateConfigVersionID, candidate.CandidateArtifactSHA256[:], loadedAt, candidate.TenantScopeID)
		if err != nil {
			return err
		}
		revertingAt := fixture.now.Add(5 * time.Second)
		revertingPayload := []byte("partial candidate reverting after load")
		revertingDigest := sha256.Sum256(revertingPayload)
		if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(id,deployment_id,event_id,
			attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
			VALUES($1,$2,$3,1,5,'reverting',$4,$5,$6,$6)`, uuid.New(), deploymentID, uuid.New(),
			revertingPayload, revertingDigest[:], revertingAt); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state='reverting',updated_at=$2
			WHERE id=$1 AND attempt=1`, deploymentID, revertingAt); err != nil {
			return err
		}
		failedAt := fixture.now.Add(6 * time.Second)
		failedPayload := []byte("partial candidate failed after load")
		failedDigest := sha256.Sum256(failedPayload)
		if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(id,deployment_id,event_id,
			attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
			VALUES($1,$2,$3,1,6,'failed',$4,$5,$6,$6)`, uuid.New(), deploymentID, uuid.New(),
			failedPayload, failedDigest[:], failedAt); err != nil {
			return err
		}
		_, err = tx.Exec(t.Context(), `UPDATE node_deployments SET state='failed',updated_at=$2
			WHERE id=$1 AND attempt=1`, deploymentID, failedAt)
		return err
	})
}

func markProductionRecoveryReverted(t *testing.T, fixture activationFixture, candidateID, nodeID uuid.UUID) error {
	return pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		var deploymentID, outboxID uuid.UUID
		if err := tx.QueryRow(t.Context(), `SELECT deployment.id,pending.outbox_id
			FROM security_policy_activation_recovery_pending_095 pending
			JOIN node_deployments deployment ON deployment.id=pending.deployment_id
			 AND deployment.attempt=pending.deployment_attempt
			WHERE pending.candidate_id=$1 AND pending.node_id=$2 AND pending.action='rollback'`,
			candidateID, nodeID).Scan(&deploymentID, &outboxID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE edge_command_outbox SET status='publishing',updated_at=$2
			WHERE id=$1 AND status='pending'`, outboxID, fixture.now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE edge_command_outbox
			SET status='published',published_at=$2,updated_at=$2 WHERE id=$1 AND status='publishing'`,
			outboxID, fixture.now); err != nil {
			return err
		}
		var at time.Time
		for index, state := range []string{"delivered", "staged", "prechecked", "reverting", "reverted"} {
			payload := []byte("exact recovery " + state)
			digest := sha256.Sum256(payload)
			at = fixture.now.Add(time.Duration(index+1) * time.Second)
			var identityAPIVersion, identitySchema, identityConfigID, identityDigest any
			if state == "reverted" {
				identityAPIVersion, identitySchema = 1, 1
				identityConfigID, identityDigest = fixture.previousConfigID, fixture.previousArtifactDigest[:]
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(id,deployment_id,event_id,
				attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at,
				active_config_identity_api_version,active_config_identity_schema,active_config_version_id,
				active_config_artifact_sha256) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$8,$9,$10,$11,$12)`,
				uuid.New(), deploymentID, uuid.New(), index+1, state, payload, digest[:], at,
				identityAPIVersion, identitySchema, identityConfigID, identityDigest); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state=$2,updated_at=$3
				WHERE id=$1 AND attempt=1`, deploymentID, state, at); err != nil {
				return err
			}
		}
		_, err := tx.Exec(t.Context(), `UPDATE node_config_state SET
			previous_config_version_id=NULL,previous_config_identity_schema=NULL,
			previous_config_artifact_sha256=NULL,current_config_version_id=$2,
			current_config_identity_schema=1,current_config_artifact_sha256=$3,updated_at=$4
			WHERE node_id=$1`, nodeID, fixture.previousConfigID, fixture.previousArtifactDigest[:], at)
		return err
	})
}

func markProductionRecoveryFailed(t *testing.T, fixture activationFixture, candidateID, nodeID uuid.UUID) error {
	return pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		var deploymentID, outboxID uuid.UUID
		if err := tx.QueryRow(t.Context(), `SELECT deployment.id,pending.outbox_id
			FROM security_policy_activation_recovery_pending_095 pending
			JOIN node_deployments deployment ON deployment.id=pending.deployment_id
			 AND deployment.attempt=pending.deployment_attempt
			WHERE pending.candidate_id=$1 AND pending.node_id=$2 AND pending.action='rollback'
			ORDER BY pending.generation DESC LIMIT 1`, candidateID, nodeID).
			Scan(&deploymentID, &outboxID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE edge_command_outbox SET status='publishing',updated_at=$2
			WHERE id=$1 AND status='pending'`, outboxID, fixture.now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE edge_command_outbox
			SET status='published',published_at=$2,updated_at=$2 WHERE id=$1 AND status='publishing'`,
			outboxID, fixture.now); err != nil {
			return err
		}
		for index, state := range []string{"delivered", "failed"} {
			at := fixture.now.Add(time.Duration(index+1) * time.Second)
			payload := []byte("failed recovery " + state)
			digest := sha256.Sum256(payload)
			if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(id,deployment_id,event_id,
				attempt,transition_sequence,state,payload,payload_sha256,occurred_at,received_at)
				VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$8)`, uuid.New(), deploymentID, uuid.New(), index+1,
				state, payload, digest[:], at); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state=$2,updated_at=$3
				WHERE id=$1 AND attempt=1`, deploymentID, state, at); err != nil {
				return err
			}
		}
		return nil
	})
}

func TestDerivedPhaseResolutionRejectsWrongKeyAndBinding(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "phase-resolution-rejects-mismatch",
		[]uuid.UUID{fixture.canaryNodeID}, 1)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := loadDerivedPhaseIdentity(t.Context(), tx, started.Candidate, "canary",
		started.Candidate.CanaryNodeIDs, "canary.wrong-key"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("wrong rollout key error = %v, want pgx.ErrNoRows", err)
	}
	wrongBinding := started.Candidate
	wrongBinding.BindingID = uuid.New()
	if _, err := loadDerivedPhaseIdentity(t.Context(), tx, wrongBinding, "canary",
		wrongBinding.CanaryNodeIDs, derivedKey("canary", wrongBinding.ID.String())); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("wrong binding error = %v, want pgx.ErrNoRows", err)
	}
}

func TestPhaseIdentityAndCandidatePromotionRollbackAtomically(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "phase-identity-atomic-rollback",
		[]uuid.UUID{fixture.canaryNodeID}, 1)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	markProductionPhaseHealthy(t, fixture, started.Candidate, "canary")
	if _, err := fixture.pool.Exec(t.Context(), `CREATE FUNCTION fail_activation_transition_test()
		RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
			RAISE EXCEPTION 'injected activation transition failure' USING ERRCODE='P0001';
		END $$;
		CREATE TRIGGER aaa_fail_activation_transition_test
		BEFORE UPDATE ON security_policy_activation_candidates
		FOR EACH ROW EXECUTE FUNCTION fail_activation_transition_test()`); err != nil {
		t.Fatal(err)
	}
	reconcile := productionReconcileInput(started.Candidate, "phase-identity-atomic-reconcile")
	if _, err := store.Reconcile(t.Context(), fixture.actor, reconcile); err == nil {
		t.Fatal("Reconcile succeeded despite injected candidate transition failure")
	}
	assertPhaseCounts(t, fixture.pool, started.Candidate.ID, 1, 0)
	assertCandidateStatus(t, fixture.pool, started.Candidate.ID, StatusClaimed, false)
	if _, err := fixture.pool.Exec(t.Context(), `DROP TRIGGER aaa_fail_activation_transition_test
		ON security_policy_activation_candidates; DROP FUNCTION fail_activation_transition_test()`); err != nil {
		t.Fatal(err)
	}
	result, err := store.Reconcile(t.Context(), fixture.actor, reconcile)
	if err != nil || result.Candidate.Status != StatusPromoted || result.Action != string(actionPromote) {
		t.Fatalf("Reconcile after removing injected failure = (%+v, %v)", result, err)
	}
	assertPhaseCounts(t, fixture.pool, started.Candidate.ID, 1, 1)
}

func prepareProductionStart(t *testing.T, fixture activationFixture, store *Store, key string,
	nodes []uuid.UUID, canarySize int) StartInput {
	t.Helper()
	var revision int64
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `UPDATE security_policy_publication_targets
			SET released_at=$2,release_reason='completed'
			WHERE publication_id=$1 AND released_at IS NULL`, fixture.bundleID, fixture.now); err != nil {
			return err
		}
		policy, err := store.clonePolicyVersionTx(t.Context(), tx, fixture.actor, fixture.scopeID,
			fixture.policyID, 2, uuid.NewString())
		revision = policy.Revision
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return StartInput{
		TenantScopeID: fixture.scopeID, SiteID: fixture.siteID, PolicyID: fixture.policyID,
		PolicyVersion: revision, ExpectedBindingRevision: 2, ExpectedActivePolicyVersion: 1,
		TargetNodeIDs: nodes, CanarySize: canarySize, IdempotencyKey: key, RequestID: uuid.NewString(),
		CorrelationID: uuid.NewString(), Traceparent: "00-11111111111111111111111111111111-2222222222222222-01",
		ExpiresAt: fixture.now.Add(10 * time.Minute),
	}
}

func productionReconcileInput(candidate Candidate, key string) ReconcileInput {
	return ReconcileInput{
		CandidateID: candidate.ID, PromotionCAS: candidate.PromotionCAS(), IdempotencyKey: key,
		RequestID: uuid.NewString(), CorrelationID: uuid.NewString(),
		Traceparent: "00-33333333333333333333333333333333-4444444444444444-01",
	}
}

func completeProductionActivation(t *testing.T, fixture activationFixture, store *Store, candidate Candidate) {
	t.Helper()
	markProductionPhaseHealthy(t, fixture, candidate, "canary")
	canaryInput := productionReconcileInput(candidate, "complete-canary-"+candidate.ID.String())
	canary, err := store.Reconcile(t.Context(), fixture.actor, canaryInput)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.ExpandNodeIDs) == 0 {
		if canary.Action != string(actionPromote) || canary.Candidate.Status != StatusPromoted {
			t.Fatalf("all-canary Reconcile = %+v", canary)
		}
		return
	}
	if canary.Action != string(actionExpand) || canary.Candidate.Status != StatusCanary {
		t.Fatalf("canary Reconcile = %+v", canary)
	}
	replayed, err := store.Reconcile(t.Context(), fixture.actor, canaryInput)
	if err != nil || !replayed.Replayed || replayed.Candidate.ID != candidate.ID {
		t.Fatalf("canary Reconcile replay = (%+v, %v)", replayed, err)
	}
	assertPhaseCounts(t, fixture.pool, candidate.ID, 2, 1)
	markProductionPhaseHealthy(t, fixture, candidate, "expand")
	final, err := store.Reconcile(t.Context(), fixture.actor,
		productionReconcileInput(candidate, "complete-expand-"+candidate.ID.String()))
	if err != nil || final.Action != string(actionPromote) || final.Candidate.Status != StatusPromoted {
		t.Fatalf("expand Reconcile = (%+v, %v)", final, err)
	}
}

// markProductionPhaseHealthy records the phase's nodes healthy, each
// reporting its own artifact (markV2PhaseHealthy).
func markProductionPhaseHealthy(t *testing.T, fixture activationFixture, candidate Candidate, phase string) {
	t.Helper()
	markV2PhaseHealthy(t, v2ActivationFixture{activationFixture: fixture, privateKeys: fixture.nodeKeys}, candidate, phase)
}

func productionPhaseRolloutID(t *testing.T, pool *pgxpool.Pool, candidateID uuid.UUID, phase string) uuid.UUID {
	t.Helper()
	var rolloutID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT id FROM rollouts WHERE idempotency_key=$1`,
		derivedKey(phase, candidateID.String())).Scan(&rolloutID); err != nil {
		t.Fatal(err)
	}
	return rolloutID
}

func assertPhaseCounts(t *testing.T, pool *pgxpool.Pool, candidateID uuid.UUID, wantRollouts, wantIdentities int) {
	t.Helper()
	var rollouts, identities int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM rollouts WHERE idempotency_key IN ($1,$2)),
		(SELECT count(*) FROM security_policy_activation_rollouts WHERE candidate_id=$3)`,
		derivedKey("canary", candidateID.String()), derivedKey("expand", candidateID.String()), candidateID).
		Scan(&rollouts, &identities); err != nil {
		t.Fatal(err)
	}
	if rollouts != wantRollouts || identities != wantIdentities {
		t.Fatalf("phase rollout/identity counts = %d/%d, want %d/%d", rollouts, identities, wantRollouts, wantIdentities)
	}
}

func TestCandidateClaimReplayAndPromotionCASAreTransactional(t *testing.T) {
	fixture := newActivationFixture(t)
	store, err := NewStore(fixture.pool, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	claim := fixture.claimInput("activation-claim")
	first, err := store.Claim(t.Context(), fixture.actor, claim)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Claim(t.Context(), fixture.actor, claim)
	if err != nil || !second.Replayed || second.Candidate.ID != first.Candidate.ID {
		t.Fatalf("claim replay = (%#v, %v)", second, err)
	}
	changed := claim
	changed.CandidateArtifactSHA256[0] ^= 0xff
	if _, err := store.Claim(t.Context(), fixture.actor, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error = %v, want ErrIdempotencyConflict", err)
	}

	if _, err := store.Promote(t.Context(), fixture.actor, first.Candidate.ID, first.Candidate.PromotionCAS()); !errors.Is(err, ErrNotHealthy) {
		t.Fatalf("premature promotion error = %v, want ErrNotHealthy", err)
	}
	fixture.markCandidateHealthy(t, first.Candidate.ID)
	staleCAS := first.Candidate.PromotionCAS()
	staleCAS.CandidateArtifactSHA256[0] ^= 0xff
	if _, err := store.Promote(t.Context(), fixture.actor, first.Candidate.ID, staleCAS); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale promotion CAS error = %v, want ErrConflict", err)
	}
	promoted, err := store.Promote(t.Context(), fixture.actor, first.Candidate.ID, first.Candidate.PromotionCAS())
	if err != nil || promoted.Status != StatusPromoted {
		t.Fatalf("Promote = (%#v, %v)", promoted, err)
	}
	var activeVersion, sourceRevision int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT binding.active_policy_version,scope.source_revision
		FROM security_policy_site_bindings binding
		JOIN edge_configuration_scopes scope ON scope.scope_id=binding.tenant_scope_id
		WHERE binding.id=$1`, fixture.bindingID).Scan(&activeVersion, &sourceRevision); err != nil {
		t.Fatal(err)
	}
	if activeVersion != claim.LastClaimedPolicyVersion || sourceRevision != claim.CandidateSourceRevision {
		t.Fatalf("promoted active/source = %d/%d", activeVersion, sourceRevision)
	}
	replayedPromotion, err := store.Promote(t.Context(), fixture.actor, first.Candidate.ID, first.Candidate.PromotionCAS())
	if err != nil || !replayedPromotion.Replayed || replayedPromotion.Status != StatusPromoted {
		t.Fatalf("promotion replay = (%#v, %v)", replayedPromotion, err)
	}
}

func TestPromotionRejectsConcurrentSourceRevisionAndCrossScopeActor(t *testing.T) {
	fixture := newActivationFixture(t)
	store, err := NewStore(fixture.pool, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Claim(t.Context(), fixture.actor, fixture.claimInput("source-conflict"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.markCandidateHealthy(t, created.Candidate.ID)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE edge_configuration_scopes
		SET source_revision=source_revision+1,updated_at=$2 WHERE scope_id=$1`, fixture.scopeID, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Promote(t.Context(), fixture.actor, created.Candidate.ID,
		created.Candidate.PromotionCAS()); !errors.Is(err, ErrSourceRevisionConflict) {
		t.Fatalf("source conflict error = %v", err)
	}
	other := fixture.actor
	other.ScopeID = uuid.New()
	if _, err := store.Get(t.Context(), other, created.Candidate.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-scope Get error = %v", err)
	}
}

func TestPromotionRejectsTargetThatNoLongerRunsCandidate(t *testing.T) {
	fixture := newActivationFixture(t)
	store, err := NewStore(fixture.pool, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Claim(t.Context(), fixture.actor, fixture.claimInput("stale-target-identity"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.markCandidateHealthy(t, created.Candidate.ID)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE node_config_state
		SET current_config_version_id=$2,current_config_artifact_sha256=$3,updated_at=$4
		WHERE node_id=$1`, fixture.canaryNodeID, fixture.previousConfigID,
		fixture.previousArtifactDigest[:], fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Promote(t.Context(), fixture.actor, created.Candidate.ID,
		created.Candidate.PromotionCAS()); !errors.Is(err, ErrNotHealthy) {
		t.Fatalf("stale target promotion error = %v, want ErrNotHealthy", err)
	}
	assertBindingActiveAndSource(t, fixture, 1, fixture.sourceRevision)
}

func TestPromotionWaitsForConcurrentTargetIdentityUpdate(t *testing.T) {
	fixture := newActivationFixture(t)
	store, err := NewStore(fixture.pool, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Claim(t.Context(), fixture.actor, fixture.claimInput("concurrent-target-identity"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.markCandidateHealthy(t, created.Candidate.ID)

	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), `UPDATE node_config_state
		SET current_config_version_id=$2,current_config_artifact_sha256=$3,updated_at=$4
		WHERE node_id=$1`, fixture.canaryNodeID, fixture.previousConfigID,
		fixture.previousArtifactDigest[:], fixture.now); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, promoteErr := store.Promote(t.Context(), fixture.actor, created.Candidate.ID,
			created.Candidate.PromotionCAS())
		result <- promoteErr
	}()
	select {
	case promoteErr := <-result:
		t.Fatalf("promotion did not wait for target identity lock: %v", promoteErr)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if promoteErr := <-result; !errors.Is(promoteErr, ErrNotHealthy) {
		t.Fatalf("promotion after target identity update = %v, want ErrNotHealthy", promoteErr)
	}
	assertBindingActiveAndSource(t, fixture, 1, fixture.sourceRevision)
}

func TestWorkerCancelsAndRecoversCandidateAfterPermissionRevocation(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "permission-revoked-worker",
		[]uuid.UUID{fixture.canaryNodeID}, 1)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	fixture.setRoleAssignment(t, false)
	worker, err := NewWorker(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertCandidateStatus(t, fixture.pool, started.Candidate.ID, StatusCancelled, false)
	var safePending int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*)
		FROM security_policy_activation_recovery_pending_095 pending
		JOIN node_config_state state ON state.node_id=pending.node_id
		 AND state.configuration_scope_id=pending.tenant_scope_id
		JOIN node_deployments deployment ON deployment.id=pending.deployment_id
		 AND deployment.attempt=pending.deployment_attempt
		JOIN edge_command_outbox outbox ON outbox.id=pending.outbox_id
		WHERE pending.candidate_id=$1 AND pending.action='apply'
		 AND state.current_config_identity_schema=1
		 AND state.current_config_version_id=pending.recovery_config_version_id
		 AND state.current_config_artifact_sha256=pending.recovery_artifact_sha256
		 AND deployment.state='cancelled' AND outbox.status='cancelled'`, started.Candidate.ID).Scan(&safePending); err != nil {
		t.Fatal(err)
	}
	if safePending != 1 {
		t.Fatalf("safe cancelled pending facts = %d, want 1", safePending)
	}
	var atomicCommands int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(DISTINCT request.id)
		FROM security_policy_activation_recovery_pending_095 pending
		JOIN security_policy_activation_candidates candidate ON candidate.id=pending.candidate_id
		JOIN node_deployments deployment ON deployment.id=pending.deployment_id
		 AND deployment.attempt=pending.deployment_attempt
		JOIN edge_command_outbox outbox ON outbox.id=pending.outbox_id
		JOIN rollouts rollout ON rollout.id=pending.rollout_id
		JOIN edge_rollout_write_requests request ON request.rollout_id=rollout.id
		 AND request.configuration_scope_id=pending.tenant_scope_id
		 AND request.operation='edge_rollout.cancel'
		JOIN audit_events event ON event.scope_id=request.actor_scope_id
		 AND event.actor_user_id=request.actor_user_id AND event.action=request.operation
		 AND event.resource_type='edge_rollout' AND event.resource_id=request.rollout_id::text
		 AND event.request_id=request.request_id::text AND event.result='success'
		WHERE pending.candidate_id=$1 AND pending.action='apply'
		 AND rollout.status='cancelled' AND rollout.revision=request.expected_revision+1
		 AND request.completed_at IS NOT NULL AND request.response_body IS NOT NULL
		 AND request.xmin::text=deployment.xmin::text AND request.xmin::text=outbox.xmin::text
		 AND request.xmin::text=rollout.xmin::text AND request.xmin::text=event.xmin::text
		 AND request.xmin::text=candidate.xmin::text`, started.Candidate.ID).Scan(&atomicCommands); err != nil {
		t.Fatal(err)
	}
	if atomicCommands != 1 {
		t.Fatalf("atomic completed cancellation commands = %d, want 1", atomicCommands)
	}
	if err := worker.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertCandidateStatus(t, fixture.pool, started.Candidate.ID, StatusCancelled, true)

	var activeVersion, sourceRevision int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT binding.active_policy_version,scope.source_revision
		FROM security_policy_site_bindings binding
		JOIN edge_configuration_scopes scope ON scope.scope_id=binding.tenant_scope_id
		WHERE binding.id=$1`, fixture.bindingID).Scan(&activeVersion, &sourceRevision); err != nil {
		t.Fatal(err)
	}
	if activeVersion != 1 || sourceRevision != fixture.sourceRevision {
		t.Fatalf("revoked candidate changed active/source = %d/%d", activeVersion, sourceRevision)
	}
	var systemAudits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND resource_id=$2
		  AND action='security_policy.activation.permission_revoked_reconcile'
		  AND actor_user_id IS NULL`, fixture.scopeID, started.Candidate.ID.String()).Scan(&systemAudits); err != nil {
		t.Fatal(err)
	}
	if systemAudits != 2 {
		t.Fatalf("permission-revoked system audits = %d, want 2", systemAudits)
	}
}

func TestWorkerCancelsFailedOutboxAfterPermissionRevocation(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "permission-revoked-failed-outbox",
		[]uuid.UUID{fixture.canaryNodeID}, 1)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	setActivationApplyOutboxStatus(t, fixture, started.Candidate.ID, "publishing")
	setActivationApplyOutboxStatus(t, fixture, started.Candidate.ID, "failed")
	fixture.setRoleAssignment(t, false)
	worker, err := NewWorker(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertCandidateStatus(t, fixture.pool, started.Candidate.ID, StatusCancelled, false)
	var cancelled int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*)
		FROM security_policy_activation_recovery_pending_095 pending
		JOIN node_deployments deployment ON deployment.id=pending.deployment_id
		 AND deployment.attempt=pending.deployment_attempt
		JOIN edge_command_outbox outbox ON outbox.id=pending.outbox_id
		WHERE pending.candidate_id=$1 AND pending.action='apply'
		 AND deployment.state='cancelled' AND outbox.status='cancelled'`,
		started.Candidate.ID).Scan(&cancelled); err != nil {
		t.Fatal(err)
	}
	if cancelled != 1 {
		t.Fatalf("failed outbox cancelled pairs = %d, want 1", cancelled)
	}
	if err := worker.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertCandidateStatus(t, fixture.pool, started.Candidate.ID, StatusCancelled, true)
}

func TestWorkerDoesNotCancelPublishingOutboxAfterPermissionRevocation(t *testing.T) {
	fixture := newActivationFixture(t)
	store := newProductionActivationStore(t, fixture)
	input := prepareProductionStart(t, fixture, store, "permission-revoked-publishing-outbox",
		[]uuid.UUID{fixture.canaryNodeID}, 1)
	started, err := store.Start(t.Context(), fixture.actor, input)
	if err != nil {
		t.Fatal(err)
	}
	setActivationApplyOutboxStatus(t, fixture, started.Candidate.ID, "publishing")
	fixture.setRoleAssignment(t, false)
	worker, err := NewWorker(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := worker.reconcile(t.Context()); err != nil {
		t.Fatal(err)
	}
	assertCandidateStatus(t, fixture.pool, started.Candidate.ID, StatusClaimed, false)
	var publishing int
	var recovered bool
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE outbox.status='publishing'),
		security_policy_activation_recovered_095($1)
		FROM security_policy_activation_recovery_pending_095 pending
		JOIN edge_command_outbox outbox ON outbox.id=pending.outbox_id
		WHERE pending.candidate_id=$1 AND pending.action='apply'`, started.Candidate.ID).
		Scan(&publishing, &recovered); err != nil {
		t.Fatal(err)
	}
	if publishing != 1 || recovered {
		t.Fatalf("publishing outbox count/recovered = %d/%t, want 1/false", publishing, recovered)
	}
}

func setActivationApplyOutboxStatus(t *testing.T, fixture activationFixture, candidateID uuid.UUID, status string) {
	t.Helper()
	command, err := fixture.pool.Exec(t.Context(), `UPDATE edge_command_outbox outbox SET status=$2,updated_at=$3
		FROM security_policy_activation_recovery_pending_095 pending
		WHERE pending.candidate_id=$1 AND pending.action='apply' AND pending.outbox_id=outbox.id`,
		candidateID, status, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if command.RowsAffected() != 1 {
		t.Fatalf("updated apply outboxes = %d, want 1", command.RowsAffected())
	}
}

func TestPromotionSerializesAfterRBACRevocation(t *testing.T) {
	fixture := newActivationFixture(t)
	store, err := NewStore(fixture.pool, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Claim(t.Context(), fixture.actor, fixture.claimInput("promotion-rbac-revocation"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.markCandidateHealthy(t, created.Candidate.ID)

	revoker, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = revoker.Rollback(context.Background()) }()
	if _, err := protocol.BeginAuthorityMutation(t.Context(), revoker, protocol.OperationCustomRoleRevoke,
		[]uuid.UUID{fixture.scopeID}); err != nil {
		t.Fatal(err)
	}
	if _, err := revoker.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.scopeID, fixture.actor.UserID, fixture.roleID); err != nil {
		t.Fatal(err)
	}
	promotionDone := make(chan error, 1)
	go func() {
		_, err := store.Promote(context.Background(), fixture.actor, created.Candidate.ID, created.Candidate.PromotionCAS())
		promotionDone <- err
	}()
	select {
	case err := <-promotionDone:
		t.Fatalf("promotion escaped uncommitted authority mutation: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := revoker.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-promotionDone; !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("promotion after revocation error = %v, want ErrPermissionDenied", err)
	}
	assertCandidateStatus(t, fixture.pool, created.Candidate.ID, StatusHealthy, false)
}

func TestRevokedCleanupSerializesAfterRBACRestore(t *testing.T) {
	fixture := newActivationFixture(t)
	store, err := NewStore(fixture.pool, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Claim(t.Context(), fixture.actor, fixture.claimInput("cleanup-rbac-restore"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.setRoleAssignment(t, false)

	restorer, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restorer.Rollback(context.Background()) }()
	if _, err := protocol.BeginAuthorityMutation(t.Context(), restorer, protocol.OperationCustomRoleAssign,
		[]uuid.UUID{fixture.scopeID}); err != nil {
		t.Fatal(err)
	}
	if _, err := restorer.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
		VALUES($1,$2,$3)`, fixture.scopeID, fixture.actor.UserID, fixture.roleID); err != nil {
		t.Fatal(err)
	}
	input := ReconcileInput{
		CandidateID: created.Candidate.ID, PromotionCAS: created.Candidate.PromotionCAS(),
		IdempotencyKey: "permission.restore.serialization", RequestID: uuid.NewString(),
	}
	cleanupDone := make(chan error, 1)
	go func() {
		_, err := store.reconcileRevokedCandidate(context.Background(), fixture.actor, input)
		cleanupDone <- err
	}()
	select {
	case err := <-cleanupDone:
		t.Fatalf("cleanup escaped uncommitted authority mutation: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := restorer.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-cleanupDone; !errors.Is(err, ErrConflict) {
		t.Fatalf("cleanup after permission restore error = %v, want ErrConflict", err)
	}
	assertCandidateStatus(t, fixture.pool, created.Candidate.ID, StatusClaimed, false)
	var systemAudits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND resource_id=$2
		  AND action='security_policy.activation.permission_revoked_reconcile'`,
		fixture.scopeID, created.Candidate.ID.String()).Scan(&systemAudits); err != nil {
		t.Fatal(err)
	}
	if systemAudits != 0 {
		t.Fatalf("restored permission cleanup audits = %d, want 0", systemAudits)
	}
}

func TestClaimUsesCustomRBACAndRevocationCancelsCandidate(t *testing.T) {
	fixture := newActivationFixture(t)
	store, err := NewStore(fixture.pool, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.Claim(t.Context(), fixture.customActor, fixture.claimInput("custom-rbac-claim"))
	if err != nil {
		t.Fatal(err)
	}
	fixture.revokeCustomGrant(t)
	if _, err := store.Get(t.Context(), fixture.customActor, created.Candidate.ID); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked custom grant Get error = %v, want ErrPermissionDenied", err)
	}
	input := ReconcileInput{
		CandidateID: created.Candidate.ID, PromotionCAS: created.Candidate.PromotionCAS(),
		IdempotencyKey: "custom.rbac.revoked.cleanup", RequestID: uuid.NewString(),
	}
	result, err := store.reconcileRevokedCandidate(t.Context(), fixture.customActor, input)
	if err != nil || result.Candidate.Status != StatusCancelled {
		t.Fatalf("custom RBAC cleanup = (%+v, %v)", result, err)
	}
	assertCandidateStatus(t, fixture.pool, created.Candidate.ID, StatusCancelled, false)
}

func assertCandidateStatus(t *testing.T, pool *pgxpool.Pool, candidateID uuid.UUID, want CandidateStatus, recovered bool) {
	t.Helper()
	var status CandidateStatus
	var recoveredAt *time.Time
	if err := pool.QueryRow(t.Context(), `SELECT candidate_status,recovered_at
		FROM security_policy_activation_candidates WHERE id=$1`, candidateID).Scan(&status, &recoveredAt); err != nil {
		t.Fatal(err)
	}
	if status != want || (recoveredAt != nil) != recovered {
		t.Fatalf("candidate status/recovered = %s/%v, want %s/%v", status, recoveredAt != nil, want, recovered)
	}
}

func assertBindingActiveAndSource(t *testing.T, fixture activationFixture, wantActive, wantSource int64) {
	t.Helper()
	var active, source int64
	if err := fixture.pool.QueryRow(t.Context(), `SELECT binding.active_policy_version,scope.source_revision
		FROM security_policy_site_bindings binding
		JOIN edge_configuration_scopes scope ON scope.scope_id=binding.tenant_scope_id
		WHERE binding.id=$1`, fixture.bindingID).Scan(&active, &source); err != nil {
		t.Fatal(err)
	}
	if active != wantActive || source != wantSource {
		t.Fatalf("binding active/source = %d/%d, want %d/%d", active, source, wantActive, wantSource)
	}
}

type activationFixture struct {
	pool                                                               *pgxpool.Pool
	now                                                                time.Time
	signer                                                             *activationIntegrationSigner
	actor                                                              securitypolicy.Actor
	customActor                                                        securitypolicy.Actor
	tenantID, scopeID, siteID, policyID, bindingID, bundleID, configID uuid.UUID
	roleID, customRoleID, customGrantID                                uuid.UUID
	previousConfigID, canaryNodeID, expandNodeID, artifactID           uuid.UUID
	previousArtifactID                                                 uuid.UUID
	artifactDigest, previousArtifactDigest, targetDigest               [32]byte
	sourceRevision                                                     int64
	// nodeKeys are the target nodes' artifact private keys.
	nodeKeys map[uuid.UUID][]byte
	// nodeFeatures, when set, is what the target nodes declare instead of
	// activationNodeFeatures (a dynamic routing node: site_runtime 9).
	nodeFeatures []*agentv1.Capability
}

type activationPermissionActor struct {
	actor   securitypolicy.Actor
	roleID  uuid.UUID
	grantID uuid.UUID
}

func (fixture activationFixture) newPermissionActor(t *testing.T, permission string) activationPermissionActor {
	t.Helper()
	userID, roleID, grantID := uuid.New(), uuid.New(), uuid.New()
	actor := securitypolicy.Actor{UserID: userID, ScopeID: fixture.scopeID, ScopeKind: "tenant"}
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		statements := []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'activation reader','hash')`, []any{userID, "activation-reader-" + userID.String()}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{fixture.scopeID, userID}},
			{`INSERT INTO custom_roles(id,tenant_id,tenant_scope_id,current_revision,current_name,created_by_user_id,
				created_by_scope_id,created_at,updated_at) VALUES($1,$2,$3,0,'activation_reader',$4,$3,$5,$5)`,
				[]any{roleID, fixture.tenantID, fixture.scopeID, fixture.actor.UserID, fixture.now}},
			{`INSERT INTO custom_role_revisions(role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
				created_by_user_id,created_by_scope_id,step_up_proof_id,step_up_method,step_up_verified_at,created_at)
				VALUES($1,$2,$3,1,'activation_reader',ARRAY[$4],'identity.custom_role.create',$5,$3,$6,'totp',$7,$7)`,
				[]any{roleID, fixture.tenantID, fixture.scopeID, permission, fixture.actor.UserID, uuid.New(), fixture.now}},
			{`UPDATE custom_roles SET current_revision=1,updated_at=$2 WHERE id=$1`, []any{roleID, fixture.now}},
			{`INSERT INTO custom_role_grants(id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
				granted_by_user_id,granted_by_scope_id,step_up_proof_id,step_up_method,step_up_verified_at,granted_at)
				VALUES($1,$2,$3,$4,1,$5,$6,$3,$7,'totp',$8,$8)`,
				[]any{grantID, fixture.tenantID, fixture.scopeID, roleID, userID, fixture.actor.UserID, uuid.New(), fixture.now}},
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return activationPermissionActor{actor: actor, roleID: roleID, grantID: grantID}
}

func (reader activationPermissionActor) revoke(t *testing.T, fixture activationFixture) {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO custom_role_grant_revocations(
		id,grant_id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
		revoked_by_user_id,revoked_by_scope_id,step_up_proof_id,step_up_method,step_up_verified_at,revoked_at)
		VALUES($1,$2,$3,$4,$5,1,$6,$7,$4,$8,'totp',$9,$9)`, uuid.New(), reader.grantID,
		fixture.tenantID, fixture.scopeID, reader.roleID, reader.actor.UserID,
		fixture.actor.UserID, uuid.New(), fixture.now); err != nil {
		t.Fatal(err)
	}
}

func newActivationFixture(t *testing.T) activationFixture {
	t.Helper()
	return buildActivationFixture(t, false)
}

// buildActivationFixture: tenantIsScope gives the tenant the scope's ID
// (see challenge_refusal_integration_test.go).
func buildActivationFixture(t *testing.T, tenantIsScope bool) activationFixture {
	t.Helper()
	return buildActivationFixtureWithFeatures(t, tenantIsScope, nil)
}

func buildActivationFixtureWithFeatures(t *testing.T, tenantIsScope bool, nodeFeatures []*agentv1.Capability) activationFixture {
	t.Helper()
	pool := isolatedActivationPool(t)
	now := time.Date(2026, 8, 2, 2, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	value := activationFixture{
		pool: pool, now: now, signer: &activationIntegrationSigner{public: publicKey, private: privateKey},
		tenantID: uuid.New(), scopeID: uuid.New(), siteID: uuid.New(),
		policyID: uuid.New(), bindingID: uuid.New(), bundleID: uuid.New(), configID: uuid.New(),
		previousConfigID: uuid.New(), canaryNodeID: uuid.New(), expandNodeID: uuid.New(), artifactID: uuid.New(),
		previousArtifactID: uuid.New(), artifactDigest: sha256.Sum256([]byte("candidate-artifact")),
		previousArtifactDigest: sha256.Sum256([]byte("previous-artifact")),
		targetDigest:           sha256.Sum256([]byte("candidate-targets")),
		nodeFeatures:           nodeFeatures,
	}
	if tenantIsScope {
		value.tenantID = value.scopeID
	}
	userID, roleID, customUserID := uuid.New(), uuid.New(), uuid.New()
	value.roleID = roleID
	value.actor = securitypolicy.Actor{UserID: userID, ScopeID: value.scopeID, ScopeKind: "tenant"}
	value.customActor = securitypolicy.Actor{UserID: customUserID, ScopeID: value.scopeID, ScopeKind: "tenant"}
	value.customRoleID, value.customGrantID = uuid.New(), uuid.New()
	policy := securitypolicy.Policy{ID: value.policyID, ScopeID: value.scopeID, Kind: securitypolicy.KindWAF,
		Name: "candidate", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 2,
		Rules: []securitypolicy.Rule{{ID: uuid.New(), Name: "allow", Priority: 1, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "method", Operator: "equals", Values: []string{"GET"}}},
			Action:     securitypolicy.ActionAllow, Flow: securitypolicy.FlowStop}}}
	previousPolicy := policy
	previousPolicy.Revision = 1
	previousDocument, err := json.Marshal(previousPolicy)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := json.Marshal(policy.Rules)
	if err != nil {
		t.Fatal(err)
	}
	previousRuntime, err := securitypolicy.CompileRuntimeSnapshot(previousPolicy, value.siteID)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := securitypolicy.CompileRuntimeSnapshot(policy, value.siteID)
	if err != nil {
		t.Fatal(err)
	}
	previousDocumentDigest := sha256.Sum256(previousDocument)
	documentDigest := sha256.Sum256(document)
	previousBundleID := uuid.New()
	installationID := uuid.NewString()
	value.targetDigest, _, err = canonicalTargetSnapshot(value.scopeID, value.siteID, []uuid.UUID{value.canaryNodeID, value.expandNodeID})
	if err != nil {
		t.Fatal(err)
	}
	keyID := value.signer.KeyID()
	previousRolloutID, previousCanaryDeploymentID, previousExpandDeploymentID := uuid.New(), uuid.New(), uuid.New()
	previousCommand := []byte("previous-activation-command")
	previousCommandDigest := sha256.Sum256(previousCommand)
	previousArtifactSignature := ed25519.Sign(value.signer.private, []byte("previous-artifact"))
	artifactSignature := ed25519.Sign(value.signer.private, []byte("candidate-artifact"))
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO control_installation_entitlement(singleton,installation_id,last_status,created_at,updated_at) VALUES(true,$1,'uninstalled',$2,$2)`, []any{installationID, now}},
		{`INSERT INTO tenants(id,display_name) VALUES($1,'activation tenant')`, []any{value.tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{value.scopeID, value.tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'activation-user','activation user','hash')`, []any{userID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{value.scopeID, userID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'activation-custom-user','activation custom user','hash')`, []any{customUserID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{value.scopeID, customUserID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','',true)`, []any{roleID, value.scopeID}},
		{`INSERT INTO role_permissions(role_id,permission_name)
			VALUES($1,'security_policies.read'),($1,'security_policies.manage') ON CONFLICT DO NOTHING`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{value.scopeID, userID, roleID}},
		{`INSERT INTO custom_roles(id,tenant_id,tenant_scope_id,current_revision,current_name,created_by_user_id,
			created_by_scope_id,created_at,updated_at) VALUES($1,$2,$3,0,'activation_security_manager',$4,$3,$5,$5)`,
			[]any{value.customRoleID, value.tenantID, value.scopeID, userID, now}},
		{`INSERT INTO custom_role_revisions(role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
			created_by_user_id,created_by_scope_id,step_up_proof_id,step_up_method,step_up_verified_at,created_at)
			VALUES($1,$2,$3,1,'activation_security_manager',ARRAY['security_policies.manage'],
			'identity.custom_role.create',$4,$3,$5,'totp',$6,$6)`,
			[]any{value.customRoleID, value.tenantID, value.scopeID, userID, uuid.New(), now}},
		{`UPDATE custom_roles SET current_revision=1,updated_at=$2 WHERE id=$1`, []any{value.customRoleID, now}},
		{`INSERT INTO custom_role_grants(id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
			granted_by_user_id,granted_by_scope_id,step_up_proof_id,step_up_method,step_up_verified_at,granted_at)
			VALUES($1,$2,$3,$4,1,$5,$6,$3,$7,'totp',$8,$8)`,
			[]any{value.customGrantID, value.tenantID, value.scopeID, value.customRoleID, customUserID, userID, uuid.New(), now}},
		{`INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
		 VALUES($1,1,$2,$3,'activation.example',ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$3,$3)`, []any{value.siteID, value.scopeID, userID}},
		{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{value.siteID}},
		{`INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'192.0.2.10',80)`, []any{value.siteID}},
		// Nodes predate the fixture clock (node identity state is monotonic in time).
		{`INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id,created_at,updated_at) VALUES($1,1,$2,$3,'active',$4,$5,$5)`, []any{value.canaryNodeID, value.scopeID, "activation-" + value.canaryNodeID.String(), userID, now.Add(-time.Hour)}},
		{`INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id,created_at,updated_at) VALUES($1,2,$2,$3,'active',$4,$5,$5)`, []any{value.expandNodeID, value.scopeID, "activation-" + value.expandNodeID.String(), userID, now.Add(-time.Hour)}},
		{`INSERT INTO security_policies(id,scope_id,tenant_id,owner_user_id,kind,name,enabled,default_action,rules,revision,
			 created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'waf','candidate',true,'allow',$5,2,$4,$4,$6,$6)`, []any{value.policyID, value.scopeID, value.tenantID, userID, rules, now}},
		{`INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,1,$2,$3,$4)`, []any{value.policyID, previousDocument, userID, now}},
		{`INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,2,$2,$3,$4)`, []any{value.policyID, document, userID, now}},
		{`INSERT INTO security_policy_site_bindings(id,tenant_scope_id,site_id,policy_id,policy_kind,active_policy_version,
			 last_claimed_policy_version,last_bundle_id,revision,created_at,updated_at) VALUES($1,$2,$3,$4,'waf',NULL,NULL,NULL,0,$5,$5)`, []any{value.bindingID, value.scopeID, value.siteID, value.policyID, now}},
		{`INSERT INTO security_policy_publications(id,binding_id,tenant_scope_id,site_id,policy_id,policy_kind,policy_version,
			 expected_binding_revision,binding_revision,expected_active_version,rollout_id,idempotency_key,request_digest,plan_request_digest,
			 canonical_payload,canonical_payload_sha256,runtime_snapshot_sha256,bundle_bytes,bundle_sha256,signing_key_id,issued_at,expires_at,
			 actor_scope_id,actor_user_id,request_id,created_at) VALUES($1,$2,$3,$4,$5,'waf',1,0,1,0,$6,'fixture-bundle-v1',$7,$7,$8,$9,$10,$8,$9,'fixture-key',$11,$12,$3,$13,'fixture-bundle-v1',$11)`,
			[]any{previousBundleID, value.bindingID, value.scopeID, value.siteID, value.policyID, uuid.New(), value.artifactDigest[:], previousDocument, previousDocumentDigest[:], previousRuntime.SHA256[:], now, now.Add(time.Hour), userID}},
		{`UPDATE security_policy_site_bindings SET active_policy_version=1,last_claimed_policy_version=1,last_bundle_id=$2,
			 revision=1,updated_at=$3 WHERE id=$1`, []any{value.bindingID, previousBundleID, now}},
		{`INSERT INTO security_policy_publications(id,binding_id,tenant_scope_id,site_id,policy_id,policy_kind,policy_version,
			 expected_binding_revision,binding_revision,expected_active_version,rollout_id,idempotency_key,request_digest,plan_request_digest,
			 canonical_payload,canonical_payload_sha256,runtime_snapshot_sha256,bundle_bytes,bundle_sha256,signing_key_id,issued_at,expires_at,
			 actor_scope_id,actor_user_id,request_id,created_at) VALUES($1,$2,$3,$4,$5,'waf',2,1,2,1,$6,'fixture-bundle-v2',$7,$7,$8,$9,$10,$8,$9,'fixture-key',$11,$12,$3,$13,'fixture-bundle-v2',$11)`,
			[]any{value.bundleID, value.bindingID, value.scopeID, value.siteID, value.policyID, uuid.New(), value.artifactDigest[:], document, documentDigest[:], runtime.SHA256[:], now, now.Add(time.Hour), userID}},
		{`UPDATE security_policy_site_bindings SET last_claimed_policy_version=2,last_bundle_id=$2,
			 revision=2,updated_at=$3 WHERE id=$1`, []any{value.bindingID, value.bundleID, now}},
		{`INSERT INTO security_policy_publication_targets(publication_id,tenant_scope_id,binding_id,node_id,claimed_at,expires_at)
			 VALUES($1,$2,$3,$4,$5,$6),($1,$2,$3,$7,$5,$6)`, []any{value.bundleID, value.scopeID, value.bindingID,
			value.canaryNodeID, now, now.Add(time.Hour), value.expandNodeID}},
		{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,generator_version,status,idempotency_key,request_digest,created_at)
			 VALUES($1,$2,$3,$4,'activation-test','1','building','activation-previous-config',$4,$5)`,
			[]any{value.previousConfigID, value.scopeID, previousDocument, previousDocumentDigest[:], now}},
		{`INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,generator_version,status,idempotency_key,request_digest,created_at)
			 VALUES($1,$2,$3,$4,'activation-test','1','building','activation-config',$4,$5)`, []any{value.configID, value.scopeID, document, documentDigest[:], now}},
		{`INSERT INTO artifact_signing_keys(id,algorithm,public_key,created_at) VALUES($1,'ed25519',$2,$3)`, []any{keyID, value.signer.public, now}},
		{`INSERT INTO configuration_artifacts(id,config_version_id,ordinal,kind,wire_bytes,size_bytes,sha256,signature,
			signing_key_id,signature_algorithm,compression,media_type,encryption_algorithm,created_at)
			VALUES($1,$2,1,'configuration',$3,$4,$5,$6,$7,'ed25519','none','application/octet-stream','none',$8)`, []any{value.previousArtifactID, value.previousConfigID, []byte("previous-artifact"), len("previous-artifact"), value.previousArtifactDigest[:], previousArtifactSignature, keyID, now}},
		{`UPDATE config_versions SET status='validating' WHERE id=$1`, []any{value.previousConfigID}},
		{`UPDATE config_versions SET status='releasable',published_at=$2 WHERE id=$1`, []any{value.previousConfigID, now}},
		{`INSERT INTO configuration_artifacts(id,config_version_id,ordinal,kind,wire_bytes,size_bytes,sha256,signature,
			signing_key_id,signature_algorithm,compression,media_type,encryption_algorithm,created_at)
			VALUES($1,$2,1,'configuration',$3,$4,$5,$6,$7,'ed25519','none','application/octet-stream','none',$8)`, []any{value.artifactID, value.configID, []byte("candidate-artifact"), len("candidate-artifact"), value.artifactDigest[:], artifactSignature, keyID, now}},
		{`UPDATE config_versions SET status='validating' WHERE id=$1`, []any{value.configID}},
		{`UPDATE config_versions SET status='releasable',published_at=$2 WHERE id=$1`, []any{value.configID, now}},
		{`INSERT INTO security_policy_activation_config_facts(tenant_scope_id,config_version_id,artifact_sha256,policy_kind,required_capabilities,created_at)
			VALUES($1,$2,$3,'waf',$4,$5)`, []any{value.scopeID, value.configID, value.artifactDigest[:],
			`[{"name":1,"api_version":1},{"name":12,"api_version":1},{"name":13,"api_version":1},{"name":15,"api_version":1}]`, now}},
		{`INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,updated_at)
			VALUES($1,$3,$4,$5),($2,$3,$4,$5)`, []any{value.canaryNodeID, value.expandNodeID,
			value.scopeID, value.previousConfigID, now}},
		{`INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,idempotency_key,
			request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
			required_consecutive_successes,deadline_at,created_at,queued_at,updated_at,revision,max_attempts,contract_version)
			VALUES($1,$2,$3,'apply','completed',$4,$5,$6,$7,1000,1000,1,$8,$9,$9,$9,1,3,0)`,
			[]any{previousRolloutID, value.scopeID, value.previousConfigID, "activation-previous-" + previousRolloutID.String(), make([]byte, 32), uuid.New(), uuid.New(), now.Add(time.Hour), now}},
		{`INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,action,state,
			command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
			VALUES($1,$2,$3,1,$4,'apply','healthy',$5,$6,$7,$8,$9,$9),
			($10,$2,$11,1,$4,'apply','healthy',$12,$6,$7,$8,$9,$9)`,
			[]any{previousCanaryDeploymentID, previousRolloutID, value.canaryNodeID, value.previousConfigID, uuid.New(), previousCommand, previousCommandDigest[:], now.Add(time.Hour), now, previousExpandDeploymentID, value.expandNodeID, uuid.New()}},
		{`INSERT INTO node_deployment_artifacts(deployment_id,deployment_attempt,config_version_id,artifact_id,ordinal)
			VALUES($1,1,$3,$4,1),($2,1,$3,$4,1)`, []any{previousCanaryDeploymentID, previousExpandDeploymentID, value.previousConfigID, value.previousArtifactID}},
		{`UPDATE node_config_state SET current_config_identity_schema=1,current_config_artifact_sha256=$2
			WHERE node_id=ANY($1)`, []any{[]uuid.UUID{value.canaryNodeID, value.expandNodeID}, value.previousArtifactDigest[:]}},
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), "SET CONSTRAINTS ALL DEFERRED"); err != nil {
			return err
		}
		for _, statement := range statements {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return fmt.Errorf("fixture SQL: %w\n%s", err, statement.sql)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	subscriptionID := insertFeatureSubscription(t, pool, value.scopeID, userID, now, true, true)
	linkFeatureSubscription(t, pool, value.siteID, subscriptionID)
	if err := pool.QueryRow(t.Context(), `SELECT source_revision FROM edge_configuration_scopes
		WHERE scope_id=$1`, value.scopeID).Scan(&value.sourceRevision); err != nil {
		t.Fatal(err)
	}
	value.nodeKeys = enrollActivationNodes(t, value)
	return value
}

func (fixture activationFixture) setRoleAssignment(t *testing.T, assigned bool) {
	t.Helper()
	operation := protocol.OperationCustomRoleRevoke
	if assigned {
		operation = protocol.OperationCustomRoleAssign
	}
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(t.Context(), tx, operation, []uuid.UUID{fixture.scopeID}); err != nil {
			return err
		}
		if assigned {
			_, err := tx.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
				VALUES($1,$2,$3)`, fixture.scopeID, fixture.actor.UserID, fixture.roleID)
			return err
		}
		_, err := tx.Exec(t.Context(), `DELETE FROM role_assignments
			WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.scopeID, fixture.actor.UserID, fixture.roleID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (fixture activationFixture) revokeCustomGrant(t *testing.T) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(t.Context(), tx, protocol.OperationCustomRoleRevoke,
			[]uuid.UUID{fixture.scopeID}); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO custom_role_grant_revocations(
			id,grant_id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
			revoked_by_user_id,revoked_by_scope_id,step_up_proof_id,step_up_method,step_up_verified_at,revoked_at)
			VALUES($1,$2,$3,$4,$5,1,$6,$7,$4,$8,'totp',$9,$9)`, uuid.New(), fixture.customGrantID,
			fixture.tenantID, fixture.scopeID, fixture.customRoleID, fixture.customActor.UserID,
			fixture.actor.UserID, uuid.New(), fixture.now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (fixture activationFixture) claimInput(key string) ClaimInput {
	return ClaimInput{
		TenantScopeID: fixture.scopeID, SiteID: fixture.siteID, BindingID: fixture.bindingID,
		BindingRevision: 2, LastBundleID: fixture.bundleID, LastClaimedPolicyVersion: 2,
		ExpectedActivePolicyVersion: 1, CandidateSourceRevision: fixture.sourceRevision + 1,
		CandidateConfigVersionID: fixture.configID, CandidateArtifactSHA256: fixture.artifactDigest,
		TargetSnapshotSHA256: fixture.targetDigest, CanaryNodeIDs: []uuid.UUID{fixture.canaryNodeID},
		ExpandNodeIDs: []uuid.UUID{fixture.expandNodeID}, RequiredCapabilities: []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_HTTP_1_1, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_CONFIG_PRECHECK, ApiVersion: 1},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 1},
		}, IdempotencyKey: key, RequestID: key,
		ExpiresAt: fixture.now.Add(time.Hour),
	}
}

func (fixture *activationFixture) markCandidateHealthy(t *testing.T, candidateID uuid.UUID) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		phases := []struct {
			name string
			node uuid.UUID
		}{{"canary", fixture.canaryNodeID}, {"expand", fixture.expandNodeID}}
		for index, phase := range phases {
			rolloutID, deploymentID := uuid.New(), uuid.New()
			command := []byte("activation-command-" + phase.name)
			commandDigest := sha256.Sum256(command)
			if _, err := tx.Exec(t.Context(), `INSERT INTO rollouts(id,configuration_scope_id,config_version_id,action,status,
				idempotency_key,request_digest,request_id,correlation_id,activation_timeout_ms,observation_window_ms,
				required_consecutive_successes,deadline_at,created_at,queued_at,revision,max_attempts,updated_at,contract_version)
				VALUES($1,$2,$3,'apply','queued',$4,$5,$6,$7,1000,1000,1,$8,$9,$9,1,3,$9,1)`,
				rolloutID, fixture.scopeID, fixture.configID, "activation-"+phase.name+"-"+candidateID.String(), make([]byte, 32), uuid.New(), candidateID, fixture.now.Add(time.Hour), fixture.now); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployments(id,rollout_id,node_id,attempt,config_version_id,
				previous_config_version_id,action,state,command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at)
				VALUES($1,$2,$3,1,$4,$5,'apply','queued',$6,$7,$8,$9,$10,$10)`, deploymentID, rolloutID, phase.node,
				fixture.configID, fixture.previousConfigID, uuid.New(), command, commandDigest[:], fixture.now.Add(time.Hour), fixture.now); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO node_deployment_artifacts(deployment_id,deployment_attempt,
				config_version_id,artifact_id,ordinal) VALUES($1,1,$2,$3,1)`, deploymentID, fixture.configID, fixture.artifactID); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO edge_command_outbox(id,deployment_id,deployment_attempt,node_id,
				subject,payload,payload_sha256,status,available_at,created_at,updated_at)
				VALUES($1,$2,1,$3,$4,$5,$6,'pending',$7,$7,$7)`, uuid.New(), deploymentID, phase.node,
				"cdnca.agent.commands."+phase.node.String(), command, commandDigest[:], fixture.now); err != nil {
				return err
			}
			for sequence, state := range []string{"delivered", "staged", "prechecked", "activated", "healthy"} {
				payload := []byte("activation-" + state + "-" + phase.name)
				payloadDigest := sha256.Sum256(payload)
				var identityAPIVersion, identitySchema, identityConfigID, identityDigest any
				if state == "healthy" {
					identityAPIVersion, identitySchema = 1, 1
					identityConfigID, identityDigest = fixture.configID, fixture.artifactDigest[:]
				}
				at := fixture.now.Add(time.Duration(index*10+sequence+1) * time.Second)
				if _, err := tx.Exec(t.Context(), `INSERT INTO deployment_status_events(id,deployment_id,event_id,attempt,
					transition_sequence,state,payload,payload_sha256,occurred_at,received_at,active_config_identity_api_version,
					active_config_identity_schema,active_config_version_id,active_config_artifact_sha256)
					VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$8,$9,$10,$11,$12)`, uuid.New(), deploymentID, uuid.New(),
					sequence+1, state, payload, payloadDigest[:], at, identityAPIVersion, identitySchema,
					identityConfigID, identityDigest); err != nil {
					return err
				}
				if _, err := tx.Exec(t.Context(), `UPDATE node_deployments SET state=$2,updated_at=$3
					WHERE id=$1 AND attempt=1`, deploymentID, state, at); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(t.Context(), `INSERT INTO security_policy_activation_rollouts(candidate_id,tenant_scope_id,
				phase,rollout_id,candidate_config_version_id,candidate_artifact_sha256,target_snapshot_sha256,node_ids,created_at)
				VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, candidateID, fixture.scopeID, phase.name, rolloutID,
				fixture.configID, fixture.artifactDigest[:], fixture.targetDigest[:], []uuid.UUID{phase.node}, fixture.now); err != nil {
				return err
			}
			if _, err := tx.Exec(t.Context(), `SELECT record_security_policy_activation_recovery_pending_095($1)`, rolloutID); err != nil {
				return err
			}
		}
		for _, nodeID := range []uuid.UUID{fixture.canaryNodeID, fixture.expandNodeID} {
			if _, err := tx.Exec(t.Context(), `UPDATE node_config_state SET configuration_scope_id=$2,current_config_version_id=$3,
				current_config_identity_schema=1,current_config_artifact_sha256=$4,updated_at=$5 WHERE node_id=$1`, nodeID,
				fixture.scopeID, fixture.configID, fixture.artifactDigest[:], fixture.now); err != nil {
				return err
			}
		}
		for _, status := range []CandidateStatus{StatusCanary, StatusExpanding, StatusHealthy} {
			if _, err := tx.Exec(t.Context(), `UPDATE security_policy_activation_candidates
				SET candidate_status=$2,updated_at=updated_at+interval '1 microsecond' WHERE id=$1`, candidateID, status); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Minute)
}

func isolatedActivationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "security_activation_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^security_activation_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatalf("migrate activation schema: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		admin.Close()
	})
	return pool
}
