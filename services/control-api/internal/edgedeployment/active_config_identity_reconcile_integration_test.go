//go:build integration

package edgedeployment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReconcileNodeConfigMovesOnlyProvenIdentityTuple(t *testing.T) {
	pool := openEdgeTestDatabase(t, true)
	store, err := NewStoreWithClock(pool, func() time.Time { return integrationClock })
	if err != nil {
		t.Fatal(err)
	}
	scopeID, userID := seedEdgeScope(t, pool)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	current := persistTestConfig(t, store, testConfigRequest(t, scopeID, "identity-current", "identity-key", publicKey, privateKey, []byte("current wire")))
	previous := persistTestConfig(t, store, testConfigRequest(t, scopeID, "identity-previous", "identity-key", publicKey, privateKey, []byte("previous wire")))
	unknown := persistTestConfig(t, store, testConfigRequest(t, scopeID, "identity-unknown", "identity-key", publicKey, privateKey, []byte("unknown wire")))
	currentDigest := configArtifactDigest087(t, pool, current.ID)
	previousDigest := configArtifactDigest087(t, pool, previous.ID)

	t.Run("previous proven tuple becomes current atomically", func(t *testing.T) {
		nodeID := uuid.New()
		seedEdgeNode(t, pool, scopeID, userID, nodeID)
		seedNodeConfigState(t, pool, nodeID, scopeID, &current.ID, &previous.ID)
		seedConfigIdentityState087(t, pool, nodeID, currentDigest, previousDigest)
		sourceID := seedIdentityRollbackFailure087(t, pool, scopeID, nodeID, current.ID)
		markReconciliationRequired087(t, pool, nodeID, sourceID)
		request := ReconcileNodeConfigRequest{
			RequestID: uuid.New(), NodeID: nodeID, ConfigurationScopeID: scopeID,
			SourceDeploymentID: sourceID, SourceDeploymentAttempt: 1,
			ObservedConfigVersionID: &previous.ID, Resolution: ReconciliationAgentObserved,
			Evidence: "signed active identity observation",
		}
		first, err := store.ReconcileNodeConfig(context.Background(), request)
		if err != nil || first.Replayed {
			t.Fatalf("first proven tuple reconciliation = (%+v, %v)", first, err)
		}
		replay, err := store.ReconcileNodeConfig(context.Background(), request)
		if err != nil || !replay.Replayed || replay.Reconciliation.ID != first.Reconciliation.ID {
			t.Fatalf("replayed proven tuple reconciliation = (%+v, %v), first=%+v", replay, err, first)
		}
		assertReconciledIdentity087(t, pool, nodeID, previous.ID, previousDigest, current.ID, currentDigest)
	})

	t.Run("post-lock request recheck returns same request replay", func(t *testing.T) {
		testReconciliationPostLockBarrier087(t, pool, scopeID, userID, current, previous,
			currentDigest, previousDigest, false)
	})

	t.Run("post-lock request recheck rejects different request digest", func(t *testing.T) {
		testReconciliationPostLockBarrier087(t, pool, scopeID, userID, current, previous,
			currentDigest, previousDigest, true)
	})

	t.Run("unproven observed UUID clears current identity", func(t *testing.T) {
		nodeID := uuid.New()
		seedEdgeNode(t, pool, scopeID, userID, nodeID)
		seedNodeConfigState(t, pool, nodeID, scopeID, &current.ID, &previous.ID)
		seedConfigIdentityState087(t, pool, nodeID, currentDigest, previousDigest)
		sourceID := seedIdentityRollbackFailure087(t, pool, scopeID, nodeID, current.ID)
		markReconciliationRequired087(t, pool, nodeID, sourceID)
		request := ReconcileNodeConfigRequest{
			RequestID: uuid.New(), NodeID: nodeID, ConfigurationScopeID: scopeID,
			SourceDeploymentID: sourceID, SourceDeploymentAttempt: 1,
			ObservedConfigVersionID: &unknown.ID, Resolution: ReconciliationOperatorConfirmed,
			Evidence: "operator confirmed runtime UUID only",
		}
		if _, err := store.ReconcileNodeConfig(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		var currentID, previousID uuid.UUID
		var currentSchema *int32
		var currentDigestAfter []byte
		if err := pool.QueryRow(t.Context(), `SELECT current_config_version_id,previous_config_version_id,
			current_config_identity_schema,current_config_artifact_sha256 FROM node_config_state WHERE node_id=$1`, nodeID).Scan(
			&currentID, &previousID, &currentSchema, &currentDigestAfter); err != nil {
			t.Fatal(err)
		}
		if currentID != unknown.ID || previousID != current.ID || currentSchema != nil || currentDigestAfter != nil {
			t.Fatalf("unproven reconciliation = current:%s previous:%s schema:%v digest:%x", currentID, previousID, currentSchema, currentDigestAfter)
		}
	})

	t.Run("transaction failure leaves no reconciliation fact or partial tuple movement", func(t *testing.T) {
		nodeID := uuid.New()
		seedEdgeNode(t, pool, scopeID, userID, nodeID)
		seedNodeConfigState(t, pool, nodeID, scopeID, &current.ID, &previous.ID)
		seedConfigIdentityState087(t, pool, nodeID, currentDigest, previousDigest)
		sourceID := seedIdentityRollbackFailure087(t, pool, scopeID, nodeID, current.ID)
		markReconciliationRequired087(t, pool, nodeID, sourceID)
		request := ReconcileNodeConfigRequest{
			RequestID: uuid.New(), NodeID: nodeID, ConfigurationScopeID: scopeID,
			SourceDeploymentID: sourceID, SourceDeploymentAttempt: 1,
			ObservedConfigVersionID: &previous.ID, Resolution: ReconciliationAgentObserved,
			Evidence: "signed active identity observation after retry",
		}
		if _, err := pool.Exec(t.Context(), `CREATE FUNCTION fail_active_identity_reconcile_087()
			RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected reconciliation failure'; END $$;
			CREATE TRIGGER fail_active_identity_reconcile_087 BEFORE UPDATE ON node_config_state
			FOR EACH ROW EXECUTE FUNCTION fail_active_identity_reconcile_087()`); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ReconcileNodeConfig(context.Background(), request); err == nil {
			t.Fatal("injected reconciliation transaction failure was accepted")
		}
		var facts int
		var required bool
		var currentID, previousID uuid.UUID
		var currentSchema, previousSchema int32
		var gotCurrentDigest, gotPreviousDigest []byte
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_config_reconciliations WHERE request_id=$1`,
			request.RequestID).Scan(&facts); err != nil {
			t.Fatal(err)
		}
		if err := pool.QueryRow(t.Context(), `SELECT reconciliation_required,current_config_version_id,
			previous_config_version_id,current_config_identity_schema,current_config_artifact_sha256,
			previous_config_identity_schema,previous_config_artifact_sha256 FROM node_config_state WHERE node_id=$1`,
			nodeID).Scan(&required, &currentID, &previousID, &currentSchema, &gotCurrentDigest,
			&previousSchema, &gotPreviousDigest); err != nil {
			t.Fatal(err)
		}
		if facts != 0 || !required || currentID != current.ID || previousID != previous.ID || currentSchema != 1 ||
			previousSchema != 1 || !bytes.Equal(gotCurrentDigest, currentDigest) || !bytes.Equal(gotPreviousDigest, previousDigest) {
			t.Fatalf("failed reconciliation persisted partial state: facts=%d required=%t current=%s/%d/%x previous=%s/%d/%x",
				facts, required, currentID, currentSchema, gotCurrentDigest, previousID, previousSchema, gotPreviousDigest)
		}
		if _, err := pool.Exec(t.Context(), `DROP TRIGGER fail_active_identity_reconcile_087 ON node_config_state;
			DROP FUNCTION fail_active_identity_reconcile_087()`); err != nil {
			t.Fatal(err)
		}
		result, err := store.ReconcileNodeConfig(context.Background(), request)
		if err != nil || result.Replayed {
			t.Fatalf("reconciliation retry = (%+v, %v)", result, err)
		}
		assertReconciledIdentity087(t, pool, nodeID, previous.ID, previousDigest, current.ID, currentDigest)
	})
}

func TestReconcileNodeConfigRecoversObservedFailedApplyIdentityLoss(t *testing.T) {
	pool := openEdgeTestDatabase(t, true)
	store, err := NewStoreWithClock(pool, func() time.Time { return integrationClock.Add(2 * time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	scopeID, _ := seedEdgeScope(t, pool)
	platformScopeID, platformUserID := seedEdgePlatformIdentity(t, pool)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	current := persistTestConfig(t, store, testConfigRequest(t, scopeID, "identity-loss-current", "identity-loss-key", publicKey, privateKey, []byte("current wire")))
	previous := persistTestConfig(t, store, testConfigRequest(t, scopeID, "identity-loss-previous", "identity-loss-key", publicKey, privateKey, []byte("previous wire")))
	observed := persistTestConfig(t, store, testConfigRequest(t, scopeID, "identity-loss-observed", "identity-loss-key", publicKey, privateKey, []byte("observed wire")))
	currentDigest := configArtifactDigest087(t, pool, current.ID)
	previousDigest := configArtifactDigest087(t, pool, previous.ID)

	t.Run("operator-confirmed live pointer chain restores version pointers without inventing identity", func(t *testing.T) {
		nodeID := uuid.New()
		seedEdgePlatformNode(t, pool, platformScopeID, platformUserID, nodeID)
		seedNodeConfigState(t, pool, nodeID, scopeID, &current.ID, &previous.ID)
		seedConfigIdentityState087(t, pool, nodeID, currentDigest, previousDigest)
		sourceID := seedFailedApplyIdentityLoss087(t, pool, scopeID, nodeID, current.ID, observed.ID, currentDigest)
		request := ReconcileNodeConfigRequest{
			RequestID: uuid.New(), NodeID: nodeID, ConfigurationScopeID: scopeID,
			SourceDeploymentID: sourceID, SourceDeploymentAttempt: 1,
			ObservedConfigVersionID: &observed.ID, Resolution: ReconciliationOperatorConfirmed,
			Evidence: "manager pointer, OpenResty health response, and fresh mTLS heartbeat agree",
		}
		first, err := store.ReconcileNodeConfig(t.Context(), request)
		if err != nil || first.Replayed {
			t.Fatalf("failed apply recovery = (%+v, %v)", first, err)
		}
		replay, err := store.ReconcileNodeConfig(t.Context(), request)
		if err != nil || !replay.Replayed || replay.Reconciliation.ID != first.Reconciliation.ID {
			t.Fatalf("failed apply recovery replay = (%+v, %v)", replay, err)
		}
		var gotCurrent, gotPrevious uuid.UUID
		var currentSchema, previousSchema *int32
		var gotCurrentDigest, gotPreviousDigest []byte
		if err := pool.QueryRow(t.Context(), `SELECT current_config_version_id,previous_config_version_id,
			current_config_identity_schema,current_config_artifact_sha256,
			previous_config_identity_schema,previous_config_artifact_sha256
			FROM node_config_state WHERE node_id=$1`, nodeID).Scan(
			&gotCurrent, &gotPrevious, &currentSchema, &gotCurrentDigest,
			&previousSchema, &gotPreviousDigest); err != nil {
			t.Fatal(err)
		}
		if gotCurrent != observed.ID || gotPrevious != current.ID || currentSchema != nil || gotCurrentDigest != nil ||
			previousSchema == nil || *previousSchema != 1 || !bytes.Equal(gotPreviousDigest, currentDigest) {
			t.Fatalf("failed apply recovery identity = current:%s/%v/%x previous:%s/%v/%x",
				gotCurrent, currentSchema, gotCurrentDigest, gotPrevious, previousSchema, gotPreviousDigest)
		}
		var facts int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_config_reconciliations WHERE request_id=$1`,
			request.RequestID).Scan(&facts); err != nil || facts != 1 {
			t.Fatalf("failed apply recovery facts = %d, %v", facts, err)
		}
	})

	t.Run("agent-observed resolution cannot bypass the rollback-failed gate", func(t *testing.T) {
		nodeID := uuid.New()
		seedEdgePlatformNode(t, pool, platformScopeID, platformUserID, nodeID)
		seedNodeConfigState(t, pool, nodeID, scopeID, &current.ID, &previous.ID)
		seedConfigIdentityState087(t, pool, nodeID, currentDigest, previousDigest)
		sourceID := seedFailedApplyIdentityLoss087(t, pool, scopeID, nodeID, current.ID, observed.ID, currentDigest)
		request := ReconcileNodeConfigRequest{
			RequestID: uuid.New(), NodeID: nodeID, ConfigurationScopeID: scopeID,
			SourceDeploymentID: sourceID, SourceDeploymentAttempt: 1,
			ObservedConfigVersionID: &observed.ID, Resolution: ReconciliationAgentObserved,
			Evidence: "heartbeat lacks the active artifact identity",
		}
		if _, err := store.ReconcileNodeConfig(t.Context(), request); !errors.Is(err, ErrReconciliationNotRequired) {
			t.Fatalf("agent-observed failed apply recovery error = %v", err)
		}
		assertReconciledIdentity087(t, pool, nodeID, current.ID, currentDigest, previous.ID, previousDigest)
	})
}

func testReconciliationPostLockBarrier087(t *testing.T, pool *pgxpool.Pool,
	scopeID, userID uuid.UUID, current, previous ConfigVersion, currentDigest, previousDigest []byte, conflict bool,
) {
	t.Helper()
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	seedNodeConfigState(t, pool, nodeID, scopeID, &current.ID, &previous.ID)
	seedConfigIdentityState087(t, pool, nodeID, currentDigest, previousDigest)
	sourceID := seedIdentityRollbackFailure087(t, pool, scopeID, nodeID, current.ID)
	markReconciliationRequired087(t, pool, nodeID, sourceID)
	request := ReconcileNodeConfigRequest{
		RequestID: uuid.New(), NodeID: nodeID, ConfigurationScopeID: scopeID,
		SourceDeploymentID: sourceID, SourceDeploymentAttempt: 1,
		ObservedConfigVersionID: &previous.ID, Resolution: ReconciliationAgentObserved,
		Evidence: "loser read request absent before node row lock",
	}

	blocker, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback(context.Background()) }()
	var blockerPID int32
	if err := blocker.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.Exec(t.Context(), `SELECT 1 FROM node_config_state WHERE node_id=$1 FOR UPDATE`, nodeID); err != nil {
		t.Fatal(err)
	}

	applicationName := "ai087_" + uuid.NewString()
	config := pool.Config().Copy()
	config.MaxConns = 1
	config.ConnConfig.RuntimeParams["application_name"] = applicationName
	loserPool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer loserPool.Close()
	loserStore, err := NewStoreWithClock(loserPool, func() time.Time { return integrationClock })
	if err != nil {
		t.Fatal(err)
	}
	type outcome struct {
		result ReconcileNodeConfigResult
		err    error
	}
	result := make(chan outcome, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		value, runErr := loserStore.ReconcileNodeConfig(ctx, request)
		result <- outcome{result: value, err: runErr}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM pg_stat_activity
			WHERE application_name=$1 AND wait_event_type='Lock'
			  AND $2::integer=ANY(pg_blocking_pids(pid))
			  AND query ILIKE '%node_config_state%FOR UPDATE%'
		)`, applicationName, blockerPID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case early := <-result:
			t.Fatalf("loser did not wait after absent request read: %+v", early)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("loser did not reach the node row lock")
		}
		time.Sleep(10 * time.Millisecond)
	}

	winnerRequest := request
	if conflict {
		winnerRequest.Evidence = "winner committed a different request digest"
	}
	winner, err := normalizeReconciliation(winnerRequest)
	if err != nil {
		t.Fatal(err)
	}
	reconciliationID := uuid.New()
	if _, err := blocker.Exec(t.Context(), `INSERT INTO node_config_reconciliations(
		id,request_id,request_digest,node_id,configuration_scope_id,source_deployment_id,
		source_deployment_attempt,previous_config_version_id,observed_config_version_id,
		resolution,evidence,reconciled_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, reconciliationID, winner.RequestID,
		winner.digest[:], winner.NodeID, winner.ConfigurationScopeID, winner.SourceDeploymentID,
		winner.SourceDeploymentAttempt, current.ID, winner.ObservedConfigVersionID, string(winner.Resolution),
		winner.Evidence, integrationClock); err != nil {
		t.Fatal(err)
	}
	if _, err := blocker.Exec(t.Context(), `UPDATE node_config_state SET reconciliation_required=false,
		reconciliation_reason=NULL,reconciliation_deployment_id=NULL,reconciliation_deployment_attempt=NULL,
		reconciliation_requested_at=NULL WHERE node_id=$1`, nodeID); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}

	got := <-result
	if conflict {
		if !errors.Is(got.err, ErrIdempotencyConflict) {
			t.Fatalf("different post-lock request = (%+v, %v), want idempotency conflict", got.result, got.err)
		}
	} else if got.err != nil || !got.result.Replayed || got.result.Reconciliation.ID != reconciliationID {
		t.Fatalf("same post-lock request = (%+v, %v), want replay %s", got.result, got.err, reconciliationID)
	}
	var facts int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_config_reconciliations WHERE request_id=$1`,
		request.RequestID).Scan(&facts); err != nil || facts != 1 {
		t.Fatalf("post-lock reconciliation facts = %d, %v", facts, err)
	}
}

func seedIdentityRollbackFailure087(t *testing.T, pool *pgxpool.Pool, scopeID, nodeID, configID uuid.UUID) uuid.UUID {
	t.Helper()
	rolloutID, deploymentID := uuid.New(), uuid.New()
	requestDigest := sha256.Sum256([]byte("active identity reconciliation rollout"))
	commandBytes := []byte("active identity reconciliation command")
	commandDigest := sha256.Sum256(commandBytes)
	deadline := integrationClock.Add(time.Hour)
	if _, err := pool.Exec(t.Context(), `INSERT INTO rollouts(
		id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,
		request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,
		deadline_at,created_at,queued_at,updated_at
	) VALUES($1,$2,$3,'apply','queued',$4,$5,$6,$7,60000,60000,1,$8,$9,$9,$9)`,
		rolloutID, scopeID, configID, rolloutID.String(), requestDigest[:], uuid.New(), uuid.New(), deadline, integrationClock); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_deployments(
		id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,
		command_bytes,command_sha256,deadline_at,created_at,updated_at
	) VALUES($1,$2,$3,1,$4,'apply','rollback_failed',$5,$6,$7,$8,$9,$9)`,
		deploymentID, rolloutID, nodeID, configID, uuid.New(), commandBytes, commandDigest[:], deadline, integrationClock); err != nil {
		t.Fatal(err)
	}
	return deploymentID
}

func seedFailedApplyIdentityLoss087(t *testing.T, pool *pgxpool.Pool,
	scopeID, nodeID, currentID, observedID uuid.UUID, currentDigest []byte,
) uuid.UUID {
	t.Helper()
	rolloutID, deploymentID := uuid.New(), uuid.New()
	requestDigest := sha256.Sum256([]byte("failed apply identity loss rollout"))
	commandBytes := []byte("failed apply identity loss command")
	commandDigest := sha256.Sum256(commandBytes)
	payloadDigest := sha256.Sum256([]byte("failed apply identity loss heartbeat"))
	deadline := integrationClock.Add(time.Hour)
	if _, err := pool.Exec(t.Context(), `INSERT INTO rollouts(
		id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,
		request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,
		deadline_at,created_at,queued_at,updated_at
	) VALUES($1,$2,$3,'apply','queued',$4,$5,$6,$7,60000,60000,1,$8,$9,$9,$9)`,
		rolloutID, scopeID, observedID, rolloutID.String(), requestDigest[:], uuid.New(), uuid.New(), deadline, integrationClock); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_deployments(
		id,rollout_id,node_id,attempt,config_version_id,previous_config_version_id,action,state,
		command_event_id,command_bytes,command_sha256,deadline_at,created_at,updated_at
	) VALUES($1,$2,$3,1,$4,$5,'apply','failed',$6,$7,$8,$9,$10,$10)`,
		deploymentID, rolloutID, nodeID, observedID, currentID, uuid.New(), commandBytes, commandDigest[:], deadline, integrationClock); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_deployment_artifacts(
		deployment_id,deployment_attempt,config_version_id,artifact_id,ordinal
	) SELECT $1,1,$2,id,ordinal FROM configuration_artifacts
	  WHERE config_version_id=$2 AND kind='configuration'`, deploymentID, observedID); err != nil {
		t.Fatal(err)
	}
	observedAt := integrationClock.Add(time.Minute)
	eventID, requestID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_presence(
		node_id,status,session_epoch,heartbeat_sequence,event_id,request_id,payload_digest,
		occurred_at,projected_at,last_seen_at,confirmed_session_epoch,confirmed_heartbeat_sequence,
		confirmed_event_id,confirmed_request_id,confirmed_payload_digest,online_since,
		current_config_version_id,previous_config_version_id,loaded_config_version_id,
		openresty_state,firewall_state,filesystem_total_bytes,filesystem_available_bytes,cache_used_bytes,
		active_deployments,updated_at,active_config_identity_api_version,
		current_config_identity_schema,current_config_artifact_sha256,
		previous_config_identity_schema,previous_config_artifact_sha256,
		loaded_config_identity_schema,loaded_config_artifact_sha256
	) VALUES($1,'online',1,1,$2,$3,$4,$5,$5,$5,1,1,$2,$3,$4,$5,
		$6,$7,NULL,'stopped','stopped',0,0,0,'[]'::jsonb,$5,1,NULL,NULL,1,$8,NULL,NULL)`,
		nodeID, eventID, requestID, payloadDigest[:], observedAt, observedID, currentID, currentDigest); err != nil {
		t.Fatal(err)
	}
	return deploymentID
}

func configArtifactDigest087(t *testing.T, pool *pgxpool.Pool, configID uuid.UUID) []byte {
	t.Helper()
	var digest []byte
	if err := pool.QueryRow(t.Context(), `SELECT sha256 FROM configuration_artifacts
		WHERE config_version_id=$1 AND kind='configuration'`, configID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	return digest
}

func seedConfigIdentityState087(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID, current, previous []byte) {
	t.Helper()
	var currentID, previousID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT current_config_version_id,previous_config_version_id
		FROM node_config_state WHERE node_id=$1`, nodeID).Scan(&currentID, &previousID); err != nil {
		t.Fatal(err)
	}
	for _, configID := range []uuid.UUID{currentID, previousID} {
		rolloutID, deploymentID := uuid.New(), uuid.New()
		requestDigest := sha256.Sum256([]byte("active identity proof " + configID.String()))
		commandBytes := []byte("active identity proof " + configID.String())
		commandDigest := sha256.Sum256(commandBytes)
		deadline := integrationClock.Add(time.Hour)
		if _, err := pool.Exec(t.Context(), `INSERT INTO rollouts(
			id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,
			request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,
			deadline_at,created_at,queued_at,updated_at
		) SELECT $1,configuration_scope_id,id,'apply','queued',$2,$3,$4,$5,60000,60000,1,$6,$7,$7,$7
		  FROM config_versions WHERE id=$8`, rolloutID, rolloutID.String(), requestDigest[:], uuid.New(), uuid.New(),
			deadline, integrationClock, configID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO node_deployments(
			id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,
			command_bytes,command_sha256,deadline_at,created_at,updated_at
		) VALUES($1,$2,$3,1,$4,'apply','healthy',$5,$6,$7,$8,$9,$9)`,
			deploymentID, rolloutID, nodeID, configID, uuid.New(), commandBytes, commandDigest[:], deadline, integrationClock); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO node_deployment_artifacts(
			deployment_id,deployment_attempt,config_version_id,artifact_id,ordinal
		) SELECT $1,1,$2,id,ordinal FROM configuration_artifacts
		  WHERE config_version_id=$2 AND kind='configuration'`, deploymentID, configID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `UPDATE node_config_state SET
		current_config_identity_schema=1,current_config_artifact_sha256=$2,
		previous_config_identity_schema=1,previous_config_artifact_sha256=$3
		WHERE node_id=$1`, nodeID, current, previous); err != nil {
		t.Fatal(err)
	}
}

func markReconciliationRequired087(t *testing.T, pool *pgxpool.Pool, nodeID, deploymentID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE node_config_state SET reconciliation_required=true,
		reconciliation_reason='rollback_failed',reconciliation_deployment_id=$2,
		reconciliation_deployment_attempt=1,reconciliation_requested_at=$3 WHERE node_id=$1`,
		nodeID, deploymentID, integrationClock); err != nil {
		t.Fatal(err)
	}
}

func assertReconciledIdentity087(t *testing.T, pool *pgxpool.Pool, nodeID, currentID uuid.UUID,
	currentDigest []byte, previousID uuid.UUID, previousDigest []byte,
) {
	t.Helper()
	var gotCurrent, gotPrevious uuid.UUID
	var currentSchema, previousSchema int32
	var gotCurrentDigest, gotPreviousDigest []byte
	if err := pool.QueryRow(t.Context(), `SELECT current_config_version_id,previous_config_version_id,
		current_config_identity_schema,current_config_artifact_sha256,
		previous_config_identity_schema,previous_config_artifact_sha256
		FROM node_config_state WHERE node_id=$1`, nodeID).Scan(
		&gotCurrent, &gotPrevious, &currentSchema, &gotCurrentDigest, &previousSchema, &gotPreviousDigest); err != nil {
		t.Fatal(err)
	}
	if gotCurrent != currentID || gotPrevious != previousID || currentSchema != 1 || previousSchema != 1 ||
		!bytes.Equal(gotCurrentDigest, currentDigest) || !bytes.Equal(gotPreviousDigest, previousDigest) {
		t.Fatalf("reconciled identity = %s/%x -> %s/%x", gotPrevious, gotPreviousDigest, gotCurrent, gotCurrentDigest)
	}
}
