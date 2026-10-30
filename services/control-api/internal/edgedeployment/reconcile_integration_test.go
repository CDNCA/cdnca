//go:build integration

package edgedeployment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRollbackFailureBlocksRolloutUntilAuditedReconciliation(t *testing.T) {
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
	configV1 := persistTestConfig(t, store, testConfigRequest(t, scopeID, "reconcile-config-v1", "reconcile-key", publicKey, privateKey, []byte("config v1")))
	configV2 := persistTestConfig(t, store, testConfigRequest(t, scopeID, "reconcile-config-v2", "reconcile-key", publicKey, privateKey, []byte("config v2")))
	configV3 := persistTestConfig(t, store, testConfigRequest(t, scopeID, "reconcile-config-v3", "reconcile-key", publicKey, privateKey, []byte("config v3")))
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	seedNodeConfigState(t, pool, nodeID, scopeID, &configV1.ID, nil)

	failedRollout, err := store.CreateRollout(context.Background(), testRolloutRequest(scopeID, configV2.ID, []uuid.UUID{nodeID}, "reconcile-failed-rollout"))
	if err != nil {
		t.Fatal(err)
	}
	failedDeployment := failedRollout.Rollout.Deployments[0]
	for _, state := range []string{"delivered", "staged", "prechecked", "reverting", "rollback_failed"} {
		advanceDeploymentState(t, pool, failedDeployment.ID, state)
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE node_config_state
		SET reconciliation_required = true,
		    reconciliation_reason = 'rollback_failed',
		    reconciliation_deployment_id = $2,
		    reconciliation_deployment_attempt = 1,
		    reconciliation_requested_at = $3,
		    revision = revision + 1,
		    updated_at = $3
		WHERE node_id = $1`, nodeID, failedDeployment.ID, integrationClock); err != nil {
		t.Fatal(err)
	}

	blocked := testRolloutRequest(scopeID, configV3.ID, []uuid.UUID{nodeID}, "reconcile-blocked-rollout")
	if _, err := store.CreateRollout(context.Background(), blocked); !errors.Is(err, ErrNodeReconciliationRequired) {
		t.Fatalf("blocked rollout error = %v", err)
	}
	assertDirectDeploymentGate(t, pool, failedDeployment.ID)

	wrongSource := ReconcileNodeConfigRequest{
		RequestID: uuid.New(), NodeID: nodeID, ConfigurationScopeID: scopeID,
		SourceDeploymentID: uuid.New(), SourceDeploymentAttempt: 1,
		ObservedConfigVersionID: &configV2.ID, Resolution: ReconciliationAgentObserved,
		Evidence: "signed agent inventory report",
	}
	if _, err := store.ReconcileNodeConfig(context.Background(), wrongSource); !errors.Is(err, ErrReconciliationSource) {
		t.Fatalf("wrong source reconciliation error = %v", err)
	}
	otherScopeID, _ := seedEdgeScope(t, pool)
	otherConfig := persistTestConfig(t, store, testConfigRequest(t, otherScopeID, "reconcile-other-config", "reconcile-key", publicKey, privateKey, []byte("other config")))
	wrongConfig := ReconcileNodeConfigRequest{
		RequestID: uuid.New(), NodeID: nodeID, ConfigurationScopeID: scopeID,
		SourceDeploymentID: failedDeployment.ID, SourceDeploymentAttempt: 1,
		ObservedConfigVersionID: &otherConfig.ID, Resolution: ReconciliationAgentObserved,
		Evidence: "signed agent inventory report",
	}
	if _, err := store.ReconcileNodeConfig(context.Background(), wrongConfig); !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("cross-scope observed config error = %v", err)
	}

	request := ReconcileNodeConfigRequest{
		RequestID: uuid.New(), NodeID: nodeID, ConfigurationScopeID: scopeID,
		SourceDeploymentID: failedDeployment.ID, SourceDeploymentAttempt: 1,
		ObservedConfigVersionID: &configV2.ID, Resolution: ReconciliationAgentObserved,
		Evidence: "signed agent inventory report",
	}
	results := make([]ReconcileNodeConfigResult, 2)
	errs := make([]error, 2)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			results[index], errs[index] = store.ReconcileNodeConfig(context.Background(), request)
		}(index)
	}
	close(start)
	wait.Wait()
	if errs[0] != nil || errs[1] != nil || results[0].Reconciliation.ID != results[1].Reconciliation.ID ||
		results[0].Replayed == results[1].Replayed {
		t.Fatalf("concurrent reconciliation results = %+v, errors = %v", results, errs)
	}
	if results[0].Reconciliation.PreviousConfigVersionID == nil ||
		*results[0].Reconciliation.PreviousConfigVersionID != configV1.ID {
		t.Fatalf("reconciliation previous version = %+v", results[0].Reconciliation.PreviousConfigVersionID)
	}

	conflict := request
	conflict.Evidence = "different evidence"
	if _, err := store.ReconcileNodeConfig(context.Background(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("reconciliation idempotency conflict error = %v", err)
	}
	var required bool
	var currentID, previousID uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		SELECT reconciliation_required, current_config_version_id, previous_config_version_id
		FROM node_config_state WHERE node_id = $1`, nodeID).Scan(&required, &currentID, &previousID); err != nil {
		t.Fatal(err)
	}
	if required || currentID != configV2.ID || previousID != configV1.ID {
		t.Fatalf("reconciled node state = required:%t current:%s previous:%s", required, currentID, previousID)
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE node_config_reconciliations SET evidence = 'changed' WHERE request_id = $1`, request.RequestID); err == nil {
		t.Fatal("append-only reconciliation audit accepted mutation")
	}

	after, err := store.CreateRollout(context.Background(), blocked)
	if err != nil || len(after.Rollout.Deployments) != 1 ||
		after.Rollout.Deployments[0].Command.PreviousConfigVersionId == nil ||
		*after.Rollout.Deployments[0].Command.PreviousConfigVersionId != configV2.ID.String() {
		t.Fatalf("post-reconciliation rollout = (%+v, %v)", after, err)
	}
}

func assertDirectDeploymentGate(t *testing.T, pool *pgxpool.Pool, deploymentID uuid.UUID) {
	t.Helper()
	commandBytes := []byte("reconciliation gate command")
	digest := sha256.Sum256(commandBytes)
	_, err := pool.Exec(context.Background(), `
		INSERT INTO node_deployments (
			id, rollout_id, node_id, attempt, config_version_id, previous_config_version_id,
			action, state, command_event_id, command_bytes, command_sha256,
			deadline_at, created_at, updated_at
		)
		SELECT $2, rollout_id, node_id, 2, config_version_id, previous_config_version_id,
		       action, 'queued', $3, $4, $5, deadline_at, $6, $6
		FROM node_deployments WHERE id = $1 AND attempt = 1`,
		deploymentID, uuid.New(), uuid.New(), commandBytes, digest[:], integrationClock)
	if err == nil {
		t.Fatal("database reconciliation gate accepted a direct deployment insert")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.ConstraintName != "node_deployments_reconciliation_gate" {
		t.Fatalf("direct deployment gate error = %v", err)
	}
}

func TestReconciliationMigrationBackfillsLatestRollbackFailure(t *testing.T) {
	pool := openEdgeTestDatabase(t, false)
	ctx := context.Background()
	// Migration 268 cannot be rolled back; start from 1..021 instead of the head.
	if err := databasetest.MigrateThrough(ctx, pool, "up", 21); err != nil {
		t.Fatal(err)
	}
	migrateEdgeDownToVersion(t, pool, 20)
	migrateEdgeDownToVersion(t, pool, 19)
	scopeID, userID := seedEdgeScope(t, pool)
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStoreWithClock(pool, func() time.Time { return integrationClock })
	if err != nil {
		t.Fatal(err)
	}
	configID := persistTestConfig(t, store, testConfigRequest(t, scopeID, "migration-reconciliation-config", "migration-reconciliation-key", publicKey, privateKey, []byte("migration config"))).ID
	seedNodeConfigState(t, pool, nodeID, scopeID, &configID, nil)
	deploymentID := seedRawRollbackFailure(t, pool, scopeID, nodeID, configID)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	var required bool
	var sourceID uuid.UUID
	if err := pool.QueryRow(ctx, `
		SELECT reconciliation_required, reconciliation_deployment_id
		FROM node_config_state WHERE node_id = $1`, nodeID).Scan(&required, &sourceID); err != nil {
		t.Fatal(err)
	}
	if !required || sourceID != deploymentID {
		t.Fatalf("migration backfill = required:%t source:%s", required, sourceID)
	}
}

func seedRawRollbackFailure(t *testing.T, pool *pgxpool.Pool, scopeID, nodeID, configID uuid.UUID) uuid.UUID {
	t.Helper()
	rolloutID, deploymentID := uuid.New(), uuid.New()
	requestDigest := sha256.Sum256([]byte("migration reconciliation rollout"))
	commandBytes := []byte("migration reconciliation command")
	commandDigest := sha256.Sum256(commandBytes)
	deadline := integrationClock.Add(time.Hour)
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO rollouts (
			id, configuration_scope_id, config_version_id, action, status,
			idempotency_key, request_digest, request_id, correlation_id,
			activation_timeout_ms, observation_window_ms, required_consecutive_successes,
			deadline_at, created_at, queued_at
		) VALUES ($1, $2, $3, 'apply', 'queued', $4, $5, $6, $7,
		          60000, 60000, 1, $8, $9, $9)`, rolloutID, scopeID, configID,
		"migration-reconciliation-rollout", requestDigest[:], uuid.New(), uuid.New(), deadline, integrationClock); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO node_deployments (
			id, rollout_id, node_id, attempt, config_version_id,
			action, state, command_event_id, command_bytes, command_sha256,
			deadline_at, created_at, updated_at
		) VALUES ($1, $2, $3, 1, $4, 'apply', 'rollback_failed', $5, $6, $7, $8, $9, $9)`,
		deploymentID, rolloutID, nodeID, configID, uuid.New(), commandBytes, commandDigest[:], deadline, integrationClock); err != nil {
		t.Fatal(err)
	}
	return deploymentID
}
