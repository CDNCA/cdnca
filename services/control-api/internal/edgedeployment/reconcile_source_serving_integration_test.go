//go:build integration

package edgedeployment

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// (fixed snapshot): the scope's first
// apply on the node ended rollback_failed while its generation kept serving;
// the node has no current version for the scope and the agent cannot rebuild
// the release. The operator, having checked the node, confirms the source
// deployment's own version. Only that node, scope, source attempt and its
// bound, verifiable version are accepted; the scope's next publication names
// the version as the previous one (what the agent's held telemetry waits for).
func TestOperatorConfirmsTheRollbackFailedSourceVersionOnly(t *testing.T) {
	fixture := newCommandIAMFixture(t, nil)
	pool, store := fixture.pool, fixture.store
	platformScopeID := seedCommandScope(t, pool, ScopeKindPlatform)
	actor := fixture.seedActor(t, platformScopeID, ScopeKindPlatform, PermissionRead, PermissionManage)
	scopeID, userID := seedEdgeScope(t, pool)
	otherScopeID, _ := seedEdgeScope(t, pool)
	source := persistTestConfig(t, store, testConfigRequest(t, scopeID, "serving-source", "serving-key", fixture.publicKey, fixture.privateKey, []byte("generation 1")))
	other := persistTestConfig(t, store, testConfigRequest(t, scopeID, "serving-other", "serving-key", fixture.publicKey, fixture.privateKey, []byte("another version")))
	next := persistTestConfig(t, store, testConfigRequest(t, scopeID, "serving-next", "serving-key", fixture.publicKey, fixture.privateKey, []byte("republished")))
	nodeID, unverifiableNodeID, unrelatedNodeID, agentNodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{nodeID, unverifiableNodeID, unrelatedNodeID, agentNodeID} {
		seedEdgeNode(t, pool, scopeID, userID, id)
	}
	failed, err := store.CreateRollout(context.Background(), testRolloutRequest(scopeID, source.ID, []uuid.UUID{nodeID, unverifiableNodeID, agentNodeID}, "serving-first-apply"))
	if err != nil {
		t.Fatal(err)
	}
	deployments := map[uuid.UUID]uuid.UUID{}
	for _, deployment := range failed.Rollout.Deployments {
		deployments[deployment.NodeID] = deployment.ID
		for _, state := range []string{"delivered", "staged", "prechecked", "reverting", "rollback_failed"} {
			advanceDeploymentState(t, pool, deployment.ID, state)
		}
		markRollbackFailedReconciliation(t, pool, deployment.NodeID, scopeID, deployment.ID)
	}
	sourceID := deployments[nodeID]
	dropSourceArtifactBinding(t, pool, deployments[unverifiableNodeID])

	command := func(node, scope, deployment uuid.UUID, attempt int32, observed *uuid.UUID, key string) ReconcileNodeConfigCommandRequest {
		return ReconcileNodeConfigCommandRequest{
			Actor: actor, NodeID: node, ConfigurationScopeID: scope, SourceDeploymentID: deployment,
			SourceDeploymentAttempt: attempt, ObservedConfigVersionID: observed,
			Resolution: ReconciliationOperatorConfirmed, Evidence: "operator verified the node still serves the source release",
			IdempotencyKey: key, RequestID: uuid.NewString(),
		}
	}
	for _, refused := range []struct {
		name    string
		request ReconcileNodeConfigCommandRequest
		want    error
	}{
		{"another version of the scope", command(nodeID, scopeID, sourceID, 1, &other.ID, "serving-other-version"), ErrReconciliationObservedNotSource},
		{"another attempt", command(nodeID, scopeID, sourceID, 2, &source.ID, "serving-other-attempt"), ErrReconciliationSource},
		{"another scope", command(nodeID, otherScopeID, sourceID, 1, &source.ID, "serving-other-scope"), ErrReconciliationNotRequired},
		{"another node", command(unrelatedNodeID, scopeID, sourceID, 1, &source.ID, "serving-other-node"), ErrReconciliationNotRequired},
		{"another node's source", command(nodeID, scopeID, deployments[unverifiableNodeID], 1, &source.ID, "serving-foreign-source"), ErrReconciliationSource},
		{"unverifiable source artifact", command(unverifiableNodeID, scopeID, deployments[unverifiableNodeID], 1, &source.ID, "serving-unverifiable"), ErrReconciliationSourceUnverifiable},
	} {
		if _, err := store.ReconcileNodeConfigCommand(context.Background(), refused.request); !errors.Is(err, refused.want) {
			t.Fatalf("%s: error = %v, want %v", refused.name, err, refused.want)
		}
	}
	for _, node := range []uuid.UUID{nodeID, unverifiableNodeID} {
		assertReconciliationOpen(t, pool, node, scopeID)
	}

	confirmed, err := store.ReconcileNodeConfigCommand(context.Background(), command(nodeID, scopeID, sourceID, 1, &source.ID, "serving-confirm"))
	if err != nil || confirmed.Replayed || confirmed.Reconciliation.ObservedConfigVersionID == nil ||
		*confirmed.Reconciliation.ObservedConfigVersionID != source.ID || confirmed.Reconciliation.PreviousConfigVersionID != nil {
		t.Fatalf("source version reconciliation = (%+v, %v)", confirmed, err)
	}
	var required bool
	var current, previous *uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT reconciliation_required,current_config_version_id,previous_config_version_id
		FROM node_config_state WHERE node_id=$1 AND configuration_scope_id=$2`, nodeID, scopeID).Scan(&required, &current, &previous); err != nil {
		t.Fatal(err)
	}
	if required || current == nil || *current != source.ID || previous != nil {
		t.Fatalf("node state after the confirmation = required:%t current:%v previous:%v", required, current, previous)
	}
	var observed uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT observed_config_version_id FROM node_config_reconciliations
		WHERE node_id=$1 AND resolution='operator_confirmed'`, nodeID).Scan(&observed); err != nil || observed != source.ID {
		t.Fatalf("reconciliation fact observed = %s, %v", observed, err)
	}
	var payload []byte
	if err := pool.QueryRow(t.Context(), `SELECT payload FROM audit_events WHERE action='edge_config.reconcile' AND resource_id=$1`,
		nodeID.String()).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var audit map[string]any
	if err := json.Unmarshal(payload, &audit); err != nil {
		t.Fatal(err)
	}
	if audit["recovery_mode"] != "rollback_failed_source_serving" || audit["operator_attestation"] == nil ||
		audit["resolution"] != string(ReconciliationOperatorConfirmed) || audit["observed_config_version_id"] != source.ID.String() {
		t.Fatalf("reconciliation audit payload = %s", payload)
	}

	// A new agent reports the serving release as the scope's current one
	// next to the rollback_failed result: agent_observed accepts it only with
	// the source artifact's digest.
	rollbackFailed := "rollback_failed"
	agentSource := deployments[agentNodeID]
	seedScopeObservation(t, pool, agentNodeID, scopeID, 1, "online", "running", &source.ID, integrationClock.Add(time.Minute),
		&agentSource, &rollbackFailed)
	observedRequest := command(agentNodeID, scopeID, agentSource, 1, &source.ID, "serving-agent-observed")
	observedRequest.Resolution = ReconciliationAgentObserved
	if _, err := store.ReconcileNodeConfigCommand(context.Background(), observedRequest); !errors.Is(err, ErrReconciliationSource) {
		t.Fatalf("agent report with another digest: error = %v, want ErrReconciliationSource", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE node_presence_scope_identities SET current_config_artifact_sha256=(
		SELECT artifact.sha256 FROM node_deployment_artifacts binding JOIN configuration_artifacts artifact
		  ON artifact.id=binding.artifact_id AND artifact.config_version_id=binding.config_version_id
		WHERE binding.deployment_id=$2 AND artifact.kind='configuration') WHERE node_id=$1`, agentNodeID, agentSource); err != nil {
		t.Fatal(err)
	}
	observedRequest.IdempotencyKey, observedRequest.RequestID = "serving-agent-observed-digest", uuid.NewString()
	if _, err := store.ReconcileNodeConfigCommand(context.Background(), observedRequest); err != nil {
		t.Fatalf("agent report of the source release: %v", err)
	}

	// The tenant publishes again: the command names the confirmed version
	// as the previous one and lists it as released.
	republished, err := store.CreateRollout(context.Background(), testRolloutRequest(scopeID, next.ID, []uuid.UUID{nodeID}, "serving-republish"))
	if err != nil || len(republished.Rollout.Deployments) != 1 ||
		republished.Rollout.Deployments[0].Command.PreviousConfigVersionId == nil ||
		*republished.Rollout.Deployments[0].Command.PreviousConfigVersionId != source.ID.String() ||
		!slices.Equal(republished.Rollout.Deployments[0].Command.ReleasedConfigVersionIds, []string{source.ID.String()}) {
		t.Fatalf("republish after the confirmation = (%+v, %v)", republished, err)
	}
}

func markRollbackFailedReconciliation(t *testing.T, pool *pgxpool.Pool, nodeID, scopeID, deploymentID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE node_config_state SET reconciliation_required=true,
		reconciliation_reason='rollback_failed',reconciliation_deployment_id=$3,reconciliation_deployment_attempt=1,
		reconciliation_requested_at=$4,revision=revision+1,updated_at=$4
		WHERE node_id=$1 AND configuration_scope_id=$2`, nodeID, scopeID, deploymentID, integrationClock); err != nil {
		t.Fatal(err)
	}
}

// dropSourceArtifactBinding: the source attempt's configuration artifact can
// no longer be verified (fixture only; the bindings are immutable).
func dropSourceArtifactBinding(t *testing.T, pool *pgxpool.Pool, deploymentID uuid.UUID) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `DELETE FROM node_deployment_artifacts WHERE deployment_id=$1`, deploymentID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func assertReconciliationOpen(t *testing.T, pool *pgxpool.Pool, nodeID, scopeID uuid.UUID) {
	t.Helper()
	var required bool
	var facts int
	if err := pool.QueryRow(t.Context(), `SELECT state.reconciliation_required,
		(SELECT count(*) FROM node_config_reconciliations WHERE node_id=$1)
		FROM node_config_state state WHERE state.node_id=$1 AND state.configuration_scope_id=$2`, nodeID, scopeID).Scan(&required, &facts); err != nil {
		t.Fatal(err)
	}
	if !required || facts != 0 {
		t.Fatalf("refused reconciliations changed node %s: required:%t facts:%d", nodeID, required, facts)
	}
}
