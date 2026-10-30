package edgedeployment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var integrationClock = time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)

func TestPersistReleasableConfigAndDatabaseGuards(t *testing.T) {
	pool := openEdgeTestDatabase(t, true)
	store, err := NewStoreWithClock(pool, func() time.Time { return integrationClock })
	if err != nil {
		t.Fatal(err)
	}
	scopeID, userID := seedEdgeScope(t, pool)
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := testConfigRequest(t, scopeID, "config-primary", "artifact-key-primary", publicKey, privateKey, []byte("exact wire bytes"))
	result, err := store.PersistReleasableConfig(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Replayed || len(result.ConfigVersion.Artifacts) != 1 {
		t.Fatalf("unexpected config result: %+v", result)
	}
	var wire, storedSnapshotDigest []byte
	var status string
	if err := pool.QueryRow(context.Background(), `
		SELECT artifact.wire_bytes, config.canonical_snapshot_sha256, config.status
		FROM config_versions config
		JOIN configuration_artifacts artifact ON artifact.config_version_id = config.id
		WHERE config.id = $1`, result.ConfigVersion.ID).Scan(&wire, &storedSnapshotDigest, &status); err != nil {
		t.Fatal(err)
	}
	expectedSnapshotDigest := sha256.Sum256(request.CanonicalSnapshot)
	if !bytes.Equal(wire, request.Artifacts[0].WireBytes) || !bytes.Equal(storedSnapshotDigest, expectedSnapshotDigest[:]) || status != "releasable" {
		t.Fatal("persisted config bytes, digest, or status changed")
	}
	replay, err := store.PersistReleasableConfig(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed || replay.ConfigVersion.ID != result.ConfigVersion.ID {
		t.Fatalf("config replay = %+v", replay)
	}
	conflict := request
	conflict.CanonicalSnapshot = []byte(`{"changed":true}`)
	if _, err := store.PersistReleasableConfig(context.Background(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("config idempotency conflict error = %v", err)
	}

	otherPublicKey, otherPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyConflict := testConfigRequest(t, scopeID, "config-key-conflict", "artifact-key-primary", otherPublicKey, otherPrivateKey, []byte("other signer"))
	if _, err := store.PersistReleasableConfig(context.Background(), keyConflict); !errors.Is(err, ErrSigningKeyConflict) {
		t.Fatalf("signing key conflict error = %v", err)
	}

	var publishedAt time.Time
	if err := pool.QueryRow(context.Background(), `SELECT published_at FROM config_versions WHERE id=$1`, result.ConfigVersion.ID).Scan(&publishedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE config_versions SET status='superseded' WHERE id=$1`, result.ConfigVersion.ID); err != nil {
		t.Fatalf("releasable -> superseded: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE config_versions SET status='revoked', published_at=$2 WHERE id=$1`,
		result.ConfigVersion.ID, publishedAt.Add(time.Second)); err == nil {
		t.Fatal("published_at mutation was accepted")
	}
	if _, err := pool.Exec(context.Background(), `UPDATE config_versions SET status='revoked' WHERE id=$1`, result.ConfigVersion.ID); err != nil {
		t.Fatalf("superseded -> revoked with frozen publication time: %v", err)
	}
	var revokedPublishedAt time.Time
	if err := pool.QueryRow(context.Background(), `SELECT published_at FROM config_versions WHERE id=$1`, result.ConfigVersion.ID).Scan(&revokedPublishedAt); err != nil {
		t.Fatal(err)
	}
	if !revokedPublishedAt.Equal(publishedAt) {
		t.Fatalf("published_at changed from %s to %s", publishedAt, revokedPublishedAt)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE config_versions SET canonical_snapshot='changed' WHERE id=$1`, result.ConfigVersion.ID); err == nil {
		t.Fatal("published config content mutation was accepted")
	}
	if _, err := pool.Exec(context.Background(), `UPDATE configuration_artifacts SET wire_bytes='changed' WHERE config_version_id=$1`, result.ConfigVersion.ID); err == nil {
		t.Fatal("artifact mutation was accepted")
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO configuration_artifacts (
			id, config_version_id, ordinal, kind, wire_bytes, size_bytes, sha256, signature,
			signing_key_id, signature_algorithm, compression, media_type, encryption_algorithm, recipient_key_id, created_at
		)
		SELECT $2, config_version_id, ordinal+1, kind, wire_bytes, size_bytes, sha256, signature,
		       signing_key_id, signature_algorithm, compression, media_type, encryption_algorithm, recipient_key_id, created_at
		FROM configuration_artifacts WHERE config_version_id=$1`, result.ConfigVersion.ID, uuid.New()); err == nil {
		t.Fatal("artifact insertion after publication was accepted")
	}

	otherScopeID, _ := seedEdgeScope(t, pool)
	otherConfig := testConfigRequest(t, otherScopeID, "other-scope-config", "artifact-key-primary", publicKey, privateKey, []byte("other scope"))
	otherResult, err := store.PersistReleasableConfig(context.Background(), otherConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO node_config_state (
			node_id, configuration_scope_id, current_config_version_id, revision, updated_at
		) VALUES ($1, $2, $3, 1, $4)`, nodeID, scopeID, otherResult.ConfigVersion.ID, integrationClock); err == nil {
		t.Fatal("cross-scope current config version was accepted")
	}
}

func TestCreateRolloutSemanticsConcurrencyAndAttempts(t *testing.T) {
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
	configV1 := persistTestConfig(t, store, testConfigRequest(t, scopeID, "config-v1", "rollout-key", publicKey, privateKey, []byte("config v1")))
	configV2 := persistTestConfig(t, store, testConfigRequest(t, scopeID, "config-v2", "rollout-key", publicKey, privateKey, []byte("config v2")))

	applyNode, replayConflictNode := uuid.New(), uuid.New()
	rollbackNode, badRollbackNode := uuid.New(), uuid.New()
	concurrentReplayNode, competingNode := uuid.New(), uuid.New()
	for _, nodeID := range []uuid.UUID{applyNode, replayConflictNode, rollbackNode, badRollbackNode, concurrentReplayNode, competingNode} {
		seedEdgeNode(t, pool, scopeID, userID, nodeID)
	}
	seedNodeConfigState(t, pool, applyNode, scopeID, &configV1.ID, nil)
	applyRequest := testRolloutRequest(scopeID, configV2.ID, []uuid.UUID{applyNode}, "apply-v2")
	applyResult, err := store.CreateRollout(context.Background(), applyRequest)
	if err != nil {
		t.Fatal(err)
	}
	applyDeployment := applyResult.Rollout.Deployments[0]
	if applyDeployment.Command.PreviousConfigVersionId == nil ||
		*applyDeployment.Command.PreviousConfigVersionId != configV1.ID.String() || len(applyDeployment.Command.Artifacts) != 1 {
		t.Fatalf("APPLY command did not derive previous/artifacts: %+v", applyDeployment.Command)
	}
	reencoded, err := marshalDeploymentCommand(applyDeployment.Command)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, applyDeployment.CommandBytes) {
		t.Fatal("stored command is not the deterministic protobuf encoding")
	}
	var outboxPayload, deploymentPayload []byte
	if err := pool.QueryRow(context.Background(), `
		SELECT outbox.payload, deployment.command_bytes
		FROM edge_command_outbox outbox
		JOIN node_deployments deployment
		  ON deployment.id=outbox.deployment_id AND deployment.attempt=outbox.deployment_attempt
		WHERE deployment.id=$1 AND deployment.attempt=1`, applyDeployment.ID).Scan(&outboxPayload, &deploymentPayload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(outboxPayload, applyDeployment.CommandBytes) || !bytes.Equal(deploymentPayload, applyDeployment.CommandBytes) ||
		applyDeployment.Subject != "cdnca.agent.commands."+applyNode.String() {
		t.Fatal("deployment and outbox did not preserve exact command bytes or subject")
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE node_deployments SET command_bytes='changed' WHERE id=$1 AND attempt=1`, applyDeployment.ID); err == nil {
		t.Fatal("node deployment command mutation was accepted")
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE edge_command_outbox SET payload='changed' WHERE deployment_id=$1 AND deployment_attempt=1`, applyDeployment.ID); err == nil {
		t.Fatal("outbox payload mutation was accepted")
	}
	if _, err := pool.Exec(context.Background(), `
		DELETE FROM node_deployment_artifacts WHERE deployment_id=$1 AND deployment_attempt=1`, applyDeployment.ID); err == nil {
		t.Fatal("deployment artifact binding deletion was accepted")
	}
	replay, err := store.CreateRollout(context.Background(), applyRequest)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed || replay.Rollout.ID != applyResult.Rollout.ID ||
		!bytes.Equal(replay.Rollout.Deployments[0].CommandBytes, applyDeployment.CommandBytes) {
		t.Fatalf("rollout replay = %+v", replay)
	}
	conflict := applyRequest
	conflict.NodeIDs = []uuid.UUID{replayConflictNode}
	if _, err := store.CreateRollout(context.Background(), conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("rollout idempotency conflict error = %v", err)
	}

	seedNodeConfigState(t, pool, rollbackNode, scopeID, &configV2.ID, &configV1.ID)
	rollbackRequest := testRolloutRequest(scopeID, configV1.ID, []uuid.UUID{rollbackNode}, "rollback-v1")
	rollbackRequest.Action = agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK
	rollbackResult, err := store.CreateRollout(context.Background(), rollbackRequest)
	if err != nil {
		t.Fatal(err)
	}
	rollbackCommand := rollbackResult.Rollout.Deployments[0].Command
	if rollbackCommand.PreviousConfigVersionId == nil || *rollbackCommand.PreviousConfigVersionId != configV2.ID.String() || len(rollbackCommand.Artifacts) != 0 {
		t.Fatalf("ROLLBACK command did not derive current baseline or omit artifacts: %+v", rollbackCommand)
	}
	var rollbackBindings int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM node_deployment_artifacts WHERE deployment_id=$1 AND deployment_attempt=1`,
		rollbackResult.Rollout.Deployments[0].ID).Scan(&rollbackBindings); err != nil || rollbackBindings != 0 {
		t.Fatalf("rollback artifact bindings = %d, %v", rollbackBindings, err)
	}
	seedNodeConfigState(t, pool, badRollbackNode, scopeID, &configV2.ID, nil)
	badRollback := testRolloutRequest(scopeID, configV1.ID, []uuid.UUID{badRollbackNode}, "bad-rollback")
	badRollback.Action = agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK
	if _, err := store.CreateRollout(context.Background(), badRollback); !errors.Is(err, ErrRollbackStateConflict) {
		t.Fatalf("invalid rollback error = %v", err)
	}

	concurrentRequest := testRolloutRequest(scopeID, configV2.ID, []uuid.UUID{concurrentReplayNode}, "concurrent-replay")
	results, errs := runConcurrentRollouts(store, concurrentRequest, concurrentRequest)
	if errs[0] != nil || errs[1] != nil || results[0].Rollout.ID != results[1].Rollout.ID || results[0].Replayed == results[1].Replayed {
		t.Fatalf("concurrent replay results = %+v errors = %v", results, errs)
	}
	competingA := testRolloutRequest(scopeID, configV2.ID, []uuid.UUID{competingNode}, "competing-a")
	competingB := testRolloutRequest(scopeID, configV2.ID, []uuid.UUID{competingNode}, "competing-b")
	competingResults, competingErrors := runConcurrentRollouts(store, competingA, competingB)
	_ = competingResults
	successes, activeConflicts := 0, 0
	for _, err := range competingErrors {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrNodeDeploymentActive) {
			activeConflicts++
		} else {
			t.Fatalf("unexpected competing rollout error: %v", err)
		}
	}
	if successes != 1 || activeConflicts != 1 {
		t.Fatalf("competing rollout outcomes: successes=%d active_conflicts=%d", successes, activeConflicts)
	}

	for index, state := range []string{"delivered", "failed"} {
		if _, err := pool.Exec(context.Background(), `
			UPDATE node_deployments SET state=$2,updated_at=$3 WHERE id=$1 AND attempt=1`,
			applyDeployment.ID, state, integrationClock.Add(time.Duration(index+1)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	retryBytes := []byte("attempt-2-command")
	retryDigest := sha256.Sum256(retryBytes)
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO node_deployments (
			id, rollout_id, node_id, attempt, config_version_id, previous_config_version_id,
			action, state, command_event_id, command_bytes, command_sha256, deadline_at, created_at, updated_at
		)
		SELECT id, rollout_id, node_id, 2, config_version_id, previous_config_version_id,
		       action, 'queued', $2, $3, $4, deadline_at, $5, $5
		FROM node_deployments WHERE id=$1 AND attempt=1`,
		applyDeployment.ID, uuid.New(), retryBytes, retryDigest[:], integrationClock.Add(2*time.Second)); err != nil {
		t.Fatalf("append deployment attempt 2: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO edge_command_outbox (
			id, deployment_id, deployment_attempt, node_id, subject, payload, payload_sha256,
			status, available_at, created_at, updated_at
		)
		VALUES ($1, $2, 2, $3, $4, $5, $6, 'pending', $7, $7, $7)`,
		uuid.New(), applyDeployment.ID, applyNode, applyDeployment.Subject, retryBytes, retryDigest[:], integrationClock.Add(2*time.Second)); err != nil {
		t.Fatalf("append outbox attempt 2: %v", err)
	}
	var attempts, outboxRows int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM node_deployments WHERE id=$1`, applyDeployment.ID).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM edge_command_outbox WHERE deployment_id=$1`, applyDeployment.ID).Scan(&outboxRows); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || outboxRows != 2 {
		t.Fatalf("attempt history was overwritten: deployments=%d outbox=%d", attempts, outboxRows)
	}
}

func TestPlatformNodeConfigurationScopeBindingIsExclusive(t *testing.T) {
	pool := openEdgeTestDatabase(t, true)
	store, err := NewStoreWithClock(pool, func() time.Time { return integrationClock })
	if err != nil {
		t.Fatal(err)
	}
	firstScopeID, _ := seedEdgeScope(t, pool)
	secondScopeID, _ := seedEdgeScope(t, pool)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	firstConfig := persistTestConfig(t, store, testConfigRequest(t, firstScopeID,
		"platform-binding-first", "platform-binding-key-first", publicKey, privateKey, []byte("first")))
	secondConfig := persistTestConfig(t, store, testConfigRequest(t, firstScopeID,
		"platform-binding-second", "platform-binding-key-second", publicKey, privateKey, []byte("second")))
	otherConfig := persistTestConfig(t, store, testConfigRequest(t, secondScopeID,
		"platform-binding-other", "platform-binding-key-other", publicKey, privateKey, []byte("other")))

	platformScopeID, platformUserID := seedEdgePlatformIdentity(t, pool)
	nodeID := uuid.New()
	seedEdgePlatformNode(t, pool, platformScopeID, platformUserID, nodeID)
	first, err := store.CreateRollout(context.Background(), testRolloutRequest(firstScopeID, firstConfig.ID,
		[]uuid.UUID{nodeID}, "platform-binding-first"))
	if err != nil {
		t.Fatal(err)
	}
	var storedNodeScopeID, storedConfigurationScopeID uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		SELECT node.scope_id,state.configuration_scope_id
		FROM nodes node JOIN node_config_state state ON state.node_id=node.id
		WHERE node.id=$1`, nodeID).Scan(&storedNodeScopeID, &storedConfigurationScopeID); err != nil {
		t.Fatal(err)
	}
	if storedNodeScopeID != platformScopeID || storedConfigurationScopeID != firstScopeID {
		t.Fatalf("platform node scope=%s configuration scope=%s", storedNodeScopeID, storedConfigurationScopeID)
	}
	for index, state := range []string{"delivered", "failed"} {
		if _, err := pool.Exec(context.Background(), `
			UPDATE node_deployments SET state=$2,updated_at=$3 WHERE id=$1 AND attempt=1`,
			first.Rollout.Deployments[0].ID, state, integrationClock.Add(time.Duration(index+1)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	second, err := store.CreateRollout(context.Background(), testRolloutRequest(firstScopeID, secondConfig.ID,
		[]uuid.UUID{nodeID}, "platform-binding-second"))
	if err != nil {
		t.Fatal(err)
	}
	for index, state := range []string{"delivered", "failed"} {
		if _, err := pool.Exec(context.Background(), `
			UPDATE node_deployments SET state=$2,updated_at=$3 WHERE id=$1 AND attempt=1`,
			second.Rollout.Deployments[0].ID, state, integrationClock.Add(time.Duration(index+3)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.CreateRollout(context.Background(), testRolloutRequest(secondScopeID, otherConfig.ID,
		[]uuid.UUID{nodeID}, "platform-binding-cross-tenant")); !errors.Is(err, ErrConfigurationScopeConflict) {
		t.Fatalf("cross-tenant platform node rollout=%v", err)
	}

	concurrentNodeID := uuid.New()
	seedEdgePlatformNode(t, pool, platformScopeID, platformUserID, concurrentNodeID)
	results, errs := runConcurrentRollouts(store,
		testRolloutRequest(firstScopeID, firstConfig.ID, []uuid.UUID{concurrentNodeID}, "platform-binding-race-first"),
		testRolloutRequest(secondScopeID, otherConfig.ID, []uuid.UUID{concurrentNodeID}, "platform-binding-race-second"))
	succeeded, conflicted := 0, 0
	var winnerScopeID uuid.UUID
	for index, err := range errs {
		switch {
		case err == nil:
			succeeded++
			if index == 0 {
				winnerScopeID = firstScopeID
			} else {
				winnerScopeID = secondScopeID
			}
		case errors.Is(err, ErrConfigurationScopeConflict):
			conflicted++
		default:
			t.Fatalf("concurrent platform binding results=%+v errors=%v", results, errs)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent platform binding success=%d conflict=%d results=%+v errors=%v", succeeded, conflicted, results, errs)
	}
	if err := pool.QueryRow(context.Background(), `
		SELECT configuration_scope_id FROM node_config_state WHERE node_id=$1`, concurrentNodeID).Scan(&storedConfigurationScopeID); err != nil {
		t.Fatal(err)
	}
	if storedConfigurationScopeID != winnerScopeID {
		t.Fatalf("concurrent platform binding scope=%s want=%s", storedConfigurationScopeID, winnerScopeID)
	}
}

// The whole site runtime bundle is retired: persisting one (encrypted per
// node as before) is refused and leaves no config row.
func TestSiteRuntimeV2BundlePersistRefused(t *testing.T) {
	pool := openEdgeTestDatabase(t, true)
	store, err := NewStoreWithClock(pool, func() time.Time { return integrationClock })
	if err != nil {
		t.Fatal(err)
	}
	scopeID, _ := seedEdgeScope(t, pool)
	configID := uuid.New()
	artifact, canonical := testSiteRuntimeV2Artifact(t, scopeID, configID, testSiteRuntimeV2Capabilities())
	recipient := "x25519:" + strings.Repeat("1", 64)
	artifact.EncryptionAlgorithm = agentv1.ArtifactEncryptionAlgorithm_ARTIFACT_ENCRYPTION_ALGORITHM_HPKE_X25519_HKDF_SHA256_AES_256_GCM
	artifact.RecipientKeyID = &recipient
	request := PersistConfigRequest{
		ConfigurationScopeID: scopeID, CanonicalSnapshot: canonical,
		GeneratorName: "site-runtime-v2", GeneratorVersion: "2", Artifacts: []ArtifactInput{artifact},
		IdempotencyKey: "site-runtime-v2-bundle-refused",
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, persistErr := store.PersistReleasableConfigTx(t.Context(), tx, configID, request)
	_ = tx.Rollback(t.Context())
	if !errors.Is(persistErr, ErrInvalidInput) {
		t.Fatalf("site runtime bundle persist error = %v, want ErrInvalidInput", persistErr)
	}
	var configs int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM config_versions WHERE id=$1`, configID).Scan(&configs); err != nil || configs != 0 {
		t.Fatalf("refused bundle left %d config rows: %v", configs, err)
	}
}

func TestSiteRuntimeV2MissingCapabilityRollsBackAllRows(t *testing.T) {
	pool := openEdgeTestDatabase(t, true)
	store, err := NewStoreWithClock(pool, func() time.Time { return integrationClock })
	if err != nil {
		t.Fatal(err)
	}
	scopeID, userID := seedEdgeScope(t, pool)
	fullCapabilities := testSiteRuntimeV2Capabilities()
	withoutSiteRuntime := fullCapabilities[:len(fullCapabilities)-1]
	tests := []struct {
		name              string
		key               string
		innerCapabilities []*agentv1.Capability
		outerCapabilities []*agentv1.Capability
	}{
		{name: "inner missing", key: "site-runtime-v2-inner-missing", innerCapabilities: withoutSiteRuntime, outerCapabilities: fullCapabilities},
		{name: "outer missing", key: "site-runtime-v2-outer-missing", innerCapabilities: fullCapabilities, outerCapabilities: withoutSiteRuntime},
		{name: "both missing", key: "site-runtime-v2-both-missing", innerCapabilities: withoutSiteRuntime, outerCapabilities: withoutSiteRuntime},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nodeID, configID := uuid.New(), uuid.New()
			seedEdgeNode(t, pool, scopeID, userID, nodeID)
			artifact, canonical := testSiteRuntimeV2Artifact(t, scopeID, configID, test.innerCapabilities)
			request := PersistConfigRequest{
				ConfigurationScopeID: scopeID, CanonicalSnapshot: canonical,
				GeneratorName: "site-runtime-v2", GeneratorVersion: "2", Artifacts: []ArtifactInput{artifact},
				IdempotencyKey: test.key,
			}
			tx, err := pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			_, operationErr := store.PersistReleasableConfigTx(t.Context(), tx, configID, request)
			if operationErr == nil {
				rolloutRequest := testRolloutRequest(scopeID, configID, []uuid.UUID{nodeID}, test.key)
				rolloutRequest.RequiredCapabilities = test.outerCapabilities
				_, operationErr = store.CreateRolloutTx(t.Context(), tx, rolloutRequest)
			}
			if !errors.Is(operationErr, ErrInvalidInput) {
				_ = tx.Rollback(t.Context())
				t.Fatalf("operation error = %v, want ErrInvalidInput", operationErr)
			}
			if err := tx.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			var configs, rollouts, deployments, outbox int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM config_versions WHERE id=$1`, configID).Scan(&configs); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM rollouts WHERE idempotency_key=$1`, test.key).Scan(&rollouts); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_deployments WHERE node_id=$1`, nodeID).Scan(&deployments); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_command_outbox WHERE node_id=$1`, nodeID).Scan(&outbox); err != nil {
				t.Fatal(err)
			}
			if configs != 0 || rollouts != 0 || deployments != 0 || outbox != 0 {
				t.Fatalf("invalid S2 capability left state: configs=%d rollouts=%d deployments=%d outbox=%d", configs, rollouts, deployments, outbox)
			}
		})
	}
}

func TestCreateRolloutRollsBackEveryNodeOnLateFailure(t *testing.T) {
	pool := openEdgeTestDatabase(t, true)
	store, err := NewStoreWithClock(pool, func() time.Time { return integrationClock })
	if err != nil {
		t.Fatal(err)
	}
	scopeID, userID := seedEdgeScope(t, pool)
	otherScopeID, otherUserID := seedEdgeScope(t, pool)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := persistTestConfig(t, store, testConfigRequest(t, scopeID, "atomic-config", "atomic-key", publicKey, privateKey, []byte("atomic")))
	goodNode := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	badNode := uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")
	seedEdgeNode(t, pool, scopeID, userID, goodNode)
	seedEdgeNode(t, pool, otherScopeID, otherUserID, badNode)
	request := testRolloutRequest(scopeID, config.ID, []uuid.UUID{badNode, goodNode}, "atomic-rollout")
	if _, err := store.CreateRollout(context.Background(), request); !errors.Is(err, ErrConfigurationScopeConflict) {
		t.Fatalf("late scope conflict error = %v", err)
	}
	var rollouts, deployments, outbox, state int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM rollouts WHERE idempotency_key='atomic-rollout'`).Scan(&rollouts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM node_deployments`).Scan(&deployments); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM edge_command_outbox`).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM node_config_state WHERE node_id=$1`, goodNode).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if rollouts != 0 || deployments != 0 || outbox != 0 || state != 0 {
		t.Fatalf("late failure left partial state: rollout=%d deployment=%d outbox=%d node_state=%d", rollouts, deployments, outbox, state)
	}
}

func TestCallerTransactionAPIsCommitReplayAndRollback(t *testing.T) {
	pool := openEdgeTestDatabase(t, true)
	store, err := NewStoreWithClock(pool, func() time.Time { return integrationClock })
	if err != nil {
		t.Fatal(err)
	}
	scopeID, userID := seedEdgeScope(t, pool)
	nodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, nodeID)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	committedConfigID := uuid.New()
	committedConfigRequest := testConfigRequest(t, scopeID, "caller-tx-config", "caller-tx-key", publicKey, privateKey, []byte("caller tx config"))
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	configResult, err := store.PersistReleasableConfigTx(context.Background(), tx, committedConfigID, committedConfigRequest)
	if err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	rolloutRequest := testRolloutRequest(scopeID, committedConfigID, []uuid.UUID{nodeID}, "caller-tx-rollout")
	rolloutResult, err := store.CreateRolloutTx(context.Background(), tx, rolloutRequest)
	if err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if configResult.ConfigVersion.ID != committedConfigID {
		t.Fatalf("caller config ID = %s, want %s", configResult.ConfigVersion.ID, committedConfigID)
	}
	configReplay, err := store.PersistReleasableConfig(context.Background(), committedConfigRequest)
	if err != nil || !configReplay.Replayed || configReplay.ConfigVersion.ID != committedConfigID {
		t.Fatalf("config replay = %+v, %v", configReplay, err)
	}
	rolloutReplay, err := store.CreateRollout(context.Background(), rolloutRequest)
	if err != nil || !rolloutReplay.Replayed || rolloutReplay.Rollout.ID != rolloutResult.Rollout.ID {
		t.Fatalf("rollout replay = %+v, %v", rolloutReplay, err)
	}

	rollbackNodeID := uuid.New()
	seedEdgeNode(t, pool, scopeID, userID, rollbackNodeID)
	rolledBackConfigID := uuid.New()
	rolledBackConfigRequest := testConfigRequest(t, scopeID, "caller-tx-rollback-config", "caller-tx-key", publicKey, privateKey, []byte("rolled back config"))
	tx, err = pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PersistReleasableConfigTx(context.Background(), tx, rolledBackConfigID, rolledBackConfigRequest); err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	rolledBackRollout := testRolloutRequest(scopeID, rolledBackConfigID, []uuid.UUID{rollbackNodeID}, "caller-tx-rollback-rollout")
	if _, err := store.CreateRolloutTx(context.Background(), tx, rolledBackRollout); err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatal(err)
	}
	if err := tx.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	var configs, rollouts, deployments, outbox int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM config_versions WHERE id=$1`, rolledBackConfigID).Scan(&configs); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM rollouts WHERE idempotency_key=$1`, rolledBackRollout.IdempotencyKey).Scan(&rollouts); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM node_deployments WHERE node_id=$1`, rollbackNodeID).Scan(&deployments); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM edge_command_outbox WHERE node_id=$1`, rollbackNodeID).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if configs != 0 || rollouts != 0 || deployments != 0 || outbox != 0 {
		t.Fatalf("outer rollback left state: configs=%d rollouts=%d deployments=%d outbox=%d", configs, rollouts, deployments, outbox)
	}

	tx, err = pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := store.PersistReleasableConfigTx(context.Background(), tx, uuid.Nil, committedConfigRequest); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil caller config ID error = %v", err)
	}
}

func TestEdgeDeploymentMigrationRoundTrip(t *testing.T) {
	pool := openEdgeTestDatabase(t, false)
	ctx := context.Background()
	// Migration 268's down is a deliberate one-way gate (P2682): round-trip the
	// early edge migrations with only 1..021 loaded, then roll forward to the head.
	if err := databasetest.MigrateThrough(ctx, pool, "up", 21); err != nil {
		t.Fatal(err)
	}
	assertRegclass(t, pool, "config_versions", true)
	assertColumn(t, pool, "node_config_state", "reconciliation_required", true)
	assertRegclass(t, pool, "edge_config_publications", true)
	migrateEdgeDownToVersion(t, pool, 20)
	assertRegclass(t, pool, "edge_config_publications", false)
	assertColumn(t, pool, "node_config_state", "reconciliation_required", true)
	migrateEdgeDownToVersion(t, pool, 19)
	assertColumn(t, pool, "node_config_state", "reconciliation_required", false)
	migrateEdgeDownToVersion(t, pool, 18)
	migrateEdgeDownToVersion(t, pool, 17)
	assertRegclass(t, pool, "config_versions", false)
	assertColumn(t, pool, "node_presence", "agent_version", true)
	migrateEdgeDownToVersion(t, pool, 16)
	assertColumn(t, pool, "node_presence", "agent_version", false)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	assertColumn(t, pool, "node_presence", "agent_version", true)
	assertRegclass(t, pool, "config_versions", true)
	assertColumn(t, pool, "node_config_state", "reconciliation_required", true)
	assertRegclass(t, pool, "edge_config_publications", true)
}

func runConcurrentRollouts(store *Store, requests ...CreateRolloutRequest) ([]CreateRolloutResult, []error) {
	results := make([]CreateRolloutResult, len(requests))
	errs := make([]error, len(requests))
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range requests {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			results[index], errs[index] = store.CreateRollout(context.Background(), requests[index])
		}(index)
	}
	close(start)
	wait.Wait()
	return results, errs
}

func testConfigRequest(
	t *testing.T,
	scopeID uuid.UUID,
	idempotencyKey, signingKeyID string,
	publicKey ed25519.PublicKey,
	privateKey ed25519.PrivateKey,
	wire []byte,
) PersistConfigRequest {
	t.Helper()
	return PersistConfigRequest{
		ConfigurationScopeID: scopeID, CanonicalSnapshot: []byte(`{"version":"` + idempotencyKey + `"}`),
		GeneratorName: "integration-generator", GeneratorVersion: "1.0.0", IdempotencyKey: idempotencyKey,
		Artifacts: []ArtifactInput{validArtifactInput(t, uuid.New(), signingKeyID, publicKey, privateKey, wire)},
	}
}

func persistTestConfig(t *testing.T, store *Store, request PersistConfigRequest) ConfigVersion {
	t.Helper()
	result, err := store.PersistReleasableConfig(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	return result.ConfigVersion
}

func testRolloutRequest(scopeID, configID uuid.UUID, nodeIDs []uuid.UUID, key string) CreateRolloutRequest {
	return CreateRolloutRequest{
		ConfigurationScopeID: scopeID, ConfigVersionID: configID,
		Action: agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY, NodeIDs: nodeIDs,
		RequiredCapabilities: []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_ATOMIC_RELEASE, ApiVersion: 1}},
		HealthCheck:          HealthCheckPolicy{ActivationTimeout: time.Minute, ObservationWindow: 5 * time.Second, RequiredConsecutiveSuccesses: 2},
		Deadline:             integrationClock.Add(time.Hour), IdempotencyKey: key,
		RequestID: uuid.NewString(), CorrelationID: uuid.NewString(), Traceparent: "",
	}
}

func seedNodeConfigState(t *testing.T, pool *pgxpool.Pool, nodeID, scopeID uuid.UUID, current, previous *uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO node_config_state (
			node_id, configuration_scope_id, current_config_version_id, previous_config_version_id, revision, updated_at
		) VALUES ($1, $2, $3, $4, 1, $5)`, nodeID, scopeID, current, previous, integrationClock); err != nil {
		t.Fatal(err)
	}
}

func seedEdgeScope(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	username := "edge-" + strings.ReplaceAll(userID.String(), "-", "")[:20]
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `INSERT INTO tenants (id, display_name) VALUES ($1, 'Edge deployment tenant')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1, 'tenant', $2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO users (id, username, display_name, password_hash)
		VALUES ($1, $2, 'Edge deployment user', 'not-used')`, userID, username); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return scopeID, userID
}

func seedEdgePlatformIdentity(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	scopeID, userID := uuid.New(), uuid.New()
	username := "edge-platform-" + strings.ReplaceAll(userID.String(), "-", "")[:16]
	if _, err := pool.Exec(context.Background(), `
		WITH scope AS (
			INSERT INTO access_scopes (id,kind) VALUES ($1,'platform')
		)
		INSERT INTO users (id,username,display_name,password_hash)
		VALUES ($2,$3,'Edge deployment platform owner','not-used')`, scopeID, userID, username); err != nil {
		t.Fatal(err)
	}
	return scopeID, userID
}

func seedEdgePlatformNode(t *testing.T, pool *pgxpool.Pool, scopeID, userID, nodeID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		WITH allocated AS (
			INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at)
			VALUES($2,2,$5)
			ON CONFLICT(scope_id) DO UPDATE SET
				next_value=node_display_id_sequences.next_value+1,
				updated_at=EXCLUDED.updated_at
			RETURNING next_value-1 AS display_id
		)
		INSERT INTO nodes (id,display_id,scope_id,name,admin_state,created_by_user_id)
		SELECT $1,allocated.display_id,$2,$3,'active',$4 FROM allocated`, nodeID, scopeID,
		"edge-platform-node-"+strings.ReplaceAll(nodeID.String(), "-", "")[:12], userID, integrationClock); err != nil {
		t.Fatal(err)
	}
}

func seedEdgeNode(t *testing.T, pool *pgxpool.Pool, scopeID, userID, nodeID uuid.UUID) {
	t.Helper()
	name := "edge-node-" + strings.ReplaceAll(nodeID.String(), "-", "")[:12]
	var displayIDs bool
	if err := pool.QueryRow(context.Background(),
		`SELECT to_regclass('node_display_id_sequences') IS NOT NULL`).Scan(&displayIDs); err != nil {
		t.Fatal(err)
	}
	if displayIDs {
		// From migration 211 on, nodes carry a per-scope display_id.
		if _, err := pool.Exec(context.Background(), `
			WITH allocated AS (
				INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at)
				VALUES($2,2,$5)
				ON CONFLICT(scope_id) DO UPDATE SET
					next_value=node_display_id_sequences.next_value+1,
					updated_at=EXCLUDED.updated_at
				RETURNING next_value-1 AS display_id
			)
			INSERT INTO nodes (id,display_id,scope_id,name,admin_state,created_by_user_id)
			SELECT $1,allocated.display_id,$2,$3,'active',$4 FROM allocated`,
			nodeID, scopeID, name, userID, integrationClock); err != nil {
			t.Fatal(err)
		}
		return
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO nodes (id, scope_id, name, admin_state, created_by_user_id)
		VALUES ($1, $2, $3, 'active', $4)`, nodeID, scopeID, name, userID); err != nil {
		t.Fatal(err)
	}
}

// openEdgeTestDatabase returns an empty schema, or with migrate a schema at
// the release head (a clone of TEST_DATABASE_TEMPLATE when it is set).
func openEdgeTestDatabase(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if migrate {
		if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
			return pool
		}
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "edge_deployment_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^edge_deployment_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema name %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop edge deployment schema: %v", err)
		}
		admin.Close()
	})
	if migrate {
		if err := database.Migrate(ctx, pool, "up"); err != nil {
			t.Fatal(err)
		}
	}
	return pool
}

func currentMigrationVersion(t *testing.T, pool *pgxpool.Pool) int64 {
	t.Helper()
	var version int64
	if err := pool.QueryRow(context.Background(), `SELECT COALESCE(max(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func migrateEdgeDownToVersion(t *testing.T, pool *pgxpool.Pool, target int64) {
	t.Helper()
	current := currentMigrationVersion(t, pool)
	if current < target {
		t.Fatalf("cannot migrate down from version %d to %d", current, target)
	}
	for current > target {
		// Load only 1..current so the rollback never needs a version above 268.
		if err := databasetest.MigrateThrough(context.Background(), pool, "down", current); err != nil {
			t.Fatalf("migrate down from version %d: %v", current, err)
		}
		next := currentMigrationVersion(t, pool)
		if next >= current {
			t.Fatalf("migration down did not advance: before=%d after=%d", current, next)
		}
		current = next
	}
	if current != target {
		t.Fatalf("migration version = %d, want %d", current, target)
	}
}

func assertRegclass(t *testing.T, pool *pgxpool.Pool, name string, expected bool) {
	t.Helper()
	var actual bool
	if err := pool.QueryRow(context.Background(), `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("%s exists = %t, want %t", name, actual, expected)
	}
}

func assertColumn(t *testing.T, pool *pgxpool.Pool, table, column string, expected bool) {
	t.Helper()
	var actual bool
	if err := pool.QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2
		)`, table, column).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("%s.%s exists = %t, want %t", table, column, actual, expected)
	}
}
