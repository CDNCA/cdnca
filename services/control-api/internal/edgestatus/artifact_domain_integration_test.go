//go:build integration

package edgestatus

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

func TestDeploymentStatusProjectsOnlyConfigurationArtifactsIntoNodeConfigState(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	pool, adminPool, schema := openStatusTestDatabase(t, databaseURL)
	defer pool.Close()
	defer adminPool.Close()
	defer func() {
		if _, err := adminPool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop integration schema: %v", err)
		}
	}()
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}

	prefix := "cdnca.integration.artifact-domain.deployment-status"
	validatorConfig := DefaultValidatorConfig()
	validatorConfig.SubjectPrefix = prefix
	validator, err := NewValidator(validatorConfig)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("configuration healthy advances running config", func(t *testing.T) {
		fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
		projectStatusPath(t, store, validator, prefix, fixture,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		)
		assertNodeConfig(t, pool, fixture.nodeID, fixture.configID, fixture.previousConfigID)
	})

	t.Run("configuration healthy cannot forge a capability-only identity", func(t *testing.T) {
		fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
		projectStatusPath(t, store, validator, prefix, fixture,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
		)
		terminal := fixtureStatus(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5)
		terminal.ActiveConfigIdentityCapability = statusIdentityCapability()
		envelope, err := validator.Decode(prefix+"."+fixture.nodeID.String(), marshalStatus(t, terminal))
		if err != nil {
			t.Fatalf("validator rejected status before authoritative artifact-domain check: %v", err)
		}
		if result, err := store.Project(t.Context(), envelope); !errors.Is(err, ErrBindingConflict) || result != (ProjectionResult{}) {
			t.Fatalf("configuration capability-only identity = (%+v, %v)", result, err)
		}
		assertDeploymentState(t, pool, fixture.deploymentID, "activated", 4)
	})

	t.Run("configuration rollback failed requests config reconciliation", func(t *testing.T) {
		fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
		states := []agentv1.NodeDeploymentState{
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTING,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED,
		}
		for index, state := range states {
			status := fixtureStatus(fixture, state, uint64(index+1))
			if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED {
				status.Error = validProtocolError()
			}
			projectFixtureStatus(t, store, validator, prefix, fixture, status)
		}
		assertNodeConfig(t, pool, fixture.nodeID, fixture.previousConfigID, uuid.Nil)
		assertReconciliationRequired(t, pool, fixture)
	})

	t.Run("secret healthy leaves running config unchanged", func(t *testing.T) {
		fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
		replaceDeploymentArtifacts(t, pool, fixture, "node_secret_bundle")
		var terminal *agentv1.DeploymentStatus
		states := []agentv1.NodeDeploymentState{
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		}
		for index, state := range states {
			status := fixtureStatus(fixture, state, uint64(index+1))
			if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
				status.ActiveConfigIdentityCapability = statusIdentityCapability()
				terminal = status
			}
			projectFixtureStatus(t, store, validator, prefix, fixture, status)
		}
		envelope := decodeFixtureStatus(t, validator, prefix, fixture.nodeID, terminal)
		if result, err := store.Project(t.Context(), envelope); err != nil || result.Outcome != OutcomeDuplicate {
			t.Fatalf("certificate status replay = (%+v, %v)", result, err)
		}
		conflict := proto.Clone(terminal).(*agentv1.DeploymentStatus)
		conflict.Checks = []*agentv1.CheckResult{{Name: "certificate", Summary: "conflicting terminal payload"}}
		if result, err := store.Project(t.Context(), decodeFixtureStatus(t, validator, prefix, fixture.nodeID, conflict)); !errors.Is(err, ErrPayloadConflict) || result != (ProjectionResult{}) {
			t.Fatalf("certificate status event conflict = (%+v, %v)", result, err)
		}
		assertNodeConfigProjection(t, pool, fixture, false)
		assertDeploymentState(t, pool, fixture.deploymentID, "healthy", len(states))
	})

	t.Run("secret reverted leaves running config unchanged", func(t *testing.T) {
		fixture := seedDeployment(t, pool, "rollback", uuid.Nil, uuid.Nil)
		replaceDeploymentArtifacts(t, pool, fixture, "node_secret_bundle")
		removeDeploymentArtifactBindings(t, pool, fixture)
		projectStatusPath(t, store, validator, prefix, fixture,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTING,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED,
		)
		assertNodeConfigProjection(t, pool, fixture, false)
	})

	t.Run("secret rollback failed does not request config reconciliation", func(t *testing.T) {
		fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
		replaceDeploymentArtifacts(t, pool, fixture, "node_secret_bundle")
		states := []agentv1.NodeDeploymentState{
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTING,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED,
		}
		for index, state := range states {
			status := fixtureStatus(fixture, state, uint64(index+1))
			if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED {
				status.Error = validProtocolError()
			}
			projectFixtureStatus(t, store, validator, prefix, fixture, status)
		}
		assertDeploymentState(t, pool, fixture.deploymentID, "rollback_failed", len(states))
		assertNodeConfigProjection(t, pool, fixture, false)
	})

	t.Run("secret deployment does not require or create node config state", func(t *testing.T) {
		fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
		replaceDeploymentArtifacts(t, pool, fixture, "node_secret_bundle")
		if _, err := pool.Exec(ctx, `DELETE FROM node_config_state WHERE node_id=$1`, fixture.nodeID); err != nil {
			t.Fatal(err)
		}
		projectStatusPath(t, store, validator, prefix, fixture,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		)
		assertDeploymentState(t, pool, fixture.deploymentID, "healthy", 5)
		var count int
		if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM node_config_state WHERE node_id=$1`, fixture.nodeID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("node config state rows = %d, want 0", count)
		}
	})

	t.Run("unsupported artifact domains fail before journal mutation", func(t *testing.T) {
		cases := []struct {
			name  string
			kinds []string
		}{
			{name: "empty"},
			{name: "mixed", kinds: []string{"configuration", "node_secret_bundle"}},
			{name: "unknown", kinds: []string{"future_secret_bundle"}},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
				if testCase.name == "unknown" {
					dropArtifactKindConstraints(t, pool)
				}
				replaceDeploymentArtifacts(t, pool, fixture, testCase.kinds...)
				status := fixtureStatus(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
				_, err := store.Project(ctx, decodeFixtureStatus(t, validator, prefix, fixture.nodeID, status))
				if !errors.Is(err, ErrProjectionConflict) {
					t.Fatalf("project %s artifact domain error = %v", testCase.name, err)
				}
				assertDeploymentState(t, pool, fixture.deploymentID, "queued", 0)
				assertNodeConfigProjection(t, pool, fixture, false)
			})
		}
	})
}

func removeDeploymentArtifactBindings(t *testing.T, pool *pgxpool.Pool, fixture deploymentFixture) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `ALTER TABLE node_deployment_artifacts DISABLE TRIGGER node_deployment_artifacts_immutable, DISABLE TRIGGER node_deployment_artifacts_immutable_del`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM node_deployment_artifacts WHERE deployment_id=$1`, fixture.deploymentID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE node_deployment_artifacts ENABLE TRIGGER node_deployment_artifacts_immutable, ENABLE TRIGGER node_deployment_artifacts_immutable_del`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func projectStatusPath(t *testing.T, store *Store, validator *Validator, prefix string,
	fixture deploymentFixture, states ...agentv1.NodeDeploymentState,
) {
	t.Helper()
	for index, state := range states {
		projectFixtureState(t, store, validator, prefix, fixture, state, uint64(index+1))
	}
}

func replaceDeploymentArtifacts(t *testing.T, pool *pgxpool.Pool, fixture deploymentFixture, kinds ...string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `ALTER TABLE node_deployment_artifacts DISABLE TRIGGER node_deployment_artifacts_immutable, DISABLE TRIGGER node_deployment_artifacts_immutable_del`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM node_deployment_artifacts WHERE deployment_id=$1`, fixture.deploymentID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE node_deployment_artifacts ENABLE TRIGGER node_deployment_artifacts_immutable, ENABLE TRIGGER node_deployment_artifacts_immutable_del`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE configuration_artifacts DISABLE TRIGGER configuration_artifacts_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM configuration_artifacts WHERE config_version_id=$1`, fixture.configID); err != nil {
		t.Fatal(err)
	}
	signingKeyID := "edge-status-" + strings.ReplaceAll(fixture.configID.String(), "-", "")
	for index, kind := range kinds {
		artifactID := uuid.New()
		wireBytes := []byte(kind + ":" + artifactID.String())
		encryption := "none"
		var recipientKeyID *string
		if kind != "configuration" {
			encryption = "hpke_x25519_hkdf_sha256_aes_256_gcm"
			recipient := "x25519:" + artifactID.String()
			recipientKeyID = &recipient
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO configuration_artifacts (
				id, config_version_id, ordinal, kind, wire_bytes, size_bytes, sha256, signature,
				signing_key_id, signature_algorithm, compression, media_type, encryption_algorithm,
				recipient_key_id, created_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'ed25519', 'none', $10, $11, $12, $13)`,
			artifactID, fixture.configID, index+1, kind, wireBytes, len(wireBytes), sha256Bytes(wireBytes),
			make([]byte, 64), signingKeyID, "application/vnd.cdnca.test+json", encryption,
			recipientKeyID, time.Now().UTC().Truncate(time.Microsecond)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO node_deployment_artifacts (
				deployment_id, deployment_attempt, config_version_id, artifact_id, ordinal
			) VALUES ($1, 1, $2, $3, $4)`, fixture.deploymentID, fixture.configID, artifactID, index+1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE configuration_artifacts ENABLE TRIGGER configuration_artifacts_immutable`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func dropArtifactKindConstraints(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	// 迁移 170 把匿名的 kind/encryption 约束换成了具名的 configuration_artifacts_kind_encryption_check。
	if _, err := pool.Exec(context.Background(), `
		ALTER TABLE configuration_artifacts
			DROP CONSTRAINT configuration_artifacts_kind_check,
			DROP CONSTRAINT configuration_artifacts_kind_encryption_check`); err != nil {
		t.Fatal(err)
	}
}

func assertNodeConfigProjection(t *testing.T, pool *pgxpool.Pool, fixture deploymentFixture, wantReconciliation bool) {
	t.Helper()
	var currentID, previousID *uuid.UUID
	var revision int64
	var reconciliation bool
	var reason *string
	var reconciliationDeploymentID *uuid.UUID
	var reconciliationAttempt *int32
	var reconciliationRequestedAt *time.Time
	if err := pool.QueryRow(context.Background(), `
		SELECT current_config_version_id, previous_config_version_id, revision,
		       reconciliation_required, reconciliation_reason, reconciliation_deployment_id,
		       reconciliation_deployment_attempt, reconciliation_requested_at
		FROM node_config_state WHERE node_id=$1`, fixture.nodeID).Scan(
		&currentID, &previousID, &revision, &reconciliation, &reason, &reconciliationDeploymentID,
		&reconciliationAttempt, &reconciliationRequestedAt,
	); err != nil {
		t.Fatal(err)
	}
	if currentID == nil || *currentID != fixture.previousConfigID || previousID != nil || revision != 1 {
		t.Fatalf("node config projection = current:%v previous:%v revision:%d", currentID, previousID, revision)
	}
	if reconciliation != wantReconciliation {
		t.Fatalf("reconciliation required = %t, want %t", reconciliation, wantReconciliation)
	}
	if !wantReconciliation && (reason != nil || reconciliationDeploymentID != nil ||
		reconciliationAttempt != nil || reconciliationRequestedAt != nil) {
		t.Fatalf("unexpected reconciliation facts = reason:%v deployment:%v attempt:%v requested:%v",
			reason, reconciliationDeploymentID, reconciliationAttempt, reconciliationRequestedAt)
	}
}
