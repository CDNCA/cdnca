//go:build integration

package edgestatus

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDeploymentStatusActiveIdentityAtomicProjection(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	pool, admin, schema := openStatusTestDatabase(t, databaseURL)
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(DefaultValidatorConfig())
	if err != nil {
		t.Fatal(err)
	}

	t.Run("v1 healthy binds exact attempt artifact", func(t *testing.T) {
		fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
		digest := deploymentArtifactDigest087(t, pool, fixture)
		for sequence, state := range []agentv1.NodeDeploymentState{
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		} {
			status := fixtureStatus(fixture, state, uint64(sequence+1))
			status.ActiveConfigIdentityCapability = statusIdentityCapability()
			if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
				status.ActiveConfigIdentity = statusIdentityBytes087(fixture.configID, digest)
			}
			projectFixtureStatus(t, store, validator, DefaultSubjectPrefix, fixture, status)
		}
		assertStatusIdentity087(t, pool, fixture, digest, true)

		duplicate := fixtureStatus(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5)
		duplicate.Event.EventId = uuid.NewString()
		duplicate.ActiveConfigIdentityCapability = statusIdentityCapability()
		duplicate.ActiveConfigIdentity = statusIdentityBytes087(fixture.configID, digest)
		if _, err := store.Project(t.Context(), decodeFixtureStatus(t, validator, DefaultSubjectPrefix, fixture.nodeID, duplicate)); err == nil {
			t.Fatal("different event reused terminal sequence")
		}
	})

	t.Run("wrong wire digest is atomic", func(t *testing.T) {
		fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
		for sequence, state := range []agentv1.NodeDeploymentState{
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
		} {
			status := fixtureStatus(fixture, state, uint64(sequence+1))
			status.ActiveConfigIdentityCapability = statusIdentityCapability()
			projectFixtureStatus(t, store, validator, DefaultSubjectPrefix, fixture, status)
		}
		status := fixtureStatus(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5)
		status.ActiveConfigIdentityCapability = statusIdentityCapability()
		status.ActiveConfigIdentity = statusIdentityBytes087(fixture.configID, make([]byte, 32))
		if _, err := store.Project(t.Context(), decodeFixtureStatus(t, validator, DefaultSubjectPrefix, fixture.nodeID, status)); err == nil {
			t.Fatal("store accepted manifest/forged digest")
		}
		var state string
		var events int
		if err := pool.QueryRow(t.Context(), `SELECT state,(SELECT count(*) FROM deployment_status_events WHERE deployment_id=$1)
			FROM node_deployments WHERE id=$1 AND attempt=1`, fixture.deploymentID).Scan(&state, &events); err != nil {
			t.Fatal(err)
		}
		if state != "activated" || events != 4 {
			t.Fatalf("failed identity changed state/event atomically: %s/%d", state, events)
		}
	})

	t.Run("legacy healthy advances UUID with unknown identity", func(t *testing.T) {
		fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
		for sequence, state := range []agentv1.NodeDeploymentState{
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		} {
			projectFixtureState(t, store, validator, DefaultSubjectPrefix, fixture, state, uint64(sequence+1))
		}
		assertStatusIdentity087(t, pool, fixture, nil, false)
	})

	t.Run("real rollback without deployment artifact binding uses previously proven tuple", func(t *testing.T) {
		rollback, digest := createRealRollbackFixture087(t, pool)
		states := []agentv1.NodeDeploymentState{
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTING,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED,
		}
		for sequence, state := range states {
			status := fixtureStatus(rollback, state, uint64(sequence+1))
			status.ActiveConfigIdentityCapability = statusIdentityCapability()
			if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED {
				status.ActiveConfigIdentity = statusIdentityBytes087(rollback.configID, digest)
			}
			projectFixtureStatus(t, store, validator, DefaultSubjectPrefix, rollback, status)
		}
		assertStatusIdentity087(t, pool, rollback, digest, true)
	})

	t.Run("v1 reverted promotes UUID-only previous state to proven tuple", func(t *testing.T) {
		rollback, digest := createRealRollbackFixture087(t, pool)
		if _, err := pool.Exec(t.Context(), `UPDATE node_config_state SET
			previous_config_identity_schema=NULL,previous_config_artifact_sha256=NULL WHERE node_id=$1`,
			rollback.nodeID); err != nil {
			t.Fatal(err)
		}
		states := []agentv1.NodeDeploymentState{
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTING,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED,
		}
		for sequence, state := range states {
			status := fixtureStatus(rollback, state, uint64(sequence+1))
			status.ActiveConfigIdentityCapability = statusIdentityCapability()
			if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED {
				status.ActiveConfigIdentity = statusIdentityBytes087(rollback.configID, digest)
			}
			projectFixtureStatus(t, store, validator, DefaultSubjectPrefix, rollback, status)
		}
		assertStatusIdentity087(t, pool, rollback, digest, true)
	})

	t.Run("rollback failed preserves UUID and atomically clears proven identity", func(t *testing.T) {
		current := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
		currentDigest := deploymentArtifactDigest087(t, pool, current)
		for sequence, state := range []agentv1.NodeDeploymentState{
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		} {
			status := fixtureStatus(current, state, uint64(sequence+1))
			status.ActiveConfigIdentityCapability = statusIdentityCapability()
			if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
				status.ActiveConfigIdentity = statusIdentityBytes087(current.configID, currentDigest)
			}
			projectFixtureStatus(t, store, validator, DefaultSubjectPrefix, current, status)
		}

		nextConfig, _ := seedReleasableConfigArtifact087(t, pool, current.scopeID)
		failed := createActualDeploymentFixture087(t, pool, current.nodeID, current.scopeID, nextConfig,
			agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY)
		for sequence, state := range []agentv1.NodeDeploymentState{
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTING,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED,
		} {
			status := fixtureStatus(failed, state, uint64(sequence+1))
			status.ActiveConfigIdentityCapability = statusIdentityCapability()
			if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED {
				status.Error = validProtocolError()
			}
			projectFixtureStatus(t, store, validator, DefaultSubjectPrefix, failed, status)
		}
		var currentID uuid.UUID
		var schema *int32
		var digest []byte
		var required bool
		var sourceID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT current_config_version_id,current_config_identity_schema,
			current_config_artifact_sha256,reconciliation_required,reconciliation_deployment_id
			FROM node_config_state WHERE node_id=$1`, current.nodeID).Scan(
			&currentID, &schema, &digest, &required, &sourceID); err != nil {
			t.Fatal(err)
		}
		if currentID != current.configID || schema != nil || digest != nil || !required || sourceID != failed.deploymentID {
			t.Fatalf("rollback failed projection = current:%s schema:%v digest:%x required:%t source:%s",
				currentID, schema, digest, required, sourceID)
		}
	})

	t.Run("terminal transaction failure rolls back event state and identity", func(t *testing.T) {
		fixture := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
		digest := deploymentArtifactDigest087(t, pool, fixture)
		for sequence, state := range []agentv1.NodeDeploymentState{
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
			agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
		} {
			status := fixtureStatus(fixture, state, uint64(sequence+1))
			status.ActiveConfigIdentityCapability = statusIdentityCapability()
			projectFixtureStatus(t, store, validator, DefaultSubjectPrefix, fixture, status)
		}
		if _, err := pool.Exec(t.Context(), `CREATE FUNCTION fail_active_identity_status_087()
			RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected status advance failure'; END $$;
			CREATE TRIGGER fail_active_identity_status_087 BEFORE UPDATE OF state ON node_deployments
			FOR EACH ROW EXECUTE FUNCTION fail_active_identity_status_087()`); err != nil {
			t.Fatal(err)
		}
		status := fixtureStatus(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5)
		status.ActiveConfigIdentityCapability = statusIdentityCapability()
		status.ActiveConfigIdentity = statusIdentityBytes087(fixture.configID, digest)
		if _, err := store.Project(t.Context(), decodeFixtureStatus(t, validator, DefaultSubjectPrefix, fixture.nodeID, status)); err == nil {
			t.Fatal("injected terminal transaction failure was accepted")
		}
		if _, err := pool.Exec(t.Context(), `DROP TRIGGER fail_active_identity_status_087 ON node_deployments;
			DROP FUNCTION fail_active_identity_status_087()`); err != nil {
			t.Fatal(err)
		}
		var state string
		var events int
		var currentID uuid.UUID
		var schema *int32
		var persistedDigest []byte
		if err := pool.QueryRow(t.Context(), `SELECT deployment.state,
			(SELECT count(*) FROM deployment_status_events event WHERE event.deployment_id=deployment.id),
			config.current_config_version_id,config.current_config_identity_schema,config.current_config_artifact_sha256
			FROM node_deployments deployment JOIN node_config_state config ON config.node_id=deployment.node_id
			WHERE deployment.id=$1 AND deployment.attempt=1`, fixture.deploymentID).Scan(
			&state, &events, &currentID, &schema, &persistedDigest); err != nil {
			t.Fatal(err)
		}
		if state != "activated" || events != 4 || currentID != fixture.previousConfigID || schema != nil || persistedDigest != nil {
			t.Fatalf("failed transaction persisted partial state: %s/%d/%s/%v/%x",
				state, events, currentID, schema, persistedDigest)
		}
	})
}

func TestDeploymentStatusSameConfigApplyPreservesHistoryAndProof(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	pool, admin, schema := openStatusTestDatabase(t, databaseURL)
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := NewValidator(DefaultValidatorConfig())
	if err != nil {
		t.Fatal(err)
	}

	for _, versioned := range []bool{true, false} {
		name := "legacy"
		if versioned {
			name = "v1"
		}
		t.Run(name, func(t *testing.T) {
			initial := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
			digest := deploymentArtifactDigest087(t, pool, initial)
			for sequence, state := range []agentv1.NodeDeploymentState{
				agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
				agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
				agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
				agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
				agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
			} {
				status := fixtureStatus(initial, state, uint64(sequence+1))
				status.ActiveConfigIdentityCapability = statusIdentityCapability()
				if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY {
					status.ActiveConfigIdentity = statusIdentityBytes087(initial.configID, digest)
				}
				projectFixtureStatus(t, store, validator, DefaultSubjectPrefix, initial, status)
			}
			fixture := createActualDeploymentFixture087(t, pool, initial.nodeID, initial.scopeID, initial.configID,
				agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY)
			digest = deploymentArtifactDigest087(t, pool, fixture)
			for sequence, state := range []agentv1.NodeDeploymentState{
				agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
				agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
				agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
				agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
			} {
				status := fixtureStatus(fixture, state, uint64(sequence+1))
				if versioned {
					status.ActiveConfigIdentityCapability = statusIdentityCapability()
				}
				projectFixtureStatus(t, store, validator, DefaultSubjectPrefix, fixture, status)
			}
			if versioned {
				wrong := fixtureStatus(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5)
				wrong.ActiveConfigIdentityCapability = statusIdentityCapability()
				wrong.ActiveConfigIdentity = statusIdentityBytes087(fixture.configID, make([]byte, 32))
				if _, err := store.Project(t.Context(), decodeFixtureStatus(t, validator, DefaultSubjectPrefix, fixture.nodeID, wrong)); err == nil {
					t.Fatal("same-config APPLY accepted a conflicting identity")
				}
			}
			terminal := fixtureStatus(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5)
			if versioned {
				terminal.ActiveConfigIdentityCapability = statusIdentityCapability()
				terminal.ActiveConfigIdentity = statusIdentityBytes087(fixture.configID, digest)
				terminal.Checks = []*agentv1.CheckResult{activeConfigProbeCheck()}
			}
			envelope := decodeFixtureStatus(t, validator, DefaultSubjectPrefix, fixture.nodeID, terminal)
			if result, err := store.Project(t.Context(), envelope); err != nil || result.Outcome != OutcomeAdvanced {
				t.Fatalf("same-config terminal projection = (%+v, %v)", result, err)
			}
			if result, err := store.Project(t.Context(), envelope); err != nil || result.Outcome != OutcomeDuplicate {
				t.Fatalf("same-config terminal replay = (%+v, %v)", result, err)
			}
			conflict := fixtureStatus(fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5)
			conflict.Event.EventId = uuid.NewString()
			if versioned {
				conflict.ActiveConfigIdentityCapability = statusIdentityCapability()
				conflict.ActiveConfigIdentity = statusIdentityBytes087(fixture.configID, digest)
			}
			if _, err := store.Project(t.Context(), decodeFixtureStatus(t, validator, DefaultSubjectPrefix, fixture.nodeID, conflict)); err == nil {
				t.Fatal("same-config APPLY accepted conflicting terminal replay")
			}
			var currentID uuid.UUID
			var previousID *uuid.UUID
			var currentSchema *int32
			var currentDigest []byte
			if err := pool.QueryRow(t.Context(), `SELECT current_config_version_id,previous_config_version_id,
				current_config_identity_schema,current_config_artifact_sha256 FROM node_config_state WHERE node_id=$1`,
				fixture.nodeID).Scan(&currentID, &previousID, &currentSchema, &currentDigest); err != nil {
				t.Fatal(err)
			}
			if currentID != fixture.configID || previousID == nil || *previousID != initial.previousConfigID ||
				currentSchema == nil || *currentSchema != 1 ||
				!bytes.Equal(currentDigest, digest) {
				t.Fatalf("same-config state = current:%s previous:%v schema:%v digest:%x",
					currentID, previousID, currentSchema, currentDigest)
			}
		})
	}
}

func createRealRollbackFixture087(t *testing.T, pool *pgxpool.Pool) (deploymentFixture, []byte) {
	t.Helper()
	// 迁移 232 起，节点运行配置身份必须由一次已 activated/healthy 且绑定了该制品的 apply 下发证明；
	// 先让脚手架 apply 走到 healthy，再把它记为节点的上一份已证明配置。
	scaffold := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	for _, state := range []string{"delivered", "staged", "prechecked", "activated", "healthy"} {
		if _, err := pool.Exec(t.Context(), `UPDATE node_deployments SET state=$2 WHERE id=$1 AND attempt=1`,
			scaffold.deploymentID, state); err != nil {
			t.Fatal(err)
		}
	}
	var digest []byte
	if err := pool.QueryRow(t.Context(), `SELECT sha256 FROM configuration_artifacts
		WHERE config_version_id=$1 AND kind='configuration'`, scaffold.configID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE node_config_state SET previous_config_version_id=$2,
		previous_config_identity_schema=1,previous_config_artifact_sha256=$3 WHERE node_id=$1`,
		scaffold.nodeID, scaffold.configID, digest); err != nil {
		t.Fatal(err)
	}
	fixture := createActualDeploymentFixture087(t, pool, scaffold.nodeID, scaffold.scopeID, scaffold.configID,
		agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK)
	if len(fixture.command.Artifacts) != 0 {
		t.Fatalf("real rollback command artifacts = %d", len(fixture.command.Artifacts))
	}
	var bindings int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_deployment_artifacts
		WHERE deployment_id=$1 AND deployment_attempt=1`, fixture.deploymentID).Scan(&bindings); err != nil || bindings != 0 {
		t.Fatalf("real rollback deployment artifact bindings = %d, %v", bindings, err)
	}
	return fixture, digest
}

func createActualDeploymentFixture087(t *testing.T, pool *pgxpool.Pool, nodeID, scopeID, configID uuid.UUID,
	action agentv1.DeploymentAction,
) deploymentFixture {
	t.Helper()
	store, err := edgedeployment.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.CreateRollout(t.Context(), edgedeployment.CreateRolloutRequest{
		ConfigurationScopeID: scopeID,
		ConfigVersionID:      configID,
		Action:               action,
		NodeIDs:              []uuid.UUID{nodeID},
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: time.Minute, RequiredConsecutiveSuccesses: 1,
		},
		Deadline:       time.Now().UTC().Add(time.Hour),
		IdempotencyKey: uuid.NewString(),
		RequestID:      uuid.NewString(),
		CorrelationID:  uuid.NewString(),
	})
	if err != nil || len(result.Rollout.Deployments) != 1 {
		t.Fatalf("create actual deployment = (%+v, %v)", result, err)
	}
	deployment := result.Rollout.Deployments[0]
	previousID := uuid.Nil
	if deployment.Command.PreviousConfigVersionId != nil {
		previousID, err = uuid.Parse(*deployment.Command.PreviousConfigVersionId)
		if err != nil {
			t.Fatal(err)
		}
	}
	return deploymentFixture{
		nodeID: nodeID, scopeID: scopeID, deploymentID: deployment.ID, rolloutID: result.Rollout.ID,
		configID: configID, previousConfigID: previousID, action: action.String(), command: deployment.Command,
	}
}

func seedReleasableConfigArtifact087(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) (uuid.UUID, []byte) {
	t.Helper()
	configID, artifactID := uuid.New(), uuid.New()
	wire := []byte("configuration:" + configID.String())
	digest := sha256Bytes(wire)
	now := time.Now().UTC().Truncate(time.Microsecond)
	keyID := "edge-status-identity-" + configID.String()
	// 创建回滚/下发时会用 Ed25519 校验存储的配置制品，夹具必须签真实签名。
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,
		canonical_snapshot_sha256,generator_name,generator_version,status,idempotency_key,request_digest,created_at)
		VALUES($1,$2,$3,$4,'integration','1','building',$5,$6,$7)`, configID, scopeID, []byte(configID.String()),
		sha256Bytes([]byte(configID.String())), configID.String(), make([]byte, 32), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO artifact_signing_keys(id,algorithm,public_key,created_at)
		VALUES($1,'ed25519',$2,$3)`, keyID, []byte(publicKey), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO configuration_artifacts(id,config_version_id,ordinal,kind,
		wire_bytes,size_bytes,sha256,signature,signing_key_id,signature_algorithm,compression,media_type,
		encryption_algorithm,created_at) VALUES($1,$2,1,'configuration',$3,$4,$5,$6,$7,'ed25519','none',
		'application/vnd.cdnca.edge-config+json;version=1','none',$8)`, artifactID, configID, wire, len(wire), digest,
		ed25519.Sign(privateKey, wire), keyID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE config_versions SET status='validating' WHERE id=$1`, configID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE config_versions SET status='releasable',published_at=$2 WHERE id=$1`,
		configID, now); err != nil {
		t.Fatal(err)
	}
	return configID, digest
}

func deploymentArtifactDigest087(t *testing.T, pool *pgxpool.Pool, fixture deploymentFixture) []byte {
	t.Helper()
	var digest []byte
	if err := pool.QueryRow(t.Context(), `SELECT artifact.sha256
		FROM node_deployment_artifacts binding JOIN configuration_artifacts artifact
		ON artifact.config_version_id=binding.config_version_id AND artifact.id=binding.artifact_id
		WHERE binding.deployment_id=$1 AND binding.deployment_attempt=1 AND artifact.kind='configuration'`,
		fixture.deploymentID).Scan(&digest); err != nil {
		t.Fatal(err)
	}
	return digest
}

func statusIdentityBytes087(configID uuid.UUID, digest []byte) *agentv1.ActiveConfigIdentity {
	return &agentv1.ActiveConfigIdentity{
		Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
		ConfigVersionId: configID.String(), ArtifactSha256: append([]byte(nil), digest...),
	}
}

func assertStatusIdentity087(t *testing.T, pool *pgxpool.Pool, fixture deploymentFixture, digest []byte, proven bool) {
	t.Helper()
	var currentID uuid.UUID
	var currentSchema *int32
	var currentDigest []byte
	if err := pool.QueryRow(t.Context(), `SELECT current_config_version_id,current_config_identity_schema,
		current_config_artifact_sha256 FROM node_config_state WHERE node_id=$1`, fixture.nodeID).Scan(
		&currentID, &currentSchema, &currentDigest); err != nil {
		t.Fatal(err)
	}
	if currentID != fixture.configID || proven != (currentSchema != nil) || proven && (*currentSchema != 1 || !bytes.Equal(currentDigest, digest)) {
		t.Fatalf("node config identity = %s/%v/%x proven=%t", currentID, currentSchema, currentDigest, proven)
	}
	var apiVersion, schema *int32
	var eventConfig *uuid.UUID
	var eventDigest []byte
	if err := pool.QueryRow(t.Context(), `SELECT active_config_identity_api_version,active_config_identity_schema,
		active_config_version_id,active_config_artifact_sha256 FROM deployment_status_events
		WHERE deployment_id=$1 ORDER BY transition_sequence DESC LIMIT 1`, fixture.deploymentID).Scan(
		&apiVersion, &schema, &eventConfig, &eventDigest); err != nil {
		t.Fatal(err)
	}
	if proven {
		if apiVersion == nil || *apiVersion != 1 || schema == nil || *schema != 1 || eventConfig == nil || *eventConfig != fixture.configID || !bytes.Equal(eventDigest, digest) {
			t.Fatalf("event identity = %v/%v/%v/%x", apiVersion, schema, eventConfig, eventDigest)
		}
	} else if apiVersion != nil || schema != nil || eventConfig != nil || eventDigest != nil {
		t.Fatalf("legacy event persisted identity = %v/%v/%v/%x", apiVersion, schema, eventConfig, eventDigest)
	}
}
