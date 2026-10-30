//go:build integration

package nodepresence

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestHeartbeatPlatformNodeUsesClaimedConfigurationScope(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	pool, admin, schema := openPresenceTestDatabase(t, databaseURL)
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}

	nodeID, platformScopeID, configurationScopeID := seedPresencePlatformNode(t, pool, true)
	configID, artifactID, digest := seedPresenceScopedIdentityArtifact(t, pool, configurationScopeID)
	deploymentID := seedPresenceScopedIdentityDeployment(t, pool, nodeID, configurationScopeID, configID, artifactID, "activated")

	now := time.Now().UTC().Truncate(time.Microsecond)
	validator := newTestValidator(t, now)
	store, err := NewStore(pool, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := platformPresenceIdentityHeartbeat(now, configID, digest, deploymentID)
	envelope, err := validator.Decode("cdnca.agent.heartbeats."+nodeID.String(), marshalHeartbeat(t, heartbeat))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := store.Project(t.Context(), envelope); err != nil || result.Outcome != OutcomeAdvanced {
		t.Fatalf("platform node heartbeat = (%+v, %v)", result, err)
	}
	assertPresenceIdentity087(t, pool, nodeID, configID, digest, deploymentID)

	foreignConfigID, _, foreignDigest := seedPresenceScopedIdentityArtifact(t, pool, platformScopeID)
	foreign := cloneHeartbeat(heartbeat, func(value *agentv1.Heartbeat) {
		foreignConfig := foreignConfigID.String()
		value.HeartbeatSequence = 2
		value.Event.EventId = uuid.NewString()
		value.Event.RequestId = uuid.NewString()
		value.CurrentConfigVersionId = &foreignConfig
		value.Runtime.LoadedConfigVersionId = &foreignConfig
		value.CurrentConfigIdentity.ConfigVersionId = foreignConfig
		value.CurrentConfigIdentity.ArtifactSha256 = append([]byte(nil), foreignDigest...)
		value.Runtime.LoadedConfigIdentity.ConfigVersionId = foreignConfig
		value.Runtime.LoadedConfigIdentity.ArtifactSha256 = append([]byte(nil), foreignDigest...)
	})
	foreignEnvelope, err := validator.Decode("cdnca.agent.heartbeats."+nodeID.String(), marshalHeartbeat(t, foreign))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Project(t.Context(), foreignEnvelope); !errors.Is(err, ErrInvalidHeartbeat) {
		t.Fatalf("platform-scope artifact error = %v, want ErrInvalidHeartbeat", err)
	}
	assertPresenceIdentity087(t, pool, nodeID, configID, digest, deploymentID)

	unclaimedNodeID, _, unclaimedConfigurationScopeID := seedPresencePlatformNode(t, pool, false)
	unclaimedConfigID, _, unclaimedDigest := seedPresenceScopedIdentityArtifact(t, pool, unclaimedConfigurationScopeID)
	unclaimedHeartbeat := platformPresenceIdentityHeartbeat(now, unclaimedConfigID, unclaimedDigest, uuid.New())
	unclaimedHeartbeat.ActiveDeployments = nil
	unclaimedEnvelope, err := validator.Decode("cdnca.agent.heartbeats."+unclaimedNodeID.String(), marshalHeartbeat(t, unclaimedHeartbeat))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Project(t.Context(), unclaimedEnvelope); !errors.Is(err, ErrInvalidHeartbeat) {
		t.Fatalf("unclaimed configuration scope error = %v, want ErrInvalidHeartbeat", err)
	}
	var rows int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_presence WHERE node_id=$1`, unclaimedNodeID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("rejected identity heartbeat inserted %d presence rows", rows)
	}

	identityFree := validPresenceHeartbeat(1, 2, now.Add(time.Second))
	identityFreeEnvelope, err := validator.Decode("cdnca.agent.heartbeats."+unclaimedNodeID.String(), marshalHeartbeat(t, identityFree))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := store.Project(t.Context(), identityFreeEnvelope); err != nil || result.Outcome != OutcomeAdvanced {
		t.Fatalf("identity-free pre-rollout heartbeat = (%+v, %v)", result, err)
	}
}

func seedPresencePlatformNode(t *testing.T, pool *pgxpool.Pool, claimConfigurationScope bool) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, configurationScopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	var platformScopeID uuid.UUID
	err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform' ORDER BY id LIMIT 1`).Scan(&platformScopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		platformScopeID = uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL)`, platformScopeID); err != nil {
			t.Fatal(err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	var nodeDisplayID int64
	if err := pool.QueryRow(t.Context(), `SELECT COALESCE(max(display_id),0)+1 FROM nodes WHERE scope_id=$1`,
		platformScopeID).Scan(&nodeDisplayID); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'Platform presence tenant')`, tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, configurationScopeID, tenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash)
			VALUES($1,$2,'Platform presence tester','not-used')`, userID, "platform-presence-"+userID.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			VALUES($1,$2,$3,'active',$4,$5)`, nodeID, platformScopeID, "platform-presence-"+nodeID.String(), userID,
			nodeDisplayID); err != nil {
			return err
		}
		if claimConfigurationScope {
			if _, err := tx.Exec(t.Context(), `INSERT INTO node_config_state(
				node_id,configuration_scope_id,current_config_version_id,previous_config_version_id,updated_at
			) VALUES($1,$2,NULL,NULL,clock_timestamp())`, nodeID, configurationScopeID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return nodeID, platformScopeID, configurationScopeID
}

func seedPresenceScopedIdentityArtifact(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) (uuid.UUID, uuid.UUID, []byte) {
	t.Helper()
	configID, artifactID := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	manifest := []byte("platform-presence-manifest:" + configID.String())
	wire := []byte("platform-presence-wire:" + configID.String())
	manifestDigest, wireDigest := sha256.Sum256(manifest), sha256.Sum256(wire)
	keyID := "platform-presence-" + configID.String()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO config_versions(
			id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
			generator_version,status,idempotency_key,request_digest,created_at
		) VALUES($1,$2,$3,$4,'platform-presence','1','building',$5,$6,$7)`,
			configID, scopeID, manifest, manifestDigest[:], configID.String(), make([]byte, 32), now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO artifact_signing_keys(id,algorithm,public_key,created_at)
			VALUES($1,'ed25519',$2,$3)`, keyID, make([]byte, 32), now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO configuration_artifacts(
			id,config_version_id,ordinal,kind,wire_bytes,size_bytes,sha256,signature,signing_key_id,
			signature_algorithm,compression,media_type,encryption_algorithm,created_at
		) VALUES($1,$2,1,'configuration',$3,$4,$5,$6,$7,'ed25519','none','application/octet-stream','none',$8)`,
			artifactID, configID, wire, len(wire), wireDigest[:], make([]byte, 64), keyID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE config_versions SET status='validating' WHERE id=$1`, configID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE config_versions SET status='releasable',published_at=$2 WHERE id=$1`, configID, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return configID, artifactID, wireDigest[:]
}

func seedPresenceScopedIdentityDeployment(t *testing.T, pool *pgxpool.Pool, nodeID, scopeID, configID, artifactID uuid.UUID, state string) uuid.UUID {
	t.Helper()
	rolloutID, deploymentID := uuid.New(), uuid.New()
	now, deadline := time.Now().UTC().Truncate(time.Microsecond), time.Now().UTC().Add(time.Hour)
	command := []byte("platform presence identity command")
	commandDigest := sha256.Sum256(command)
	if _, err := pool.Exec(t.Context(), `INSERT INTO rollouts(
		id,configuration_scope_id,config_version_id,action,status,idempotency_key,request_digest,
		request_id,correlation_id,activation_timeout_ms,observation_window_ms,required_consecutive_successes,
		deadline_at,created_at,queued_at,updated_at
	) VALUES($1,$2,$3,'apply','queued',$4,$5,$6,$7,1000,1000,1,$8,$9,$9,$9)`,
		rolloutID, scopeID, configID, rolloutID.String(), make([]byte, 32), uuid.New(), uuid.New(), deadline, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_deployments(
		id,rollout_id,node_id,attempt,config_version_id,action,state,command_event_id,command_bytes,
		command_sha256,deadline_at,created_at,updated_at
	) VALUES($1,$2,$3,3,$4,'apply',$5,$6,$7,$8,$9,$10,$10)`,
		deploymentID, rolloutID, nodeID, configID, state, uuid.New(), command, commandDigest[:], deadline, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_deployment_artifacts(
		deployment_id,deployment_attempt,config_version_id,artifact_id,ordinal
	) VALUES($1,3,$2,$3,1)`, deploymentID, configID, artifactID); err != nil {
		t.Fatal(err)
	}
	return deploymentID
}

func platformPresenceIdentityHeartbeat(now time.Time, configID uuid.UUID, digest []byte, deploymentID uuid.UUID) *agentv1.Heartbeat {
	heartbeat := validPresenceHeartbeat(1, 1, now)
	configString := configID.String()
	heartbeat.CurrentConfigVersionId = &configString
	heartbeat.Runtime.LoadedConfigVersionId = &configString
	heartbeat.ActiveConfigIdentityCapability = activeIdentityCapability()
	heartbeat.CurrentConfigIdentity = &agentv1.ActiveConfigIdentity{
		Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
		ConfigVersionId: configString, ArtifactSha256: append([]byte(nil), digest...),
	}
	heartbeat.Runtime.LoadedConfigIdentity = &agentv1.ActiveConfigIdentity{
		Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
		ConfigVersionId: configString, ArtifactSha256: append([]byte(nil), digest...),
	}
	heartbeat.ActiveDeployments = []*agentv1.ActiveDeployment{{
		DeploymentId: deploymentID.String(), Attempt: 3, ConfigVersionId: configString,
		State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		ObservedActiveConfigIdentity: &agentv1.ActiveConfigIdentity{
			Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
			ConfigVersionId: configString, ArtifactSha256: append([]byte(nil), digest...),
		},
	}}
	return heartbeat
}

// live-site D1: an agent reported the platform-scope artifact set it applied
// as a scoped apply result; the whole heartbeat was terminated and the node
// stayed offline. Such an entry is ignored, the heartbeat projects.
func TestHeartbeatIgnoresPlatformScopeArtifactApplyResult(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	pool, admin, schema := openPresenceTestDatabase(t, databaseURL)
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	nodeID, platformScopeID, _ := seedPresencePlatformNode(t, pool, false)
	now := time.Now().UTC().Truncate(time.Microsecond)
	validator := newTestValidator(t, now)
	store, err := NewStore(pool, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := validPresenceHeartbeat(1, 1, now)
	heartbeat.ActiveConfigIdentityCapability = activeIdentityCapability()
	heartbeat.ScopedConfigIdentities = []*agentv1.ScopedConfigIdentity{{
		ConfigurationScopeId: platformScopeID.String(),
		LastApplyResult: &agentv1.ScopedApplyResult{DeploymentId: uuid.NewString(), Attempt: 1,
			ConfigVersionId: uuid.NewString(), State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY},
	}}
	envelope, err := validator.Decode("cdnca.agent.heartbeats."+nodeID.String(), marshalHeartbeat(t, heartbeat))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := store.Project(t.Context(), envelope); err != nil || result.Outcome != OutcomeAdvanced {
		t.Fatalf("platform-scope artifact result heartbeat = (%+v, %v)", result, err)
	}
	var identities int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_presence_scope_identities WHERE node_id=$1`, nodeID).
		Scan(&identities); err != nil || identities != 0 {
		t.Fatalf("scoped identities=%d err=%v", identities, err)
	}
}
