//go:build integration

package nodepresence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

func TestHeartbeatActiveConfigIdentityJetStreamReload(t *testing.T) {
	databaseURL, natsURL := os.Getenv("TEST_DATABASE_URL"), os.Getenv("CDNCA_TEST_NATS_URL")
	if databaseURL == "" || natsURL == "" {
		t.Skip("TEST_DATABASE_URL and CDNCA_TEST_NATS_URL are required")
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
	nodeID := seedPresenceNode(t, pool)
	configID, artifactID, digest, _ := seedPresenceIdentityArtifact(t, pool, nodeID, "configuration")
	deploymentID := seedPresenceIdentityDeployment(t, pool, nodeID, configID, artifactID)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	stream, durable := "IDENTITY_087_"+suffix, "identity_087_"+suffix
	prefix := "cdnca.integration." + suffix + ".heartbeats"
	connection := connectPresenceNATS(t, natsURL)
	defer connection.Close()
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: stream, Subjects: []string{prefix + ".*"}, Retention: nats.LimitsPolicy,
		Storage: nats.FileStorage, Duplicates: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(stream) }()
	consumer, err := NewNATSConsumer(connection, NATSConsumerConfig{
		Stream: stream, SubjectPrefix: prefix, Durable: durable, AckWait: time.Second,
		FetchTimeout: time.Second, OperationTimeout: time.Second, NakDelay: time.Millisecond,
		MaxAckPending: 8, MaxWaiting: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)
	heartbeat := validPresenceHeartbeat(1, 1, now)
	configString := configID.String()
	heartbeat.CurrentConfigVersionId = &configString
	heartbeat.Runtime.LoadedConfigVersionId = &configString
	heartbeat.ActiveConfigIdentityCapability = activeIdentityCapability()
	heartbeat.CurrentConfigIdentity = &agentv1.ActiveConfigIdentity{
		Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
		ConfigVersionId: configString, ArtifactSha256: digest,
	}
	heartbeat.Runtime.LoadedConfigIdentity = &agentv1.ActiveConfigIdentity{
		Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
		ConfigVersionId: configString, ArtifactSha256: digest,
	}
	heartbeat.ActiveDeployments = []*agentv1.ActiveDeployment{{
		DeploymentId: deploymentID.String(), Attempt: 1, ConfigVersionId: configString,
		State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		ObservedActiveConfigIdentity: &agentv1.ActiveConfigIdentity{
			Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
			ConfigVersionId: configString, ArtifactSha256: digest,
		},
	}}
	publishPresenceHeartbeat(t, js, prefix, nodeID, heartbeat)
	delivery := nextPresenceDelivery(t, consumer)
	validator, err := NewValidator(ValidatorConfig{
		SubjectPrefix: prefix, MaxHeartbeatBytes: 1 << 20, MaxActiveDeployments: 128,
		MaxFutureSkew: 5 * time.Minute, MaxPastAge: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	validator.now = func() time.Time { return now }
	envelope, err := validator.Decode(delivery.Subject(), delivery.Data())
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(pool, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Project(t.Context(), envelope); err != nil {
		t.Fatal(err)
	}
	if err := delivery.Ack(t.Context()); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewStore(pool, time.Minute)
	if err != nil || reloaded == nil {
		t.Fatalf("reload store = (%v, %v)", reloaded, err)
	}
	assertPresenceIdentity087(t, pool, nodeID, configID, digest, deploymentID)
}

func TestHeartbeatActiveConfigIdentityProjectionAndBinding(t *testing.T) {
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
	nodeID := seedPresenceNode(t, pool)
	configID, artifactID, digest, manifestDigest := seedPresenceIdentityArtifact(t, pool, nodeID, "configuration")
	deploymentID := seedPresenceIdentityDeployment(t, pool, nodeID, configID, artifactID)

	now := time.Now().UTC().Truncate(time.Microsecond)
	validator := newTestValidator(t, now)
	store, err := NewStore(pool, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
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
		DeploymentId: deploymentID.String(), Attempt: 1, ConfigVersionId: configString,
		State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
		ObservedActiveConfigIdentity: &agentv1.ActiveConfigIdentity{
			Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
			ConfigVersionId: configString, ArtifactSha256: append([]byte(nil), digest...),
		},
	}}
	envelope, err := validator.Decode("cdnca.agent.heartbeats."+nodeID.String(), marshalHeartbeat(t, heartbeat))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := store.Project(t.Context(), envelope); err != nil || result.Outcome != OutcomeAdvanced {
		t.Fatalf("v1 projection = (%+v, %v)", result, err)
	}
	assertPresenceIdentity087(t, pool, nodeID, configID, digest, deploymentID)
	if result, err := store.Project(t.Context(), envelope); err != nil || result.Outcome != OutcomeDuplicate {
		t.Fatalf("v1 replay = (%+v, %v)", result, err)
	}

	tests := []struct {
		name   string
		mutate func(*agentv1.Heartbeat)
	}{
		{name: "manifest digest is not wire digest", mutate: func(value *agentv1.Heartbeat) {
			value.CurrentConfigIdentity.ArtifactSha256 = append([]byte(nil), manifestDigest...)
			value.Runtime.LoadedConfigIdentity.ArtifactSha256 = append([]byte(nil), manifestDigest...)
			value.ActiveDeployments[0].ObservedActiveConfigIdentity.ArtifactSha256 = append([]byte(nil), manifestDigest...)
		}},
		{name: "wrong attempt", mutate: func(value *agentv1.Heartbeat) { value.ActiveDeployments[0].Attempt = 2 }},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := cloneHeartbeat(heartbeat, test.mutate)
			candidate.HeartbeatSequence = uint64(index + 2)
			candidate.Event.EventId = uuid.NewString()
			candidate.Event.RequestId = uuid.NewString()
			decoded, decodeErr := validator.Decode("cdnca.agent.heartbeats."+nodeID.String(), marshalHeartbeat(t, candidate))
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if _, projectErr := store.Project(t.Context(), decoded); projectErr == nil {
				t.Fatal("store accepted unbound active identity")
			}
			assertPresenceIdentity087(t, pool, nodeID, configID, digest, deploymentID)
		})
	}
}

func TestHeartbeatActiveConfigIdentityRealRollbackWithoutArtifactBinding(t *testing.T) {
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
	nodeID := seedPresenceNode(t, pool)
	currentID, _, _, _ := seedPresenceIdentityArtifact(t, pool, nodeID, "configuration")
	targetID, targetArtifactID, targetDigest, _ := seedPresenceIdentityArtifact(t, pool, nodeID, "configuration")
	var scopeID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT scope_id FROM nodes WHERE id=$1`, nodeID).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_config_state(
		node_id,configuration_scope_id,current_config_version_id,previous_config_version_id,updated_at
	) VALUES($1,$2,$3,$4,clock_timestamp())`, nodeID, scopeID, currentID, targetID); err != nil {
		t.Fatal(err)
	}
	// 回滚目标必须曾被一次绑定了该制品的 healthy apply 证明过（迁移 232 的身份校验）。
	seedPresenceIdentityDeployment(t, pool, nodeID, targetID, targetArtifactID)
	rollouts, err := edgedeployment.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	created, err := rollouts.CreateRollout(t.Context(), edgedeployment.CreateRolloutRequest{
		ConfigurationScopeID: scopeID,
		ConfigVersionID:      targetID,
		Action:               agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK,
		NodeIDs:              []uuid.UUID{nodeID},
		HealthCheck: edgedeployment.HealthCheckPolicy{
			ActivationTimeout: time.Minute, ObservationWindow: time.Minute, RequiredConsecutiveSuccesses: 1,
		},
		Deadline:       time.Now().UTC().Add(time.Hour),
		IdempotencyKey: uuid.NewString(),
		RequestID:      uuid.NewString(),
		CorrelationID:  uuid.NewString(),
	})
	if err != nil || len(created.Rollout.Deployments) != 1 {
		t.Fatalf("create real rollback rollout = (%+v, %v)", created, err)
	}
	deployment := created.Rollout.Deployments[0]
	if len(deployment.Command.Artifacts) != 0 {
		t.Fatalf("rollback command artifacts = %d", len(deployment.Command.Artifacts))
	}
	var bindings int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM node_deployment_artifacts
		WHERE deployment_id=$1 AND deployment_attempt=1`, deployment.ID).Scan(&bindings); err != nil || bindings != 0 {
		t.Fatalf("rollback artifact bindings = %d, %v", bindings, err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	heartbeat := validPresenceHeartbeat(1, 1, now)
	targetString, currentString := targetID.String(), currentID.String()
	heartbeat.CurrentConfigVersionId = &targetString
	heartbeat.PreviousConfigVersionId = &currentString
	heartbeat.Runtime.LoadedConfigVersionId = &targetString
	heartbeat.ActiveConfigIdentityCapability = activeIdentityCapability()
	heartbeat.CurrentConfigIdentity = &agentv1.ActiveConfigIdentity{
		Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
		ConfigVersionId: targetString, ArtifactSha256: append([]byte(nil), targetDigest...),
	}
	heartbeat.Runtime.LoadedConfigIdentity = &agentv1.ActiveConfigIdentity{
		Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
		ConfigVersionId: targetString, ArtifactSha256: append([]byte(nil), targetDigest...),
	}
	heartbeat.ActiveDeployments = []*agentv1.ActiveDeployment{{
		DeploymentId: deployment.ID.String(), Attempt: 1, ConfigVersionId: targetString,
		State: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED,
		ObservedActiveConfigIdentity: &agentv1.ActiveConfigIdentity{
			Schema:          agentv1.ActiveConfigIdentitySchema_ACTIVE_CONFIG_IDENTITY_SCHEMA_V1,
			ConfigVersionId: targetString, ArtifactSha256: append([]byte(nil), targetDigest...),
		},
	}}
	validator := newTestValidator(t, now)
	envelope, err := validator.Decode("cdnca.agent.heartbeats."+nodeID.String(), marshalHeartbeat(t, heartbeat))
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(pool, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := store.Project(t.Context(), envelope); err != nil || result.Outcome != OutcomeAdvanced {
		t.Fatalf("project real rollback heartbeat = (%+v, %v)", result, err)
	}
	assertPresenceIdentity087(t, pool, nodeID, targetID, targetDigest, deployment.ID)
}

func seedPresenceIdentityArtifact(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID, kind string) (uuid.UUID, uuid.UUID, []byte, []byte) {
	t.Helper()
	var scopeID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT scope_id FROM nodes WHERE id=$1`, nodeID).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	configID, artifactID := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Microsecond)
	manifest := []byte("manifest:" + configID.String())
	wire := []byte("signed-wire:" + configID.String())
	manifestDigest, wireDigest := sha256.Sum256(manifest), sha256.Sum256(wire)
	keyID := "presence-identity-" + configID.String()
	// 发布时会用 Ed25519 校验存储的配置制品，夹具必须签真实签名。
	publicKey, privateKey, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	signature := ed25519.Sign(privateKey, wire)
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO config_versions(
			id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,generator_name,
			generator_version,status,idempotency_key,request_digest,created_at
		) VALUES($1,$2,$3,$4,'presence-identity','1','building',$5,$6,$7)`,
			configID, scopeID, manifest, manifestDigest[:], configID.String(), make([]byte, 32), now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO artifact_signing_keys(id,algorithm,public_key,created_at)
			VALUES($1,'ed25519',$2,$3)`, keyID, []byte(publicKey), now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO configuration_artifacts(
			id,config_version_id,ordinal,kind,wire_bytes,size_bytes,sha256,signature,signing_key_id,
			signature_algorithm,compression,media_type,encryption_algorithm,created_at
		) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,'ed25519','none','application/octet-stream','none',$9)`,
			artifactID, configID, kind, wire, len(wire), wireDigest[:], signature, keyID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE config_versions SET status='validating' WHERE id=$1`, configID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE config_versions SET status='releasable',published_at=$2 WHERE id=$1`, configID, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return configID, artifactID, wireDigest[:], manifestDigest[:]
}

func seedPresenceIdentityDeployment(t *testing.T, pool *pgxpool.Pool, nodeID, configID, artifactID uuid.UUID) uuid.UUID {
	t.Helper()
	var scopeID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT scope_id FROM nodes WHERE id=$1`, nodeID).Scan(&scopeID); err != nil {
		t.Fatal(err)
	}
	rolloutID, deploymentID := uuid.New(), uuid.New()
	now, deadline := time.Now().UTC().Truncate(time.Microsecond), time.Now().UTC().Add(time.Hour)
	command := []byte("presence identity command")
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
	) VALUES($1,$2,$3,1,$4,'apply','healthy',$5,$6,$7,$8,$9,$9)`,
		deploymentID, rolloutID, nodeID, configID, uuid.New(), command, commandDigest[:], deadline, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_deployment_artifacts(
		deployment_id,deployment_attempt,config_version_id,artifact_id,ordinal
	) VALUES($1,1,$2,$3,1)`, deploymentID, configID, artifactID); err != nil {
		t.Fatal(err)
	}
	// 与发布路径一致：节点下发配置后在 node_config_state 认领配置作用域，心跳身份才可绑定。
	// 291 起一个节点可承载多个作用域，主键是 (node_id,configuration_scope_id)。
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_config_state(
		node_id,configuration_scope_id,current_config_version_id,previous_config_version_id,updated_at
	) VALUES($1,$2,NULL,NULL,clock_timestamp())
	ON CONFLICT (node_id,configuration_scope_id) DO NOTHING`, nodeID, scopeID); err != nil {
		t.Fatal(err)
	}
	return deploymentID
}

func assertPresenceIdentity087(t *testing.T, pool *pgxpool.Pool, nodeID, configID uuid.UUID, digest []byte, deploymentID uuid.UUID) {
	t.Helper()
	var apiVersion, currentSchema, loadedSchema *int32
	var currentDigest, loadedDigest, activeJSON []byte
	var sequence int64
	if err := pool.QueryRow(t.Context(), `SELECT active_config_identity_api_version,
		current_config_identity_schema,current_config_artifact_sha256,
		loaded_config_identity_schema,loaded_config_artifact_sha256,active_deployments,heartbeat_sequence
		FROM node_presence WHERE node_id=$1`, nodeID).Scan(
		&apiVersion, &currentSchema, &currentDigest, &loadedSchema, &loadedDigest, &activeJSON, &sequence); err != nil {
		t.Fatal(err)
	}
	if apiVersion == nil || *apiVersion != 1 || currentSchema == nil || *currentSchema != 1 || loadedSchema == nil || *loadedSchema != 1 ||
		!bytes.Equal(currentDigest, digest) || !bytes.Equal(loadedDigest, digest) || sequence != 1 {
		t.Fatalf("presence identity api/schema/digest/sequence = %v/%v/%x/%v/%x/%d", apiVersion, currentSchema, currentDigest, loadedSchema, loadedDigest, sequence)
	}
	var active []map[string]any
	if err := json.Unmarshal(activeJSON, &active); err != nil || len(active) != 1 {
		t.Fatalf("active deployment JSON = %s err=%v", activeJSON, err)
	}
	identity, ok := active[0]["observed_active_config_identity"].(map[string]any)
	if !ok || identity["schema"] != float64(1) || identity["config_version_id"] != configID.String() ||
		identity["artifact_sha256"] != stringHex(digest) || active[0]["deployment_id"] != deploymentID.String() {
		t.Fatalf("active identity JSON = %#v", active[0])
	}
}

func stringHex(value []byte) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, len(value)*2)
	for index, item := range value {
		encoded[index*2] = digits[item>>4]
		encoded[index*2+1] = digits[item&15]
	}
	return string(encoded)
}
