//go:build integration

package edgestatus

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
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type deploymentFixture struct {
	nodeID, scopeID, deploymentID, rolloutID uuid.UUID
	configID, previousConfigID               uuid.UUID
	action                                   string
	command                                  *agentv1.DeploymentCommand
}

func TestDeploymentStatusPostgresJetStreamLifecycle(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if databaseURL == "" || natsURL == "" {
		t.Skip("TEST_DATABASE_URL and CDNCA_TEST_NATS_URL are required")
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

	connection, err := nats.Connect(natsURL, nats.Name("control-api-edge-status-integration"), nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	stream := "EDGE_STATUS_" + suffix
	durable := "edge_status_" + suffix
	prefix := "cdnca.integration." + suffix + ".deployment-status"
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: stream, Subjects: []string{prefix + ".*", prefix + ".generic-v2.*.*"}, Retention: nats.LimitsPolicy, Storage: nats.MemoryStorage,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(stream) }()
	consumerConfig := NATSConsumerConfig{
		Stream: stream, SubjectPrefix: prefix, Durable: durable,
		AckWait: 2 * time.Second, FetchTimeout: 500 * time.Millisecond, OperationTimeout: time.Second,
		NakDelay: 25 * time.Millisecond, MaxAckPending: 32, MaxWaiting: 8,
	}
	if _, err := NewNATSConsumer(connection, consumerConfig); err == nil {
		t.Fatal("consumer bound before the durable was provisioned")
	}
	if _, err := js.AddConsumer(stream, &nats.ConsumerConfig{
		Durable: durable, DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy,
		AckWait: consumerConfig.AckWait, MaxDeliver: -1, FilterSubjects: []string{prefix + ".*", prefix + ".generic-v2.*.*"},
		ReplayPolicy: nats.ReplayInstantPolicy, MaxAckPending: consumerConfig.MaxAckPending,
		MaxWaiting: consumerConfig.MaxWaiting, MaxRequestBatch: 1, MaxRequestExpires: consumerConfig.FetchTimeout,
	}); err != nil {
		t.Fatal(err)
	}
	mismatch := consumerConfig
	mismatch.AckWait += time.Second
	if _, err := NewNATSConsumer(connection, mismatch); err == nil {
		t.Fatal("consumer accepted a mismatched pre-created durable")
	}
	consumer, err := NewNATSConsumer(connection, consumerConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer consumer.Close()
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
	processor, err := NewProcessor(validator, store, consumerConfig.NakDelay, consumerConfig.OperationTimeout)
	if err != nil {
		t.Fatal(err)
	}

	apply := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	delivered := fixtureStatus(apply, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	publishStatus(t, js, prefix, apply.nodeID, delivered)
	delivery := nextStatusDelivery(t, consumer)
	if disposition, err := processor.Process(ctx, delivery); err != nil || disposition != DispositionAck {
		t.Fatalf("process delivered = (%q, %v)", disposition, err)
	}
	assertDeploymentState(t, pool, apply.deploymentID, "delivered", 1)

	deliveredEnvelope := decodeFixtureStatus(t, validator, prefix, apply.nodeID, delivered)
	if duplicate, err := store.Project(ctx, deliveredEnvelope); err != nil || duplicate.Outcome != OutcomeDuplicate {
		t.Fatalf("duplicate projection = (%+v, %v)", duplicate, err)
	}
	conflicting := proto.Clone(delivered).(*agentv1.DeploymentStatus)
	conflicting.Checks = []*agentv1.CheckResult{{Name: "journal", Succeeded: true}}
	if _, err := store.Project(ctx, decodeFixtureStatus(t, validator, prefix, apply.nodeID, conflicting)); !errors.Is(err, ErrPayloadConflict) {
		t.Fatalf("same event with changed payload error = %v", err)
	}
	sequenceConflict := proto.Clone(delivered).(*agentv1.DeploymentStatus)
	sequenceConflict.Event.EventId = uuid.NewString()
	if _, err := store.Project(ctx, decodeFixtureStatus(t, validator, prefix, apply.nodeID, sequenceConflict)); !errors.Is(err, ErrPayloadConflict) {
		t.Fatalf("same sequence with changed event error = %v", err)
	}
	wrongNode := decodeFixtureStatus(t, validator, prefix, uuid.New(), proto.Clone(delivered).(*agentv1.DeploymentStatus))
	wrongNode.Status.Event.EventId = uuid.NewString()
	wrongNode = decodeFixtureStatus(t, validator, prefix, wrongNode.NodeID, wrongNode.Status)
	if _, err := store.Project(ctx, wrongNode); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("wrong node error = %v", err)
	}
	wrongConfigStatus := proto.Clone(delivered).(*agentv1.DeploymentStatus)
	wrongConfigStatus.Event.EventId = uuid.NewString()
	wrongConfigStatus.ConfigVersionId = uuid.NewString()
	if _, err := store.Project(ctx, decodeFixtureStatus(t, validator, prefix, apply.nodeID, wrongConfigStatus)); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("wrong config error = %v", err)
	}
	wrongAttemptStatus := proto.Clone(delivered).(*agentv1.DeploymentStatus)
	wrongAttemptStatus.Event.EventId = uuid.NewString()
	wrongAttemptStatus.Attempt = 2
	if _, err := store.Project(ctx, decodeFixtureStatus(t, validator, prefix, apply.nodeID, wrongAttemptStatus)); !errors.Is(err, ErrDeploymentMissing) {
		t.Fatalf("wrong attempt error = %v", err)
	}
	wrongRequestStatus := proto.Clone(delivered).(*agentv1.DeploymentStatus)
	wrongRequestStatus.Event.EventId = uuid.NewString()
	wrongRequestStatus.Event.RequestId = uuid.NewString()
	if _, err := store.Project(ctx, decodeFixtureStatus(t, validator, prefix, apply.nodeID, wrongRequestStatus)); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("wrong request metadata error = %v", err)
	}
	wrongCausationStatus := proto.Clone(delivered).(*agentv1.DeploymentStatus)
	wrongCausationStatus.Event.EventId = uuid.NewString()
	wrongCausation := uuid.NewString()
	wrongCausationStatus.Event.CausationId = &wrongCausation
	if _, err := store.Project(ctx, decodeFixtureStatus(t, validator, prefix, apply.nodeID, wrongCausationStatus)); !errors.Is(err, ErrBindingConflict) {
		t.Fatalf("wrong causation metadata error = %v", err)
	}

	projectFixtureState(t, store, validator, prefix, apply, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, 2)
	projectFixtureState(t, store, validator, prefix, apply, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED, 3)
	projectFixtureState(t, store, validator, prefix, apply, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED, 4)
	failedAfterActivation := fixtureStatus(apply, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, 5)
	failedAfterActivation.RunningConfigUnchanged = true
	failedAfterActivation.Error = validProtocolError()
	if _, err := store.Project(ctx, decodeFixtureStatus(t, validator, prefix, apply.nodeID, failedAfterActivation)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("activated to failed error = %v", err)
	}
	assertDeploymentState(t, pool, apply.deploymentID, "activated", 4)
	projectFixtureState(t, store, validator, prefix, apply, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5)
	assertNodeConfig(t, pool, apply.nodeID, apply.configID, apply.previousConfigID)

	jump := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	jumped := fixtureStatus(jump, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, 1)
	if _, err := store.Project(ctx, decodeFixtureStatus(t, validator, prefix, jump.nodeID, jumped)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("queued to staged error = %v", err)
	}
	assertDeploymentState(t, pool, jump.deploymentID, "queued", 0)

	failed := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	projectFixtureState(t, store, validator, prefix, failed, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	failedStatus := fixtureStatus(failed, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, 2)
	failedStatus.RunningConfigUnchanged = true
	failedStatus.Error = validProtocolError()
	projectFixtureStatus(t, store, validator, prefix, failed, failedStatus)
	assertDeploymentState(t, pool, failed.deploymentID, "failed", 2)
	assertNodeConfig(t, pool, failed.nodeID, failed.previousConfigID, uuid.Nil)

	outOfOrder := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	projectFixtureState(t, store, validator, prefix, outOfOrder, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 10)
	projectFixtureState(t, store, validator, prefix, outOfOrder, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, 12)
	stale := fixtureStatus(outOfOrder, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 11)
	if _, err := store.Project(ctx, decodeFixtureStatus(t, validator, prefix, outOfOrder.nodeID, stale)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("out-of-order branch rewrite error = %v", err)
	}
	assertDeploymentState(t, pool, outOfOrder.deploymentID, "staged", 2)

	staleFailed := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	projectFixtureState(t, store, validator, prefix, staleFailed, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 10)
	staleFailedStatus := fixtureStatus(staleFailed, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, 12)
	staleFailedStatus.RunningConfigUnchanged = true
	staleFailedStatus.Error = validProtocolError()
	projectFixtureStatus(t, store, validator, prefix, staleFailed, staleFailedStatus)
	lateStaged := fixtureStatus(staleFailed, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, 11)
	lateResult, err := store.Project(ctx, decodeFixtureStatus(t, validator, prefix, staleFailed.nodeID, lateStaged))
	if err != nil || lateResult.Outcome != OutcomeStale {
		t.Fatalf("valid stale failed predecessor = (%+v, %v)", lateResult, err)
	}
	assertDeploymentState(t, pool, staleFailed.deploymentID, "failed", 3)

	invalidStale := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	projectFixtureState(t, store, validator, prefix, invalidStale, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 10)
	invalidStaleFailed := fixtureStatus(invalidStale, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, 12)
	invalidStaleFailed.RunningConfigUnchanged = true
	invalidStaleFailed.Error = validProtocolError()
	projectFixtureStatus(t, store, validator, prefix, invalidStale, invalidStaleFailed)
	forgedPrechecked := fixtureStatus(invalidStale, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED, 11)
	if _, err := store.Project(ctx, decodeFixtureStatus(t, validator, prefix, invalidStale.nodeID, forgedPrechecked)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid stale failed predecessor error = %v", err)
	}
	assertDeploymentState(t, pool, invalidStale.deploymentID, "failed", 2)

	concurrent := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	concurrentStatus := fixtureStatus(concurrent, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	concurrentEnvelope := decodeFixtureStatus(t, validator, prefix, concurrent.nodeID, concurrentStatus)
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 8)
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.Project(ctx, concurrentEnvelope)
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent duplicate projection: %v", err)
		}
	}
	assertDeploymentState(t, pool, concurrent.deploymentID, "delivered", 1)

	rollback := seedDeployment(t, pool, "rollback", uuid.Nil, uuid.Nil)
	for sequence, state := range []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTING,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED,
	} {
		projectFixtureState(t, store, validator, prefix, rollback, state, uint64(sequence+1))
	}
	assertNodeConfig(t, pool, rollback.nodeID, rollback.configID, rollback.previousConfigID)

	automatic := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	for sequence, state := range []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTING,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTED,
	} {
		projectFixtureState(t, store, validator, prefix, automatic, state, uint64(sequence+1))
	}
	assertNodeConfig(t, pool, automatic.nodeID, automatic.previousConfigID, uuid.Nil)

	rollbackFailed := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	states := []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_REVERTING,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED,
	}
	for sequence, state := range states {
		status := fixtureStatus(rollbackFailed, state, uint64(sequence+1))
		if state == agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ROLLBACK_FAILED {
			status.Error = validProtocolError()
		}
		projectFixtureStatus(t, store, validator, prefix, rollbackFailed, status)
	}
	assertNodeConfig(t, pool, rollbackFailed.nodeID, rollbackFailed.previousConfigID, uuid.Nil)
	assertReconciliationRequired(t, pool, rollbackFailed)

	rolledBackTx := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	for sequence, state := range []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
	} {
		projectFixtureState(t, store, validator, prefix, rolledBackTx, state, uint64(sequence+1))
	}
	unrelatedConfig := seedConfigVersion(t, pool, rolledBackTx.scopeID)
	if _, err := pool.Exec(ctx, `UPDATE node_config_state SET current_config_version_id = $2 WHERE node_id = $1`, rolledBackTx.nodeID, unrelatedConfig); err != nil {
		t.Fatal(err)
	}
	healthy := fixtureStatus(rolledBackTx, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5)
	failedTransactionDelivery := &fakeDelivery{
		subject: prefix + "." + rolledBackTx.nodeID.String(), data: marshalStatus(t, healthy),
	}
	if disposition, err := processor.Process(ctx, failedTransactionDelivery); err != nil || disposition != DispositionTerm ||
		failedTransactionDelivery.acks != 0 || failedTransactionDelivery.terms != 1 {
		t.Fatalf("baseline conflict disposition = (%q, %v), delivery=%+v", disposition, err, failedTransactionDelivery)
	}
	assertDeploymentState(t, pool, rolledBackTx.deploymentID, "activated", 4)

	cancelled := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	cancelledStatus := fixtureStatus(cancelled, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.Project(cancelledCtx, decodeFixtureStatus(t, validator, prefix, cancelled.nodeID, cancelledStatus)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled projection error = %v", err)
	}
	assertDeploymentState(t, pool, cancelled.deploymentID, "queued", 0)
}

func openStatusTestDatabase(t *testing.T, databaseURL string) (*pgxpool.Pool, *pgxpool.Pool, string) {
	t.Helper()
	adminPool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := adminPool.Ping(context.Background()); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	schema := "edge_status_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^edge_status_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	if _, err := adminPool.Exec(context.Background(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return pool, adminPool, schema
}

func seedDeployment(t *testing.T, pool *pgxpool.Pool, action string, currentID, previousID uuid.UUID) deploymentFixture {
	t.Helper()
	ctx := context.Background()
	tenantID, scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	targetID := uuid.New()
	if currentID == uuid.Nil {
		currentID = uuid.New()
	}
	if action == "rollback" {
		previousID = targetID
	} else if previousID == uuid.Nil {
		previousID = currentID
	}
	rolloutID, deploymentID, commandEventID := uuid.New(), uuid.New(), uuid.New()
	requestID, correlationID := uuid.New(), uuid.New()
	now := time.Now().UTC().Add(-time.Second).Truncate(time.Microsecond)
	deadline := now.Add(time.Hour)
	previousString := currentID.String()
	commandAction := agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY
	if action == "rollback" {
		commandAction = agentv1.DeploymentAction_DEPLOYMENT_ACTION_ROLLBACK
	}
	command := &agentv1.DeploymentCommand{
		Event: &commonv1.EventMetadata{
			EventId: commandEventID.String(), RequestId: requestID.String(), OccurredTime: timestamppb.New(now),
			CorrelationId: correlationID.String(),
		},
		DeploymentId: deploymentID.String(), Attempt: 1, RolloutId: rolloutID.String(),
		ConfigVersionId: targetID.String(), PreviousConfigVersionId: &previousString, Action: commandAction,
		HealthCheck: &agentv1.HealthCheckPolicy{
			ActivationTimeoutDuration: durationpb.New(time.Minute), ObservationWindowDuration: durationpb.New(time.Minute),
			RequiredConsecutiveSuccesses: 1,
		},
		DeadlineTime: timestamppb.New(deadline),
	}
	commandBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	commandDigest := sha256.Sum256(commandBytes)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants (id, display_name) VALUES ($1, 'Edge status integration tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1, 'tenant', $2)`, []any{scopeID, tenantID}},
		{`INSERT INTO users (id, username, display_name, password_hash) VALUES ($1, $2, 'Edge status tester', 'unused')`, []any{userID, "edge-status-" + strings.ReplaceAll(userID.String(), "-", "")[:16]}},
		{`INSERT INTO nodes (id, scope_id, name, admin_state, created_by_user_id, display_id) VALUES ($1, $2, $3, 'active', $4, 1)`, []any{nodeID, scopeID, "edge-status-" + strings.ReplaceAll(nodeID.String(), "-", "")[:8], userID}},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, configID := range []uuid.UUID{currentID, targetID} {
		status := "releasable"
		var publishedAt *time.Time
		if configID == targetID {
			status = "building"
		} else {
			publishedAt = &now
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO config_versions (
				id, configuration_scope_id, canonical_snapshot, canonical_snapshot_sha256,
				generator_name, generator_version, status, idempotency_key, request_digest, created_at, published_at
			) VALUES ($1, $2, $3, $4, 'integration', '1', $5, $6, $7, $8, $9)`,
			configID, scopeID, []byte(configID.String()), sha256Bytes([]byte(configID.String())),
			status, configID.String(), make([]byte, 32), now, publishedAt); err != nil {
			t.Fatal(err)
		}
	}
	signingKeyID := "edge-status-" + strings.ReplaceAll(targetID.String(), "-", "")
	artifactID := uuid.New()
	artifactBytes := []byte("configuration:" + targetID.String())
	// 创建回滚/下发时会用 Ed25519 校验存储的配置制品，夹具必须签真实签名。
	signingPublicKey, signingPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO artifact_signing_keys (id, algorithm, public_key, created_at)
		VALUES ($1, 'ed25519', $2, $3)`, signingKeyID, []byte(signingPublicKey), now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO configuration_artifacts (
			id, config_version_id, ordinal, kind, wire_bytes, size_bytes, sha256, signature,
			signing_key_id, signature_algorithm, compression, media_type, encryption_algorithm,
			recipient_key_id, created_at
		) VALUES ($1, $2, 1, 'configuration', $3, $4, $5, $6, $7, 'ed25519', 'none',
			'application/vnd.cdnca.edge-config+json;version=1', 'none', NULL, $8)`,
		artifactID, targetID, artifactBytes, len(artifactBytes), sha256Bytes(artifactBytes),
		ed25519.Sign(signingPrivateKey, artifactBytes), signingKeyID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE config_versions SET status='validating' WHERE id=$1`, targetID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE config_versions SET status='releasable', published_at=$2 WHERE id=$1`, targetID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO rollouts (
			id, configuration_scope_id, config_version_id, action, status, idempotency_key,
			request_digest, request_id, correlation_id, activation_timeout_ms, observation_window_ms,
			required_consecutive_successes, deadline_at, created_at, queued_at, updated_at
		) VALUES ($1, $2, $3, $4, 'queued', $5, $6, $7, $8, 60000, 60000, 1, $9, $10, $10, $10)`,
		rolloutID, scopeID, targetID, action, rolloutID.String(), make([]byte, 32), requestID, correlationID, deadline, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_config_state (
			node_id, configuration_scope_id, current_config_version_id, previous_config_version_id, updated_at
		) VALUES ($1, $2, $3, NULL, $4)`, nodeID, scopeID, currentID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
			INSERT INTO node_deployments (
			id, rollout_id, node_id, attempt, config_version_id, previous_config_version_id,
			action, state, command_event_id, command_bytes, command_sha256, deadline_at, created_at, updated_at
		) VALUES ($1, $2, $3, 1, $4, $5, $6, 'queued', $7, $8, $9, $10, $11, $11)`,
		deploymentID, rolloutID, nodeID, targetID, currentID, action, commandEventID, commandBytes, commandDigest[:], deadline, now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO node_deployment_artifacts (
			deployment_id, deployment_attempt, config_version_id, artifact_id, ordinal
		) VALUES ($1, 1, $2, $3, 1)`, deploymentID, targetID, artifactID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return deploymentFixture{
		nodeID: nodeID, scopeID: scopeID, deploymentID: deploymentID, rolloutID: rolloutID,
		configID: targetID, previousConfigID: currentID, action: action, command: command,
	}
}

func seedConfigVersion(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	value := []byte(id.String())
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO config_versions (
			id, configuration_scope_id, canonical_snapshot, canonical_snapshot_sha256,
			generator_name, generator_version, status, idempotency_key, request_digest, created_at, published_at
		) VALUES ($1, $2, $3, $4, 'integration', '1', 'releasable', $5, $6, $7, $7)`,
		id, scopeID, value, sha256Bytes(value), id.String(), make([]byte, 32), now); err != nil {
		t.Fatal(err)
	}
	return id
}

func fixtureStatus(fixture deploymentFixture, state agentv1.NodeDeploymentState, sequence uint64) *agentv1.DeploymentStatus {
	causationID := fixture.command.Event.EventId
	return &agentv1.DeploymentStatus{
		Event: &commonv1.EventMetadata{
			EventId: uuid.NewString(), RequestId: fixture.command.Event.RequestId,
			OccurredTime: timestamppb.Now(), CausationId: &causationID,
			CorrelationId: fixture.command.Event.CorrelationId,
		},
		DeploymentId: fixture.deploymentID.String(), Attempt: 1, ConfigVersionId: fixture.configID.String(),
		State: state, TransitionSequence: sequence,
	}
}

func projectFixtureState(t *testing.T, store *Store, validator *Validator, prefix string,
	fixture deploymentFixture, state agentv1.NodeDeploymentState, sequence uint64,
) {
	t.Helper()
	status := fixtureStatus(fixture, state, sequence)
	projectFixtureStatus(t, store, validator, prefix, fixture, status)
}

func projectFixtureStatus(t *testing.T, store *Store, validator *Validator, prefix string,
	fixture deploymentFixture, status *agentv1.DeploymentStatus,
) {
	t.Helper()
	// 带配置身份的终态必须附运行时探测结果（requireTerminalConfigConvergence），与节点代理实际上报一致。
	if status.ActiveConfigIdentity != nil && len(status.Checks) == 0 {
		status.Checks = []*agentv1.CheckResult{activeConfigProbeCheck()}
	}
	result, err := store.Project(context.Background(), decodeFixtureStatus(t, validator, prefix, fixture.nodeID, status))
	if err != nil || result.Outcome != OutcomeAdvanced {
		t.Fatalf("project state %s sequence %d = (%+v, %v)", status.State, status.TransitionSequence, result, err)
	}
}

func decodeFixtureStatus(t *testing.T, validator *Validator, prefix string, nodeID uuid.UUID, status *agentv1.DeploymentStatus) Envelope {
	t.Helper()
	envelope, err := validator.Decode(prefix+"."+nodeID.String(), marshalStatus(t, status))
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func publishStatus(t *testing.T, js nats.JetStreamContext, prefix string, nodeID uuid.UUID, status *agentv1.DeploymentStatus) {
	t.Helper()
	message := nats.NewMsg(prefix + "." + nodeID.String())
	message.Data = marshalStatus(t, status)
	message.Header.Set(nats.MsgIdHdr, status.Event.EventId)
	if _, err := js.PublishMsg(message); err != nil {
		t.Fatal(err)
	}
}

func nextStatusDelivery(t *testing.T, consumer *NATSConsumer) Delivery {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for {
		delivery, err := consumer.Next(ctx)
		if errors.Is(err, ErrNoMessage) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		return delivery
	}
}

func assertDeploymentState(t *testing.T, pool *pgxpool.Pool, deploymentID uuid.UUID, want string, wantEvents int) {
	t.Helper()
	var state string
	var events int
	if err := pool.QueryRow(context.Background(), `
		SELECT deployment.state, COUNT(event.id)
		FROM node_deployments deployment
		LEFT JOIN deployment_status_events event ON event.deployment_id = deployment.id AND event.attempt = deployment.attempt
		WHERE deployment.id = $1 GROUP BY deployment.state`, deploymentID).Scan(&state, &events); err != nil {
		t.Fatal(err)
	}
	if state != want || events != wantEvents {
		t.Fatalf("deployment state/events = (%q, %d), want (%q, %d)", state, events, want, wantEvents)
	}
}

func assertNodeConfig(t *testing.T, pool *pgxpool.Pool, nodeID, wantCurrent, wantPrevious uuid.UUID) {
	t.Helper()
	var current, previous *uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		SELECT current_config_version_id, previous_config_version_id FROM node_config_state WHERE node_id = $1`, nodeID).Scan(&current, &previous); err != nil {
		t.Fatal(err)
	}
	if current == nil || *current != wantCurrent {
		t.Fatalf("current node config = %v, want %s", current, wantCurrent)
	}
	if wantPrevious == uuid.Nil {
		if previous != nil {
			t.Fatalf("previous node config = %v, want nil", previous)
		}
	} else if previous == nil || *previous != wantPrevious {
		t.Fatalf("previous node config = %v, want %s", previous, wantPrevious)
	}
}

func assertReconciliationRequired(t *testing.T, pool *pgxpool.Pool, fixture deploymentFixture) {
	t.Helper()
	var required bool
	var reason string
	var deploymentID uuid.UUID
	var attempt int32
	if err := pool.QueryRow(context.Background(), `
		SELECT reconciliation_required, reconciliation_reason,
		       reconciliation_deployment_id, reconciliation_deployment_attempt
		FROM node_config_state WHERE node_id = $1`, fixture.nodeID).Scan(
		&required, &reason, &deploymentID, &attempt); err != nil {
		t.Fatal(err)
	}
	if !required || reason != "rollback_failed" || deploymentID != fixture.deploymentID || attempt != 1 {
		t.Fatalf("reconciliation gate = required:%t reason:%q deployment:%s attempt:%d",
			required, reason, deploymentID, attempt)
	}
}

func sha256Bytes(value []byte) []byte {
	digest := sha256.Sum256(value)
	return bytes.Clone(digest[:])
}

func activeConfigProbeCheck() *agentv1.CheckResult {
	return &agentv1.CheckResult{
		Name: activeConfigProbeCheckName, Succeeded: true,
		Summary: activeConfigProbeCheckSummary, LatencyDuration: durationpb.New(time.Millisecond),
	}
}
