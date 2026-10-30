//go:build integration

package edgeoutbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
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
	"google.golang.org/protobuf/types/known/timestamppb"
)

type integrationFixture struct {
	pool        *pgxpool.Pool
	admin       *pgxpool.Pool
	schema      string
	databaseURL string
	scopeID     uuid.UUID
	userID      uuid.UUID
	configID    uuid.UUID
	rolloutID   uuid.UUID
}

type integrationDeployment struct {
	outboxID     uuid.UUID
	deploymentID uuid.UUID
	nodeID       uuid.UUID
	eventID      uuid.UUID
	subject      string
	payload      []byte
}

func TestPostgresJetStreamPublisherLifecycle(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if databaseURL == "" || natsURL == "" {
		t.Skip("TEST_DATABASE_URL and CDNCA_TEST_NATS_URL are required")
	}
	fixture := newIntegrationFixture(t, databaseURL)
	defer fixture.close(t)
	nodes := make([]uuid.UUID, 6)
	subjects := make([]string, len(nodes))
	for index := range nodes {
		nodes[index] = uuid.New()
		subjects[index] = CommandSubjectPrefix + "." + nodes[index].String()
	}

	connection, err := nats.Connect(natsURL, nats.Name("control-api-edge-outbox-integration"), nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	jetstream, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	stream := "EDGE_COMMANDS_" + suffix
	if _, err := jetstream.AddStream(&nats.StreamConfig{
		Name: stream, Subjects: subjects, Retention: nats.LimitsPolicy,
		Storage: nats.FileStorage, Duplicates: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = jetstream.DeleteStream(stream) }()

	config := DefaultConfig()
	config.Stream = stream
	config.BatchSize = 1
	config.OperationTimeout = time.Second
	config.LeaseTimeout = 5 * time.Second
	config.BaseBackoff = 50 * time.Millisecond
	config.MaxBackoff = 100 * time.Millisecond
	first, err := New(fixture.pool, connection, config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(fixture.pool, connection, config)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("two publishers claim once", func(t *testing.T) {
		deployment := fixture.seedDeployment(t, nodes[0])
		start := make(chan struct{})
		results := make(chan BatchResult, 2)
		errorsChannel := make(chan error, 2)
		var wait sync.WaitGroup
		for _, publisher := range []*Publisher{first, second} {
			wait.Add(1)
			go func(publisher *Publisher) {
				defer wait.Done()
				<-start
				result, err := publisher.PublishBatch(context.Background())
				results <- result
				errorsChannel <- err
			}(publisher)
		}
		close(start)
		wait.Wait()
		close(results)
		close(errorsChannel)
		claimed, published := 0, 0
		for err := range errorsChannel {
			if err != nil {
				t.Fatal(err)
			}
		}
		for result := range results {
			claimed += result.Claimed
			published += result.Published
		}
		if claimed != 1 || published != 1 {
			t.Fatalf("combined claimed=%d published=%d", claimed, published)
		}
		assertOutboxState(t, fixture.pool, deployment.outboxID, "published", 1, true, "")
		assertPublishedMessage(t, jetstream, stream, deployment)
	})

	t.Run("active lease then stale duplicate recovery", func(t *testing.T) {
		deployment := fixture.seedDeployment(t, nodes[1])
		store := &postgresStore{pool: fixture.pool}
		initialClaims, err := store.claim(context.Background(), 1, config.LeaseTimeout)
		if err != nil || len(initialClaims) != 1 {
			t.Fatalf("initial claim count=%d error=%v", len(initialClaims), err)
		}
		if _, err := jetstream.PublishMsg(
			&nats.Msg{Subject: deployment.subject, Data: deployment.payload, Header: nats.Header{nats.MsgIdHdr: []string{deployment.eventID.String()}}},
			nats.ExpectStream(stream),
		); err != nil {
			t.Fatal(err)
		}
		activeClaims, err := store.claim(context.Background(), 1, config.LeaseTimeout)
		if err != nil || len(activeClaims) != 0 {
			t.Fatalf("active re-claim count=%d error=%v", len(activeClaims), err)
		}
		if _, err := fixture.pool.Exec(context.Background(), `
			UPDATE edge_command_outbox SET updated_at = CURRENT_TIMESTAMP - interval '1 minute' WHERE id = $1`, deployment.outboxID); err != nil {
			t.Fatal(err)
		}
		reclaimed, err := store.claim(context.Background(), 1, config.LeaseTimeout)
		if err != nil || len(reclaimed) != 1 {
			t.Fatalf("stale re-claim count=%d error=%v", len(reclaimed), err)
		}
		if err := store.markPublished(context.Background(), deployment.outboxID, initialClaims[0].claimToken); !errors.Is(err, ErrClaimLost) {
			t.Fatalf("stale token finalize error=%v, want ErrClaimLost", err)
		}
		result, err := first.PublishBatch(context.Background())
		if err != nil || result.Claimed != 0 {
			t.Fatalf("replacement active claim result=%+v error=%v", result, err)
		}
		if _, err := fixture.pool.Exec(context.Background(), `
			UPDATE edge_command_outbox SET updated_at = CURRENT_TIMESTAMP - interval '1 minute' WHERE id = $1`, deployment.outboxID); err != nil {
			t.Fatal(err)
		}
		result, err = second.PublishBatch(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if result.Claimed != 1 || result.Published != 1 || result.Duplicates != 1 {
			t.Fatalf("stale recovery result = %+v", result)
		}
		assertOutboxState(t, fixture.pool, deployment.outboxID, "published", 3, true, "")
		assertPublishedMessage(t, jetstream, stream, deployment)
	})

	t.Run("wrong expected stream is a permanent classified failure", func(t *testing.T) {
		deployment := fixture.seedDeployment(t, nodes[2])
		wrongConfig := config
		wrongConfig.Stream = "MISSING_" + suffix
		publisher, err := New(fixture.pool, connection, wrongConfig)
		if err != nil {
			t.Fatal(err)
		}
		before := streamMessageCount(t, jetstream, stream)
		result, err := publisher.PublishBatch(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if result.PermanentFailures != 1 || result.Published != 0 {
			t.Fatalf("wrong-stream result = %+v", result)
		}
		assertOutboxState(t, fixture.pool, deployment.outboxID, "failed", 1, false, "configuration:publish_rejected")
		if after := streamMessageCount(t, jetstream, stream); after != before {
			t.Fatalf("wrong-stream publish changed message count from %d to %d", before, after)
		}
	})

	t.Run("tampered payload never reaches NATS", func(t *testing.T) {
		deployment := fixture.seedDeploymentWithOutboxMutation(t, nodes[3], func(payload []byte) []byte {
			return append(bytes.Clone(payload), 0)
		})
		before := streamMessageCount(t, jetstream, stream)
		result, err := first.PublishBatch(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if result.PermanentFailures != 1 || result.Published != 0 {
			t.Fatalf("tamper result = %+v", result)
		}
		assertOutboxState(t, fixture.pool, deployment.outboxID, "failed", 1, false, "integrity:payload_digest_mismatch")
		if after := streamMessageCount(t, jetstream, stream); after != before {
			t.Fatalf("tampered publish changed message count from %d to %d", before, after)
		}
	})

	t.Run("canceled claim attempt leaves the fact pending", func(t *testing.T) {
		deployment := fixture.seedDeployment(t, nodes[4])
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := first.PublishBatch(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled publish error = %v", err)
		}
		assertOutboxState(t, fixture.pool, deployment.outboxID, "pending", 0, false, "")
	})

	t.Run("database outage leaves the fact pending", func(t *testing.T) {
		deployment := fixture.seedDeployment(t, nodes[5])
		isolatedPool := openSchemaPool(t, fixture.databaseURL, fixture.schema)
		publisher, err := New(isolatedPool, connection, config)
		if err != nil {
			isolatedPool.Close()
			t.Fatal(err)
		}
		isolatedPool.Close()
		if _, err := publisher.PublishBatch(context.Background()); err == nil {
			t.Fatal("publisher succeeded with a closed PostgreSQL pool")
		}
		assertOutboxState(t, fixture.pool, deployment.outboxID, "pending", 0, false, "")
	})
}

func newIntegrationFixture(t *testing.T, databaseURL string) *integrationFixture {
	t.Helper()
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(ctx); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "edge_outbox_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^edge_outbox_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema name %q", schema)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	pool := openSchemaPool(t, databaseURL, schema)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		pool.Close()
		admin.Close()
		t.Fatal(err)
	}
	fixture := &integrationFixture{
		pool: pool, admin: admin, schema: schema, databaseURL: databaseURL,
		scopeID: uuid.New(), userID: uuid.New(), configID: uuid.New(), rolloutID: uuid.New(),
	}
	fixture.seedParents(t)
	return fixture
}

func (f *integrationFixture) seedParents(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	tenantID := uuid.New()
	snapshot := []byte(`{"version":1}`)
	snapshotDigest := sha256.Sum256(snapshot)
	requestDigest := sha256.Sum256([]byte("edge-outbox-integration"))
	username := "edge-outbox-" + strings.ReplaceAll(f.userID.String(), "-", "")[:16]
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants (id, display_name) VALUES ($1, 'Edge outbox integration')`, []any{tenantID}},
		{`INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1, 'tenant', $2)`, []any{f.scopeID, tenantID}},
		{`INSERT INTO users (id, username, display_name, password_hash) VALUES ($1, $2, 'Edge outbox tester', 'not-used')`, []any{f.userID, username}},
		{`INSERT INTO config_versions (
			id, configuration_scope_id, canonical_snapshot, canonical_snapshot_sha256,
			generator_name, generator_version, status, idempotency_key, request_digest, created_at, published_at
		) VALUES ($1, $2, $3, $4, 'integration', '1', 'releasable', $5, $6, $7, $7)`,
			[]any{f.configID, f.scopeID, snapshot, snapshotDigest[:], "config-" + f.configID.String(), requestDigest[:], now}},
		{`INSERT INTO rollouts (
			id, configuration_scope_id, config_version_id, action, status, idempotency_key,
			request_digest, request_id, correlation_id, activation_timeout_ms,
			observation_window_ms, required_consecutive_successes, deadline_at, created_at, queued_at, updated_at
		) VALUES ($1, $2, $3, 'apply', 'queued', $4, $5, $6, $7, 1000, 1000, 1, $8, $9, $9, $9)`,
			[]any{f.rolloutID, f.scopeID, f.configID, "rollout-" + f.rolloutID.String(), requestDigest[:], uuid.New(), uuid.New(), now.Add(time.Hour), now}},
	}
	for _, statement := range statements {
		if _, err := f.pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *integrationFixture) seedDeployment(t *testing.T, nodeID uuid.UUID) integrationDeployment {
	return f.seedDeploymentWithOutboxMutation(t, nodeID, nil)
}

func (f *integrationFixture) seedDeploymentWithOutboxMutation(
	t *testing.T,
	nodeID uuid.UUID,
	mutate func([]byte) []byte,
) integrationDeployment {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	deployment := integrationDeployment{
		outboxID: uuid.New(), deploymentID: uuid.New(), nodeID: nodeID,
		eventID: uuid.New(), subject: CommandSubjectPrefix + "." + nodeID.String(),
	}
	command := &agentv1.DeploymentCommand{
		Event: &commonv1.EventMetadata{
			EventId: deployment.eventID.String(), RequestId: uuid.NewString(),
			CorrelationId: uuid.NewString(), OccurredTime: timestamppb.New(now),
		},
		DeploymentId: deployment.deploymentID.String(), Attempt: 1,
		RolloutId: f.rolloutID.String(), ConfigVersionId: f.configID.String(),
		Action:       agentv1.DeploymentAction_DEPLOYMENT_ACTION_APPLY,
		DeadlineTime: timestamppb.New(now.Add(time.Hour)),
	}
	deployment.payload = deterministicCommand(t, command)
	commandDigest := sha256.Sum256(deployment.payload)
	if _, err := f.pool.Exec(ctx, `
		WITH allocated AS (
			INSERT INTO node_display_id_sequences(scope_id, next_value, updated_at) VALUES($2, 2, $5)
			ON CONFLICT(scope_id) DO UPDATE SET
				next_value = node_display_id_sequences.next_value + 1, updated_at = EXCLUDED.updated_at
			RETURNING next_value - 1 AS display_id
		)
		INSERT INTO nodes (id, scope_id, name, admin_state, created_by_user_id, display_id)
		SELECT $1, $2, $3, 'active', $4, display_id FROM allocated`,
		nodeID, f.scopeID, "edge-node-"+strings.ReplaceAll(nodeID.String(), "-", "")[:12], f.userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO node_deployments (
			id, rollout_id, node_id, attempt, config_version_id, action, state,
			command_event_id, command_bytes, command_sha256, deadline_at, created_at, updated_at
		) VALUES ($1, $2, $3, 1, $4, 'apply', 'queued', $5, $6, $7, $8, $9, $9)`,
		deployment.deploymentID, f.rolloutID, nodeID, f.configID, deployment.eventID,
		deployment.payload, commandDigest[:], now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	outboxPayload := bytes.Clone(deployment.payload)
	if mutate != nil {
		outboxPayload = mutate(outboxPayload)
	}
	outboxDigest := sha256.Sum256(outboxPayload)
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO edge_command_outbox (
			id, deployment_id, deployment_attempt, node_id, subject, payload,
			payload_sha256, status, available_at, created_at, updated_at
		) VALUES ($1, $2, 1, $3, $4, $5, $6, 'pending', $7, $7, $7)`,
		deployment.outboxID, deployment.deploymentID, nodeID, deployment.subject,
		outboxPayload, outboxDigest[:], now); err != nil {
		t.Fatal(err)
	}
	return deployment
}

func (f *integrationFixture) close(t *testing.T) {
	t.Helper()
	f.pool.Close()
	defer f.admin.Close()
	if _, err := f.admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{f.schema}.Sanitize()+" CASCADE"); err != nil {
		t.Errorf("drop integration schema: %v", err)
	}
}

func openSchemaPool(t *testing.T, databaseURL, schema string) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	return pool
}

func assertOutboxState(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, status string, attempts int, published bool, lastError string) {
	t.Helper()
	var actualStatus, availableAt string
	var actualAttempts int
	var actualPublished bool
	var actualError sql.NullString
	if err := pool.QueryRow(context.Background(), `
		SELECT status, publish_attempts, published_at IS NOT NULL, last_error, available_at::text
		FROM edge_command_outbox WHERE id = $1`, id).Scan(
		&actualStatus, &actualAttempts, &actualPublished, &actualError, &availableAt,
	); err != nil {
		t.Fatal(err)
	}
	if actualStatus != status || actualAttempts != attempts || actualPublished != published ||
		actualError.String != lastError || actualError.Valid != (lastError != "") {
		t.Fatalf("outbox state=(%s,%d,%v,%q), want=(%s,%d,%v,%q)",
			actualStatus, actualAttempts, actualPublished, actualError.String,
			status, attempts, published, lastError)
	}
	if status == "failed" && (strings.HasPrefix(lastError, "integrity:") || strings.HasPrefix(lastError, "configuration:")) {
		if availableAt != "infinity" {
			t.Fatalf("permanent failure available_at = %q, want infinity", availableAt)
		}
	}
}

func assertPublishedMessage(t *testing.T, jetstream nats.JetStreamContext, stream string, deployment integrationDeployment) {
	t.Helper()
	message, err := jetstream.GetLastMsg(stream, deployment.subject)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message.Data, deployment.payload) || message.Header.Get(nats.MsgIdHdr) != deployment.eventID.String() {
		t.Fatalf("published message identity or payload changed")
	}
}

func streamMessageCount(t *testing.T, jetstream nats.JetStreamContext, stream string) uint64 {
	t.Helper()
	info, err := jetstream.StreamInfo(stream)
	if err != nil {
		t.Fatal(err)
	}
	return info.State.Msgs
}
