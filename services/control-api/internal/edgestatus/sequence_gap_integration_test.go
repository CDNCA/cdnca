//go:build integration

package edgestatus

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/nodeserving"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

type gapHarness struct {
	pool           *pgxpool.Pool
	connection     *nats.Conn
	js             nats.JetStreamContext
	consumer       *NATSConsumer
	consumerConfig NATSConsumerConfig
	validator      *Validator
	validatorConf  ValidatorConfig
	store          *Store
	processor      *Processor
	prefix         string
}

func newGapHarness(t *testing.T) gapHarness {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if databaseURL == "" || natsURL == "" {
		t.Skip("TEST_DATABASE_URL and CDNCA_TEST_NATS_URL are required")
	}
	ctx := context.Background()
	pool, adminPool, schema := openStatusTestDatabase(t, databaseURL)
	t.Cleanup(func() {
		if _, err := adminPool.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop integration schema: %v", err)
		}
		pool.Close()
		adminPool.Close()
	})
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	connection, err := nats.Connect(natsURL, nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	stream, durable := "EDGE_STATUS_GAP_"+suffix, "edge_status_gap_"+suffix
	prefix := "cdnca.integration.gap" + suffix + ".deployment-status"
	subjects := []string{prefix + ".*", prefix + ".generic-v2.*.*"}
	if _, err := js.AddStream(&nats.StreamConfig{Name: stream, Subjects: subjects, Storage: nats.MemoryStorage}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = js.DeleteStream(stream) })
	consumerConfig := NATSConsumerConfig{
		Stream: stream, SubjectPrefix: prefix, Durable: durable,
		AckWait: 30 * time.Second, FetchTimeout: 500 * time.Millisecond, OperationTimeout: 2 * time.Second,
		NakDelay: 25 * time.Millisecond, MaxAckPending: 32, MaxWaiting: 8,
	}
	if _, err := js.AddConsumer(stream, &nats.ConsumerConfig{
		Durable: durable, DeliverPolicy: nats.DeliverAllPolicy, AckPolicy: nats.AckExplicitPolicy,
		AckWait: consumerConfig.AckWait, MaxDeliver: -1, FilterSubjects: subjects,
		ReplayPolicy: nats.ReplayInstantPolicy, MaxAckPending: consumerConfig.MaxAckPending,
		MaxWaiting: consumerConfig.MaxWaiting, MaxRequestBatch: 1, MaxRequestExpires: consumerConfig.FetchTimeout,
	}); err != nil {
		t.Fatal(err)
	}
	consumer, err := NewNATSConsumer(connection, consumerConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = consumer.Close() })
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

	return gapHarness{pool: pool, connection: connection, js: js, consumer: consumer, consumerConfig: consumerConfig,
		validator: validator, validatorConf: validatorConfig, store: store, processor: processor, prefix: prefix}
}

// 11-26 fresh install (NATS stopped 8 s): the node's STARTED, delivered to a
// control-api that then exited, came back only after AckWait; the restarted
// control-api got STAGED..HEALTHY first and terminated them as invalid
// transitions. The deployment stayed at STARTED and the node's heartbeats,
// naming the new configuration, were dropped for good. Statuses ahead of a
// missing one now wait (nak) and the deployment converges to healthy once it
// arrives; a wrong status right after the stored one, or any after the
// deployment ended, is still refused.
func TestSequenceGapWaitsForPredecessorAndConverges(t *testing.T) {
	h := newGapHarness(t)
	ctx := context.Background()
	pool, js, consumer, validator, store, processor, prefix := h.pool, h.js, h.consumer, h.validator, h.store, h.processor, h.prefix
	apply := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	projectFixtureState(t, store, validator, prefix, apply, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	// STAGED (2) is late; the later ones arrive first and must not be dropped.
	for sequence, state := range map[uint64]agentv1.NodeDeploymentState{
		3: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		4: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
		5: agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
	} {
		publishStatus(t, js, prefix, apply.nodeID, fixtureStatus(apply, state, sequence))
	}
	for range 3 {
		disposition, err := processor.Process(ctx, nextStatusDelivery(t, consumer))
		if err != nil || disposition != DispositionNak {
			t.Fatalf("status ahead of a missing one = (%q, %v), want nak", disposition, err)
		}
	}
	assertDeploymentState(t, pool, apply.deploymentID, "delivered", 1)
	publishStatus(t, js, prefix, apply.nodeID,
		fixtureStatus(apply, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, 2))
	deadline := time.Now().Add(15 * time.Second)
	for state := ""; state != "healthy"; {
		if time.Now().After(deadline) {
			t.Fatalf("deployment did not converge, state %q", state)
		}
		fetchCtx, cancel := context.WithTimeout(ctx, time.Second)
		delivery, err := consumer.Next(fetchCtx)
		cancel()
		if err != nil && !errors.Is(err, ErrNoMessage) && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if delivery != nil {
			if disposition, err := processor.Process(ctx, delivery); err != nil || disposition == DispositionTerm {
				t.Fatalf("process during convergence = (%q, %v)", disposition, err)
			}
		}
		if err := pool.QueryRow(ctx, `SELECT state FROM node_deployments WHERE id=$1`, apply.deploymentID).Scan(&state); err != nil {
			t.Fatal(err)
		}
	}
	assertDeploymentState(t, pool, apply.deploymentID, "healthy", 5)
	assertNodeConfig(t, pool, apply.nodeID, apply.configID, apply.previousConfigID)

	// A wrong status right after the stored one is still refused.
	wrong := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	projectFixtureState(t, store, validator, prefix, wrong, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	healthyNext := fixtureStatus(wrong, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 2)
	if _, err := store.Project(ctx, decodeFixtureStatus(t, validator, prefix, wrong.nodeID, healthyNext)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("adjacent invalid transition error = %v", err)
	}
	// After the deployment ended nothing can fill the gap: refused too.
	ended := seedDeployment(t, pool, "apply", uuid.Nil, uuid.Nil)
	projectFixtureState(t, store, validator, prefix, ended, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	failedStatus := fixtureStatus(ended, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_FAILED, 2)
	failedStatus.RunningConfigUnchanged = true
	failedStatus.Error = validProtocolError()
	projectFixtureStatus(t, store, validator, prefix, ended, failedStatus)
	afterEnd := fixtureStatus(ended, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED, 4)
	if _, err := store.Project(ctx, decodeFixtureStatus(t, validator, prefix, ended.nodeID, afterEnd)); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("gap after the deployment ended error = %v", err)
	}
}

// The deployments already stranded before the upgrade: their later statuses
// were terminated (the durable consumer never delivers them again) and only
// an earlier one is stored. The status runtime replays them from the stream
// once at start, so the deployment reaches healthy and the node's running
// configuration is recorded, with no republish or manual step.
func TestStrandedDeploymentConvergesByStartupReplay(t *testing.T) {
	h := newGapHarness(t)
	stranded := seedStrandedDeployment(t, h)
	// A finished deployment of another node is not touched.
	done := seedDeployment(t, h.pool, "apply", uuid.Nil, uuid.Nil)
	for sequence, state := range []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
	} {
		projectFixtureState(t, h.store, h.validator, h.prefix, done, state, uint64(sequence)+1)
	}
	runtime := startGapRuntime(t, h, nil)
	waitDeploymentHealthy(t, h, stranded)
	assertNodeConfig(t, h.pool, stranded.nodeID, stranded.configID, stranded.previousConfigID)
	assertDeploymentState(t, h.pool, done.deploymentID, "healthy", 5)
	waitReplayDone(t, runtime)
}

// A round that hits a transient error does not complete the replay: it is
// retried, and the next round recovers the deployment.
func TestStrandedReplayRetriesAfterTransientError(t *testing.T) {
	h := newGapHarness(t)
	stranded := seedStrandedDeployment(t, h)
	var calls atomic.Int32
	runtime := startGapRuntime(t, h, func(replay *strandedReplay) {
		replay.retry = 50 * time.Millisecond
		project := replay.project
		replay.project = func(ctx context.Context, envelope Envelope) (ProjectionResult, error) {
			if calls.Add(1) == 1 {
				return ProjectionResult{}, errors.New("read deployment status high water: conn closed")
			}
			return project(ctx, envelope)
		}
	})
	waitDeploymentHealthy(t, h, stranded)
	waitReplayDone(t, runtime)
	if failures := runtime.replay.failures.Load(); failures != 1 {
		t.Fatalf("failed replay rounds = %d, want 1", failures)
	}
}

// Running deployments beyond one page are all replayed.
func TestStrandedReplayCoversEveryPage(t *testing.T) {
	h := newGapHarness(t)
	stranded := []deploymentFixture{seedStrandedDeployment(t, h), seedStrandedDeployment(t, h), seedStrandedDeployment(t, h)}
	runtime := startGapRuntime(t, h, func(replay *strandedReplay) { replay.pageSize = 1 })
	for _, fixture := range stranded {
		waitDeploymentHealthy(t, h, fixture)
	}
	waitReplayDone(t, runtime)
}

// A node subject is read in bounded batches, each projected before the next
// is read from where the last one stopped: with batches of at most 2 messages
// read and (bytes limit 1) one status kept, a stranded deployment whose
// statuses span several batches still converges to healthy.
func TestStrandedReplayReadsInBoundedBatches(t *testing.T) {
	h := newGapHarness(t)
	stranded := seedStrandedDeployment(t, h)
	runtime := startGapRuntime(t, h, func(replay *strandedReplay) {
		replay.maxMessages = 2
		replay.maxBytes = 1
	})
	waitDeploymentHealthy(t, h, stranded)
	waitReplayDone(t, runtime)
	assertNodeConfig(t, h.pool, stranded.nodeID, stranded.configID, stranded.previousConfigID)
	if batches := runtime.replay.batches.Load(); batches < 3 {
		t.Fatalf("replay batches = %d, want at least 3", batches)
	}
}

// A status whose predecessor comes in a later batch waits for it: stream
// order HEALTHY, ACTIVATED, PRECHECKED with one message per batch.
func TestStrandedReplayCarriesGapIntoLaterBatch(t *testing.T) {
	h := newGapHarness(t)
	fixture := seedDeployment(t, h.pool, "apply", uuid.Nil, uuid.Nil)
	projectFixtureState(t, h.store, h.validator, h.prefix, fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	projectFixtureState(t, h.store, h.validator, h.prefix, fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, 2)
	for _, step := range []struct {
		state    agentv1.NodeDeploymentState
		sequence uint64
	}{
		{agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5},
		{agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED, 4},
		{agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED, 3},
	} {
		publishStatus(t, h.js, h.prefix, fixture.nodeID, fixtureStatus(fixture, step.state, step.sequence))
	}
	for range 3 {
		if err := nextStatusDelivery(t, h.consumer).Term(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	runtime := startGapRuntime(t, h, func(replay *strandedReplay) { replay.maxMessages = 1 })
	waitDeploymentHealthy(t, h, fixture)
	waitReplayDone(t, runtime)
	if batches := runtime.replay.batches.Load(); batches < 3 {
		t.Fatalf("replay batches = %d, want at least 3", batches)
	}
}

// Stream order 1,2,4,5,6,7,3 through the multi-tenant queue path (1, 2
// acknowledged, the rest terminated by the earlier control-api), two messages
// per batch: 4..7 wait across batches for 3 and the deployment reaches
// healthy with the node's configuration identity bound (same scenario as the
// Codex review's independent test).
func TestStrandedReplayEarlierBatchGapsWaitForLaterPredecessor(t *testing.T) {
	h := newGapHarness(t)
	fixture := seedDeployment(t, h.pool, "apply", uuid.Nil, uuid.Nil)
	digest := deploymentArtifactDigest087(t, h.pool, fixture)
	scope := fixture.scopeID.String()
	states := []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_AGENT_QUEUED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STARTED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
	}
	for _, i := range []int{0, 1, 3, 4, 5, 6, 2} {
		status := fixtureStatus(fixture, states[i], uint64(i+1))
		status.ConfigurationScopeId = &scope
		status.ActiveConfigIdentityCapability = statusIdentityCapability()
		if i == 6 {
			status.ActiveConfigIdentity = statusIdentityBytes087(fixture.configID, digest)
			status.Checks = []*agentv1.CheckResult{activeConfigProbeCheck()}
		}
		publishStatus(t, h.js, h.prefix, fixture.nodeID, status)
		delivery := nextStatusDelivery(t, h.consumer)
		if i < 2 {
			if disposition, err := h.processor.Process(t.Context(), delivery); err != nil || disposition != DispositionAck {
				t.Fatalf("initial sequence %d = %q, %v", i+1, disposition, err)
			}
		} else if err := delivery.Term(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	runtime := startGapRuntime(t, h, func(replay *strandedReplay) { replay.maxMessages = 2 })
	waitReplayDone(t, runtime)
	assertDeploymentState(t, h.pool, fixture.deploymentID, "healthy", 7)
	assertStatusIdentity087(t, h.pool, fixture, digest, true)
}

// The statuses carried to the next batch are bounded: with room for one,
// stream order HEALTHY, ACTIVATED, PRECHECKED (one per batch) leaves HEALTHY
// out of the first round; the round moved the deployment, so another round
// reads it again and the deployment still reaches healthy.
func TestStrandedReplayBoundsWaitingStatuses(t *testing.T) {
	h := newGapHarness(t)
	fixture := seedDeployment(t, h.pool, "apply", uuid.Nil, uuid.Nil)
	projectFixtureState(t, h.store, h.validator, h.prefix, fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	projectFixtureState(t, h.store, h.validator, h.prefix, fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, 2)
	for _, step := range []struct {
		state    agentv1.NodeDeploymentState
		sequence uint64
	}{
		{agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY, 5},
		{agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED, 4},
		{agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED, 3},
	} {
		publishStatus(t, h.js, h.prefix, fixture.nodeID, fixtureStatus(fixture, step.state, step.sequence))
	}
	for range 3 {
		if err := nextStatusDelivery(t, h.consumer).Term(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	runtime := startGapRuntime(t, h, func(replay *strandedReplay) {
		replay.maxMessages = 1
		replay.maxWaiting = 1
	})
	waitReplayDone(t, runtime)
	assertDeploymentState(t, h.pool, fixture.deploymentID, "healthy", 5)
	if dropped := runtime.replay.dropped.Load(); dropped < 1 {
		t.Fatalf("deferred waiting statuses = %d, want at least 1", dropped)
	}
	if rounds := runtime.replay.rounds.Load(); rounds < 2 {
		t.Fatalf("replay rounds = %d, want at least 2", rounds)
	}
}

// After a control-api stop longer than the deployment deadline, a deployment
// the node finished (its statuses still unprojected in the stream) must not be
// timed out before the startup replay: with the hold it ends healthy, without
// it the timeout fails it for good (the control deployment).
func TestOverdueDeploymentReplayedBeforeTimeout(t *testing.T) {
	h := newGapHarness(t)
	ctx := context.Background()
	makeOverdue := func(fixture deploymentFixture) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, h.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE node_deployments SET created_at=clock_timestamp()-interval '1 hour',
				deadline_at=clock_timestamp()-interval '10 minutes'
				WHERE id=$1`, fixture.deploymentID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	timeouts, err := nodeserving.NewStore(h.pool)
	if err != nil {
		t.Fatal(err)
	}
	control := seedStrandedDeployment(t, h)
	makeOverdue(control)
	if err := nodeserving.NewDeploymentTimeoutEvaluator(timeouts).Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	assertDeploymentState(t, h.pool, control.deploymentID, "failed", 2)

	stranded := seedStrandedDeployment(t, h)
	makeOverdue(stranded)
	runtime, err := NewRuntime(h.pool, h.connection, h.consumerConfig, h.validatorConf, nil)
	if err != nil {
		t.Fatal(err)
	}
	held := nodeserving.NewDeploymentTimeoutEvaluator(timeouts).HoldUntil(runtime.ReplayDone)
	// The sweep runs before the status runtime starts and keeps running.
	if err := held.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	stopped := make(chan error, 1)
	go func() { stopped <- runtime.Run(runCtx) }()
	defer func() { cancel(); <-stopped; _ = runtime.Close() }()
	for deadline := time.Now().Add(20 * time.Second); !runtime.ReplayDone(); time.Sleep(20 * time.Millisecond) {
		if err := held.Evaluate(ctx); err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("replay did not complete")
		}
	}
	if err := held.Evaluate(ctx); err != nil {
		t.Fatal(err)
	}
	assertDeploymentState(t, h.pool, stranded.deploymentID, "healthy", 5)
	assertNodeConfig(t, h.pool, stranded.nodeID, stranded.configID, stranded.previousConfigID)
	var timedOut int
	if err := h.pool.QueryRow(ctx, `SELECT count(*) FROM node_deployment_timeouts WHERE deployment_id=$1`,
		stranded.deploymentID).Scan(&timedOut); err != nil || timedOut != 0 {
		t.Fatalf("timeouts of the replayed deployment = %d, %v", timedOut, err)
	}
}

// seedStrandedDeployment stores DELIVERED and STAGED of a new deployment and
// terminates its PRECHECKED, ACTIVATED and HEALTHY in the stream.
func seedStrandedDeployment(t *testing.T, h gapHarness) deploymentFixture {
	t.Helper()
	fixture := seedDeployment(t, h.pool, "apply", uuid.Nil, uuid.Nil)
	projectFixtureState(t, h.store, h.validator, h.prefix, fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_DELIVERED, 1)
	projectFixtureState(t, h.store, h.validator, h.prefix, fixture, agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_STAGED, 2)
	for sequence, state := range []agentv1.NodeDeploymentState{
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_PRECHECKED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_ACTIVATED,
		agentv1.NodeDeploymentState_NODE_DEPLOYMENT_STATE_HEALTHY,
	} {
		publishStatus(t, h.js, h.prefix, fixture.nodeID, fixtureStatus(fixture, state, uint64(sequence)+3))
	}
	for range 3 { // what the earlier control-api did with them
		if err := nextStatusDelivery(t, h.consumer).Term(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	assertDeploymentState(t, h.pool, fixture.deploymentID, "staged", 2)
	return fixture
}

func startGapRuntime(t *testing.T, h gapHarness, configure func(*strandedReplay)) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(h.pool, h.connection, h.consumerConfig, h.validatorConf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if configure != nil {
		configure(runtime.replay)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- runtime.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-stopped
		_ = runtime.Close()
	})
	return runtime
}

func waitDeploymentHealthy(t *testing.T, h gapHarness, fixture deploymentFixture) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		var state string
		if err := h.pool.QueryRow(context.Background(), `SELECT state FROM node_deployments WHERE id=$1`,
			fixture.deploymentID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state == "healthy" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stranded deployment state %q, want healthy", state)
		}
		time.Sleep(100 * time.Millisecond)
	}
	assertDeploymentState(t, h.pool, fixture.deploymentID, "healthy", 5)
}

func waitReplayDone(t *testing.T, runtime *Runtime) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !runtime.replay.done.Load() {
		if time.Now().After(deadline) {
			t.Fatal("replay did not complete")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
