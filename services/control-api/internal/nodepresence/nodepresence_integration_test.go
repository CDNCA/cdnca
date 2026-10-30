//go:build integration

package nodepresence

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
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
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"google.golang.org/protobuf/proto"
)

const offlineTestAdvisoryLock int64 = 77314590217

type failingAckDelivery struct {
	Delivery
}

func (d failingAckDelivery) Ack(context.Context) error { return errors.New("injected ACK failure") }

type integrationRedisServer struct {
	address string
	dir     string
	command *exec.Cmd
	done    chan error
	logs    lockedBuffer
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(value)
}

func (b *lockedBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buffer.Reset()
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func TestNodePresencePostgresRedisJetStreamLifecycle(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if databaseURL == "" || natsURL == "" {
		t.Skip("TEST_DATABASE_URL and CDNCA_TEST_NATS_URL are required")
	}
	ctx := context.Background()
	pool, adminPool, schema := openPresenceTestDatabase(t, databaseURL)
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
	latestMigrationVersion := currentMigrationVersion(t, pool)
	nodeID := seedPresenceNode(t, pool)

	redisServer := newIntegrationRedisServer(t)
	redisServer.Start(t)
	defer redisServer.Stop(t)
	redisClient := newIntegrationRedisClient(t, redisServer.URL())
	defer redisClient.Close()

	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	stream := "NODE_PRESENCE_" + suffix
	durable := "node_presence_" + suffix
	subjectPrefix := "cdnca.integration." + suffix + ".heartbeats"
	natsConnection := connectPresenceNATS(t, natsURL)
	defer natsConnection.Close()
	js, err := natsConnection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{
		Name: stream, Subjects: []string{subjectPrefix + ".*"}, Retention: nats.LimitsPolicy,
		Storage: nats.FileStorage, Duplicates: time.Minute,
	}); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = js.DeleteStream(stream) }()

	consumerConfig := NATSConsumerConfig{
		Stream: stream, SubjectPrefix: subjectPrefix, Durable: durable,
		AckWait: 250 * time.Millisecond, FetchTimeout: time.Second,
		OperationTimeout: time.Second, NakDelay: 50 * time.Millisecond,
		MaxAckPending: 32, MaxWaiting: 8,
	}
	missingStreamConfig := consumerConfig
	missingStreamConfig.Stream = "MISSING_" + suffix
	if _, err := NewNATSConsumer(natsConnection, missingStreamConfig); err == nil {
		t.Fatal("durable consumer accepted a missing heartbeat stream")
	}
	consumer := newIntegrationConsumer(t, natsConnection, consumerConfig)
	defer consumer.Close()
	mismatchedConsumerConfig := consumerConfig
	mismatchedConsumerConfig.AckWait = 500 * time.Millisecond
	if _, err := NewNATSConsumer(natsConnection, mismatchedConsumerConfig); err == nil {
		t.Fatal("durable consumer accepted mismatched existing ACK configuration")
	}
	const leaseTTL = 2 * time.Second
	validator, err := NewValidator(ValidatorConfig{
		SubjectPrefix: subjectPrefix, MaxHeartbeatBytes: 1 << 20,
		MaxActiveDeployments: 128, MaxFutureSkew: 5 * time.Minute, MaxPastAge: leaseTTL,
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(pool, leaseTTL)
	if err != nil {
		t.Fatal(err)
	}
	leases, err := NewRedisLeaseStore(redisClient, "cdnca:presence-test:"+suffix, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	processor, err := NewProcessor(validator, store, leases, consumerConfig.NakDelay, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	backlogNodeID := seedPresenceNode(t, pool)
	expired := validPresenceHeartbeat(1, 1, time.Now().Add(-leaseTTL-time.Millisecond))
	publishPresenceHeartbeat(t, js, subjectPrefix, backlogNodeID, expired)
	processPresenceDelivery(t, processor, nextPresenceDelivery(t, consumer), DispositionTerm)
	assertNoPresenceProjection(t, pool, backlogNodeID)
	if exists, err := leases.Exists(ctx, backlogNodeID); err != nil || exists {
		t.Fatalf("expired backlog lease = (%t, %v)", exists, err)
	}
	fresh := validPresenceHeartbeat(1, 2, time.Now())
	freshVersion := "2.4.1"
	fresh.AgentVersion = &freshVersion
	publishPresenceHeartbeat(t, js, subjectPrefix, backlogNodeID, fresh)
	processPresenceDelivery(t, processor, nextPresenceDelivery(t, consumer), DispositionAck)
	assertPresenceProjection(t, pool, backlogNodeID, StatusOnline, 1, 2, 2)
	assertLeaseVersion(t, redisClient, leases.key(backlogNodeID), 1, 2)
	assertConfirmedRequestID(t, pool, backlogNodeID, uuid.MustParse(fresh.Event.RequestId))
	assertConfirmedAgentVersion(t, pool, backlogNodeID, &freshVersion)
	leaseExpiryBefore, err := redisClient.PExpireTime(ctx, leases.key(backlogNodeID)).Result()
	if err != nil {
		t.Fatal(err)
	}
	expiredRefresh := validPresenceHeartbeat(1, 3, time.Now().Add(-leaseTTL-time.Millisecond))
	publishPresenceHeartbeat(t, js, subjectPrefix, backlogNodeID, expiredRefresh)
	processPresenceDelivery(t, processor, nextPresenceDelivery(t, consumer), DispositionTerm)
	assertPresenceProjection(t, pool, backlogNodeID, StatusOnline, 1, 2, 2)
	leaseExpiryAfter, err := redisClient.PExpireTime(ctx, leases.key(backlogNodeID)).Result()
	if err != nil {
		t.Fatal(err)
	}
	if leaseExpiryAfter != leaseExpiryBefore {
		t.Fatalf("expired backlog refreshed lease: before=%s after=%s", leaseExpiryBefore, leaseExpiryAfter)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM node_presence WHERE node_id = $1`, backlogNodeID); err != nil {
		t.Fatal(err)
	}
	if err := redisClient.Del(ctx, leases.key(backlogNodeID)).Err(); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	first := validPresenceHeartbeat(1, 1, now)
	publishPresenceHeartbeat(t, js, subjectPrefix, nodeID, first)
	delivery := nextPresenceDelivery(t, consumer)
	disposition, err := processor.Process(ctx, failingAckDelivery{Delivery: delivery})
	if disposition != DispositionAck || err == nil {
		t.Fatalf("injected ACK result = (%q, %v)", disposition, err)
	}
	assertPresenceProjection(t, pool, nodeID, StatusOnline, 1, 1, 2)
	assertLeaseVersion(t, redisClient, leases.key(nodeID), 1, 1)
	assertAuditTransitions(t, pool, nodeID, 1, 0)
	if err := consumer.Close(); err != nil {
		t.Fatal(err)
	}
	consumer = newIntegrationConsumer(t, natsConnection, consumerConfig)
	defer consumer.Close()
	delivery = nextPresenceDelivery(t, consumer)
	processPresenceDelivery(t, processor, delivery, DispositionAck)
	assertPresenceProjection(t, pool, nodeID, StatusOnline, 1, 1, 2)
	assertAuditTransitions(t, pool, nodeID, 1, 0)
	firstEnvelope, err := validator.Decode(subjectPrefix+"."+nodeID.String(), marshalHeartbeat(t, first))
	if err != nil {
		t.Fatal(err)
	}
	oldProjection, err := store.Project(ctx, firstEnvelope)
	if err != nil || oldProjection.Outcome != OutcomeDuplicate {
		t.Fatalf("duplicate projection = (%+v, %v)", oldProjection, err)
	}

	third := validPresenceHeartbeat(1, 3, time.Now())
	second := validPresenceHeartbeat(1, 2, time.Now())
	publishPresenceHeartbeat(t, js, subjectPrefix, nodeID, third)
	publishPresenceHeartbeat(t, js, subjectPrefix, nodeID, second)
	processPresenceDelivery(t, processor, nextPresenceDelivery(t, consumer), DispositionAck)
	processPresenceDelivery(t, processor, nextPresenceDelivery(t, consumer), DispositionAck)
	assertPresenceProjection(t, pool, nodeID, StatusOnline, 1, 3, 4)
	assertLeaseVersion(t, redisClient, leases.key(nodeID), 1, 3)
	assertAuditTransitions(t, pool, nodeID, 1, 0)
	if confirmed, err := store.ConfirmOnline(ctx, oldProjection); err != nil || confirmed {
		t.Fatalf("superseded online confirmation = (%t, %v)", confirmed, err)
	}
	assertConfirmedVersion(t, pool, nodeID, 1, 3)
	thirdEnvelope, err := validator.Decode(subjectPrefix+"."+nodeID.String(), marshalHeartbeat(t, third))
	if err != nil {
		t.Fatal(err)
	}
	currentProjection, err := store.Project(ctx, thirdEnvelope)
	if err != nil || currentProjection.Outcome != OutcomeDuplicate {
		t.Fatalf("current duplicate projection = (%+v, %v)", currentProjection, err)
	}
	conflictingProjection := currentProjection
	conflictingProjection.Digest[0] ^= 0xff
	if confirmed, err := store.ConfirmOnline(ctx, conflictingProjection); err != nil || confirmed {
		t.Fatalf("digest-conflicting online confirmation = (%t, %v)", confirmed, err)
	}
	assertConfirmedVersion(t, pool, nodeID, 1, 3)
	if err := leases.Put(ctx, LeaseRecord{
		NodeID: nodeID, SessionEpoch: 1, HeartbeatSequence: 1,
		EventID: oldProjection.EventID, LastSeenAt: time.Now(), ExpiresAt: time.Now().Add(leaseTTL),
	}); err != nil {
		t.Fatal(err)
	}
	assertLeaseVersion(t, redisClient, leases.key(nodeID), 1, 3)

	fourth := validPresenceHeartbeat(1, 4, time.Now())
	publishPresenceHeartbeat(t, js, subjectPrefix, nodeID, fourth)
	brokenPool := openPresenceSchemaPool(t, databaseURL, schema)
	brokenStore, err := NewStore(brokenPool, leaseTTL)
	if err != nil {
		t.Fatal(err)
	}
	brokenPool.Close()
	brokenProcessor, err := NewProcessor(validator, brokenStore, leases, consumerConfig.NakDelay, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	processPresenceDelivery(t, brokenProcessor, nextPresenceDelivery(t, consumer), DispositionNak)
	processPresenceDelivery(t, processor, nextPresenceDelivery(t, consumer), DispositionAck)
	assertPresenceProjection(t, pool, nodeID, StatusOnline, 1, 4, 6)
	assertConfirmedVersion(t, pool, nodeID, 1, 4)
	lastSeenBeforeRedisFailure := confirmedLastSeen(t, pool, nodeID)

	fifth := validPresenceHeartbeat(1, 5, time.Now())
	unleasedNodeID := seedPresenceNode(t, pool)
	unleasedFirst := validPresenceHeartbeat(1, 1, time.Now())
	publishPresenceHeartbeat(t, js, subjectPrefix, nodeID, fifth)
	publishPresenceHeartbeat(t, js, subjectPrefix, unleasedNodeID, unleasedFirst)
	delivery = nextPresenceDelivery(t, consumer)
	redisServer.Stop(t)
	processPresenceDelivery(t, processor, delivery, DispositionNak)
	processPresenceDelivery(t, processor, nextPresenceDelivery(t, consumer), DispositionNak)
	assertPresenceProjection(t, pool, nodeID, StatusOnline, 1, 5, 7)
	assertConfirmedVersion(t, pool, nodeID, 1, 4)
	if actual := confirmedLastSeen(t, pool, nodeID); !actual.Equal(lastSeenBeforeRedisFailure) {
		t.Fatalf("Redis failure refreshed confirmed last_seen: before=%s after=%s", lastSeenBeforeRedisFailure, actual)
	}
	assertPresenceProjection(t, pool, unleasedNodeID, StatusOffline, 1, 1, 1)
	assertAuditTransitions(t, pool, unleasedNodeID, 0, 0)
	_ = redisClient.Close()
	redisServer.Start(t)
	redisClient = newIntegrationRedisClient(t, redisServer.URL())
	defer redisClient.Close()
	leases, err = NewRedisLeaseStore(redisClient, "cdnca:presence-test:"+suffix, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	processor, err = NewProcessor(validator, store, leases, consumerConfig.NakDelay, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	processPresenceDelivery(t, processor, nextPresenceDelivery(t, consumer), DispositionAck)
	processPresenceDelivery(t, processor, nextPresenceDelivery(t, consumer), DispositionAck)
	assertLeaseVersion(t, redisClient, leases.key(nodeID), 1, 5)
	assertLeaseVersion(t, redisClient, leases.key(unleasedNodeID), 1, 1)
	assertPresenceProjection(t, pool, nodeID, StatusOnline, 1, 5, 8)
	assertConfirmedVersion(t, pool, nodeID, 1, 5)
	assertPresenceProjection(t, pool, unleasedNodeID, StatusOnline, 1, 1, 2)
	assertAuditTransitions(t, pool, unleasedNodeID, 1, 0)
	if _, err := pool.Exec(ctx, `DELETE FROM node_presence WHERE node_id = $1`, unleasedNodeID); err != nil {
		t.Fatal(err)
	}

	publishRawPresence(t, js, subjectPrefix+"."+nodeID.String(), []byte{0xff}, uuid.NewString())
	processPresenceDelivery(t, processor, nextPresenceDelivery(t, consumer), DispositionTerm)
	assertPresenceProjection(t, pool, nodeID, StatusOnline, 1, 5, 8)

	eventuallyPresence(t, 4*time.Second, func() bool {
		exists, err := leases.Exists(ctx, nodeID)
		return err == nil && !exists
	}, "versioned Redis lease did not expire")
	workers := make([]*OfflineWorker, 8)
	for index := range workers {
		workers[index], err = NewOfflineWorker(store, leases, leaseTTL, 20*time.Millisecond, time.Second, 100)
		if err != nil {
			t.Fatal(err)
		}
	}
	var wait sync.WaitGroup
	transitionCounts := make(chan int, len(workers))
	for _, worker := range workers {
		wait.Add(1)
		go func(worker *OfflineWorker) {
			defer wait.Done()
			count, runErr := worker.RunOnce(ctx)
			if runErr != nil {
				t.Errorf("offline worker: %v", runErr)
			}
			transitionCounts <- count
		}(worker)
	}
	wait.Wait()
	close(transitionCounts)
	totalTransitions := 0
	for count := range transitionCounts {
		totalTransitions += count
	}
	if totalTransitions != 1 {
		t.Fatalf("multi-worker offline transitions = %d, want 1", totalTransitions)
	}
	assertPresenceProjection(t, pool, nodeID, StatusOffline, 1, 5, 9)
	assertAuditTransitions(t, pool, nodeID, 1, 1)

	sixth := validPresenceHeartbeat(2, 1, time.Now())
	publishPresenceHeartbeat(t, js, subjectPrefix, nodeID, sixth)
	processPresenceDelivery(t, processor, nextPresenceDelivery(t, consumer), DispositionAck)
	assertPresenceProjection(t, pool, nodeID, StatusOnline, 2, 1, 11)
	assertAuditTransitions(t, pool, nodeID, 2, 1)

	eventuallyPresence(t, 4*time.Second, func() bool {
		exists, err := leases.Exists(ctx, nodeID)
		return err == nil && !exists
	}, "recovery lease did not expire")
	installOfflineBlockingTrigger(t, pool)
	lockConnection, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lockConnection.Release()
	if _, err := lockConnection.Exec(ctx, "SELECT pg_advisory_lock($1)", offlineTestAdvisoryLock); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = lockConnection.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", offlineTestAdvisoryLock)
	}()
	worker := workers[0]
	offlineDone := make(chan struct {
		count int
		err   error
	}, 1)
	go func() {
		count, runErr := worker.RunOnce(ctx)
		offlineDone <- struct {
			count int
			err   error
		}{count: count, err: runErr}
	}()
	eventuallyPresence(t, time.Second, func() bool {
		var waiting bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_stat_activity
				WHERE wait_event_type = 'Lock' AND query ILIKE '%UPDATE node_presence%'
			)`).Scan(&waiting)
		return err == nil && waiting
	}, "offline worker did not hold the presence row before the recovery race")
	seventh := validPresenceHeartbeat(2, 2, time.Now())
	publishPresenceHeartbeat(t, js, subjectPrefix, nodeID, seventh)
	delivery = nextPresenceDelivery(t, consumer)
	recoveryDone := make(chan error, 1)
	go func() {
		disposition, processErr := processor.Process(ctx, delivery)
		if processErr == nil && disposition != DispositionAck {
			processErr = fmt.Errorf("recovery disposition = %s", disposition)
		}
		recoveryDone <- processErr
	}()
	select {
	case err := <-recoveryDone:
		t.Fatalf("recovery completed before offline row lock released: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if _, err := lockConnection.Exec(ctx, "SELECT pg_advisory_unlock($1)", offlineTestAdvisoryLock); err != nil {
		t.Fatal(err)
	}
	offlineResult := <-offlineDone
	if offlineResult.err != nil || offlineResult.count != 1 {
		t.Fatalf("racing offline result = %+v", offlineResult)
	}
	if err := <-recoveryDone; err != nil {
		t.Fatal(err)
	}
	removeOfflineBlockingTrigger(t, pool)
	assertPresenceProjection(t, pool, nodeID, StatusOnline, 2, 2, 14)
	assertAuditTransitions(t, pool, nodeID, 3, 2)

	eventuallyPresence(t, time.Second, func() bool {
		info, err := js.ConsumerInfo(stream, durable)
		return err == nil && info.NumAckPending == 0 && info.NumPending == 0
	}, "durable heartbeat consumer did not settle")

	// Migration 268's down is a deliberate one-way gate (P2682), so the 017
	// round trip runs on its own schema with only 1..020 loaded.
	roundTrip, roundTripAdmin, roundTripSchema := openPresenceTestDatabase(t, databaseURL)
	defer roundTrip.Close()
	defer roundTripAdmin.Close()
	defer func() {
		if _, err := roundTripAdmin.Exec(ctx, "DROP SCHEMA "+pgx.Identifier{roundTripSchema}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop round-trip schema: %v", err)
		}
	}()
	const roundTripHead = 20
	if err := databasetest.MigrateThrough(ctx, roundTrip, "up", roundTripHead); err != nil {
		t.Fatal(err)
	}
	for version := currentMigrationVersion(t, roundTrip); version > 17; version = currentMigrationVersion(t, roundTrip) {
		if err := databasetest.MigrateThrough(ctx, roundTrip, "down", roundTripHead); err != nil {
			t.Fatalf("migrate down from version %d: %v", version, err)
		}
	}
	assertMigrationVersion(t, roundTrip, 17)
	assertAgentVersionColumn(t, roundTrip, true)
	if err := databasetest.MigrateThrough(ctx, roundTrip, "down", roundTripHead); err != nil {
		t.Fatal(err)
	}
	assertMigrationVersion(t, roundTrip, 16)
	assertNodePresenceTable(t, roundTrip, true)
	assertAgentVersionColumn(t, roundTrip, false)
	if err := database.Migrate(ctx, roundTrip, "up"); err != nil {
		t.Fatal(err)
	}
	assertMigrationVersion(t, roundTrip, latestMigrationVersion)
	assertAgentVersionColumn(t, roundTrip, true)
}

func TestNodePresenceOfflineAuditUsesConfirmedRequestID(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	pool, adminPool, schema := openPresenceTestDatabase(t, databaseURL)
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
	nodeID := seedPresenceNode(t, pool)

	redisServer := newIntegrationRedisServer(t)
	redisServer.Start(t)
	defer redisServer.Stop(t)
	redisClient := newIntegrationRedisClient(t, redisServer.URL())
	defer redisClient.Close()
	keyPrefix := "cdnca:presence-request-test:" + strings.ReplaceAll(uuid.NewString(), "-", "")
	leases, err := NewRedisLeaseStore(redisClient, keyPrefix, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	const leaseTTL = 10 * time.Second
	store, err := NewStore(pool, leaseTTL)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Truncate(time.Microsecond)
	clock := base
	store.now = func() time.Time { return clock }
	validator, err := NewValidator(ValidatorConfig{
		SubjectPrefix: "cdnca.request-audit.heartbeats", MaxHeartbeatBytes: 1 << 20,
		MaxActiveDeployments: 128, MaxFutureSkew: time.Minute, MaxPastAge: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	validator.now = func() time.Time { return base.Add(time.Minute) }

	first := validPresenceHeartbeat(1, 1, base)
	firstRequestID := uuid.MustParse(first.Event.RequestId)
	firstEnvelope, err := validator.Decode(
		"cdnca.request-audit.heartbeats."+nodeID.String(), marshalHeartbeat(t, first),
	)
	if err != nil {
		t.Fatal(err)
	}
	firstProjection, err := store.Project(ctx, firstEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := leases.Put(ctx, leaseForProjection(firstProjection)); err != nil {
		t.Fatal(err)
	}
	if confirmed, err := store.ConfirmOnline(ctx, firstProjection); err != nil || !confirmed {
		t.Fatalf("confirm first heartbeat = (%t, %v)", confirmed, err)
	}
	assertConfirmedRequestID(t, pool, nodeID, firstRequestID)

	clock = base.Add(4 * time.Second)
	second := validPresenceHeartbeat(1, 2, base)
	secondRequestID := uuid.MustParse(second.Event.RequestId)
	secondEnvelope, err := validator.Decode(
		"cdnca.request-audit.heartbeats."+nodeID.String(), marshalHeartbeat(t, second),
	)
	if err != nil {
		t.Fatal(err)
	}
	secondProjection, err := store.Project(ctx, secondEnvelope)
	if err != nil || secondProjection.Outcome != OutcomeAdvanced {
		t.Fatalf("project second heartbeat = (%+v, %v)", secondProjection, err)
	}
	redisServer.Stop(t)
	if err := leases.Put(ctx, leaseForProjection(secondProjection)); err == nil {
		t.Fatal("second heartbeat lease unexpectedly succeeded while Redis was unavailable")
	}
	assertConfirmedVersion(t, pool, nodeID, 1, 1)
	assertConfirmedRequestID(t, pool, nodeID, firstRequestID)
	_ = redisClient.Close()
	redisServer.Start(t)
	redisClient = newIntegrationRedisClient(t, redisServer.URL())
	defer redisClient.Close()
	leases, err = NewRedisLeaseStore(redisClient, keyPrefix, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	clock = base.Add(leaseTTL + time.Millisecond)
	worker, err := NewOfflineWorker(store, leases, leaseTTL, time.Second, time.Second, 10)
	if err != nil {
		t.Fatal(err)
	}
	worker.now = func() time.Time { return clock }
	if changed, err := worker.RunOnce(ctx); err != nil || changed != 1 {
		t.Fatalf("first offline transition = (%d, %v)", changed, err)
	}
	assertOfflineAuditRequestIDs(t, pool, nodeID, []uuid.UUID{firstRequestID})

	retryProjection, err := store.Project(ctx, secondEnvelope)
	if err != nil || retryProjection.Outcome != OutcomeDuplicate || !retryProjection.RefreshLease {
		t.Fatalf("retry second projection = (%+v, %v)", retryProjection, err)
	}
	if err := leases.Put(ctx, leaseForProjection(retryProjection)); err != nil {
		t.Fatal(err)
	}
	if confirmed, err := store.ConfirmOnline(ctx, retryProjection); err != nil || !confirmed {
		t.Fatalf("confirm retried second heartbeat = (%t, %v)", confirmed, err)
	}
	assertConfirmedRequestID(t, pool, nodeID, secondRequestID)

	clock = secondProjection.LeaseExpiresAt.Add(time.Millisecond)
	if err := redisClient.Del(ctx, leases.key(nodeID)).Err(); err != nil {
		t.Fatal(err)
	}
	if changed, err := worker.RunOnce(ctx); err != nil || changed != 1 {
		t.Fatalf("second offline transition = (%d, %v)", changed, err)
	}
	assertOfflineAuditRequestIDs(t, pool, nodeID, []uuid.UUID{firstRequestID, secondRequestID})
	assertNodePresenceEvents(t, pool, nodeID)
}

// assertNodePresenceEvents: every presence transition committed one
// node.status_changed fact for the node's tenant (migration 369), in order,
// with the previous status and without the node address.
func assertNodePresenceEvents(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID) {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT coalesce(payload->>'previous_status','-')||'>'||(payload->>'status'),
		payload::text FROM domain_event_outbox_368 WHERE event_type='io.cdnca.node.v1.status_changed' AND subject=$1
		AND payload->>'kind'='presence' ORDER BY subject_sequence`, "node/"+nodeID.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var transitions []string
	for rows.Next() {
		var transition, payload string
		if err := rows.Scan(&transition, &payload); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(payload, "ipv4") || strings.Contains(payload, "ipv6") || strings.Contains(payload, "address") {
			t.Fatalf("node event exposes an address: %s", payload)
		}
		transitions = append(transitions, transition)
	}
	got := strings.Join(transitions, ",")
	if rows.Err() != nil || !strings.HasSuffix(got, "offline>online,online>offline,offline>online,online>offline") {
		t.Fatalf("node presence events = %s, %v", got, rows.Err())
	}
}

func openPresenceTestDatabase(t *testing.T, databaseURL string) (*pgxpool.Pool, *pgxpool.Pool, string) {
	t.Helper()
	ctx := context.Background()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := adminPool.Ping(ctx); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	schema := "node_presence_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^node_presence_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema name %q", schema)
	}
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		adminPool.Close()
		t.Fatal(err)
	}
	pool := openPresenceSchemaPool(t, databaseURL, schema)
	return pool, adminPool, schema
}

func openPresenceSchemaPool(t *testing.T, databaseURL, schema string) *pgxpool.Pool {
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

func seedPresenceNode(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	tenantID, scopeID, userID, nodeID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(context.Background(), `INSERT INTO tenants (id, display_name) VALUES ($1, 'Presence integration tenant')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1, 'tenant', $2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO users (id, username, display_name, password_hash)
		VALUES ($1, $2, 'Presence tester', 'not-used')`, userID, "presence-"+strings.ReplaceAll(userID.String(), "-", "")[:16]); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(context.Background(), `
		INSERT INTO nodes (id, scope_id, name, admin_state, created_by_user_id, display_id)
		VALUES ($1, $2, $3, 'active', $4, 1)`, nodeID, scopeID, "presence-node-"+strings.ReplaceAll(nodeID.String(), "-", "")[:8], userID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	return nodeID
}

func connectPresenceNATS(t *testing.T, url string) *nats.Conn {
	t.Helper()
	connection, err := nats.Connect(url, nats.Name("control-api-node-presence-integration"), nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	return connection
}

func newIntegrationConsumer(t *testing.T, connection *nats.Conn, config NATSConsumerConfig) *NATSConsumer {
	t.Helper()
	consumer, err := NewNATSConsumer(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	return consumer
}

func nextPresenceDelivery(t *testing.T, consumer *NATSConsumer) Delivery {
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

func publishPresenceHeartbeat(t *testing.T, js nats.JetStreamContext, prefix string, nodeID uuid.UUID, heartbeat proto.Message) {
	t.Helper()
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(heartbeat)
	if err != nil {
		t.Fatal(err)
	}
	eventID := heartbeat.(*agentv1.Heartbeat).Event.EventId
	publishRawPresence(t, js, prefix+"."+nodeID.String(), payload, eventID)
}

func publishRawPresence(t *testing.T, js nats.JetStreamContext, subject string, payload []byte, messageID string) {
	t.Helper()
	if _, err := js.Publish(subject, payload, nats.MsgId(messageID)); err != nil {
		t.Fatal(err)
	}
}

func processPresenceDelivery(t *testing.T, processor *Processor, delivery Delivery, expected string) {
	t.Helper()
	disposition, err := processor.Process(context.Background(), delivery)
	if err != nil || disposition != expected {
		t.Fatalf("Process() = (%q, %v), want %s", disposition, err, expected)
	}
}

func assertPresenceProjection(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID, status string, epoch, sequence, revision int64) {
	t.Helper()
	var actualStatus string
	var actualEpoch, actualSequence, actualRevision int64
	err := pool.QueryRow(context.Background(), `
		SELECT status, session_epoch, heartbeat_sequence, revision
		FROM node_presence WHERE node_id = $1`, nodeID).Scan(&actualStatus, &actualEpoch, &actualSequence, &actualRevision)
	if err != nil {
		t.Fatal(err)
	}
	if actualStatus != status || actualEpoch != epoch || actualSequence != sequence || actualRevision != revision {
		t.Fatalf("presence = status=%s epoch=%d sequence=%d revision=%d", actualStatus, actualEpoch, actualSequence, actualRevision)
	}
}

func assertNoPresenceProjection(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID) {
	t.Helper()
	var exists bool
	if err := pool.QueryRow(context.Background(), `
		SELECT EXISTS (SELECT 1 FROM node_presence WHERE node_id = $1)`, nodeID).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatalf("node %s has a presence projection", nodeID)
	}
}

func assertConfirmedVersion(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID, epoch, sequence int64) {
	t.Helper()
	var actualEpoch, actualSequence int64
	if err := pool.QueryRow(context.Background(), `
		SELECT confirmed_session_epoch, confirmed_heartbeat_sequence
		FROM node_presence WHERE node_id = $1`, nodeID).Scan(&actualEpoch, &actualSequence); err != nil {
		t.Fatal(err)
	}
	if actualEpoch != epoch || actualSequence != sequence {
		t.Fatalf("confirmed presence version = (%d,%d), want (%d,%d)", actualEpoch, actualSequence, epoch, sequence)
	}
}

func confirmedLastSeen(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID) time.Time {
	t.Helper()
	var value time.Time
	if err := pool.QueryRow(context.Background(), `SELECT last_seen_at FROM node_presence WHERE node_id = $1`, nodeID).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func assertConfirmedRequestID(t *testing.T, pool *pgxpool.Pool, nodeID, expected uuid.UUID) {
	t.Helper()
	var actual uuid.UUID
	if err := pool.QueryRow(context.Background(), `
		SELECT confirmed_request_id FROM node_presence WHERE node_id = $1`, nodeID).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("confirmed request ID = %s, want %s", actual, expected)
	}
}

func assertConfirmedAgentVersion(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID, expected *string) {
	t.Helper()
	var actual *string
	if err := pool.QueryRow(context.Background(), `
		SELECT confirmed_agent_version FROM node_presence WHERE node_id = $1`, nodeID).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if !equalOptionalString(actual, expected) {
		t.Fatalf("confirmed agent version = %v, want %v", actual, expected)
	}
}

func assertOfflineAuditRequestIDs(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID, expected []uuid.UUID) {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT request_id
		FROM audit_events
		WHERE resource_type = 'node' AND resource_id = $1 AND action = 'node.presence.offline'
		ORDER BY stream_position`, nodeID.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	actual := make([]uuid.UUID, 0, len(expected))
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			t.Fatal(err)
		}
		parsed, err := uuid.Parse(value)
		if err != nil {
			t.Fatalf("offline audit request ID %q is not a UUID", value)
		}
		actual = append(actual, parsed)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(actual) != len(expected) {
		t.Fatalf("offline audit request IDs = %v, want %v", actual, expected)
	}
	for index := range expected {
		if actual[index] != expected[index] {
			t.Fatalf("offline audit request IDs = %v, want %v", actual, expected)
		}
	}
}

func leaseForProjection(projection ProjectionResult) LeaseRecord {
	return LeaseRecord{
		NodeID: projection.NodeID, SessionEpoch: projection.SessionEpoch,
		HeartbeatSequence: projection.HeartbeatSequence, EventID: projection.EventID,
		LastSeenAt: projection.ProjectedAt, ExpiresAt: projection.LeaseExpiresAt,
	}
}

func assertLeaseVersion(t *testing.T, client *redis.Client, key string, epoch, sequence int64) {
	t.Helper()
	values, err := client.HMGet(context.Background(), key, "session_epoch", "heartbeat_sequence").Result()
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(values[0]) != strconv.FormatInt(epoch, 10) || fmt.Sprint(values[1]) != strconv.FormatInt(sequence, 10) {
		t.Fatalf("lease version = %v", values)
	}
}

func assertAuditTransitions(t *testing.T, pool *pgxpool.Pool, nodeID uuid.UUID, online, offline int) {
	t.Helper()
	var actualOnline, actualOffline int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FILTER (WHERE action = 'node.presence.online'),
		       count(*) FILTER (WHERE action = 'node.presence.offline')
		FROM audit_events
		WHERE resource_type = 'node' AND resource_id = $1`, nodeID.String()).Scan(&actualOnline, &actualOffline); err != nil {
		t.Fatal(err)
	}
	if actualOnline != online || actualOffline != offline {
		t.Fatalf("audit transitions online=%d offline=%d", actualOnline, actualOffline)
	}
}

func installOfflineBlockingTrigger(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), fmt.Sprintf(`
		CREATE FUNCTION block_offline_transition() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			PERFORM pg_advisory_xact_lock(%d);
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER block_offline_transition
		BEFORE UPDATE OF status ON node_presence
		FOR EACH ROW WHEN (NEW.status = 'offline')
		EXECUTE FUNCTION block_offline_transition();`, offlineTestAdvisoryLock))
	if err != nil {
		t.Fatal(err)
	}
}

func removeOfflineBlockingTrigger(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		DROP TRIGGER block_offline_transition ON node_presence;
		DROP FUNCTION block_offline_transition();`); err != nil {
		t.Fatal(err)
	}
}

func assertMigrationVersion(t *testing.T, pool *pgxpool.Pool, expected int64) {
	t.Helper()
	var version int64
	if err := pool.QueryRow(context.Background(), "SELECT max(version) FROM schema_migrations").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != expected {
		t.Fatalf("migration version = %d, want %d", version, expected)
	}
}

func eventuallyPresence(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(message)
}

func newIntegrationRedisServer(t *testing.T) *integrationRedisServer {
	t.Helper()
	if _, err := exec.LookPath("redis-server"); err != nil {
		t.Skip("redis-server is required")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return &integrationRedisServer{address: "127.0.0.1:" + strconv.Itoa(port), dir: t.TempDir()}
}

func (s *integrationRedisServer) URL() string { return "redis://" + s.address + "/0" }

func (s *integrationRedisServer) Start(t *testing.T) {
	t.Helper()
	if s.command != nil {
		t.Fatal("integration Redis is already running")
	}
	s.logs.Reset()
	port := strings.TrimPrefix(s.address, "127.0.0.1:")
	s.command = exec.Command("redis-server", "--bind", "127.0.0.1", "--port", port,
		"--protected-mode", "no", "--save", "", "--appendonly", "no", "--dir", filepath.Clean(s.dir))
	s.command.Stdout = &s.logs
	s.command.Stderr = &s.logs
	if err := s.command.Start(); err != nil {
		t.Fatal(err)
	}
	s.done = make(chan error, 1)
	go func(command *exec.Cmd) { s.done <- command.Wait() }(s.command)
	client := newIntegrationRedisClient(t, s.URL())
	defer client.Close()
	eventuallyPresence(t, 3*time.Second, func() bool {
		return client.Ping(context.Background()).Err() == nil
	}, "integration Redis did not start: "+s.logs.String())
}

func (s *integrationRedisServer) Stop(t *testing.T) {
	t.Helper()
	if s.command == nil {
		return
	}
	if err := s.command.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.done:
	case <-time.After(3 * time.Second):
		_ = s.command.Process.Kill()
		<-s.done
		t.Fatal("integration Redis did not stop")
	}
	s.command = nil
	s.done = nil
}

func newIntegrationRedisClient(t *testing.T, url string) *redis.Client {
	t.Helper()
	options, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	options.DialTimeout = 250 * time.Millisecond
	options.ReadTimeout = 250 * time.Millisecond
	options.WriteTimeout = 250 * time.Millisecond
	options.MaxRetries = 0
	options.ContextTimeoutEnabled = true
	return redis.NewClient(options)
}
