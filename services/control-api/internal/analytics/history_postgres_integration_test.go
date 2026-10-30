package analytics

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresIngestHistoryFixtureV1 struct {
	pool       *pgxpool.Pool
	history    IngestHistoryAuthorityV1
	generation IngestHistoryGenerationV1
	clock      *postgresIngestHistoryClockV1
	config     PostgresIngestHistoryConfig
}

type postgresIngestHistoryClockV1 struct {
	mu  sync.Mutex
	now time.Time
}

// Now advances 1ms per read like a real clock: 098 receipt/stream guards require
// updated_at to strictly increase on every state write, so a frozen clock makes
// Receive followed by MarkPrepared fail as "state is not monotonic" (P9802).
func (clock *postgresIngestHistoryClockV1) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(time.Millisecond)
	return clock.now
}

func (clock *postgresIngestHistoryClockV1) Advance(delta time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(delta)
	clock.mu.Unlock()
}

func TestPostgresIngestHistoryReceiptReplayConflictAndAtomicProgress(t *testing.T) {
	fixture := openPostgresIngestHistoryFixtureV1(t)
	receipt := postgresIngestReceiptV1(t, fixture.generation, 41, "postgres-receipt")
	state, err := fixture.history.Receive(t.Context(), receipt)
	if err != nil || state != IngestReceiptStateReceived {
		t.Fatalf("first receive = (%v, %v)", state, err)
	}
	state, err = fixture.history.Receive(t.Context(), receipt)
	if err != nil || state != IngestReceiptStateReceived {
		t.Fatalf("same replay = (%v, %v)", state, err)
	}
	conflict := receipt
	conflict.MessageID += "-conflict"
	conflict.ReceiptIdentitySHA256[0]++
	if _, err := fixture.history.Receive(t.Context(), conflict); !errors.Is(err, ErrIngestReceiptConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}

	missing := postgresIngestReceiptV1(t, fixture.generation, 42, "missing-before-prepare")
	if _, err := fixture.history.MarkPrepared(t.Context(), missing); !errors.Is(err, ErrIngestReceiptConflict) {
		t.Fatalf("missing receipt prepare error = %v", err)
	}
	assertPostgresIngestHistoryStateV1(t, fixture.pool, fixture.generation.HistoryEpoch, 41, "received", 40)

	progress, err := fixture.history.MarkPrepared(t.Context(), receipt)
	if err != nil || progress.PreparedStreamFloor != 41 || progress.CommittedStreamAckFloor != 40 {
		t.Fatalf("prepared progress = (%#v, %v)", progress, err)
	}
	assertPostgresIngestHistoryStateV1(t, fixture.pool, fixture.generation.HistoryEpoch, 41, "prepared", 41)
	if err := fixture.history.MarkBrokerAckObserved(t.Context(), receipt.Key); err != nil {
		t.Fatal(err)
	}
	assertPostgresIngestHistoryStateV1(t, fixture.pool, fixture.generation.HistoryEpoch, 41, "broker_ack_observed", 41)
	if progress, err := fixture.history.MarkPrepared(t.Context(), receipt); err != nil || progress.PreparedStreamFloor != 41 {
		t.Fatalf("non-regressing prepared replay = (%#v, %v)", progress, err)
	}
}

func TestPostgresIngestHistoryConcurrentReplayAndConflict(t *testing.T) {
	fixture := openPostgresIngestHistoryFixtureV1(t)
	receipt := postgresIngestReceiptV1(t, fixture.generation, 41, "postgres-concurrent")
	if _, err := fixture.history.Receive(t.Context(), receipt); err != nil {
		t.Fatal(err)
	}
	conflict := receipt
	conflict.MessageID += "-conflict"
	conflict.ReceiptIdentitySHA256[0]++
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, candidate := range []IngestReceiptV1{receipt, conflict} {
		candidate := candidate
		go func() {
			<-start
			_, err := fixture.history.Receive(context.Background(), candidate)
			results <- err
		}()
	}
	close(start)
	var replayed, conflicted int
	for range 2 {
		err := <-results
		switch {
		case err == nil:
			replayed++
		case errors.Is(err, ErrIngestReceiptConflict):
			conflicted++
		default:
			t.Fatalf("concurrent receive error = %v", err)
		}
	}
	if replayed != 1 || conflicted != 1 {
		t.Fatalf("concurrent replay/conflict = %d/%d, want 1/1", replayed, conflicted)
	}
}

func TestPostgresIngestHistoryRecoveryClaimTakeoverAndFencing(t *testing.T) {
	fixture := openPostgresIngestHistoryFixtureV1(t)
	receipt := postgresIngestReceiptV1(t, fixture.generation, 41, "postgres-recovery")
	if _, err := fixture.history.Receive(t.Context(), receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.history.MarkPrepared(t.Context(), receipt); err != nil {
		t.Fatal(err)
	}
	if err := fixture.history.ScheduleRecovery(t.Context(), fixture.generation); err != nil {
		t.Fatal(err)
	}

	secondConfig := fixture.config
	secondConfig.ClaimedBy = "postgres-history-worker-2"
	secondHistory, secondGeneration, err := OpenPostgresIngestHistoryV1(t.Context(), fixture.pool, secondConfig)
	if err != nil || secondGeneration != fixture.generation {
		t.Fatalf("second authority = (%#v, %v)", secondGeneration, err)
	}
	start := make(chan struct{})
	type claimResult struct {
		claim IngestRecoveryClaimV1
		ok    bool
		err   error
	}
	claims := make(chan claimResult, 2)
	for _, authority := range []IngestHistoryAuthorityV1{fixture.history, secondHistory} {
		authority := authority
		go func() {
			<-start
			claim, ok, err := authority.ClaimScheduledRecovery(context.Background(), fixture.generation)
			claims <- claimResult{claim: claim, ok: ok, err: err}
		}()
	}
	close(start)
	var first IngestRecoveryClaimV1
	winners := 0
	for range 2 {
		result := <-claims
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.ok {
			winners++
			first = result.claim
		}
	}
	if winners != 1 || first.RecoveryID == "" || first.Token == "" || first.ClaimedBy == "" {
		t.Fatalf("claim winners=%d claim=%#v", winners, first)
	}
	snapshot := IngestBrokerHistorySnapshotV1{Generation: fixture.generation, ConsumerAckFloor: 1, StreamAckFloor: 41}
	wrong := first
	wrong.Token = uuid.NewString()
	if _, err := fixture.history.ReconcileBroker(t.Context(), wrong, snapshot); !errors.Is(err, ErrIngestRecoveryFenced) {
		t.Fatalf("wrong-token reconcile error = %v", err)
	}
	if err := fixture.history.CompleteScheduledRecovery(t.Context(), wrong); !errors.Is(err, ErrIngestRecoveryFenced) {
		t.Fatalf("wrong-token complete error = %v", err)
	}
	wrongID := first
	wrongID.RecoveryID = uuid.NewString()
	if _, err := fixture.history.ReconcileBroker(t.Context(), wrongID, snapshot); !errors.Is(err, ErrIngestRecoveryFenced) {
		t.Fatalf("wrong-recovery reconcile error = %v", err)
	}
	if err := fixture.history.CompleteScheduledRecovery(t.Context(), wrongID); !errors.Is(err, ErrIngestRecoveryFenced) {
		t.Fatalf("wrong-recovery complete error = %v", err)
	}
	var brokerFloor uint64
	var reconciled, completed bool
	if err := fixture.pool.QueryRow(t.Context(), `SELECT stream.broker_stream_ack_floor,
		recovery.reconciled_at IS NOT NULL,recovery.completed_at IS NOT NULL
		FROM analytics_history_streams stream
		JOIN analytics_history_recoveries recovery USING(history_epoch)
		WHERE recovery.recovery_id=$1`, first.RecoveryID).Scan(&brokerFloor, &reconciled, &completed); err != nil {
		t.Fatal(err)
	}
	if brokerFloor != 40 || reconciled || completed {
		t.Fatalf("fenced recovery mutated floor/reconciled/completed = %d/%t/%t", brokerFloor, reconciled, completed)
	}

	fixture.clock.Advance(fixture.config.RecoveryLease)
	second, ok, err := secondHistory.ClaimScheduledRecovery(t.Context(), fixture.generation)
	if err != nil || !ok || second.Token == first.Token || second.RecoveryID != first.RecoveryID {
		t.Fatalf("expired takeover = (%#v, %t, %v), first=%#v", second, ok, err, first)
	}
	if _, err := fixture.history.ReconcileBroker(t.Context(), first, snapshot); !errors.Is(err, ErrIngestRecoveryFenced) {
		t.Fatalf("stale reconcile error = %v", err)
	}
	if err := fixture.history.CompleteScheduledRecovery(t.Context(), first); !errors.Is(err, ErrIngestRecoveryFenced) {
		t.Fatalf("stale complete error = %v", err)
	}
	progress, err := secondHistory.ReconcileBroker(t.Context(), second, snapshot)
	if err != nil || progress.CommittedStreamAckFloor != 41 {
		t.Fatalf("takeover reconcile = (%#v, %v)", progress, err)
	}
	if err := secondHistory.CompleteScheduledRecovery(t.Context(), second); err != nil {
		t.Fatal(err)
	}
	if claim, ok, err := fixture.history.ClaimScheduledRecovery(t.Context(), fixture.generation); err != nil || ok || claim != (IngestRecoveryClaimV1{}) {
		t.Fatalf("completed recovery claim = (%#v, %t, %v)", claim, ok, err)
	}
}

func TestOpenPostgresIngestHistoryRequiresOneActiveGeneration(t *testing.T) {
	fixture := openPostgresIngestHistoryFixtureV1(t)
	missing := fixture.config
	missing.StreamName += "_missing"
	if history, generation, err := OpenPostgresIngestHistoryV1(t.Context(), fixture.pool, missing); !errors.Is(err, ErrIngestHistoryGenerationUnavailable) || history != nil || generation != (IngestHistoryGenerationV1{}) {
		t.Fatalf("missing active generation = (%#v, %#v, %v)", history, generation, err)
	}
	retiredAt := fixture.clock.Now().Add(time.Second)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE analytics_history_streams
		SET retired_at=$2,revision=revision+1,updated_at=$2 WHERE history_epoch=$1`,
		fixture.generation.HistoryEpoch, retiredAt); err != nil {
		t.Fatal(err)
	}
	if history, generation, err := OpenPostgresIngestHistoryV1(t.Context(), fixture.pool, fixture.config); !errors.Is(err, ErrIngestHistoryGenerationUnavailable) || history != nil || generation != (IngestHistoryGenerationV1{}) {
		t.Fatalf("retired generation = (%#v, %#v, %v)", history, generation, err)
	}
}

func openPostgresIngestHistoryFixtureV1(t *testing.T) postgresIngestHistoryFixtureV1 {
	t.Helper()
	// 迁移到发布头的独立 schema（或 TEST_DATABASE_TEMPLATE 克隆），不再依赖外部预先迁移的库。
	pool := databasetest.MigratedPool(t, nil)
	var receipts, recoveries bool
	if err := pool.QueryRow(t.Context(), `SELECT to_regclass('analytics_ingest_receipts') IS NOT NULL,
		to_regclass('analytics_history_recoveries') IS NOT NULL`).Scan(&receipts, &recoveries); err != nil {
		t.Fatal(err)
	}
	if !receipts || !recoveries {
		t.Fatal("analytics ingest history migration 098 is required")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	// 131 起实时期望计数按 (scope,tenant)/(scope,site) 外键落库，插入 0 行即判回执冲突
	// （history_postgres.go persistRealtimeExpectedCountsTx）；种下回执里事件所属的租户与站点。
	scopeID, ownerID := uuid.New(), uuid.New()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO tenants(id,display_name) VALUES($1,'analytics-history-tenant')`, []any{testTenantID}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, testTenantID}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'analytics-history-owner','owner','x')`, []any{ownerID}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, ownerID}},
			{`INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
				VALUES($1,1,$2,$3,'analytics-history.example.test',ARRAY['192.0.2.10'],ARRAY['192.0.2.10'],$3,$3)`,
				[]any{testSiteID, scopeID, ownerID}},
			{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{testSiteID}},
			{`INSERT INTO site_origins(site_id,position,host,port,level) VALUES($1,1,'192.0.2.10',80,0)`, []any{testSiteID}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed analytics history tenant and site: %v", err)
	}
	var installationID string
	err := pool.QueryRow(t.Context(), `SELECT installation_id FROM control_installation_entitlement WHERE singleton=true`).Scan(&installationID)
	if errors.Is(err, pgx.ErrNoRows) {
		installationID = "analytics-history-" + uuid.NewString()
		_, err = pool.Exec(t.Context(), `INSERT INTO control_installation_entitlement(
			singleton,installation_id,last_status,created_at,updated_at
		) VALUES(true,$1,'uninstalled',$2,$2)`, installationID, now)
	}
	if err != nil {
		t.Fatal(err)
	}
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")
	streamName := "ANALYTICS_HISTORY_" + suffix
	durableName := "analytics_history_" + suffix
	streamCreated := now.UnixNano()
	consumerCreated := streamCreated + int64(time.Second)
	historyEpoch := uuid.NewString()
	if _, err := pool.Exec(t.Context(), `INSERT INTO analytics_history_streams(
		installation_id,nats_domain,stream_name,durable_name,
		stream_created_unix_nano,consumer_created_unix_nano,history_epoch,
		history_start_sequence,history_start_at,legacy_baseline_kind,
		legacy_baseline_at,legacy_baseline_sha256,
		broker_consumer_ack_floor,broker_stream_ack_floor,prepared_stream_floor,
		revision,last_reconciled_at,created_at,updated_at
	) VALUES($1,'',$2,$3,$4,$5,$6,41,$7,'current_visible_state',$7,
		decode(repeat('ab',32),'hex'),0,40,40,1,$7,$7,$7)`,
		installationID, streamName, durableName, streamCreated, consumerCreated, historyEpoch, now); err != nil {
		t.Fatal(err)
	}
	clock := &postgresIngestHistoryClockV1{now: now.Add(2 * time.Second)}
	config := PostgresIngestHistoryConfig{
		InstallationID: installationID, StreamName: streamName, DurableName: durableName,
		ClaimedBy: "postgres-history-worker-1", RecoveryLease: time.Minute, Now: clock.Now,
	}
	history, generation, err := OpenPostgresIngestHistoryV1(t.Context(), pool, config)
	if err != nil {
		t.Fatal(err)
	}
	return postgresIngestHistoryFixtureV1{
		pool: pool, history: history, generation: generation, clock: clock, config: config,
	}
}

func postgresIngestReceiptV1(t *testing.T, generation IngestHistoryGenerationV1, sequence uint64, messageID string) IngestReceiptV1 {
	t.Helper()
	decoded := authorityDecodedIngestV1(t)
	decoded.MessageID = messageID
	decoded.InstallationID = generation.InstallationID
	for index := range decoded.AccessEvents {
		decoded.AccessEvents[index].InstallationID = generation.InstallationID
	}
	receipt, err := NewIngestReceiptV1(generation, sequence, decoded)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func assertPostgresIngestHistoryStateV1(
	t *testing.T,
	pool *pgxpool.Pool,
	historyEpoch string,
	sequence uint64,
	wantState string,
	wantPreparedFloor uint64,
) {
	t.Helper()
	var state string
	var preparedFloor uint64
	if err := pool.QueryRow(t.Context(), `SELECT receipt.state,stream.prepared_stream_floor
		FROM analytics_ingest_receipts receipt
		JOIN analytics_history_streams stream USING(history_epoch)
		WHERE receipt.history_epoch=$1 AND receipt.stream_sequence=$2`, historyEpoch, sequence).Scan(&state, &preparedFloor); err != nil {
		t.Fatal(err)
	}
	if state != wantState || preparedFloor != wantPreparedFloor {
		t.Fatalf("receipt state/prepared floor = %s/%d, want %s/%d", state, preparedFloor, wantState, wantPreparedFloor)
	}
}
