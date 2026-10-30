package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

const (
	runtimeSmokeTenantID = "10000000-0000-4000-8000-000000000001"
	runtimeSmokeSiteID   = "20000000-0000-4000-8000-000000000001"
	runtimeSmokeNodeID   = "30000000-0000-4000-8000-000000000001"
	runtimeSmokeConfigID = "40000000-0000-4000-8000-000000000001"
	runtimeSmokeInstall  = "runtime-smoke-analytics-installation"
	runtimeSmokeEpochA   = "40000000-0000-4000-8000-000000000001"
	runtimeSmokeEpochB   = "40000000-0000-4000-8000-000000000002"
	runtimeSmokeEpochBad = "40000000-0000-4000-8000-000000000003"
)

func TestAnalyticsIngestRuntimeProcessLifecycle(t *testing.T) {
	if os.Getenv("ANALYTICS_INGEST_RUNTIME_INTEGRATION") != "1" {
		t.Skip("set ANALYTICS_INGEST_RUNTIME_INTEGRATION=1 to run the process runtime smoke")
	}
	setAnalyticsIngestRuntimeRequiredConfig(t)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load formal analytics ingest config: %v", err)
	}
	// runServer installs the evidence isolation provider before opening the
	// runtime (main.go); this smoke opens the runtime directly, so do the same.
	isolationKeyProvider, err := analytics.NewAESGCMIsolationKeyProvider(
		cfg.AnalyticsIngest.IsolationWrappingKeyID, cfg.AnalyticsIngest.IsolationWrappingKey)
	if err != nil {
		t.Fatalf("initialize analytics evidence isolation provider: %v", err)
	}
	cfg.AnalyticsIngest.JetStream.IsolationKeyProvider = isolationKeyProvider
	pool, err := pgxpool.New(t.Context(), cfg.DatabaseURL)
	if err != nil {
		t.Fatal("open task PostgreSQL pool")
	}
	defer pool.Close()
	if err := pool.Ping(t.Context()); err != nil {
		t.Fatal("ping task PostgreSQL")
	}
	seedRuntimeSmokeInstallation(t, pool)
	assertRuntimeHistoryRejectedBeforeNetwork(t, cfg, pool, "missing active generation")

	directClickHouseURL := cfg.AnalyticsIngest.ClickHouseURL
	target, err := url.Parse(directClickHouseURL)
	if err != nil {
		t.Fatal("parse task ClickHouse URL")
	}
	faults := newAnalyticsIngestFaultProxy(target)
	proxyServer := httptest.NewServer(faults)
	defer proxyServer.Close()
	cfg.AnalyticsIngest.ClickHouseURL = proxyServer.URL

	queryClient, err := analytics.NewClient(analytics.Config{
		Endpoint: directClickHouseURL, Database: cfg.AnalyticsIngest.ClickHouseDatabase,
		Username: cfg.AnalyticsIngest.ClickHouseUsername, Password: cfg.AnalyticsIngest.ClickHousePassword,
		QueryTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	publisher, err := nats.Connect(cfg.AnalyticsIngest.NATSURL,
		nats.UserInfo(cfg.AnalyticsIngest.NATSUsername, cfg.AnalyticsIngest.NATSPassword),
		nats.Name("cdnca-analytics-ingest-runtime-smoke-publisher"), nats.Timeout(time.Second), nats.NoReconnect())
	if err != nil {
		t.Fatal("connect task NATS publisher")
	}
	defer publisher.Close()
	jetstream, err := publisher.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal("open task JetStream context")
	}
	// The isolation evidence bucket is provisioned with NATS, not by the runtime
	// (scripts/native-runtime/native-nats-profile.json KV_AIEVIDENCE_*; analytics expectedEvidenceStore).
	jsConfig := cfg.AnalyticsIngest.JetStream
	evidenceDigest := sha256.Sum256([]byte(jsConfig.Stream + "\x00" + jsConfig.Durable))
	evidenceBucket := "AIEVIDENCE_" + hex.EncodeToString(evidenceDigest[:8])
	cleanupNATS := func() {
		_ = jetstream.DeleteConsumer(jsConfig.Stream, jsConfig.Durable)
		_ = jetstream.DeleteStream(jsConfig.Stream)
		_ = jetstream.DeleteStream(jsConfig.IsolationStream)
		_ = jetstream.DeleteStream("KV_" + evidenceBucket)
	}
	defer cleanupNATS()
	cleanupNATS()
	if _, err := jetstream.AddStream(&nats.StreamConfig{Name: "KV_" + evidenceBucket,
		Subjects: []string{"$KV." + evidenceBucket + ".>"}, Retention: nats.LimitsPolicy, MaxConsumers: -1, MaxMsgs: -1,
		MaxBytes: jsConfig.IsolationMaxBytes, Discard: nats.DiscardNew, MaxMsgsPerSubject: 1, MaxMsgSize: 2162688,
		Storage: nats.FileStorage, Replicas: jsConfig.Replicas, Duplicates: 2 * time.Minute,
		DenyDelete: true, AllowRollup: true, AllowDirect: true}); err != nil {
		t.Fatalf("provision task evidence bucket: %v", err)
	}
	if err := analytics.EnsureIngestJetStream(t.Context(), publisher, cfg.AnalyticsIngest.JetStream); err != nil {
		t.Fatalf("create task JetStream history identity: %v", err)
	}
	streamInfo, err := jetstream.StreamInfo(cfg.AnalyticsIngest.JetStream.Stream)
	if err != nil {
		t.Fatal("read task ingest stream identity")
	}
	consumerInfo, err := jetstream.ConsumerInfo(cfg.AnalyticsIngest.JetStream.Stream, cfg.AnalyticsIngest.JetStream.Durable)
	if err != nil {
		t.Fatal("read task ingest consumer identity")
	}
	seedRuntimeSmokeHistoryGeneration(t, pool, cfg, runtimeSmokeEpochA, streamInfo.Created, consumerInfo.Created)
	restoreDuplicate := corruptRuntimeSmokeDuplicateGeneration(t, pool, cfg, streamInfo.Created, consumerInfo.Created)
	assertRuntimeHistoryRejectedBeforeNetwork(t, cfg, pool, "duplicate active generation")
	restoreDuplicate()
	retireRuntimeSmokeHistoryGeneration(t, pool, runtimeSmokeEpochA)
	assertRuntimeHistoryRejectedBeforeNetwork(t, cfg, pool, "retired generation")
	if err := jetstream.DeleteConsumer(cfg.AnalyticsIngest.JetStream.Stream, cfg.AnalyticsIngest.JetStream.Durable); err != nil {
		t.Fatal("delete retired task consumer identity")
	}
	if err := analytics.EnsureIngestJetStream(t.Context(), publisher, cfg.AnalyticsIngest.JetStream); err != nil {
		t.Fatalf("recreate task JetStream consumer identity: %v", err)
	}
	consumerInfo, err = jetstream.ConsumerInfo(cfg.AnalyticsIngest.JetStream.Stream, cfg.AnalyticsIngest.JetStream.Durable)
	if err != nil {
		t.Fatal("read recreated task ingest consumer identity")
	}
	seedRuntimeSmokeHistoryGeneration(t, pool, cfg, runtimeSmokeEpochB, streamInfo.Created, consumerInfo.Created)
	assertRuntimeConnectorContracts(t, cfg, pool)

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	faults.unavailable.Store(true)
	if failedRuntime, openErr := openAnalyticsIngestRuntime(context.Background(), cfg, pool, logger, nats.Connect, proxyServer.Client()); openErr == nil || failedRuntime != nil || openErr.Error() != "verify analytics ingest ClickHouse" {
		t.Fatalf("unavailable startup did not fail closed: runtime=%v error=%v", failedRuntime, openErr)
	}
	faults.unavailable.Store(false)
	faults.rejectEmptyInsertStatus.Store(http.StatusForbidden)
	if failedRuntime, openErr := openAnalyticsIngestRuntime(context.Background(), cfg, pool, logger, nats.Connect, proxyServer.Client()); openErr == nil || failedRuntime != nil || openErr.Error() != "verify analytics ingest ClickHouse" {
		t.Fatalf("missing INSERT permission did not fail closed: runtime=%v error=%v", failedRuntime, openErr)
	}
	if faults.rejectedEmptyInserts.Load() == 0 {
		t.Fatal("startup permission gate did not issue a zero-row INSERT")
	}
	faults.rejectEmptyInsertStatus.Store(0)
	history, generation, err := analytics.OpenPostgresIngestHistoryV1(t.Context(), pool, analytics.PostgresIngestHistoryConfig{
		InstallationID: cfg.ControlInstallationID,
		StreamName:     cfg.AnalyticsIngest.JetStream.Stream,
		DurableName:    cfg.AnalyticsIngest.JetStream.Durable,
		ClaimedBy:      "analytics-ingest-runtime-smoke",
		RecoveryLease:  cfg.AnalyticsIngest.JetStream.OperationTimeout,
		Now:            time.Now,
	})
	if err != nil {
		t.Fatalf("open task PostgreSQL history authority: %v", err)
	}
	if err := history.ScheduleRecovery(t.Context(), generation); err != nil {
		t.Fatalf("schedule task history recovery: %v", err)
	}
	runtime, runCancel, runDone := startAnalyticsIngestRuntimeSmoke(t, cfg, pool, logger, proxyServer.Client())
	waitForRuntimeSmokeRecoveryCompleted(t, pool, generation.HistoryEpoch)
	now := time.Now().UTC().Truncate(time.Millisecond)
	filter := analytics.Filter{From: now.Truncate(time.Hour).Add(-time.Hour), To: now.Truncate(time.Hour).Add(time.Hour)}

	baseline := runtimeSmokeAccessEvent("runtime-baseline", now.Add(-4*time.Minute))
	baseline.ResponseBytes = 1024
	publishRuntimeSmokeEnvelope(t, jetstream, cfg.AnalyticsIngest.JetStream.Stream, "runtime-baseline-message", now,
		analytics.AccessEnvelopeType, []analytics.AccessEvent{baseline}, nil)
	security := runtimeSmokeSecurityEvent("runtime-security", now.Add(-3*time.Minute))
	publishRuntimeSmokeEnvelope(t, jetstream, cfg.AnalyticsIngest.JetStream.Stream, "runtime-security-message", now,
		analytics.SecurityEnvelopeType, nil, []analytics.SecurityEvent{security})
	waitForRuntimeSmokeSummary(t, queryClient, filter, 1, 1)
	waitForRuntimeSmokeReceipt(t, pool, "runtime-baseline-message", "broker_ack_observed")
	waitForRuntimeSmokeReceipt(t, pool, "runtime-security-message", "broker_ack_observed")

	faults.failCommittedInsert.Store(true)
	top := runtimeSmokeAccessEvent("runtime-restart", now.Add(-2*time.Minute))
	top.Host, top.Path, top.ClientIP = "top.example.test", "/top.js", "2001:db8::9"
	top.CountryCode, top.Carrier, top.ResponseBytes = "US", "carrier-top", 4096
	publishRuntimeSmokeEnvelope(t, jetstream, cfg.AnalyticsIngest.JetStream.Stream, "runtime-restart-message", now,
		analytics.AccessEnvelopeType, []analytics.AccessEvent{top}, nil)
	waitForRuntimeSmokeCondition(t, 10*time.Second, func() bool { return faults.committedFailures.Load() == 1 })
	waitForRuntimeSmokeCondition(t, 10*time.Second, func() bool { return runtime.Health().State == "degraded" })
	unknownToken := waitForRuntimeSmokeReceipt(t, pool, "runtime-restart-message", "received")
	stopAnalyticsIngestRuntimeSmoke(t, runtime, runCancel, runDone)

	runtime, runCancel, runDone = startAnalyticsIngestRuntimeSmoke(t, cfg, pool, logger, proxyServer.Client())
	waitForRuntimeSmokeSummary(t, queryClient, filter, 2, 1)
	if recoveredToken := waitForRuntimeSmokeReceipt(t, pool, "runtime-restart-message", "broker_ack_observed"); recoveredToken != unknownToken {
		t.Fatalf("unknown ClickHouse outcome token changed across restart: before=%q after=%q", unknownToken, recoveredToken)
	}

	poison := nats.NewMsg(analytics.IngestSubjectPrefix + "." + runtimeSmokeNodeID)
	poison.Header.Set(nats.MsgIdHdr, "runtime-poison-message")
	poison.Data = []byte(`{"schema_version":1,"secret":"poison-must-not-leak",`)
	if _, err := jetstream.PublishMsg(poison, nats.ExpectStream(cfg.AnalyticsIngest.JetStream.Stream)); err != nil {
		t.Fatal(err)
	}
	waitForRuntimeSmokeCondition(t, 10*time.Second, func() bool {
		info, infoErr := jetstream.StreamInfo(cfg.AnalyticsIngest.JetStream.IsolationStream)
		return infoErr == nil && info.State.Msgs == 1
	})

	faults.rejectWriteStatus.Store(http.StatusUnauthorized)
	recovery := runtimeSmokeAccessEvent("runtime-recovery", now.Add(-time.Minute))
	recovery.ResponseBytes = 2048
	publishRuntimeSmokeEnvelope(t, jetstream, cfg.AnalyticsIngest.JetStream.Stream, "runtime-recovery-message", now,
		analytics.AccessEnvelopeType, []analytics.AccessEvent{recovery}, nil)
	waitForRuntimeSmokeCondition(t, 10*time.Second, func() bool {
		info, infoErr := jetstream.ConsumerInfo(cfg.AnalyticsIngest.JetStream.Stream, cfg.AnalyticsIngest.JetStream.Durable)
		return infoErr == nil && runtime.Health().State == "degraded" && (info.NumPending > 0 || info.NumAckPending > 0)
	})
	summary, err := queryClient.Summary(context.Background(), analytics.AdminScope(), filter)
	if err != nil || summary.RequestCount != 2 {
		t.Fatalf("ClickHouse authorization failure advanced confirmed summary: summary=%#v error=%v", summary, err)
	}
	if faults.rejectedWrites.Load() == 0 {
		t.Fatal("runtime authorization fault was not exercised")
	}
	faults.rejectWriteStatus.Store(0)
	waitForRuntimeSmokeSummary(t, queryClient, filter, 3, 1)
	waitForRuntimeSmokeCondition(t, 5*time.Second, func() bool { return runtime.Health().State == "running" })

	faults.blockInsert.Store(true)
	shutdownEvent := runtimeSmokeAccessEvent("runtime-shutdown", now.Add(-30*time.Second))
	shutdownEvent.ResponseBytes = 512
	publishRuntimeSmokeEnvelope(t, jetstream, cfg.AnalyticsIngest.JetStream.Stream, "runtime-shutdown-message", now,
		analytics.AccessEnvelopeType, []analytics.AccessEvent{shutdownEvent}, nil)
	waitForRuntimeSmokeCondition(t, 10*time.Second, func() bool { return faults.blockedInserts.Load() > 0 })
	stopAnalyticsIngestRuntimeSmoke(t, runtime, runCancel, runDone)
	info, err := jetstream.ConsumerInfo(cfg.AnalyticsIngest.JetStream.Stream, cfg.AnalyticsIngest.JetStream.Durable)
	if err != nil || (info.NumPending == 0 && info.NumAckPending == 0) {
		t.Fatalf("graceful stop lost in-flight backlog: info=%#v error=%v", info, err)
	}

	faults.blockInsert.Store(false)
	runtime, runCancel, runDone = startAnalyticsIngestRuntimeSmoke(t, cfg, pool, logger, proxyServer.Client())
	waitForRuntimeSmokeSummary(t, queryClient, filter, 4, 1)
	stopAnalyticsIngestRuntimeSmoke(t, runtime, runCancel, runDone)

	summary, err = queryClient.Summary(context.Background(), analytics.AdminScope(), filter)
	if err != nil || summary.RequestCount != 4 || summary.RequestBytes != 400 || summary.ResponseBytes != 7680 ||
		summary.TotalBytes != 8080 || summary.Status2xx != 4 || summary.SecurityEvents != 1 {
		t.Fatalf("final runtime summary reconciliation = %#v, error=%v", summary, err)
	}
	for _, ranking := range []struct {
		dimension analytics.RankDimension
		want      string
	}{
		{analytics.RankByURL, "/top.js"},
		{analytics.RankByIP, "2001:db8::9"},
		{analytics.RankByDomain, "top.example.test"},
		{analytics.RankByRegion, "US"},
		{analytics.RankByCarrier, "carrier-top"},
	} {
		page, rankErr := queryClient.Rank(context.Background(), analytics.AdminScope(), filter, ranking.dimension, 10, "")
		if rankErr != nil || len(page.Items) == 0 || page.Items[0].Key != ranking.want ||
			page.Items[0].RequestCount != 1 || page.Items[0].ResponseBytes != 4096 {
			t.Fatalf("rank %s reconciliation = %#v, error=%v", ranking.dimension, page, rankErr)
		}
	}
	consumerInfo, err = jetstream.ConsumerInfo(cfg.AnalyticsIngest.JetStream.Stream, cfg.AnalyticsIngest.JetStream.Durable)
	if err != nil || consumerInfo.NumPending != 0 || consumerInfo.NumAckPending != 0 {
		t.Fatalf("final consumer backlog = %#v, error=%v", consumerInfo, err)
	}
	for _, forbidden := range []string{
		"poison-must-not-leak", cfg.AnalyticsIngest.NATSPassword, cfg.AnalyticsIngest.ClickHousePassword,
		cfg.AnalyticsIngest.NATSURL, cfg.AnalyticsIngest.ClickHouseURL,
	} {
		if forbidden != "" && strings.Contains(logs.String(), forbidden) {
			t.Fatalf("runtime logs exposed protected value: %s", logs.String())
		}
	}
	t.Logf("reconciled requests=%d security=%d restart_redeliveries=%d five_rankings=ok",
		summary.RequestCount, summary.SecurityEvents, faults.committedFailures.Load())

	cleanupNATS()
	if _, err := jetstream.StreamInfo(cfg.AnalyticsIngest.JetStream.Stream); !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatalf("task ingest stream cleanup error = %v", err)
	}
	if _, err := jetstream.StreamInfo(cfg.AnalyticsIngest.JetStream.IsolationStream); !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatalf("task isolation stream cleanup error = %v", err)
	}
}

func seedRuntimeSmokeInstallation(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := pool.Exec(t.Context(), `INSERT INTO control_installation_entitlement(
		singleton,installation_id,last_status,created_at,updated_at
	) VALUES(true,$1,'uninstalled',$2,$2)`, runtimeSmokeInstall, now); err != nil {
		t.Fatalf("seed task control installation: %v", err)
	}
	// 131 起实时期望计数按 (scope,tenant)/(scope,site) 外键落库，租户作用域缺失时插入 0 行即判
	// RECEIPT_CONFLICT（history_postgres.go persistRealtimeExpectedCountsTx）；种下事件所属的租户与站点。
	const scopeID, ownerID = "50000000-0000-4000-8000-000000000001", "60000000-0000-4000-8000-000000000001"
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`INSERT INTO tenants(id,display_name) VALUES($1,'analytics-runtime-smoke-tenant')`, []any{runtimeSmokeTenantID}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{scopeID, runtimeSmokeTenantID}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'analytics-runtime-smoke-owner','owner','x')`, []any{ownerID}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{scopeID, ownerID}},
			{`INSERT INTO sites(id,display_id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id)
			VALUES($1,1,$2,$3,'baseline.example.test',ARRAY['192.0.2.10'],ARRAY['192.0.2.10'],$3,$3)`,
				[]any{runtimeSmokeSiteID, scopeID, ownerID}},
			{`INSERT INTO site_origin_pools(site_id) VALUES($1)`, []any{runtimeSmokeSiteID}},
			{`INSERT INTO site_origins(site_id,position,host,port,level) VALUES($1,1,'192.0.2.10',80,0)`, []any{runtimeSmokeSiteID}},
		} {
			if _, err := tx.Exec(t.Context(), statement.sql, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed task analytics tenant and site: %v", err)
	}
}

func seedRuntimeSmokeHistoryGeneration(
	t *testing.T,
	pool *pgxpool.Pool,
	cfg config.Config,
	historyEpoch string,
	streamCreated, consumerCreated time.Time,
) {
	t.Helper()
	createdAt := time.Now().UTC()
	if _, err := pool.Exec(t.Context(), `INSERT INTO analytics_history_streams(
		installation_id,nats_domain,stream_name,durable_name,
		stream_created_unix_nano,consumer_created_unix_nano,history_epoch,
		history_start_sequence,history_start_at,legacy_baseline_kind,
		broker_consumer_ack_floor,broker_stream_ack_floor,prepared_stream_floor,
		revision,last_reconciled_at,created_at,updated_at
	) VALUES($1,'',$2,$3,$4,$5,$6,1,$7,'none',0,0,0,1,$8,$8,$8)`,
		runtimeSmokeInstall, cfg.AnalyticsIngest.JetStream.Stream, cfg.AnalyticsIngest.JetStream.Durable,
		streamCreated.UnixNano(), consumerCreated.UnixNano(), historyEpoch, consumerCreated.UTC(), createdAt); err != nil {
		t.Fatalf("seed task analytics history generation: %v", err)
	}
}

func corruptRuntimeSmokeDuplicateGeneration(
	t *testing.T,
	pool *pgxpool.Pool,
	cfg config.Config,
	streamCreated, consumerCreated time.Time,
) func() {
	t.Helper()
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		ctx := context.Background()
		_, _ = pool.Exec(ctx, `ALTER TABLE analytics_history_streams DISABLE TRIGGER analytics_history_streams_guard_083`)
		_, _ = pool.Exec(ctx, `DELETE FROM analytics_history_streams WHERE history_epoch=$1`, runtimeSmokeEpochBad)
		_, _ = pool.Exec(ctx, `ALTER TABLE analytics_history_streams ENABLE TRIGGER analytics_history_streams_guard_083`)
		if _, err := pool.Exec(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS analytics_history_streams_one_active_identity_idx
			ON analytics_history_streams(installation_id,nats_domain,stream_name,durable_name)
			WHERE retired_at IS NULL`); err != nil {
			t.Errorf("restore analytics history active identity index: %v", err)
		}
	}
	t.Cleanup(restore)
	if _, err := pool.Exec(t.Context(), `DROP INDEX analytics_history_streams_one_active_identity_idx`); err != nil {
		t.Fatalf("drop active identity guard for corruption fixture: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `ALTER TABLE analytics_history_streams DISABLE TRIGGER analytics_history_streams_guard_083`); err != nil {
		t.Fatalf("disable history guard for corruption fixture: %v", err)
	}
	createdAt := time.Now().UTC()
	_, err := pool.Exec(t.Context(), `INSERT INTO analytics_history_streams(
		installation_id,nats_domain,stream_name,durable_name,
		stream_created_unix_nano,consumer_created_unix_nano,history_epoch,
		history_start_sequence,history_start_at,legacy_baseline_kind,
		broker_consumer_ack_floor,broker_stream_ack_floor,prepared_stream_floor,
		revision,last_reconciled_at,created_at,updated_at
	) VALUES($1,'',$2,$3,$4,$5,$6,1,$7,'none',0,0,0,1,$8,$8,$8)`,
		runtimeSmokeInstall, cfg.AnalyticsIngest.JetStream.Stream, cfg.AnalyticsIngest.JetStream.Durable,
		streamCreated.UnixNano(), consumerCreated.UnixNano()+1, runtimeSmokeEpochBad, consumerCreated.UTC(), createdAt)
	if _, enableErr := pool.Exec(t.Context(), `ALTER TABLE analytics_history_streams ENABLE TRIGGER analytics_history_streams_guard_083`); enableErr != nil {
		t.Fatalf("enable history guard after corruption fixture: %v", enableErr)
	}
	if err != nil {
		t.Fatalf("seed duplicate active generation corruption fixture: %v", err)
	}
	return restore
}

func retireRuntimeSmokeHistoryGeneration(t *testing.T, pool *pgxpool.Pool, historyEpoch string) {
	t.Helper()
	retiredAt := time.Now().UTC().Add(time.Millisecond)
	if _, err := pool.Exec(t.Context(), `UPDATE analytics_history_streams
		SET retired_at=$2,revision=revision+1,last_reconciled_at=$2,updated_at=$2
		WHERE history_epoch=$1`, historyEpoch, retiredAt); err != nil {
		t.Fatalf("retire task analytics history generation: %v", err)
	}
}

func assertRuntimeHistoryRejectedBeforeNetwork(t *testing.T, cfg config.Config, pool *pgxpool.Pool, state string) {
	t.Helper()
	var connectorCalls atomic.Int32
	httpClient := &analyticsIngestNetworkProbe{}
	runtime, err := openAnalyticsIngestRuntime(t.Context(), cfg, pool, nil,
		func(string, ...nats.Option) (*nats.Conn, error) {
			connectorCalls.Add(1)
			return nil, errors.New("must not connect")
		}, httpClient)
	if err == nil || runtime != nil || connectorCalls.Load() != 0 || httpClient.calls.Load() != 0 {
		t.Fatalf("%s runtime=%v error=%v connector_calls=%d http_calls=%d",
			state, runtime, err, connectorCalls.Load(), httpClient.calls.Load())
	}
}

func assertRuntimeConnectorContracts(t *testing.T, cfg config.Config, pool *pgxpool.Pool) {
	t.Helper()
	const secret = "nats-visible-secret"
	sentinel := errors.New("dial failed with " + secret)
	httpClient := &analyticsIngestNetworkProbe{}
	_, err := openAnalyticsIngestRuntime(t.Context(), cfg, pool, nil,
		func(string, ...nats.Option) (*nats.Conn, error) { return nil, sentinel }, httpClient)
	if !errors.Is(err, sentinel) || err.Error() != "connect analytics ingest NATS" ||
		strings.Contains(err.Error(), secret) || httpClient.calls.Load() != 0 {
		t.Fatalf("connection failure = %v, HTTP calls=%d", err, httpClient.calls.Load())
	}

	sentinel = errors.New("stop after options")
	_, err = openAnalyticsIngestRuntime(t.Context(), cfg, pool, nil,
		func(_ string, optionFunctions ...nats.Option) (*nats.Conn, error) {
			options := nats.GetDefaultOptions()
			for _, apply := range optionFunctions {
				if applyErr := apply(&options); applyErr != nil {
					t.Fatal(applyErr)
				}
			}
			if !options.NoCallbacksAfterClientClose {
				t.Fatal("client close callbacks remain enabled")
			}
			if want := min(cfg.AnalyticsIngest.JetStream.OperationTimeout, cfg.ShutdownPeriod/2); options.DrainTimeout != want {
				t.Fatalf("NATS drain timeout = %s, want %s", options.DrainTimeout, want)
			}
			return nil, sentinel
		}, httpClient)
	if !errors.Is(err, sentinel) {
		t.Fatalf("open error = %v", err)
	}
}

func waitForRuntimeSmokeRecoveryCompleted(t *testing.T, pool *pgxpool.Pool, historyEpoch string) {
	t.Helper()
	waitForRuntimeSmokeCondition(t, 10*time.Second, func() bool {
		var completed bool
		err := pool.QueryRow(t.Context(), `SELECT EXISTS(
			SELECT 1 FROM analytics_history_recoveries
			WHERE history_epoch=$1 AND completed_at IS NOT NULL
		)`, historyEpoch).Scan(&completed)
		return err == nil && completed
	})
}

func waitForRuntimeSmokeReceipt(t *testing.T, pool *pgxpool.Pool, messageID, wantState string) string {
	t.Helper()
	var state, token string
	waitForRuntimeSmokeCondition(t, 10*time.Second, func() bool {
		err := pool.QueryRow(t.Context(), `SELECT state,clickhouse_token
			FROM analytics_ingest_receipts WHERE message_id=$1
			ORDER BY updated_at DESC LIMIT 1`, messageID).Scan(&state, &token)
		return err == nil && state == wantState && token != ""
	})
	return token
}

type analyticsIngestFaultProxy struct {
	target                  *url.URL
	reverseProxy            *httputil.ReverseProxy
	unavailable             atomic.Bool
	rejectEmptyInsertStatus atomic.Int32
	rejectedEmptyInserts    atomic.Int32
	rejectWriteStatus       atomic.Int32
	rejectedWrites          atomic.Int32
	failCommittedInsert     atomic.Bool
	committedFailures       atomic.Int32
	blockInsert             atomic.Bool
	blockedInserts          atomic.Int32
}

func newAnalyticsIngestFaultProxy(target *url.URL) *analyticsIngestFaultProxy {
	return &analyticsIngestFaultProxy{target: target, reverseProxy: httputil.NewSingleHostReverseProxy(target)}
}

func (proxy *analyticsIngestFaultProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if proxy.unavailable.Load() {
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(request.Body)
	if err != nil {
		writer.WriteHeader(http.StatusBadGateway)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	isInsert := bytes.HasPrefix(body, []byte("INSERT INTO "))
	isEmptyInsert := isInsert && bytes.Count(body, []byte{'\n'}) == 1 && bytes.HasSuffix(body, []byte{'\n'})
	if status := proxy.rejectEmptyInsertStatus.Load(); isEmptyInsert && status != 0 {
		proxy.rejectedEmptyInserts.Add(1)
		writer.WriteHeader(int(status))
		return
	}
	if status := proxy.rejectWriteStatus.Load(); isInsert && !isEmptyInsert && status != 0 {
		proxy.rejectedWrites.Add(1)
		writer.WriteHeader(int(status))
		return
	}
	if isInsert && proxy.blockInsert.Load() {
		proxy.blockedInserts.Add(1)
		<-request.Context().Done()
		return
	}
	if isInsert && proxy.failCommittedInsert.CompareAndSwap(true, false) {
		proxy.forwardThenFail(writer, request, body)
		return
	}
	proxy.reverseProxy.ServeHTTP(writer, request)
}

func (proxy *analyticsIngestFaultProxy) forwardThenFail(writer http.ResponseWriter, request *http.Request, body []byte) {
	upstream := request.Clone(request.Context())
	upstream.URL.Scheme = proxy.target.Scheme
	upstream.URL.Host = proxy.target.Host
	upstream.Host = proxy.target.Host
	upstream.RequestURI = ""
	upstream.Body = io.NopCloser(bytes.NewReader(body))
	upstream.ContentLength = int64(len(body))
	response, err := http.DefaultClient.Do(upstream)
	if err != nil {
		writer.WriteHeader(http.StatusBadGateway)
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		writer.WriteHeader(response.StatusCode)
		return
	}
	proxy.committedFailures.Add(1)
	writer.WriteHeader(http.StatusServiceUnavailable)
}

func startAnalyticsIngestRuntimeSmoke(
	t *testing.T,
	cfg config.Config,
	pool *pgxpool.Pool,
	logger *slog.Logger,
	httpClient analytics.HTTPClient,
) (*analyticsIngestProcessRuntime, context.CancelFunc, <-chan error) {
	t.Helper()
	runtime, err := openAnalyticsIngestRuntime(context.Background(), cfg, pool, logger, nats.Connect, httpClient)
	if err != nil {
		t.Fatalf("open formal analytics ingest runtime: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	waitForRuntimeSmokeCondition(t, 5*time.Second, func() bool { return runtime.Health().State == "running" })
	return runtime, cancel, done
}

func stopAnalyticsIngestRuntimeSmoke(
	t *testing.T,
	runtime *analyticsIngestProcessRuntime,
	cancel context.CancelFunc,
	done <-chan error,
) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("formal runtime stop error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("formal runtime did not stop within the shutdown bound")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close formal runtime: %v", err)
	}
	if state := runtime.Health().State; state != "stopped" {
		t.Fatalf("formal runtime health after close = %q", state)
	}
}

func publishRuntimeSmokeEnvelope(
	t *testing.T,
	jetstream nats.JetStreamContext,
	stream, messageID string,
	producedAt time.Time,
	kind string,
	accessEvents []analytics.AccessEvent,
	securityEvents []analytics.SecurityEvent,
) {
	t.Helper()
	var envelope any
	switch kind {
	case analytics.AccessEnvelopeType:
		envelope = analytics.AccessIngestEnvelope{
			SchemaVersion: analytics.IngestSchemaVersion, Type: kind, MessageID: messageID,
			ProducedAt: producedAt, TenantID: runtimeSmokeTenantID, NodeID: runtimeSmokeNodeID, Events: accessEvents,
		}
	case analytics.SecurityEnvelopeType:
		envelope = analytics.SecurityIngestEnvelope{
			SchemaVersion: analytics.IngestSchemaVersion, Type: kind, MessageID: messageID,
			ProducedAt: producedAt, TenantID: runtimeSmokeTenantID, NodeID: runtimeSmokeNodeID, Events: securityEvents,
		}
	default:
		t.Fatalf("unsupported smoke envelope kind %q", kind)
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	subject, err := analytics.IngestSubject(runtimeSmokeNodeID)
	if err != nil {
		t.Fatal(err)
	}
	message := nats.NewMsg(subject)
	// 与 agent-gateway telemetry_nats.go 发布的权威头一致；缺任一个 trustedIngestAuthority 即判 IDENTITY_MISMATCH 隔离。
	message.Header.Set(nats.MsgIdHdr, messageID)
	message.Header.Set("Cdnca-Node-Id", runtimeSmokeNodeID)
	message.Header.Set("Cdnca-Tenant-Id", runtimeSmokeTenantID)
	message.Header.Set("Cdnca-Site-Id", runtimeSmokeSiteID)
	message.Header.Set("Cdnca-Config-Version-Id", runtimeSmokeConfigID)
	message.Header.Set("Cdnca-Installation-Id", runtimeSmokeInstall)
	message.Data = payload
	// 不用 nats.ExpectStream：它以 Nats-Expected-Stream 头随消息落盘，权威头数不再是 6，
	// trustedIngestAuthority 会拒（网关 telemetry_nats.go 也不带）；改为校验回执流名。
	ack, err := jetstream.PublishMsg(message)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Stream != stream {
		t.Fatalf("smoke envelope landed in stream %q, want %q", ack.Stream, stream)
	}
}

func runtimeSmokeAccessEvent(eventID string, occurredAt time.Time) analytics.AccessEvent {
	return analytics.AccessEvent{
		MetricVersion: analytics.MetricVersion, EventID: eventID, OccurredAt: occurredAt,
		TenantID: runtimeSmokeTenantID, SiteID: runtimeSmokeSiteID, NodeID: runtimeSmokeNodeID,
		ConfigVersion: runtimeSmokeConfigID,
		Host:          "baseline.example.test", Path: "/baseline.js", ClientIP: "2001:db8::1",
		CountryCode: "CN", Carrier: "carrier-baseline", Method: "GET", Protocol: "HTTP/2",
		CacheStatus: "HIT", StatusCode: 200, RequestBytes: 100, ResponseBytes: 1024, DurationUS: 1000,
	}
}

func runtimeSmokeSecurityEvent(eventID string, occurredAt time.Time) analytics.SecurityEvent {
	return analytics.SecurityEvent{
		MetricVersion: analytics.MetricVersion, EventID: eventID, OccurredAt: occurredAt,
		TenantID: runtimeSmokeTenantID, SiteID: runtimeSmokeSiteID, NodeID: runtimeSmokeNodeID,
		ConfigVersion: runtimeSmokeConfigID,
		Host:          "baseline.example.test", Path: "/blocked", ClientIP: "2001:db8::2",
		CountryCode: "CN", Carrier: "carrier-baseline", EventType: "waf", Action: "block",
		Severity: "high", StatusCode: 403, RequestBytes: 50, ResponseBytes: 100,
	}
}

func waitForRuntimeSmokeSummary(
	t *testing.T,
	client *analytics.Client,
	filter analytics.Filter,
	wantRequests, wantSecurity uint64,
) {
	t.Helper()
	waitForRuntimeSmokeCondition(t, 15*time.Second, func() bool {
		summary, err := client.Summary(context.Background(), analytics.AdminScope(), filter)
		return err == nil && summary.RequestCount == wantRequests && summary.SecurityEvents == wantSecurity
	})
}

func waitForRuntimeSmokeCondition(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("runtime smoke condition was not met before timeout")
}

func setAnalyticsIngestRuntimeRequiredConfig(t *testing.T) {
	t.Helper()
	databaseURL := os.Getenv("ANALYTICS_INGEST_RUNTIME_POSTGRES_URL")
	if databaseURL == "" {
		databaseURL = os.Getenv("DATABASE_URL")
	}
	if databaseURL == "" {
		t.Fatal("ANALYTICS_INGEST_RUNTIME_POSTGRES_URL or DATABASE_URL is required")
	}
	t.Setenv("DATABASE_URL", databaseURL)
	t.Setenv("CONTROL_INSTALLATION_ID", runtimeSmokeInstall)
	t.Setenv("ACCESS_TOKEN_SECRET", "runtime-smoke-access-token-secret-at-least-thirty-two-bytes")
	t.Setenv("API_KEY_PEPPER_BASE64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	t.Setenv("API_KEY_PEPPER_VERSION", "legacy-v1")
	t.Setenv("DNS_CREDENTIAL_KEY_ID", "runtime-smoke")
	t.Setenv("DNS_CREDENTIAL_KEY_BASE64", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)))
	t.Setenv("EDGE_DEPLOYMENT_NATS_URL", "nats://127.0.0.1:4222")
	t.Setenv("CONTROL_INTERNAL_SERVER_CERT_FILE", "/runtime-smoke/server.crt")
	t.Setenv("CONTROL_INTERNAL_SERVER_PRIVATE_KEY_FILE", "/runtime-smoke/server.key")
	t.Setenv("CONTROL_INTERNAL_GATEWAY_CLIENT_CA_FILE", "/runtime-smoke/ca.crt")
	t.Setenv("CONTROL_INTERNAL_GATEWAY_WORKLOAD_URI_SAN", "spiffe://cdnca/runtime-smoke")
	t.Setenv("NODE_CA_CERTIFICATE_CHAIN_FILE", "/runtime-smoke/node-ca.crt")
	t.Setenv("NODE_CA_PRIVATE_KEY_FILE", "/runtime-smoke/node-ca.key")
}
