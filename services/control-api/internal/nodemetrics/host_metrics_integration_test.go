//go:build integration

package nodemetrics

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

func TestHostMetricsFormalSchema(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	// Migration from scratch takes minutes on a loaded machine.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "host_metrics_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := databasetest.CleanupContext()
		defer done()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// The ledger assertions are written for head 275. Migration 268's down is a
	// deliberate one-way gate (P2682) and later migrations sit on top of 275,
	// so only 1..275 are loaded.
	const currentMigration = 275
	if err := databasetest.MigrateThrough(ctx, pool, "up", currentMigration); err != nil {
		t.Fatal(err)
	}
	assertMigrationHead := func(want int) {
		t.Helper()
		var count, head int
		if err := pool.QueryRow(ctx, "SELECT count(*), COALESCE(max(version), 0) FROM schema_migrations").Scan(&count, &head); err != nil || count != want || head != want {
			t.Fatalf("migration ledger: count=%d head=%d want=%d err=%v", count, head, want, err)
		}
	}
	// Migrate down targets the current head, not the host metrics migration.
	for head := currentMigration; head >= 269; head-- {
		assertMigrationHead(head)
		if err := databasetest.MigrateThrough(ctx, pool, "down", currentMigration); err != nil {
			t.Fatalf("empty migration %d rollback: %v", head, err)
		}
		assertMigrationHead(head - 1)
	}
	if err := databasetest.MigrateThrough(ctx, pool, "up", currentMigration); err != nil {
		t.Fatalf("migration reapply: %v", err)
	}
	assertMigrationHead(currentMigration)
	scopeID, userID := uuid.New(), uuid.New()
	nodeID := uuid.MustParse("01990000-0000-7000-8000-000000000007")
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'host-test','Host test','test-only')`, []any{userID}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'host-test','active',$3,1)`, []any{nodeID, scopeID, userID}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	delivery := testMetricDelivery(t, true)
	report := &agentv1.NodeMonitoringReport{}
	if err := proto.Unmarshal(delivery.payload, report); err != nil {
		t.Fatal(err)
	}
	report.Kind = agentv1.NodeMonitoringRecordKind_NODE_MONITORING_RECORD_KIND_HOST_METRIC
	report.ConfigRevision = 0
	report.LoadMetricsV1.Telemetry.NetworkInterfaces = append(report.LoadMetricsV1.Telemetry.NetworkInterfaces,
		&agentv1.NodeNetworkInterfaceMetricsV1{Name: "internal0", RxBandwidthBps: 999999, TxBandwidthBps: 999999})
	report.LoadMetricsV1.Telemetry.NetworkSelection = &agentv1.NodeNetworkSelectionV1{Source: "default_route", Interfaces: []string{"eth0"}}
	report.PayloadJson, _ = json.Marshal(map[string]any{"schema_version": 1, "node_id": report.NodeId, "observed_at": report.Event.OccurredTime.AsTime()})
	delivery.payload, _ = proto.MarshalOptions{Deterministic: true}.Marshal(report)
	sample, _, err := NewDecoder(DefaultDecoderConfig()).Decode(delivery)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := NewPostgresStore(pool)
	if replay, err := store.Put(ctx, sample); err != nil || replay {
		t.Fatalf("first host sample: replay=%v err=%v", replay, err)
	}
	if replay, err := store.Put(ctx, sample); err != nil || !replay {
		t.Fatalf("host replay: replay=%v err=%v", replay, err)
	}
	conflict := sample
	conflict.WireSHA256[0] ^= 1
	if _, err := store.Put(ctx, conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting replay: %v", err)
	}
	var probes int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM node_metric_latest").Scan(&probes); err != nil || probes != 0 {
		t.Fatalf("host sample leaked into legacy probe view: %d %v", probes, err)
	}
	for _, role := range []string{"cdnca_control_app", "cdnca_control_runtime"} {
		if _, err := pool.Exec(ctx, "GRANT USAGE ON SCHEMA "+identifier+" TO "+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Fatal(err)
		}
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
				return err
			}
			var count int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM node_load_latest").Scan(&count); err != nil {
				return err
			}
			var writable bool
			if err := tx.QueryRow(ctx, "SELECT has_table_privilege(current_user, 'node_load_latest', 'INSERT,UPDATE,DELETE,TRUNCATE')").Scan(&writable); err != nil {
				return err
			}
			if count != 1 || writable {
				t.Fatalf("%s load view: count=%d writable=%v", role, count, writable)
			}
			return nil
		}); err != nil {
			t.Fatalf("%s least-privilege read: %v", role, err)
		}
	}
	for name, fields := range map[string]map[string]any{
		"fake revision": {"config_revision": 1},
		"fake probe":    {"healthy": true},
		"missing load":  {"metrics_known": false},
		"unknown kind":  {"record_kind": "unknown_metric"},
	} {
		t.Run(name, func(t *testing.T) {
			fields["event_id"] = uuid.NewString()
			fields["publication_sequence"] = sample.PublicationSequence + 1
			fields["puback_sequence"] = sample.PubAckSequence + 1
			payload, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			_, err = pool.Exec(ctx, `INSERT INTO node_metric_samples
				SELECT (jsonb_populate_record(NULL::node_metric_samples, to_jsonb(sample) || $2::jsonb)).*
				FROM node_metric_samples sample WHERE event_id=$1`, sample.EventID, payload)
			var failure *pgconn.PgError
			if !errors.As(err, &failure) || failure.Code != "23514" {
				t.Fatalf("invalid direct SQL record not rejected by shape check: %v", err)
			}
		})
	}
	// reader 读节点能力（迁移 277 的 node_session_capabilities）；本用例只迁到 275，
	// 补一张只含所读列的空表（不进迁移账本，不影响下面 275→269 的回滚断言）。
	if _, err := pool.Exec(ctx, `CREATE TABLE node_session_capabilities(
		node_id uuid NOT NULL, session_epoch bigint NOT NULL, capabilities_snapshot bytea NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	reader, _ := NewPostgresReader(pool)
	latest, err := reader.Latest(ctx, scopeID, nodeID)
	if err != nil || !latest.Known || latest.ConfigRevision != 0 || latest.Telemetry == nil || latest.Telemetry.NetworkInterfaces[0].Name != "eth0" {
		t.Fatalf("host latest: %+v %v", latest, err)
	}
	from, to := sample.ObservedAt.Add(-time.Minute), sample.ObservedAt.Add(time.Minute)
	top, err := reader.Top(ctx, scopeID, from, to, "bandwidth", 1, true)
	if err != nil || len(top) != 1 || top[0].NIC != "eth0" || top[0].Inbound != 1200 || top[0].Outbound != 2400 {
		t.Fatalf("host ranking: %+v %v", top, err)
	}
	all, err := reader.Top(ctx, scopeID, from, to, "bandwidth", 1, false)
	if err != nil || len(all) != 1 || all[0].NIC != "internal0" {
		t.Fatalf("all-NIC diagnostics: %+v %v", all, err)
	}
	if latest.Telemetry.NetworkSelection == nil || latest.Telemetry.NetworkSelection.Source != "default_route" {
		t.Fatal("stored selection lost")
	}
	series, err := reader.Realtime(ctx, scopeID, nodeID, from, to, "bandwidth", 10, true)
	if err != nil || len(series.Data["eth0"]) != 2 || len(series.Data["internal0"]) != 0 {
		t.Fatalf("external series = %+v %v", series, err)
	}
	history, err := reader.History(ctx, scopeID, nodeID, from, to, 10)
	if err != nil || len(history) != 1 || !history[0].Known {
		t.Fatalf("host history: %+v %v", history, err)
	}
	if _, err := reader.Latest(ctx, uuid.New(), nodeID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-scope latest: %v", err)
	}
	if other, err := reader.Top(ctx, uuid.New(), from, to, "bandwidth", 10, true); err != nil || len(other) != 0 {
		t.Fatalf("cross-scope ranking: %+v %v", other, err)
	}
	for head := currentMigration; head > 269; head-- {
		assertMigrationHead(head)
		if err := databasetest.MigrateThrough(ctx, pool, "down", currentMigration); err != nil {
			t.Fatalf("migration %d rollback before host guard: %v", head, err)
		}
		assertMigrationHead(head - 1)
	}
	var rollbackFailure *pgconn.PgError
	if err := databasetest.MigrateThrough(ctx, pool, "down", currentMigration); !errors.As(err, &rollbackFailure) || rollbackFailure.Code != "P2692" {
		t.Fatalf("host facts must block migration 269 rollback with P2692: %v", err)
	}
	assertMigrationHead(269)
	if _, err := reader.Latest(ctx, scopeID, nodeID); err != nil {
		t.Fatalf("failed rollback changed readable host evidence: %v", err)
	}
	if err := databasetest.MigrateThrough(ctx, pool, "up", currentMigration); err != nil {
		t.Fatalf("migration reapply after host rollback refusal: %v", err)
	}
	assertMigrationHead(currentMigration)
	probeSample, _, err := NewDecoder(DefaultDecoderConfig()).Decode(testMetricDelivery(t, true))
	if err != nil {
		t.Fatal(err)
	}
	probeSample.EventID, probeSample.RequestID = uuid.NewString(), uuid.NewString()
	probeSample.PublicationSequence, probeSample.PubAckSequence = sample.PublicationSequence+1, sample.PubAckSequence+1
	probeSample.ConsumerSequence++
	if _, err := store.Put(ctx, probeSample); err != nil {
		t.Fatalf("existing probe report after host sample: %v", err)
	}
	latest, err = reader.Latest(ctx, scopeID, nodeID)
	if err != nil || latest.RecordKind != RecordMetric || latest.ConfigRevision != probeSample.ConfigRevision {
		t.Fatalf("probe policy enabled transition: %+v %v", latest, err)
	}
	sample.EventID, sample.RequestID = uuid.NewString(), uuid.NewString()
	sample.PublicationSequence += 2
	sample.PubAckSequence += 2
	sample.ConsumerSequence += 2
	if _, err := store.Put(ctx, sample); err != nil {
		t.Fatalf("host report after probe disabled: %v", err)
	}
	pool.Close()
	restarted, err := pgxpool.NewWithConfig(ctx, config.Copy())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	reader, _ = NewPostgresReader(restarted)
	latest, err = reader.Latest(ctx, scopeID, nodeID)
	if err != nil || latest.RecordKind != RecordHostMetric || latest.ConfigRevision != 0 || latest.Telemetry == nil {
		t.Fatalf("host evidence after reader restart: %+v %v", latest, err)
	}
	if err := restarted.QueryRow(ctx, "SELECT count(*) FROM node_metric_latest").Scan(&probes); err != nil || probes != 1 {
		t.Fatalf("legacy reader lost probe evidence: %d %v", probes, err)
	}
	t.Run("JetStream persistence and retry", func(t *testing.T) {
		natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
		if natsURL == "" {
			t.Skip("CDNCA_TEST_NATS_URL must point to an isolated test server")
		}
		connection, err := nats.Connect(natsURL, nats.Timeout(time.Second), nats.NoReconnect())
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		js, err := connection.JetStream(nats.MaxWait(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := js.StreamInfo(NodeMonitoringStatusStream); !errors.Is(err, nats.ErrStreamNotFound) {
			t.Fatalf("test requires an unused node metrics stream: %v", err)
		}
		if _, err := js.AddStream(&nats.StreamConfig{Name: NodeMonitoringStatusStream,
			Subjects: []string{DefaultSubjectPrefix + ".*"}, Retention: nats.WorkQueuePolicy, Storage: nats.FileStorage}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = js.DeleteStream(NodeMonitoringStatusStream) }()
		consumer, err := NewNATSConsumer(connection, DefaultNATSConsumerConfig())
		if err != nil {
			t.Fatal(err)
		}
		defer consumer.Close()
		report.Event.EventId, report.Event.RequestId = uuid.NewString(), uuid.NewString()
		report.PublicationSequence = sample.PublicationSequence + 1
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		ack, err := js.Publish(DefaultSubjectPrefix+"."+report.NodeId, payload, nats.MsgId(report.Event.EventId))
		if err != nil {
			t.Fatal(err)
		}
		message, err := consumer.Next(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// The original pool is closed: transient storage failure must NAK, never ACK.
		processor, _ := NewProcessor(NewDecoder(DefaultDecoderConfig()), store, 10*time.Millisecond, time.Second)
		if disposition, err := processor.Process(ctx, message); err != nil || disposition != DispositionNak {
			t.Fatalf("unavailable storage: %s %v", disposition, err)
		}
		message, err = consumer.Next(ctx)
		if err != nil || message.Metadata().NumDelivered < 2 {
			t.Fatalf("retry delivery: %v", err)
		}
		restartedStore, _ := NewPostgresStore(restarted)
		processor, _ = NewProcessor(NewDecoder(DefaultDecoderConfig()), restartedStore, time.Second, time.Second)
		if disposition, err := processor.Process(ctx, message); err != nil || disposition != DispositionAck {
			t.Fatalf("persist then ACK: %s %v", disposition, err)
		}
		persisted, err := reader.Latest(ctx, scopeID, nodeID)
		if err != nil || persisted.RecordKind != RecordHostMetric || persisted.PubAckSequence != ack.Sequence ||
			persisted.ConsumerSequence != message.Metadata().ConsumerSequence || persisted.Telemetry == nil {
			t.Fatalf("JetStream host evidence: %+v %v", persisted, err)
		}
	})
}
