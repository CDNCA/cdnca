//go:build integration

package nodemetrics

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"
)

type batchMetricsQueryTracer struct{ calls atomic.Int64 }

func (tracer *batchMetricsQueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	tracer.calls.Add(1)
	return ctx
}

func (*batchMetricsQueryTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestPostgresReaderLatestBatch(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	tracer := &batchMetricsQueryTracer{}
	// A release-head clone of the template when one is configured (a full
	// migration within the minute above timed out on a loaded host).
	pool := databasetest.ClonedMigratedPool(t, func(config *pgxpool.Config) { config.ConnConfig.Tracer = tracer })
	if pool == nil {
		pool = migratedBatchMetricsPool(t, ctx, dsn, tracer)
	}
	testPostgresReaderLatestBatch(t, ctx, pool, tracer)
}

func migratedBatchMetricsPool(t *testing.T, ctx context.Context, dsn string, tracer *batchMetricsQueryTracer) *pgxpool.Pool {
	t.Helper()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "node_metrics_batch_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	config.ConnConfig.Tracer = tracer
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}

func testPostgresReaderLatestBatch(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tracer *batchMetricsQueryTracer) {
	t.Helper()
	// The formal schema is the full release head; derive it from the embedded
	// migrations instead of a count that every new migration would break.
	upScripts, err := fs.Glob(controlmigrations.FS, "*.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	var migrationCount int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM schema_migrations").Scan(&migrationCount); err != nil ||
		migrationCount != len(upScripts) {
		t.Fatalf("formal schema: migrations=%d want=%d err=%v", migrationCount, len(upScripts), err)
	}
	scope, user, tenant, foreignScope, foreignNode := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, []any{scope}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'metricsbatch','Metrics batch','test-only')`, []any{user}},
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Other scope')`, []any{tenant}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{foreignScope, tenant}},
		{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id) VALUES($1,$2,'other-node','active',$3,301)`, []any{foreignNode, foreignScope, user}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	ids := make([]uuid.UUID, 300)
	for index := range ids {
		ids[index] = uuid.New()
	}
	if _, err := pool.Exec(ctx, `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
		SELECT id,$2,'batch-' || ordinal,'active',$3,ordinal FROM unnest($1::uuid[]) WITH ORDINALITY AS requested(id,ordinal)`, ids, scope, user); err != nil {
		t.Fatal(err)
	}
	store, _ := NewPostgresStore(pool)
	for index, id := range ids[:2] {
		sample, _, err := NewDecoder(DefaultDecoderConfig()).Decode(testMetricDelivery(t, index == 0))
		if err != nil {
			t.Fatal(err)
		}
		sample.NodeID, sample.EventID, sample.RequestID = id.String(), uuid.NewString(), uuid.NewString()
		sample.PubAckSequence += uint64(index)
		sample.ConsumerSequence += uint64(index)
		if index == 0 {
			sample.Kind, sample.ConfigRevision, sample.ActiveConfigRevision, sample.ProbePort = RecordHostMetric, 0, 0, 0
			sample.Healthy, sample.ProbeSucceeded, sample.ProbesTotal = false, false, 0
			sample.Telemetry.NetworkSelection = &NetworkSelection{Source: "default_route", Interfaces: []string{"eth0"}}
		}
		if _, err := store.Put(ctx, sample); err != nil {
			t.Fatal(err)
		}
	}
	recovery := Sample{EventID: uuid.NewString(), RequestID: uuid.NewString(), NodeID: ids[1].String(),
		SchemaVersion: 1, Kind: RecordRecoveryNotification, ConfigRevision: 7, PublicationSequence: 42,
		ObservedAt: time.Unix(960, 0).UTC(), RecoveryReasonCode: RecoveryReasonProbeRecovered,
		PubAckStream: NodeMonitoringStatusStream, PubAckSequence: 93, ConsumerDurable: DefaultConsumerDurable,
		ConsumerSequence: 19, NumDelivered: 1, WireSHA256: sha256.Sum256([]byte("synthetic-recovery"))}
	if _, err := store.Put(ctx, recovery); err != nil {
		t.Fatal(err)
	}
	// fz-x11 (待出包前全量跑): telemetry_detail is read from the node's latest
	// session: ids[0] declared NODE_TELEMETRY_DETAIL in session 1 only, ids[1]
	// in its latest session 2.
	for _, session := range []struct {
		node     uuid.UUID
		epoch    int64
		declares bool
	}{{ids[0], 1, true}, {ids[0], 2, false}, {ids[1], 1, false}, {ids[1], 2, true}} {
		var features []*agentv1.Capability
		if session.declares {
			features = []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_NODE_TELEMETRY_DETAIL, ApiVersion: 1}}
		}
		snapshot, err := proto.Marshal(&agentv1.AgentCapabilities{AgentVersion: "1.0.35", Features: features})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(snapshot)
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO node_session_capabilities(node_id,session_epoch,certificate_id,
				certificate_sha256,artifact_key_id,selected_protocol_major,selected_protocol_minor,capabilities_snapshot,
				capabilities_sha256,facts_snapshot,facts_sha256,gateway_workload_identity,gateway_instance_id,registered_at)
				VALUES($1,$2,$3,$4,'x25519:test',1,0,$5,$4,'\x01',$4,'gw','gw-1',now())`,
				session.node, session.epoch, uuid.New(), digest[:], snapshot)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	reader, _ := NewPostgresReader(pool)
	batch, ok := any(reader).(interface {
		LatestBatch(context.Context, uuid.UUID, []uuid.UUID) ([]LatestView, []uuid.UUID, error)
	})
	if !ok {
		t.Fatal("PostgresReader is missing single-query batch metrics capability")
	}
	tracer.calls.Store(0)
	items, missing, err := batch.LatestBatch(ctx, scope, ids)
	if err != nil || tracer.calls.Load() != 3 || len(items) != 2 || !reflect.DeepEqual(missing, ids[2:]) {
		t.Fatalf("batch: items=%d missing=%d queries=%d err=%v", len(items), len(missing), tracer.calls.Load(), err)
	}
	for index := range items {
		single, err := reader.Latest(ctx, scope, ids[index])
		if err != nil {
			t.Fatal(err)
		}
		got, _ := json.Marshal(items[index])
		want, _ := json.Marshal(single)
		if string(got) != string(want) {
			t.Fatal("batch changed existing latest evidence")
		}
	}
	if items[0].RecordKind != RecordHostMetric || !items[0].Known || items[0].Healthy || items[0].ProbePort != 0 ||
		items[0].Telemetry.NetworkSelection.Source != "default_route" || items[1].Known || items[1].RXBandwidthBPS != nil || items[1].LatestRecovery == nil {
		t.Fatal("known/probe/telemetry/recovery facts changed")
	}
	if items[0].TelemetryDetail || !items[1].TelemetryDetail {
		t.Fatalf("telemetry_detail must follow the latest session: %v %v", items[0].TelemetryDetail, items[1].TelemetryDetail)
	}
	tracer.calls.Store(0)
	items, missing, err = batch.LatestBatch(ctx, scope, []uuid.UUID{ids[2]})
	if err != nil || tracer.calls.Load() != 3 || items == nil || len(items) != 0 || !reflect.DeepEqual(missing, []uuid.UUID{ids[2]}) {
		t.Fatalf("no sample is not a zero sample: %+v %+v %v", items, missing, err)
	}
	for _, requested := range [][]uuid.UUID{{ids[0], foreignNode}, {ids[0], uuid.New()}} {
		tracer.calls.Store(0)
		items, missing, err = batch.LatestBatch(ctx, scope, requested)
		if !errors.Is(err, ErrNotFound) || items != nil || missing != nil || tracer.calls.Load() != 1 {
			t.Fatalf("membership rejection leaked partial data: items=%d missing=%d queries=%d err=%v", len(items), len(missing), tracer.calls.Load(), err)
		}
	}
	for _, requested := range [][]uuid.UUID{nil, {}, {uuid.Nil}, {ids[0], ids[0]}, append(append([]uuid.UUID{}, ids...), uuid.New())} {
		tracer.calls.Store(0)
		if _, _, err := batch.LatestBatch(ctx, scope, requested); !errors.Is(err, ErrInvalidConfiguration) || tracer.calls.Load() != 0 {
			t.Fatalf("invalid batch queried storage: queries=%d err=%v", tracer.calls.Load(), err)
		}
	}
	if _, _, err := batch.LatestBatch(ctx, uuid.New(), ids[:1]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong scope: %v", err)
	}
	if _, err := reader.Latest(ctx, scope, ids[2]); !errors.Is(err, ErrNotFound) {
		t.Fatalf("single-node missing sample changed: %v", err)
	}
	// The SQL shape permits opaque telemetry JSON; the existing reader must still
	// reject an unknown field instead of exposing a partially decoded batch.
	if _, err := pool.Exec(ctx, `INSERT INTO node_metric_samples
		SELECT (jsonb_populate_record(NULL::node_metric_samples, to_jsonb(sample) ||
			jsonb_build_object('event_id',$2::text,'publication_sequence',43,'puback_sequence',94,
			'telemetry_json',sample.telemetry_json || '{"unknown":true}'::jsonb))).*
		FROM node_metric_samples sample WHERE node_id=$1`, ids[0], uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Latest(ctx, scope, ids[0]); !errors.Is(err, ErrInvalidSample) {
		t.Fatalf("single-node corrupt telemetry accepted: %v", err)
	}
	if items, missing, err := batch.LatestBatch(ctx, scope, ids[:2]); !errors.Is(err, ErrInvalidSample) || items != nil || missing != nil {
		t.Fatalf("batch corrupt telemetry accepted: items=%d missing=%d err=%v", len(items), len(missing), err)
	}
	if _, _, err := batch.LatestBatch(ctx, scope, []uuid.UUID{ids[0], foreignNode}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("membership denial must precede sibling data decoding: %v", err)
	}
}
