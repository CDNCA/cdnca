//go:build integration

package nodemetrics

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMonitoringLatestProbeSnapshot(t *testing.T) {
	pool := monitoringSnapshotPool(t)
	admin, err := identity.NewStore(pool).BootstrapPlatformUser(t.Context(), "monitoringreader", "Monitoring reader", "synthetic-not-login-hash", "monitoring-reader-test")
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]uuid.UUID, 300)
	for index := range ids {
		ids[index] = uuid.New()
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
		SELECT id,$2,'probe-' || position,'active',$3,position FROM unnest($1::uuid[]) WITH ORDINALITY requested(id,position)`, ids, admin.ScopeID, admin.UserID); err != nil {
		t.Fatal(err)
	}
	trace := &monitoringBatchTrace{}
	readConfig := pool.Config()
	readConfig.ConnConfig.Tracer = trace
	readPool, err := pgxpool.NewWithConfig(t.Context(), readConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(readPool.Close)
	reader, _ := NewPostgresReader(readPool)
	store, _ := NewPostgresStore(pool)
	read := func() MonitoringSnapshot {
		t.Helper()
		trace.mu.Lock()
		trace.queries = nil
		trace.mu.Unlock()
		got, err := reader.MonitoringLatest(t.Context(), admin.ScopeID, ids)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Items) != len(ids) {
			t.Fatalf("coverage=%d", len(got.Items))
		}
		for index, item := range got.Items {
			if item.NodeID != ids[index] {
				t.Fatal("request order changed")
			}
		}
		trace.mu.Lock()
		queries := append([]string(nil), trace.queries...)
		trace.mu.Unlock()
		probeQueries := 0
		for _, query := range queries {
			lower := strings.ToLower(query)
			if strings.Contains(lower, "node_metric_latest") {
				probeQueries++
			}
			if strings.Contains(lower, "for update") || strings.Contains(lower, "for share") || strings.Contains(lower, "node_load_latest") {
				t.Fatal("reader locked/mutated or mixed host-only evidence")
			}
		}
		// Unconfigured scopes do not have a policy lookup, while configured scopes
		// also read monthly traffic, node overrides, serving holds and apply receipts in the same snapshot.
		if len(queries) < 4 || len(queries) > 9 || queries[0] != "begin isolation level repeatable read read only" || queries[len(queries)-1] != "commit" || probeQueries != 1 {
			t.Fatalf("expected one batch probe query plus monthly traffic and apply-receipt reads in a read-only repeatable snapshot; queries=%d probe=%d", len(queries), probeQueries)
		}
		return got
	}
	initial := read()
	if initial.Configuration.State != "unconfigured" || initial.SchemaVersion != 1 || initial.ObservedAt.Location() != time.UTC {
		t.Fatalf("bootstrap: %+v", initial.Configuration)
	}
	for _, item := range initial.Items {
		if item.Sample != nil || item.StaleAfterMS != nil || item.Freshness != "not_reported" || item.RevisionState != "unknown" {
			t.Fatal("fabricated empty probe")
		}
	}
	// An active serving hold (migration 280) is reported on its node only.
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_serving_holds(node_id,source,held,reason_code,revision,held_since,
		protected_groups,changed_at,updated_at) VALUES($1,'availability_monitor',true,'probe_unhealthy',1,now(),1,now(),now())`, ids[5]); err != nil {
		t.Fatal(err)
	}
	held := read()
	for index, item := range held.Items {
		if index == 5 {
			if len(item.ServingHolds) != 1 || item.ServingHolds[0].Source != "availability_monitor" ||
				item.ServingHolds[0].ReasonCode != "probe_unhealthy" || item.ServingHolds[0].ProtectedGroups != 1 ||
				item.ServingHolds[0].HeldSince.IsZero() {
				t.Fatalf("serving hold = %+v", item.ServingHolds)
			}
		} else if item.ServingHolds != nil {
			t.Fatalf("hold leaked to node %d", index)
		}
	}
	if _, err := pool.Exec(t.Context(), `UPDATE node_serving_holds SET held=false,held_since=NULL,protected_groups=0,
		revision=2,reason_code='probe_recovered' WHERE node_id=$1`, ids[5]); err != nil {
		t.Fatal(err)
	}
	if released := read(); released.Items[5].ServingHolds != nil {
		t.Fatal("released hold still reported")
	}
	clock := time.Now().UTC().Add(-5 * time.Minute).Truncate(time.Microsecond)
	service, err := systemconfig.NewServiceWithDependencies(pool, audit.New(pool), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	actor := systemconfig.Actor{UserID: admin.UserID, ScopeID: admin.ScopeID, ScopeKind: "platform"}
	draft, err := service.CreateDraft(t.Context(), actor, systemconfig.CreateDraftRequest{Configuration: systemconfig.ProjectBootstrapConfiguration(), IdempotencyKey: "probe-draft", RequestID: "probe-draft"})
	if err != nil {
		t.Fatal(err)
	}
	if got := read(); got.Configuration.State != "not_activated" || got.Configuration.Policy != nil {
		t.Fatal("draft promoted to policy")
	}
	checks := []systemconfig.PreflightCheck{}
	for _, name := range []string{systemconfig.PreflightSchema, systemconfig.PreflightReferences, systemconfig.PreflightCapacity, systemconfig.PreflightNginxSafety, systemconfig.PreflightErrorPages} {
		checks = append(checks, systemconfig.PreflightCheck{Name: name, Status: systemconfig.CheckPass})
	}
	if _, err := service.RecordPreflight(t.Context(), actor, systemconfig.RecordPreflightRequest{Revision: draft.Revision, ExpectedStatus: systemconfig.StatusDraft, SnapshotSHA256: draft.SnapshotSHA256, Checks: checks, IdempotencyKey: "probe-preflight", RequestID: "probe-preflight"}); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Activate(t.Context(), actor, systemconfig.ActivateRequest{Revision: draft.Revision, IdempotencyKey: "probe-activate", RequestID: "probe-activate"}); err != nil {
		t.Fatal(err)
	}
	observed := time.Now().UTC().Truncate(time.Microsecond)
	for index := range ids[:7] {
		sample := monitoringStoredProbe(ids[index], uint64(index+1), observed)
		switch index {
		case 0:
			sample.Kind, sample.ConfigRevision, sample.ActiveConfigRevision, sample.ProbePort = RecordHostMetric, 0, 0, 0
			sample.Known, sample.MemoryUsedBytes, sample.MemoryTotalBytes = true, 1, 2
			sample.ProbesTotal = 0
		case 2:
			sample.ObservedAt = observed.Add(-time.Minute)
		case 3:
			sample.ObservedAt = observed.Add(time.Minute)
		case 4:
			sample.ConfigRevision = 2
		case 5:
			sample.ConfigRevision, sample.RolledBack = 2, true
		case 6:
			sample.ProbesTotal, sample.ProbeFailuresTotal = math.MaxInt64, 9007199254740993
		}
		if _, err := store.Put(t.Context(), sample); err != nil {
			t.Fatal(err)
		}
	}
	// A newer host-only observation must not hide an existing actual probe.
	host := monitoringStoredProbe(ids[1], 8, observed.Add(time.Second))
	host.Kind, host.ConfigRevision, host.ActiveConfigRevision, host.ProbePort = RecordHostMetric, 0, 0, 0
	host.Known, host.MemoryUsedBytes, host.MemoryTotalBytes, host.ProbesTotal = true, 1, 2, 0
	if _, err := store.Put(t.Context(), host); err != nil {
		t.Fatal(err)
	}
	got := read()
	if got.Configuration.State != "active" || got.Configuration.HeadRevision != 1 || got.Configuration.Policy == nil || !got.Configuration.Policy.Enabled {
		t.Fatal("active policy missing")
	}
	if got.Items[0].Sample != nil || got.Items[7].Sample != nil || *got.Items[0].StaleAfterMS != 43000 {
		t.Fatal("host-only/no sample fabricated probe")
	}
	for index, want := range []struct{ fresh, revision string }{{"not_reported", "unknown"}, {"fresh", "current"}, {"stale", "current"}, {"clock_skew", "current"}, {"fresh", "different"}, {"fresh", "rolled_back"}, {"fresh", "current"}} {
		item := got.Items[index]
		if item.Freshness != want.fresh || item.RevisionState != want.revision {
			t.Fatalf("item %d: %+v", index, item)
		}
	}
	if got.Items[1].Sample.PublicationSequence != 2 || got.Items[1].Sample.Healthy || !got.Items[1].Sample.ObservedAt.Equal(observed) {
		t.Fatal("probe-only sample changed or was replaced by host")
	}
	for _, item := range got.Items {
		if item.DeliveryState != DeliveryAwaitingConfiguration {
			t.Fatalf("never configured node delivery state=%q, want awaiting_configuration", item.DeliveryState)
		}
	}
	servingConfig := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,
		canonical_snapshot_sha256,generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at)
		VALUES($1,$2,'serving',$3,'monitoring-reader','1','releasable','monitoring-reader-serving',$3,now(),now())`,
		servingConfig, admin.ScopeID, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_config_state(node_id,configuration_scope_id,current_config_version_id,updated_at)
		VALUES($1,$3,$4,now()),($2,$3,NULL,now())`, ids[1], ids[2], admin.ScopeID, servingConfig); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE nodes SET admin_state='disabled' WHERE id=$1`, ids[3]); err != nil {
		t.Fatal(err)
	}
	delivery := read()
	for index, want := range []string{DeliveryAwaitingConfiguration, DeliveryServing, DeliveryAwaitingConfiguration, DeliveryInactive} {
		if delivery.Items[index].DeliveryState != want {
			t.Fatalf("item %d delivery state=%q, want %q", index, delivery.Items[index].DeliveryState, want)
		}
	}
	if _, err := pool.Exec(t.Context(), `UPDATE nodes SET admin_state='active' WHERE id=$1`, ids[3]); err != nil {
		t.Fatal(err)
	}
	// A node override shifts only that node's expected revision and policy.
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_monitoring_overrides(node_id,scope_id,protocol,probe_timeout_ms,
		revision,updated_by_user_id,created_at,updated_at) VALUES($1,$2,'http',5000,1,$3,now(),now())`,
		ids[4], admin.ScopeID, admin.UserID); err != nil {
		t.Fatal(err)
	}
	overridden := read()
	if item := overridden.Items[4]; item.EffectiveRevision == nil || *item.EffectiveRevision != 2 || item.EffectivePolicy == nil ||
		item.EffectivePolicy.RequestedProtocol != "http" || item.EffectivePolicy.ProbeTimeoutMS != 5000 ||
		*item.StaleAfterMS != 45000 || item.RevisionState != "different" || item.Sample.Source != "agent_local_http" {
		t.Fatalf("overridden item before its revision applied: %+v", item)
	}
	if item := overridden.Items[1]; item.EffectiveRevision != nil || item.EffectivePolicy != nil || item.RevisionState != "current" ||
		item.Sample.Source != "agent_local_tcp" || *item.StaleAfterMS != 43000 {
		t.Fatalf("override leaked to another node: %+v", item)
	}
	applied := monitoringStoredProbe(ids[4], 21, time.Now().UTC().Truncate(time.Microsecond))
	applied.ConfigRevision, applied.ActiveConfigRevision = 2, 2
	if _, err := store.Put(t.Context(), applied); err != nil {
		t.Fatal(err)
	}
	if item := read().Items[4]; item.RevisionState != "current" || item.Sample.ConfigRevision != 2 {
		t.Fatalf("overridden item at its effective revision: %+v", item)
	}
	raw, err := json.Marshal(got.Items[6].Sample)
	if err != nil || !strings.Contains(string(raw), `"probe_failures_total":"9007199254740993"`) {
		t.Fatal("unsafe numeric serialization")
	}
	// A newer disabled HTTP request is still a draft; active legacy TCP remains.
	configuration := systemconfig.ProjectBootstrapConfiguration()
	monitoring, disabled := systemconfig.EffectiveNodeMonitoring(nil), false
	monitoring.MonitorEnabled, monitoring.Protocol = &disabled, "http"
	configuration.NodeMonitoring = &monitoring
	if _, err := service.CreateDraft(t.Context(), actor, systemconfig.CreateDraftRequest{ExpectedHeadRevision: 1, Configuration: configuration, IdempotencyKey: "probe-draft2", RequestID: "probe-draft2"}); err != nil {
		t.Fatal(err)
	}
	if got := read(); got.Configuration.HeadRevision != 2 || *got.Configuration.ActiveRevision != 1 || !got.Configuration.Policy.Enabled || got.Configuration.Policy.RequestedProtocol != "tcp" {
		t.Fatal("unactivated draft changed probe policy")
	}
	for _, requested := range [][]uuid.UUID{nil, {uuid.Nil}, {ids[0], ids[0]}, append(append([]uuid.UUID{}, ids...), uuid.New())} {
		if _, err := reader.MonitoringLatest(t.Context(), admin.ScopeID, requested); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("invalid batch: %v", err)
		}
	}
	tenant, otherScope, otherNode := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'foreign')`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, otherScope, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO nodes(id,scope_id,name,created_by_user_id,display_id) VALUES($1,$2,'foreign',$3,1)`, otherNode, otherScope, admin.UserID); err != nil {
		t.Fatal(err)
	}
	// Persisted int64 revisions beyond JSON's safe range must fail, not round.
	unsafe := monitoringStoredProbe(ids[1], 9, observed)
	unsafe.ConfigRevision = 1 << 53
	if _, err := store.Put(t.Context(), unsafe); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.MonitoringLatest(t.Context(), admin.ScopeID, ids[:2]); !errors.Is(err, ErrInvalidSample) {
		t.Fatalf("unsafe persisted revision accepted: %v", err)
	}
	for _, absent := range []uuid.UUID{otherNode, uuid.New()} {
		result, err := reader.MonitoringLatest(t.Context(), admin.ScopeID, []uuid.UUID{ids[1], absent})
		if !errors.Is(err, ErrNotFound) || result.Items != nil {
			t.Fatalf("membership leaked sibling data/corruption: %+v %v", result, err)
		}
	}
	// A corrupt view with a NULL required field on a present row must be
	// unavailable, never interpreted as a missing sample. Only this owned schema
	// is altered; append-only rows and all formal constraints stay untouched.
	var definition string
	if err := pool.QueryRow(t.Context(), `SELECT pg_get_viewdef('node_metric_latest'::regclass,true)`).Scan(&definition); err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(definition, "\n    config_revision,", "\n    NULL::bigint AS config_revision,", 1)
	if changed == definition {
		t.Fatal("missing precise corruption-injection target")
	}
	if _, err := pool.Exec(t.Context(), "CREATE OR REPLACE VIEW node_metric_latest AS "+changed); err != nil {
		t.Fatal(err)
	}
	result, err := reader.MonitoringLatest(t.Context(), admin.ScopeID, ids[2:3])
	if err == nil || result.Items != nil {
		t.Fatal("corrupt present row became an absent/zero probe")
	}
}

type monitoringBatchTrace struct {
	mu      sync.Mutex
	queries []string
}

func (trace *monitoringBatchTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	trace.mu.Lock()
	trace.queries = append(trace.queries, data.SQL)
	trace.mu.Unlock()
	return ctx
}

func (*monitoringBatchTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func monitoringStoredProbe(id uuid.UUID, sequence uint64, observed time.Time) Sample {
	return Sample{EventID: uuid.NewString(), RequestID: uuid.NewString(), NodeID: id.String(), SchemaVersion: 1,
		Kind: RecordMetric, ConfigRevision: 1, ActiveConfigRevision: 1, ProbePort: 80,
		PublicationSequence: sequence, ObservedAt: observed, ProbesTotal: 1,
		PubAckStream: NodeMonitoringStatusStream, PubAckSequence: sequence, ConsumerDurable: DefaultConsumerDurable,
		ConsumerSequence: sequence, NumDelivered: 1, WireSHA256: sha256.Sum256([]byte(fmt.Sprintf("synthetic-probe-%d", sequence)))}
}

func monitoringSnapshotPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "monitoring_snapshot_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Errorf("owned schema cleanup: %v", err)
		}
	})
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	var count int
	var verified, includes273 bool
	if err := pool.QueryRow(t.Context(), `SELECT count(*),bool_and(integrity_state='verified'),bool_or(version=273) FROM schema_migrations`).Scan(&count, &verified, &includes273); err != nil || !verified || !includes273 {
		t.Fatalf("formal migrations: %d %t %t %v", count, verified, includes273, err)
	}
	t.Logf("formal verified migrations: %d", count)
	return pool
}
