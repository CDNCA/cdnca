//go:build integration

package l4forward

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
	"time"
	_ "unsafe"

	_ "github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:linkname migrateL4Package092FS github.com/cdnca/cdnca/services/control-api/internal/database.migrateFS
func migrateL4Package092FS(context.Context, *pgxpool.Pool, string, fs.FS) error

const (
	migration091ID   = "091_notification_control_idempotency_receipts"
	migration091Up   = "9c556085f7396024a5011f74b06e0a6e3b83f5f6c5ab050b4b5c7b2ad036758c"
	migration091Down = "7999ad3ae6ecf6b0eb182a1de59e82a37570264223a64f112c7bf8a8b8da8e04"
)

func TestL4PackageRuntime092CharacterContract(t *testing.T) {
	up := mustReadL4Package092(t, "../../migrations/092_l4_package_runtime_contract.up.sql")
	down := mustReadL4Package092(t, "../../migrations/092_l4_package_runtime_contract.down.sql")
	for _, fragment := range []string{
		migration091ID, migration091Up, migration091Down,
		"migration 092 requires the exact verified 091 release head",
		"ERRCODE = 'P9200'", "ERRCODE = 'P9201'",
		"package_subscription_id", "max_connections_per_client",
		"configuration_source_revision", "publish_intent_id",
		"FOREIGN KEY (scope_id, package_subscription_id)",
		"FOREIGN KEY (publish_intent_id, target_scope_id, source_resource_id, source_revision)",
		"balance", "origin", "max_fails", "fail_timeout_ms", "drain_timeout_ms",
		"proxy_protocol_inbound", "proxy_protocol_outbound", "proxy_protocol_v1",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("092 up missing %q", fragment)
		}
	}
	upSHA := fmt.Sprintf("%x", sha256.Sum256([]byte(up)))
	for _, fragment := range []string{
		migration091ID, migration091Up, migration091Down, upSHA,
		"migration 092 rollback requires the verified 092 head",
		"migration 092 rollback would discard L4 package/runtime facts",
		"ERRCODE = 'P9200'", "ERRCODE = 'P9201'",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("092 down missing %q", fragment)
		}
	}
}

func TestL4PackageRuntime092MigrationRoundTripAndHeadPins(t *testing.T) {
	t.Run("fresh 1 through 092 and roundtrip", func(t *testing.T) {
		pool := l4Package092Pool(t, 91)
		mustMigrateL4Package092(t, pool, "up", 92)
		assertL4Package092Ledger(t, pool, 92)
		mustMigrateL4Package092(t, pool, "down", 92)
		assertL4Package092Ledger(t, pool, 91)
		mustMigrateL4Package092(t, pool, "up", 92)
		assertL4Package092Ledger(t, pool, 92)
	})
	t.Run("wrong 091 head", func(t *testing.T) {
		pool := l4Package092Pool(t, 91)
		if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations SET checksum_sha256=repeat('a',64) WHERE version=91`); err != nil {
			t.Fatal(err)
		}
		_, err := pool.Exec(t.Context(), string(mustReadL4Package092Bytes(t, "../../migrations/092_l4_package_runtime_contract.up.sql")))
		assertL4Package092Code(t, err, "P9200")
	})
	t.Run("wrong 092 down head", func(t *testing.T) {
		pool := l4Package092Pool(t, 92)
		if _, err := pool.Exec(t.Context(), `UPDATE schema_migrations SET checksum_sha256=repeat('b',64) WHERE version=92`); err != nil {
			t.Fatal(err)
		}
		_, err := pool.Exec(t.Context(), string(mustReadL4Package092Bytes(t, "../../migrations/092_l4_package_runtime_contract.down.sql")))
		assertL4Package092Code(t, err, "P9200")
	})
}

func TestL4PackageRuntime092RejectsAmbiguousLegacyRows(t *testing.T) {
	pool := l4Package092Pool(t, 91)
	fixture := seedL4Package092Fixture(t, pool)
	if _, err := pool.Exec(t.Context(), `INSERT INTO l4_forwards(
		id,scope_id,owner_user_id,name,protocol,listen_address,listen_port,upstream_address,
		upstream_port,connect_timeout_ms,response_timeout_ms,proxy_protocol_v1,enabled,
		created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,$2,$3,'legacy','tcp','*',19092,'192.0.2.92',443,1000,30000,false,true,$3,$3,clock_timestamp(),clock_timestamp())`,
		uuid.New(), fixture.scopeID, fixture.userID); err != nil {
		t.Fatal(err)
	}
	err := migrateL4Package092Version(t.Context(), pool, "up", 92)
	assertL4Package092Code(t, err, "P9201")
	var exists bool
	if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='l4_forwards' AND column_name='package_subscription_id')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("rejected legacy migration left 092 columns behind")
	}
}

func TestL4PackageRuntime092StoreDurabilityEligibilityReplayAtomicSerialization(t *testing.T) {
	pool := l4Package092Pool(t, 89)
	fixture := seedL4Package092Fixture(t, pool)
	mustMigrateL4Package092(t, pool, "up", l4Package092ReleaseHead(t))
	installL4Package092AutomaticPolicy(t, pool, fixture)
	service := NewService(NewStore(pool))
	actor := Actor{UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: "tenant"}
	request := CreateRequest{
		Fields: Fields{
			PackageSubscriptionID: new(fixture.subscriptionID), Name: "package runtime", Protocol: ProtocolTCP,
			ListenAddress: "*", ListenPort: 19292, UpstreamAddress: "192.0.2.29", UpstreamPort: 443,
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100,
			ProxyProtocolV1: true, Enabled: true,
		},
		IdempotencyKey: "l4-092-create", RequestID: "l4-092-create",
	}
	created, err := service.Create(t.Context(), actor, request)
	if err != nil {
		t.Fatalf("eligible create: %v", err)
	}
	if created.Forward.PackageSubscriptionID == nil || *created.Forward.PackageSubscriptionID != fixture.subscriptionID ||
		created.Forward.EligibilityState != EligibilityEligible ||
		created.Forward.MaxConnectionsPerClient != 100 ||
		created.Forward.PublishIntent.ConfigurationSourceRevision < 1 ||
		created.Forward.PublishIntent.RuntimeSpec.MaxConnectionsPerClient != 100 {
		t.Fatalf("created durable contract=%#v", created.Forward)
	}
	var storedPackage, storedIntent uuid.UUID
	var storedLimit int
	var storedRevision, requestRevision int64
	if err := pool.QueryRow(t.Context(), `SELECT f.package_subscription_id,f.max_connections_per_client,
		i.configuration_source_revision,r.publish_intent_id,r.source_revision
		FROM l4_forwards f JOIN l4_publish_intents i ON i.stream_id=f.id
		JOIN edge_automatic_publication_requests r ON r.source_resource_id=f.id
		WHERE f.id=$1`, created.Forward.ID).Scan(&storedPackage, &storedLimit, &storedRevision, &storedIntent, &requestRevision); err != nil {
		t.Fatal(err)
	}
	if storedPackage != fixture.subscriptionID || storedLimit != 100 || storedIntent != created.Forward.PublishIntent.ID ||
		storedRevision != requestRevision || storedRevision != created.Forward.PublishIntent.ConfigurationSourceRevision {
		t.Fatalf("durable package/limit/revisions=%s/%d/%d/%s/%d", storedPackage, storedLimit, storedRevision, storedIntent, requestRevision)
	}
	assertL4Package092MalformedRuntimeSpecs(t, pool, fixture, created.Forward)
	// The store runs at the release head, so the 092 down gate is covered by
	// TestL4PackageRuntime092RejectsAmbiguousLegacyRows on a 092 schema instead.
	beforeDown := snapshotL4Package092Facts(t, pool, fixture.scopeID, created.Forward.ID)
	installL4Package092LateAuditFailure(t, pool)
	failedUpdate := UpdateRequest{
		ID: created.Forward.ID, ExpectedRevision: created.Forward.Revision, Fields: request.Fields,
		IdempotencyKey: "l4-092-update-late-audit", RequestID: "l4-092-update-late-audit",
	}
	failedUpdate.Fields.Name = "late audit rollback"
	if _, err := service.Update(t.Context(), actor, failedUpdate); err == nil ||
		!strings.Contains(err.Error(), "injected late L4 092 audit failure") {
		t.Fatalf("late audit update error=%v", err)
	}
	assertL4Package092Snapshot(t, beforeDown,
		snapshotL4Package092Facts(t, pool, fixture.scopeID, created.Forward.ID))
	claim, found, err := edgeautopublish.NewStore(pool).Claim(t.Context(), "l4-092-worker", time.Minute)
	if err != nil || !found || claim.Request.PublishIntentID != created.Forward.PublishIntent.ID {
		t.Fatalf("claimed publish intent=%s found=%t err=%v want=%s",
			claim.Request.PublishIntentID, found, err, created.Forward.PublishIntent.ID)
	}
	before := snapshotL4Package092Facts(t, pool, fixture.scopeID, created.Forward.ID)
	cancelL4Package092Subscription(t, pool, fixture)
	replayed, err := service.Create(t.Context(), actor, request)
	if err != nil {
		t.Fatalf("completed replay after cancellation: %v", err)
	}
	if !replayed.Replayed || replayed.Forward.ID != created.Forward.ID || replayed.Forward.EligibilityState != EligibilityIneligible {
		t.Fatalf("dynamic completed replay=%#v", replayed)
	}
	assertL4Package092Snapshot(t, before,
		snapshotL4Package092Facts(t, pool, fixture.scopeID, created.Forward.ID))
	update := UpdateRequest{ID: created.Forward.ID, ExpectedRevision: created.Forward.Revision,
		Fields: request.Fields, IdempotencyKey: "l4-092-update-ineligible", RequestID: "l4-092-update-ineligible"}
	// Since b2d72c9d quota admission (packageaddon.LockRuntimeLimits) rejects an inactive subscription.
	if _, err := service.Update(t.Context(), actor, update); !errors.Is(err, packageaddon.ErrSubscriptionInactive) {
		t.Fatalf("ineligible update error=%v want %v", err, packageaddon.ErrSubscriptionInactive)
	}
	assertL4Package092Snapshot(t, before,
		snapshotL4Package092Facts(t, pool, fixture.scopeID, created.Forward.ID))
	if _, err := service.Delete(t.Context(), actor, DeleteRequest{ID: created.Forward.ID,
		ExpectedRevision: created.Forward.Revision, IdempotencyKey: "l4-092-delete", RequestID: "l4-092-delete"}); err != nil {
		t.Fatalf("ineligible delete cleanup: %v", err)
	}
}

func TestL4PackageRuntime092EligibilityLocks(t *testing.T) {
	t.Run("subscription cancellation", func(t *testing.T) {
		pool, fixture, actor, request, created := createL4Package092Forward(t, "cancellation lock", "l4-092-lock-cancel")
		assertL4Package092EligibilityLock(t, pool, fixture, actor, request, created, "cancel", func(ctx context.Context, tx pgx.Tx) error {
			var now time.Time
			if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE package_subscriptions SET lifecycle_status='cancelled',cancelled_at=$2,
				revision=revision+1,updated_by_user_id=$3,updated_at=$2 WHERE id=$1`,
				fixture.subscriptionID, now, fixture.userID); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO package_subscription_versions(
				subscription_id,revision,operation,snapshot,created_by_user_id,created_at)
				SELECT id,revision,'cancel',jsonb_build_object('lifecycle_status','cancelled'),$2,$3
				FROM package_subscriptions WHERE id=$1`, fixture.subscriptionID, fixture.userID, now)
			return err
		})
	})
	t.Run("entitlement revocation", func(t *testing.T) {
		pool, fixture, actor, request, created := createL4Package092Forward(t, "revocation lock", "l4-092-lock-revoke")
		orderID := insertL4Package092RevocationOrder(t, pool, fixture)
		assertL4Package092EligibilityLock(t, pool, fixture, actor, request, created, "revoke", func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, `WITH moment AS (SELECT clock_timestamp() AS now)
				INSERT INTO package_subscription_entitlement_versions(
					subscription_id,revision,supersedes_subscription_id,supersedes_revision,
					tenant_scope_id,effective_at,effective_until,product_id,product_revision,product_snapshot,
					site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,custom_cycle_days,
					tcp_factor_numerator,tcp_factor_denominator,package_period,period_price_minor,currency,
					entitlement_status,source_order_id,operation,created_by_user_id,created_at)
				SELECT entitlement.subscription_id,2,entitlement.subscription_id,entitlement.revision,
					entitlement.tenant_scope_id,GREATEST(entitlement.effective_at,moment.now),NULL,
					entitlement.product_id,entitlement.product_revision,entitlement.product_snapshot,
					entitlement.site_limit,entitlement.domain_limit,entitlement.node_limit,
					entitlement.traffic_limit_bytes,entitlement.timezone,entitlement.cycle_kind,
					entitlement.custom_cycle_days,entitlement.tcp_factor_numerator,
					entitlement.tcp_factor_denominator,entitlement.package_period,
					entitlement.period_price_minor,entitlement.currency,'revoked',$2,'void',$3,
					GREATEST(entitlement.created_at,moment.now)
				FROM package_subscription_entitlement_versions entitlement CROSS JOIN moment
				WHERE entitlement.subscription_id=$1 AND entitlement.revision=1`,
				fixture.subscriptionID, orderID, fixture.userID)
			return err
		})
	})
}

type l4Package092FactSnapshot struct {
	forward, intents, writes, automaticRequests, automaticStates, audits string
	publishCounter, sourceRevision                                       int64
}

func assertL4Package092MalformedRuntimeSpecs(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture l4Package092Fixture,
	created Forward,
) {
	t.Helper()
	base, err := json.Marshal(created.PublishIntent.RuntimeSpec)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(map[string]any) map[string]any
	}{
		{name: "empty object", mutate: func(map[string]any) map[string]any { return map[string]any{} }},
		{name: "numeric string", mutate: func(spec map[string]any) map[string]any {
			spec["listen_port"] = fmt.Sprint(created.ListenPort)
			return spec
		}},
		// 151 起 drain_timeout_ms 合法区间为 1000–600000（092 时只认 30000），取区间外的值。
		{name: "wrong drain timeout", mutate: func(spec map[string]any) map[string]any {
			spec["drain_timeout_ms"] = 600001
			return spec
		}},
		{name: "extra key", mutate: func(spec map[string]any) map[string]any {
			spec["unexpected"] = true
			return spec
		}},
		// v2 运行时（151 起）顶层已无 balance（ip_hash 在 endpoint 内且可选），删一个必需键。
		{name: "missing key", mutate: func(spec map[string]any) map[string]any {
			delete(spec, "drain_timeout_ms")
			return spec
		}},
	}
	var before int64
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM l4_publish_intents WHERE stream_id=$1`,
		created.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for index, test := range tests {
		t.Run("runtime spec "+test.name, func(t *testing.T) {
			var spec map[string]any
			if err := json.Unmarshal(base, &spec); err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(test.mutate(spec))
			if err != nil {
				t.Fatal(err)
			}
			_, err = pool.Exec(t.Context(), `INSERT INTO l4_publish_intents(
				id,scope_id,stream_id,version,operation,desired_state,resource_revision,
				configuration_source_revision,runtime_spec,created_by_user_id,created_at)
				VALUES($1,$2,$3,$4,'update','enabled',$5,$6,$7::jsonb,$8,clock_timestamp())`,
				uuid.New(), fixture.scopeID, created.ID, created.PublishIntent.Version+100+int64(index),
				created.Revision, created.PublishIntent.ConfigurationSourceRevision, payload, fixture.userID)
			// The runtime spec check is re-added by later migrations (currently 316).
			assertL4Package092ConstraintPrefix(t, err, "23514", "l4_publish_intents_runtime_spec_")
			var after int64
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM l4_publish_intents WHERE stream_id=$1`,
				created.ID).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if after != before {
				t.Fatalf("malformed runtime changed intent count from %d to %d", before, after)
			}
		})
	}
}

func assertL4Package092SchemaRetained(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var columns, constraints int64
	var validator bool
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema()
		AND (table_name,column_name) IN (('l4_forwards','package_subscription_id'),
		('l4_forwards','max_connections_per_client'),('l4_publish_intents','configuration_source_revision'),
		('edge_automatic_publication_requests','publish_intent_id'))`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM pg_constraint WHERE conname IN (
		'package_subscriptions_tenant_id_092','l4_forwards_scope_package_092','l4_forwards_id_scope_092',
		'l4_publish_intents_stream_scope_092','l4_publish_intents_runtime_spec_092',
		'l4_publish_intents_request_identity_092','edge_automatic_publication_l4_intent_presence_092',
		'edge_automatic_publication_l4_intent_092')`).Scan(&constraints); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT to_regprocedure(
		'validate_l4_runtime_spec_092(uuid,jsonb)') IS NOT NULL`).Scan(&validator); err != nil {
		t.Fatal(err)
	}
	if columns != 4 || constraints != 8 || !validator {
		t.Fatalf("retained 092 schema columns/constraints/validator=%d/%d/%t", columns, constraints, validator)
	}
}

func installL4Package092LateAuditFailure(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, statement := range []string{
		`CREATE FUNCTION l4_package_092_fail_late_update_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action='stream.update' AND NEW.request_id='l4-092-update-late-audit' THEN
				RAISE EXCEPTION 'injected late L4 092 audit failure';
			END IF;
			RETURN NEW;
		END $$`,
		`CREATE TRIGGER l4_package_092_fail_late_update_audit
		BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION l4_package_092_fail_late_update_audit()`,
	} {
		if _, err := pool.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
}

func snapshotL4Package092Facts(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID, forwardID uuid.UUID,
) l4Package092FactSnapshot {
	t.Helper()
	var snapshot l4Package092FactSnapshot
	if err := pool.QueryRow(t.Context(), `SELECT
		COALESCE((SELECT to_jsonb(forward_row)::text FROM l4_forwards forward_row WHERE id=$2),'null'),
		COALESCE((SELECT jsonb_agg(to_jsonb(intent) ORDER BY intent.version,intent.id)::text
			FROM l4_publish_intents intent WHERE intent.stream_id=$2),'[]'),
		COALESCE((SELECT jsonb_agg(to_jsonb(write_row) ORDER BY write_row.operation,write_row.idempotency_key)::text
			FROM l4_write_requests write_row WHERE write_row.target_scope_id=$1),'[]'),
		COALESCE((SELECT current_version FROM l4_scope_publish_counters WHERE scope_id=$1),0),
		COALESCE((SELECT source_revision FROM edge_configuration_scopes WHERE scope_id=$1),0),
		COALESCE((SELECT jsonb_agg(to_jsonb(request_row) ORDER BY request_row.source_revision,request_row.id)::text
			FROM edge_automatic_publication_requests request_row
			WHERE request_row.target_scope_id=$1 AND request_row.source_kind='l4'),'[]'),
		COALESCE((SELECT jsonb_agg(to_jsonb(state_row) ORDER BY state_row.request_id,state_row.sequence)::text
			FROM edge_automatic_publication_request_state_facts state_row
			JOIN edge_automatic_publication_requests request_row ON request_row.id=state_row.request_id
			WHERE request_row.target_scope_id=$1 AND request_row.source_kind='l4'),'[]'),
		COALESCE((SELECT jsonb_agg(to_jsonb(event) ORDER BY event.stream_position,event.id)::text
			FROM audit_events event WHERE event.scope_id=$1 AND event.action LIKE 'stream.%'),'[]')`,
		scopeID, forwardID).Scan(&snapshot.forward, &snapshot.intents, &snapshot.writes,
		&snapshot.publishCounter, &snapshot.sourceRevision, &snapshot.automaticRequests,
		&snapshot.automaticStates, &snapshot.audits); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func assertL4Package092Snapshot(t *testing.T, want, got l4Package092FactSnapshot) {
	t.Helper()
	if got != want {
		t.Fatalf("L4 facts changed\nwant=%#v\ngot=%#v", want, got)
	}
}

func createL4Package092Forward(
	t *testing.T,
	name, key string,
) (*pgxpool.Pool, l4Package092Fixture, Actor, CreateRequest, Forward) {
	t.Helper()
	pool := l4Package092Pool(t, 89)
	fixture := seedL4Package092Fixture(t, pool)
	mustMigrateL4Package092(t, pool, "up", l4Package092ReleaseHead(t))
	installL4Package092AutomaticPolicy(t, pool, fixture)
	actor := Actor{UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: "tenant"}
	request := CreateRequest{
		Fields: Fields{
			PackageSubscriptionID: new(fixture.subscriptionID), Name: name, Protocol: ProtocolTCP,
			ListenAddress: "*", ListenPort: 19392, UpstreamAddress: "192.0.2.39", UpstreamPort: 443,
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100,
			ProxyProtocolV1: true, Enabled: true,
		},
		IdempotencyKey: key, RequestID: key,
	}
	created, err := NewService(NewStore(pool)).Create(t.Context(), actor, request)
	if err != nil {
		t.Fatal(err)
	}
	return pool, fixture, actor, request, created.Forward
}

func assertL4Package092EligibilityLock(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture l4Package092Fixture,
	actor Actor,
	request CreateRequest,
	created Forward,
	caseName string,
	changeEligibility func(context.Context, pgx.Tx) error,
) {
	t.Helper()
	before := snapshotL4Package092Facts(t, pool, fixture.scopeID, created.ID)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	blocker, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Release()
	blockerTx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_ = blockerTx.Rollback(cleanupCtx)
	}()
	if err := changeEligibility(ctx, blockerTx); err != nil {
		t.Fatal(err)
	}
	var blockerPID int32
	if err := blockerTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	workerPool, workerPID := l4Package092WorkerPool(t, pool)
	update := UpdateRequest{
		ID: created.ID, ExpectedRevision: created.Revision, Fields: request.Fields,
		IdempotencyKey: "l4-092-lock-" + caseName, RequestID: "l4-092-lock-" + caseName,
	}
	update.Fields.Name += " blocked"
	result := make(chan error, 1)
	go func() {
		_, updateErr := NewService(NewStore(workerPool)).Update(ctx, actor, update)
		result <- updateErr
	}()
	waitForL4Package092Block(t, pool, workerPID, blockerPID)
	if err := blockerTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, packageaddon.ErrSubscriptionInactive) {
			t.Fatalf("eligibility-fenced update error=%v want %v", err, packageaddon.ErrSubscriptionInactive)
		}
	case <-ctx.Done():
		t.Fatalf("eligibility-fenced update did not finish: %v", ctx.Err())
	}
	assertL4Package092Snapshot(t, before,
		snapshotL4Package092Facts(t, pool, fixture.scopeID, created.ID))
	current, err := NewService(NewStore(pool)).Get(ctx, actor, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if current.EligibilityState != EligibilityIneligible {
		t.Fatalf("dynamic eligibility=%q want %q", current.EligibilityState, EligibilityIneligible)
	}
}

func l4Package092WorkerPool(t *testing.T, source *pgxpool.Pool) (*pgxpool.Pool, int32) {
	t.Helper()
	config := source.Config()
	config.MinConns = 0
	config.MaxConns = 1
	worker, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(worker.Close)
	connection, err := worker.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var pid int32
	if err := connection.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		connection.Release()
		t.Fatal(err)
	}
	connection.Release()
	return worker, pid
}

func waitForL4Package092Block(t *testing.T, pool *pgxpool.Pool, blockedPID, blockerPID int32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT $2::integer=ANY(pg_blocking_pids($1::integer))`,
			blockedPID, blockerPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("backend %d was not blocked by %d: %v", blockedPID, blockerPID, ctx.Err())
		case <-ticker.C:
		}
	}
}

func insertL4Package092RevocationOrder(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture l4Package092Fixture,
) uuid.UUID {
	t.Helper()
	orderID := uuid.New()
	requestID := "l4-092-revoke-" + strings.ReplaceAll(orderID.String(), "-", "")
	if _, err := pool.Exec(t.Context(), `WITH moment AS (SELECT clock_timestamp() AS now)
		INSERT INTO package_orders(
			id,tenant_scope_id,user_id,operation,subscription_id,product_kind,product_id,product_revision,
			package_period,product_snapshot,entitlement_snapshot,pricing_snapshot,currency,
			original_amount_minor,discount_amount_minor,payable_amount_minor,settlement_direction,
			funding_source,effective_mode,effective_at,request_id,trace_id,
			created_by_scope_id,created_by_user_id,created_at)
		SELECT $1,subscription.tenant_scope_id,$2,'renew',subscription.id,'package_subscription',
			subscription.product_id,subscription.product_revision,'month',subscription.product_snapshot,
			jsonb_build_object('subscription_id',subscription.id),'{}'::jsonb,'CNY',0,0,0,
			'debit','balance','immediate',moment.now,$4,$4,subscription.tenant_scope_id,$2,moment.now
		FROM package_subscriptions subscription CROSS JOIN moment WHERE subscription.id=$3`,
		orderID, fixture.userID, fixture.subscriptionID, requestID); err != nil {
		t.Fatal(err)
	}
	return orderID
}

func assertL4Package092ConstraintPrefix(t *testing.T, err error, code, prefix string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code || !strings.HasPrefix(pgErr.ConstraintName, prefix) {
		t.Fatalf("PostgreSQL error=%v want SQLSTATE %s constraint %s*", err, code, prefix)
	}
}

func assertL4Package092Constraint(t *testing.T, err error, code, constraint string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != code || pgErr.ConstraintName != constraint {
		t.Fatalf("PostgreSQL error=%v want SQLSTATE %s constraint %s", err, code, constraint)
	}
}

type l4Package092Fixture struct {
	scopeID, userID, subscriptionID uuid.UUID
}

func seedL4Package092Fixture(t *testing.T, pool *pgxpool.Pool) l4Package092Fixture {
	t.Helper()
	fixture := l4Package092Fixture{scopeID: uuid.New(), userID: uuid.New(), subscriptionID: uuid.New()}
	tenantID, platformScopeID, roleID, productID, groupID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	productSpec := validL4Package092ProductSpec(groupID)
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO access_scopes(id,kind) SELECT $1,'platform' WHERE NOT EXISTS(SELECT 1 FROM access_scopes WHERE kind='platform')`, []any{platformScopeID}},
			{`INSERT INTO tenants(id,display_name) VALUES($1,'L4 092 tenant')`, []any{tenantID}},
			{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{fixture.scopeID, tenantID}},
			{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'L4 092 owner','hash')`, []any{fixture.userID, "l4092-" + strings.ReplaceAll(fixture.userID.String(), "-", "")}},
			{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{fixture.scopeID, fixture.userID}},
			{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','L4 092',true)`, []any{roleID, fixture.scopeID}},
			{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'streams.manage')`, []any{roleID}},
			{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{fixture.scopeID, fixture.userID, roleID}},
		} {
			if _, err := tx.Exec(t.Context(), statement.query, statement.args...); err != nil {
				return err
			}
		}
		if err := tx.QueryRow(t.Context(), `SELECT id FROM access_scopes
			WHERE kind='platform' AND tenant_id IS NULL`).Scan(&platformScopeID); err != nil {
			return err
		}
		var durableCatalog bool
		if err := tx.QueryRow(t.Context(), `SELECT to_regclass('package_catalog_commit_watermark_090') IS NOT NULL`).Scan(
			&durableCatalog); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_groups(
			id,name,visible,sort_order,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,'L4 092 group',true,1,1,$2,$2,clock_timestamp(),clock_timestamp())`,
			groupID, fixture.userID); err != nil {
			return err
		}
		if durableCatalog {
			if err := insertL4PackageCatalogAudit092(t.Context(), tx, platformScopeID, fixture.userID,
				"package.group.create", "package_group", groupID, `{"revision":1,"visible":true}`); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_products(
			id,name,enabled,sort_order,spec,revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			VALUES($1,'L4 092 product',true,1,$2::jsonb,1,$3,$3,clock_timestamp(),clock_timestamp())`,
			productID, productSpec, fixture.userID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_product_versions(
			product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at)
			VALUES($1,1,'L4 092 product',true,1,$2::jsonb,false,$3,clock_timestamp())`,
			productID, productSpec, fixture.userID); err != nil {
			return err
		}
		if durableCatalog {
			if err := insertL4PackageCatalogAudit092(t.Context(), tx, platformScopeID, fixture.userID,
				"package.product.create", "package_product", productID, `{"revision":1,"enabled":true}`); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(t.Context(), `WITH moment AS (SELECT clock_timestamp() AS now)
			INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,
			site_limit,domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,
			custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,lifecycle_status,revision,
			created_by_user_id,updated_by_user_id,created_at,updated_at)
			SELECT $1,$2,p.product_id,p.revision,jsonb_build_object('id',p.product_id::text,'revision',p.revision,'name',p.name,'spec',p.spec),
			10,10,10,-1,moment.now-interval '1 hour',moment.now+interval '1 day','UTC','monthly',0,1,1,'active',1,$3,$3,moment.now,moment.now
			FROM package_product_versions p CROSS JOIN moment WHERE p.product_id=$4 AND p.revision=1`,
			fixture.subscriptionID, fixture.scopeID, fixture.userID, productID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO package_subscription_entitlement_versions(
			subscription_id,revision,supersedes_subscription_id,supersedes_revision,
			tenant_scope_id,effective_at,effective_until,product_id,product_revision,product_snapshot,
			site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,custom_cycle_days,
			tcp_factor_numerator,tcp_factor_denominator,package_period,period_price_minor,currency,
			entitlement_status,source_order_id,operation,created_by_user_id,created_at)
			SELECT subscription.id,1,NULL,NULL,subscription.tenant_scope_id,subscription.starts_at,NULL,
			subscription.product_id,subscription.product_revision,subscription.product_snapshot,
			subscription.site_limit,subscription.domain_limit,subscription.node_limit,subscription.traffic_limit_bytes,
			subscription.timezone,subscription.cycle_kind,subscription.custom_cycle_days,
			subscription.tcp_factor_numerator,subscription.tcp_factor_denominator,NULL,NULL,'CNY',
			'active',NULL,'migration_backfill',$2,clock_timestamp()
			FROM package_subscriptions AS subscription WHERE subscription.id=$1`, fixture.subscriptionID, fixture.userID)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func insertL4PackageCatalogAudit092(
	ctx context.Context,
	tx pgx.Tx,
	platformScopeID, actorUserID uuid.UUID,
	action, resourceType string,
	resourceID uuid.UUID,
	payload string,
) error {
	_, err := tx.Exec(ctx, `WITH previous AS (
		SELECT stream_position,event_hash FROM audit_events WHERE scope_id=$2
		ORDER BY stream_position DESC LIMIT 1
	)
	INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at)
	SELECT $1,$2,COALESCE(previous.stream_position,0)+1,$3,$4,$5,$6,
		$7,'success',$8::jsonb,previous.event_hash,$9,clock_timestamp()
	FROM (SELECT true) seed LEFT JOIN previous ON true`, uuid.New(), platformScopeID,
		actorUserID, action, resourceType, resourceID.String(), "l4-092-catalog-"+uuid.NewString(),
		payload, make([]byte, sha256.Size))
	return err
}

func validL4Package092ProductSpec(groupID uuid.UUID) string {
	return `{"name":"L4 092 product","description":"contract","group_ids":["` + groupID.String() + `"],` +
		`"region_id":"11111111-1111-4111-8111-111111111111","node_group_id":"22222222-2222-4222-8222-222222222222","backup_node_group_id":null,` +
		`"limits":{"monthly_traffic_bytes":1024,"bandwidth_bps":1024,"connections":100,"stream_ports":10,"domains":10,"root_domains":10,"http_ports":10,"custom_cc":false,"websocket":true,"http3":true,"l2_origin":false},` +
		`"protection":{"cc":"","ddos":""},"prices":{"currency":"CNY","monthly_minor":100,"quarterly_minor":270,"yearly_minor":1000},` +
		`"cname":{"hostname":"","domain":"cdn.example.com","mode":"per_site"},"purchase":{"per_user_limit":-1,"sale_expires_at":null,"require_real_name":false,"restrict_source_ips":false,"renew_before_days":-1},` +
		`"commercial_terms":{"timezone":"UTC","cycle_kind":"monthly","custom_cycle_days":0,"site_limit":10,"node_limit":10,"tcp_factor_numerator":1,"tcp_factor_denominator":1},"sort_order":1,"enabled":true}`
}

func installL4Package092AutomaticPolicy(t *testing.T, pool *pgxpool.Pool, fixture l4Package092Fixture) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds,actor_scope_id,actor_user_id,reason,created_at)
		VALUES($1,1,'automatic',ARRAY[$2::uuid],30000,15000,2,3,600,$1,$3,'L4 092',clock_timestamp())`,
		fixture.scopeID, uuid.New(), fixture.userID); err != nil {
		t.Fatal(err)
	}
}

func cancelL4Package092Subscription(t *testing.T, pool *pgxpool.Pool, fixture l4Package092Fixture) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var now time.Time
		if err := tx.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `UPDATE package_subscriptions SET lifecycle_status='cancelled',cancelled_at=$2,
			revision=revision+1,updated_by_user_id=$3,updated_at=$2 WHERE id=$1`, fixture.subscriptionID, now, fixture.userID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO package_subscription_versions(
			subscription_id,revision,operation,snapshot,created_by_user_id,created_at)
			SELECT id,revision,'cancel',jsonb_build_object('lifecycle_status','cancelled'),$2,$3
			FROM package_subscriptions WHERE id=$1`, fixture.subscriptionID, fixture.userID, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func l4Package092Pool(t *testing.T, maximum int64) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "l4_package_092_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^l4_package_092_test_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		_, _ = admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	mustMigrateL4Package092(t, pool, "up", maximum)
	return pool
}

func migrateL4Package092Version(ctx context.Context, pool *pgxpool.Pool, direction string, target int64) error {
	files := make(fstest.MapFS, int(target)*2)
	for version := int64(1); version <= target; version++ {
		for _, suffix := range []string{"up", "down"} {
			pattern := fmt.Sprintf("%03d_*.%s.sql", version, suffix)
			matches, err := fs.Glob(controlmigrations.FS, pattern)
			if err != nil || len(matches) != 1 {
				return fmt.Errorf("resolve migration %03d %s: matches=%v err=%v", version, suffix, matches, err)
			}
			payload, err := fs.ReadFile(controlmigrations.FS, matches[0])
			if err != nil {
				return err
			}
			files[matches[0]] = &fstest.MapFile{Data: payload}
		}
	}
	return migrateL4Package092FS(ctx, pool, direction, files)
}

// l4Package092ReleaseHead is the release head. Tests that drive the current
// Store must migrate there after seeding the 089-shaped fixture: the store
// reads tables added after 092 (e.g. l4_stream_user_defaults from 236), and
// production never runs the current binary on a 092 schema.
func l4Package092ReleaseHead(t *testing.T) int64 {
	t.Helper()
	ups, err := fs.Glob(controlmigrations.FS, "*.up.sql")
	if err != nil || len(ups) == 0 {
		t.Fatalf("list embedded migrations: %d %v", len(ups), err)
	}
	return int64(len(ups))
}

func mustMigrateL4Package092(t *testing.T, pool *pgxpool.Pool, direction string, target int64) {
	t.Helper()
	if err := migrateL4Package092Version(t.Context(), pool, direction, target); err != nil {
		t.Fatalf("migrate %s %03d: %v", direction, target, err)
	}
}

func assertL4Package092Ledger(t *testing.T, pool *pgxpool.Pool, maximum int64) {
	t.Helper()
	var count, minimum, maximumFound, invalid int64
	if err := pool.QueryRow(t.Context(), `SELECT count(*),min(version),max(version),count(*) FILTER(
		WHERE migration_id IS NULL OR checksum_sha256 !~ '^[0-9a-f]{64}$' OR down_checksum_sha256 !~ '^[0-9a-f]{64}$'
		OR integrity_state<>'verified' OR metadata_recorded_at IS NULL OR applied_at IS NULL) FROM schema_migrations`).Scan(
		&count, &minimum, &maximumFound, &invalid); err != nil {
		t.Fatal(err)
	}
	if count != maximum || minimum != 1 || maximumFound != maximum || invalid != 0 {
		t.Fatalf("ledger count/min/max/invalid=%d/%d/%d/%d", count, minimum, maximumFound, invalid)
	}
}

func assertL4Package092Code(t *testing.T, err error, want string) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != want {
		t.Fatalf("PostgreSQL error=%v want SQLSTATE %s", err, want)
	}
}

func mustReadL4Package092(t *testing.T, name string) string {
	t.Helper()
	return string(mustReadL4Package092Bytes(t, name))
}

func mustReadL4Package092Bytes(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
