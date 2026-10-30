//go:build integration

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrolruntime"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

func TestBuildCacheControlRuntimeClosePreservesCallerOwnedResources(t *testing.T) {
	databaseURL := os.Getenv("CDNCA_CACHE_CONTROL_COMPOSITION_DATABASE_URL")
	natsURL := os.Getenv("CDNCA_CACHE_CONTROL_COMPOSITION_NATS_URL")
	taskID := os.Getenv("CDNCA_CACHE_CONTROL_COMPOSITION_TASK_ID")
	if databaseURL == "" || natsURL == "" || taskID == "" {
		t.Skip("task-only cache control composition integration environment is required")
	}

	pool := openCacheControlCompositionDatabase(t, databaseURL)
	assertCacheControlTaskPostgres(t, pool, taskID)

	connection, err := nats.Connect(natsURL, nats.Timeout(2*time.Second),
		nats.Name("cache-control-composition-integration"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	assertCacheControlTaskNATS(t, connection, natsURL, taskID)
	jetstream, err := connection.JetStream(nats.MaxWait(2 * time.Second))
	if err != nil {
		t.Fatal(err)
	}

	suffix := strings.ToLower(strings.ReplaceAll(uuid.NewString(), "-", "")[:12])
	workerConfig := cachecontrolruntime.DefaultConfig()
	workerConfig.Replicas = 1
	workerConfig.CommandStream = "CC_COMPOSITION_COMMAND_" + strings.ToUpper(suffix)
	workerConfig.StatusStream = "CC_COMPOSITION_STATUS_" + strings.ToUpper(suffix)
	workerConfig.CommandSubjectPrefix = "cdnca.test.cache.composition.command." + suffix
	workerConfig.StatusSubjectPrefix = "cdnca.test.cache.composition.status." + suffix
	workerConfig.DLQSubjectPrefix = "cdnca.test.cache.composition.dlq." + suffix
	workerConfig.Durable = "cc_composition_status_" + suffix
	workerConfig.WorkerID = "cc_composition_worker_" + suffix
	workerConfig.PollInterval = 10 * time.Millisecond
	workerConfig.FetchTimeout = 250 * time.Millisecond
	workerConfig.OperationTimeout = 2 * time.Second
	workerConfig.ClaimBatch = 1
	now := time.Now().UTC().Truncate(time.Microsecond)
	workerConfig.Clock = func() time.Time { return now }
	fixture := seedCacheControlCompositionFixture(t, pool, now, suffix)
	precreateCacheControlResources(t, jetstream, workerConfig)

	leases := &cacheControlCompositionLeases{
		nodeID: fixture.nodeID, called: make(chan uuid.UUID, 1),
	}
	dependencies := cacheControlCompositionDependencies(t, pool, connection, leases)
	runtimeConfig := cacheControlRuntimeConfig{
		Enabled: true, CursorKey: bytes.Repeat([]byte{0x63}, 32), Worker: workerConfig,
	}
	subscriptionsBeforeBuild := connection.NumSubscriptions()
	assertConfigurationGate := func(name string, candidate cacheControlRuntimeConfig, candidateDependencies cacheControlRuntimeDependencies) {
		t.Helper()
		candidateRuntime, candidateErr := buildCacheControlRuntime(candidate, candidateDependencies)
		if candidateRuntime != nil || candidateErr == nil || candidateErr.Error() != "cache control runtime configuration is incomplete" {
			t.Fatalf("%s runtime = (%v, %v), want configuration gate", name, candidateRuntime, candidateErr)
		}
		if got := connection.NumSubscriptions(); got != subscriptionsBeforeBuild {
			t.Fatalf("%s bound worker subscriptions = %d, want %d", name, got, subscriptionsBeforeBuild)
		}
	}
	for length := 1; length < 32; length++ {
		candidate := runtimeConfig
		candidate.CursorKey = bytes.Repeat([]byte{0x63}, length)
		assertConfigurationGate(fmt.Sprintf("%d-byte cursor key", length), candidate, dependencies)
	}
	for _, candidate := range []struct {
		name         string
		dependencies cacheControlRuntimeDependencies
	}{
		{name: "unconfigured identity", dependencies: func() cacheControlRuntimeDependencies {
			value := dependencies
			value.Identity = &identity.Service{}
			return value
		}()},
		{name: "unconfigured IAM", dependencies: func() cacheControlRuntimeDependencies {
			value := dependencies
			value.IAM = &iamlock.Authorizer{}
			return value
		}()},
	} {
		assertConfigurationGate(candidate.name, runtimeConfig, candidate.dependencies)
	}
	closedConnection, err := nats.Connect(natsURL, nats.Timeout(2*time.Second),
		nats.Name("cache-control-composition-closed-gate"))
	if err != nil {
		t.Fatal(err)
	}
	closedConnection.Close()
	closedDependencies := dependencies
	closedDependencies.NATS = closedConnection
	assertConfigurationGate("closed NATS", runtimeConfig, closedDependencies)
	if got := closedConnection.NumSubscriptions(); got != 0 {
		t.Fatalf("closed NATS worker subscriptions = %d, want 0", got)
	}
	consumerBeforeInvalidWorker, err := jetstream.ConsumerInfo(workerConfig.StatusStream, workerConfig.Durable)
	if err != nil {
		t.Fatal(err)
	}
	invalidWorkerConfig := runtimeConfig
	invalidWorkerConfig.Worker.ClaimBatch = 0
	invalidRuntime, invalidErr := buildCacheControlRuntime(invalidWorkerConfig, dependencies)
	if invalidRuntime != nil || !errors.Is(invalidErr, cachecontrolruntime.ErrInvalidConfig) {
		t.Fatalf("invalid worker runtime = (%v, %v), want invalid config", invalidRuntime, invalidErr)
	}
	if got := connection.NumSubscriptions(); got != subscriptionsBeforeBuild {
		t.Fatalf("invalid worker bound subscriptions = %d, want %d", got, subscriptionsBeforeBuild)
	}
	consumerAfterInvalidWorker, err := jetstream.ConsumerInfo(workerConfig.StatusStream, workerConfig.Durable)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(consumerAfterInvalidWorker, consumerBeforeInvalidWorker) {
		t.Fatalf("invalid worker changed durable consumer state: before=%+v after=%+v",
			consumerBeforeInvalidWorker, consumerAfterInvalidWorker)
	}

	runtime, err := buildCacheControlRuntime(runtimeConfig, dependencies)
	if err != nil {
		t.Fatalf("%v: %v", err, errors.Unwrap(err))
	}
	if runtime == nil {
		t.Fatal("cache control composition runtime is nil")
	}
	if got := connection.NumSubscriptions(); got != subscriptionsBeforeBuild+1 {
		t.Fatalf("NATS subscriptions after build = %d, want %d", got, subscriptionsBeforeBuild+1)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background()) }()
	select {
	case nodeID := <-leases.called:
		if nodeID != fixture.nodeID {
			t.Fatalf("cache worker checked node lease %s, want %s", nodeID, fixture.nodeID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("real cache worker did not query caller PostgreSQL facts and node leases")
	}
	command := waitForCacheControlCompositionCommand(t, jetstream, workerConfig, fixture.nodeID)
	if command.NodeId != fixture.nodeID.String() || command.ControlOperationId != fixture.operationID.String() ||
		command.ConfigVersionId != fixture.configID.String() || command.ConfigRevision != 7 {
		t.Fatalf("cache composition command = %+v", command)
	}
	workerLeaseCalls := leases.calls.Load()
	if workerLeaseCalls < 1 {
		t.Fatal("real cache worker did not call caller-owned node leases")
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("real cache worker was not ready before HTTP composition request: %v", err)
	}
	if runtime.pool != pool || runtime.handlerDependencies.Pool != pool {
		t.Fatal("real worker and HTTP handler do not share the caller-owned PostgreSQL pool")
	}
	tokens, err := identity.NewTokenManager(strings.Repeat("c", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := uuid.New()
	// Store.CreateSession only accepts a verified login (password or code), so
	// the fixture writes the session row directly and reads the principal back.
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,user_agent,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,'cache-control-composition',now(),$6)`, sessionID, uuid.New(), fixture.userID, fixture.scopeID,
		bytes.Repeat([]byte{0x73}, 32), time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	principal, err := identity.NewStore(pool).PrincipalForSession(t.Context(), fixture.userID, fixture.scopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	accessToken, _, err := tokens.Mint(fixture.userID, fixture.scopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	var authenticateCalls atomic.Int32
	handler, err := runtime.HandlerFactory()(func(request *http.Request) (identity.Principal, error) {
		authenticateCalls.Add(1)
		if request.Header.Get("Authorization") != "Bearer "+accessToken {
			return identity.Principal{}, identity.ErrInvalidSession
		}
		return principal, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/cache-operations?limit=10", nil)
	request.Header.Set("Authorization", "Bearer "+accessToken)
	request.Header.Set("X-Request-ID", "cache-composition-handler-"+suffix)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), fixture.operationID.String()) {
		t.Fatalf("real cache HTTP composition response = %d %s", response.Code, response.Body.String())
	}
	if authenticateCalls.Load() != 1 {
		t.Fatalf("real cache HTTP authenticate calls = %d, want 1", authenticateCalls.Load())
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("real cache worker stopped during HTTP composition request: %v", err)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- runtime.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("real cache control composition Close did not wait for Run")
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("real cache control composition Run() after Close = %v, want canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("real cache control composition Run survived Close")
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := connection.FlushTimeout(2 * time.Second); err != nil {
		t.Fatalf("caller-owned NATS connection is unusable after runtime Close: %v", err)
	}
	if connection.IsClosed() || connection.Status() != nats.CONNECTED {
		t.Fatalf("caller-owned NATS status after runtime Close = %s", connection.Status())
	}
	if got := connection.NumSubscriptions(); got != subscriptionsBeforeBuild {
		t.Fatalf("NATS subscriptions after runtime Close = %d, want %d", got, subscriptionsBeforeBuild)
	}
	for _, streamName := range []string{workerConfig.CommandStream, workerConfig.StatusStream} {
		info, err := jetstream.StreamInfo(streamName)
		if err != nil {
			t.Fatalf("runtime Close deleted caller-created stream %s: %v", streamName, err)
		}
		if info.Config.Name != streamName || info.Config.Storage != nats.FileStorage {
			t.Fatalf("caller-created stream after Close = (%s, %v)", info.Config.Name, info.Config.Storage)
		}
	}
	if _, err := jetstream.ConsumerInfo(workerConfig.StatusStream, workerConfig.Durable); err != nil {
		t.Fatalf("runtime Close deleted the caller-created durable consumer: %v", err)
	}
	var one int
	if err := pool.QueryRow(t.Context(), `SELECT 1`).Scan(&one); err != nil || one != 1 {
		t.Fatalf("caller-owned PostgreSQL pool after runtime Close = (%d, %v)", one, err)
	}
	if exists, err := leases.Exists(t.Context(), fixture.nodeID); err != nil || !exists {
		t.Fatalf("caller-owned node leases after runtime Close = (%t, %v)", exists, err)
	}
	if leases.closeCalls.Load() != 0 {
		t.Fatalf("caller-owned node leases Close calls = %d, want 0", leases.closeCalls.Load())
	}
	if err := runtime.Run(t.Context()); err == nil {
		t.Fatal("closed real cache control runtime restarted")
	}
}

func openCacheControlCompositionDatabase(t *testing.T, databaseURL string) *pgxpool.Pool {
	t.Helper()
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.Ping(t.Context()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	schema := "cache_control_composition_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cancel := databasetest.CleanupContext()
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop cache control composition schema: %v", err)
		}
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}

type cacheControlCompositionFixture struct {
	userID      uuid.UUID
	scopeID     uuid.UUID
	nodeID      uuid.UUID
	configID    uuid.UUID
	operationID uuid.UUID
}

func seedCacheControlCompositionFixture(
	t *testing.T,
	pool *pgxpool.Pool,
	now time.Time,
	suffix string,
) cacheControlCompositionFixture {
	t.Helper()
	actor := cachecontrol.Actor{UserID: uuid.New(), ScopeID: uuid.New()}
	actor.ActorScopeID = actor.ScopeID
	fixture := cacheControlCompositionFixture{
		userID: actor.UserID, scopeID: actor.ScopeID, nodeID: uuid.New(), configID: uuid.New(),
	}
	tenantID, siteID, roleID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query     string
		arguments []any
	}{
		{`INSERT INTO tenants(id,display_name,status) VALUES($1,'Cache composition tenant','active')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{actor.ScopeID, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash,status)
		 VALUES($1,$2,'Cache composition actor','test-hash','active')`, []any{actor.UserID, "cache-composition-" + suffix}},
		{`INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`, []any{actor.ScopeID, actor.UserID}},
		{`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'Cache composition role',true)`, []any{roleID, actor.ScopeID, "cache-composition-role-" + suffix}},
		{`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'sites.read'),($1,'sites.manage')`, []any{roleID}},
		{`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, []any{actor.ScopeID, actor.UserID, roleID}},
	} {
		if _, err := pool.Exec(t.Context(), statement.query, statement.arguments...); err != nil {
			t.Fatal(err)
		}
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		// display_id from the per-scope sequence, as site.Store allocates it
		// (NOT NULL since migration 210).
		if _, err := tx.Exec(t.Context(), `WITH display AS (
			INSERT INTO site_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,now())
			ON CONFLICT(scope_id) DO UPDATE SET next_value=site_display_id_sequences.next_value+1,
				updated_at=EXCLUDED.updated_at
			RETURNING next_value-1 AS display_id
		)
		INSERT INTO sites(
			id,display_id,scope_id,owner_user_id,domain,http_ports,https_ports,origins,origin_hosts,
			https_enabled,enabled,status,created_by_user_id,updated_by_user_id
		) SELECT $1,display.display_id,$2,$3,$4,$5,$6,$7,$7,true,true,'active',$3,$3 FROM display`, siteID, actor.ScopeID,
			actor.UserID, "composition-"+suffix+".example", []string{"80"}, []string{"443"},
			[]string{"192.0.2.40"}); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, siteID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
			VALUES($1,1,'192.0.2.40',80,1,true)`, siteID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// display_id from the per-scope sequence, as node.Store allocates it
	// (NOT NULL since migration 211).
	if _, err := pool.Exec(t.Context(), `WITH display AS (
		INSERT INTO node_display_id_sequences(scope_id,next_value,updated_at) VALUES($2,2,now())
		ON CONFLICT(scope_id) DO UPDATE SET next_value=node_display_id_sequences.next_value+1,
			updated_at=EXCLUDED.updated_at
		RETURNING next_value-1 AS display_id
	)
	INSERT INTO nodes(id,display_id,scope_id,name,admin_state,created_by_user_id)
	SELECT $1,display.display_id,$2,$3,'active',$4 FROM display`, fixture.nodeID, actor.ScopeID,
		"cache-composition-node-"+suffix, actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO config_versions(
		id,configuration_scope_id,canonical_snapshot,canonical_snapshot_sha256,
		generator_name,generator_version,status,idempotency_key,request_digest,created_at,published_at
	) VALUES($1,$2,$3,$4,'cache-composition','1','releasable',$5,$4,$6,$6)`, fixture.configID,
		actor.ScopeID, []byte("composition-active-config"), make([]byte, 32),
		"cache-composition-config-"+suffix, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO node_config_state(
		node_id,configuration_scope_id,current_config_version_id,revision,updated_at
	) VALUES($1,$2,$3,7,$4)`, fixture.nodeID, actor.ScopeID, fixture.configID, now); err != nil {
		t.Fatal(err)
	}
	store, err := cachecontrol.NewStore(pool, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateOperation(t.Context(), actor, cachecontrol.CreateOperationRequest{
		SiteID: siteID, Action: cachecontrol.ActionPrewarm, TargetType: cachecontrol.TargetExactURL,
		Targets: []string{"http://composition-" + suffix + ".example/assets/app.js"},
		NodeIDs: []uuid.UUID{fixture.nodeID}, MaxRetries: 1,
		IdempotencyKey: "composition-operation-" + suffix,
		RequestID:      "composition-operation-request-" + suffix,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.operationID = created.Operation.ID
	return fixture
}

func waitForCacheControlCompositionCommand(
	t *testing.T,
	jetstream nats.JetStreamContext,
	config cachecontrolruntime.Config,
	nodeID uuid.UUID,
) *agentv1.CacheControlCommand {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		message, err := jetstream.GetLastMsg(config.CommandStream,
			config.CommandSubjectPrefix+"."+nodeID.String())
		if err == nil {
			command := new(agentv1.CacheControlCommand)
			if err := proto.Unmarshal(message.Data, command); err != nil {
				t.Fatal(err)
			}
			return command
		}
		if !errors.Is(err, nats.ErrMsgNotFound) {
			t.Fatal(err)
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("real cache worker did not publish to caller-owned NATS")
		}
	}
}

func assertCacheControlTaskPostgres(t *testing.T, pool *pgxpool.Pool, taskID string) {
	t.Helper()
	var version, listenAddresses, maxConnections, maxLocks, socketDirectory string
	if err := pool.QueryRow(t.Context(), `SELECT current_setting('server_version_num'),
current_setting('listen_addresses'),current_setting('max_connections'),
current_setting('max_locks_per_transaction'),current_setting('unix_socket_directories')`).Scan(
		&version, &listenAddresses, &maxConnections, &maxLocks, &socketDirectory,
	); err != nil {
		t.Fatal(err)
	}
	host := pool.Config().ConnConfig.Host
	if version != "170009" || listenAddresses != "" || maxConnections != "20" || maxLocks != "512" ||
		host != socketDirectory || !strings.Contains(host, taskID) {
		t.Fatalf("non-task PostgreSQL rejected: version=%s listen=%q connections=%s locks=%s host=%q socket=%q",
			version, listenAddresses, maxConnections, maxLocks, host, socketDirectory)
	}
}

func assertCacheControlTaskNATS(t *testing.T, connection *nats.Conn, rawURL, taskID string) {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	host := parsed.Hostname()
	if connection.ConnectedServerName() != taskID || host != "127.0.0.1" && host != "localhost" {
		t.Fatalf("non-task NATS rejected: server=%q host=%q", connection.ConnectedServerName(), host)
	}
}

func precreateCacheControlResources(t *testing.T, jetstream nats.JetStreamContext, config cachecontrolruntime.Config) {
	t.Helper()
	for _, stream := range []*nats.StreamConfig{
		{
			Name: config.CommandStream, Subjects: []string{config.CommandSubjectPrefix + ".*"},
			Retention: nats.LimitsPolicy, MaxConsumers: -1,
			MaxMsgs: 2_000_000, MaxBytes: 2 << 30,
			Discard: nats.DiscardOld, MaxAge: 7 * 24 * time.Hour, MaxMsgsPerSubject: -1,
			MaxMsgSize: int32(config.MaxPayloadBytes), Storage: nats.FileStorage,
			Replicas: config.Replicas, Duplicates: 10 * time.Minute,
		},
		{
			Name:      config.StatusStream,
			Subjects:  []string{config.StatusSubjectPrefix + ".*", config.DLQSubjectPrefix + ".*"},
			Retention: nats.LimitsPolicy, MaxConsumers: -1,
			MaxMsgs: 2_000_000, MaxBytes: 2 << 30,
			Discard: nats.DiscardOld, MaxAge: 7 * 24 * time.Hour, MaxMsgsPerSubject: -1,
			MaxMsgSize: int32(config.MaxPayloadBytes), Storage: nats.FileStorage,
			Replicas: config.Replicas, Duplicates: 10 * time.Minute,
		},
	} {
		if _, err := jetstream.AddStream(stream); err != nil {
			t.Fatal(err)
		}
		streamName := stream.Name
		t.Cleanup(func() {
			if err := jetstream.DeleteStream(streamName); err != nil {
				t.Errorf("delete task-owned cache control stream %s: %v", streamName, err)
			}
		})
	}
	consumer := &nats.ConsumerConfig{
		Durable: config.Durable, Name: config.Durable, DeliverPolicy: nats.DeliverAllPolicy,
		AckPolicy: nats.AckExplicitPolicy, AckWait: config.AckWait,
		MaxDeliver: config.MaxDeliver, FilterSubject: config.StatusSubjectPrefix + ".*",
		ReplayPolicy: nats.ReplayInstantPolicy, MaxAckPending: config.MaxAckPending,
		MaxWaiting: config.MaxWaiting, MaxRequestBatch: 1, MaxRequestExpires: config.FetchTimeout,
		MaxRequestMaxBytes: config.MaxPayloadBytes,
	}
	if _, err := jetstream.AddConsumer(config.StatusStream, consumer); err != nil {
		t.Fatal(err)
	}
}

func cacheControlCompositionDependencies(
	t *testing.T,
	pool *pgxpool.Pool,
	connection *nats.Conn,
	leases *cacheControlCompositionLeases,
) cacheControlRuntimeDependencies {
	t.Helper()
	tokens, err := identity.NewTokenManager(strings.Repeat("c", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x42}, 32), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	return cacheControlRuntimeDependencies{
		Pool: pool, NATS: connection, NodeLeases: leases,
		Entitlement: entitlementguard.NewGuard(pool, time.Now, nil), Identity: identityService, IAM: authorizer,
	}
}

type cacheControlCompositionLeases struct {
	nodeID     uuid.UUID
	called     chan uuid.UUID
	closed     atomic.Bool
	calls      atomic.Int32
	closeCalls atomic.Int32
}

func (leases *cacheControlCompositionLeases) Exists(_ context.Context, nodeID uuid.UUID) (bool, error) {
	if leases.closed.Load() {
		return false, errors.New("caller-owned node leases are closed")
	}
	leases.calls.Add(1)
	if leases.called != nil {
		select {
		case leases.called <- nodeID:
		default:
		}
	}
	if nodeID != leases.nodeID {
		return false, nil
	}
	return true, nil
}

func (leases *cacheControlCompositionLeases) Close() error {
	leases.closeCalls.Add(1)
	if !leases.closed.CompareAndSwap(false, true) {
		return fmt.Errorf("caller-owned node leases closed twice")
	}
	return nil
}
