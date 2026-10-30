package notificationruntime

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type integrationProvider struct {
	mu           sync.Mutex
	calls        chan ProviderMessage
	releaseFirst chan struct{}
	count        int
	closed       int
}

type settlementRegistryDispatcher struct {
	mu      sync.Mutex
	results map[uuid.UUID]notification.AnonymousDispatchResult
	calls   map[uuid.UUID]int
}

func (d *settlementRegistryDispatcher) Dispatch(
	_ context.Context,
	attempt notification.AnonymousDeliveryAttempt,
) notification.AnonymousDispatchResult {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls[attempt.OutboxID]++
	return d.results[attempt.OutboxID]
}

func (d *settlementRegistryDispatcher) callCount(outboxID uuid.UUID) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls[outboxID]
}

func (p *integrationProvider) Ready(context.Context) error { return nil }

func (p *integrationProvider) Send(_ context.Context, message ProviderMessage) (ProviderResult, error) {
	p.mu.Lock()
	p.count++
	count := p.count
	p.mu.Unlock()
	p.calls <- message
	if count == 1 {
		<-p.releaseFirst
	}
	return ProviderResult{Disposition: ProviderAccepted}, nil
}

func (p *integrationProvider) Close(context.Context) error {
	p.mu.Lock()
	p.closed++
	p.mu.Unlock()
	return nil
}

func TestRuntimePostgresAcceptedSettlementFailureBecomesUnknownWithoutRedelivery(t *testing.T) {
	pool := isolatedRuntimePool(t)
	ctx := t.Context()
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	tenantID, scopeID, userID := seedRuntimeMember(t, pool)
	_ = tenantID
	template := notification.TemplateRef{ID: "runtime_delivery", Version: 1, Channel: notification.ChannelEmail}
	if err := store.SaveTemplate(ctx, notification.TemplateDefinition{
		Ref: template, Subject: "运行时通知", Body: "通知正文", Variables: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(ctx, notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetSubscription(ctx, scopeID, userID, "runtime.delivery", notification.Subscription{Email: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION fail_runtime_settle_once() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected settle failure'; END $$;
		CREATE TRIGGER fail_runtime_settle_once
		BEFORE UPDATE ON notification_outbox
		FOR EACH ROW WHEN (NEW.status='accepted' AND OLD.status='leased')
		EXECUTE FUNCTION fail_runtime_settle_once()`); err != nil {
		t.Fatal(err)
	}

	provider := &integrationProvider{
		calls: make(chan ProviderMessage, 4), releaseFirst: make(chan struct{}),
	}
	workerConfig := notification.DefaultWorkerConfig()
	workerConfig.BatchSize = 1
	workerConfig.LeaseDuration = 200 * time.Millisecond
	workerConfig.LeaseSafetyMargin = 25 * time.Millisecond
	workerConfig.BaseDelay = 10 * time.Millisecond
	workerConfig.MaxDelay = 50 * time.Millisecond
	runtime, err := Build(RuntimeConfig{
		Enabled: true, Worker: workerConfig, RecoveryTemplates: map[notification.Channel]notification.TemplateRef{
			notification.ChannelEmail: template,
		}, IdleWait: 10 * time.Millisecond, ErrorBackoffBase: 10 * time.Millisecond,
		ErrorBackoffMax: 50 * time.Millisecond, MaxConsecutiveFailures: 10,
		SendTimeout: time.Second, ShutdownTimeout: time.Second,
	}, Dependencies{
		Store: store, MemberContacts: &testContactResolver{contact: "member@example.test"},
		Providers: map[notification.Channel]ProviderTransport{notification.ChannelEmail: provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background()) }()
	waitFor(t, time.Second, func() bool { return runtime.Health().WorkerRunning })
	waitForRuntimeReady(t, runtime, ctx, notification.ChannelSwitches{Email: true})

	enqueued, err := store.Enqueue(ctx, notification.EnqueueRequest{
		ScopeID: scopeID, RecipientID: userID, SourceEventID: "runtime-delivery-1",
		EventType: "runtime.delivery", Policy: notification.DeliveryTenantSubscribed,
		Templates:   map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: template},
		Contexts:    map[notification.Channel]notification.TemplateContext{notification.ChannelEmail: {}},
		ActorUserID: &userID, AuditRequestID: "runtime-delivery-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(enqueued.Deliveries) != 1 {
		t.Fatalf("deliveries = %+v", enqueued.Deliveries)
	}

	first := receiveProviderMessage(t, provider.calls)
	close(provider.releaseFirst)
	waitFor(t, time.Second, func() bool {
		return runtime.Health().ConsecutiveFailures == 1
	})
	if _, err := pool.Exec(ctx, `
		DROP TRIGGER fail_runtime_settle_once ON notification_outbox;
		DROP FUNCTION fail_runtime_settle_once()`); err != nil {
		t.Fatal(err)
	}
	if first.IdempotencyKey == "" || first.AttemptNumber != 1 {
		t.Fatalf("first provider delivery=%+v", first)
	}
	waitFor(t, 2*time.Second, func() bool {
		var status string
		return pool.QueryRow(ctx, `SELECT status FROM notification_outbox WHERE id=$1`, first.OutboxID).Scan(&status) == nil &&
			status == notification.OutboxUnknown
	})
	select {
	case duplicate := <-provider.calls:
		t.Fatalf("accepted notification was redelivered: %+v", duplicate)
	case <-time.After(300 * time.Millisecond):
	}
	var unknown int
	if err := pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE outcome='unknown')
		FROM notification_attempts WHERE outbox_id=$1`, first.OutboxID).Scan(&unknown); err != nil {
		t.Fatal(err)
	}
	if unknown != 1 {
		t.Fatalf("unknown attempts=%d", unknown)
	}

	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-runDone; err != nil {
		t.Fatalf("Run() = %v", err)
	}
	provider.mu.Lock()
	count, closed := provider.count, provider.closed
	provider.mu.Unlock()
	if count != 1 || closed != 1 {
		t.Fatalf("provider count=%d closed=%d", count, closed)
	}
}

func TestRuntimePostgresAnonymousDispatchWaitsForRegistrationWithoutMemberFallback(t *testing.T) {
	pool := isolatedRuntimePool(t)
	ctx := t.Context()
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	_, scopeID, _ := seedRuntimeMember(t, pool)
	template := notification.TemplateRef{ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail}
	if err := store.SaveTemplate(ctx, notification.TemplateDefinition{
		Ref: template, Subject: "账户恢复", Body: "恢复账户", Variables: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(ctx, notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}

	provider := &testProvider{result: ProviderResult{Disposition: ProviderAccepted}}
	workerConfig := notification.DefaultWorkerConfig()
	workerConfig.BatchSize = 1
	workerConfig.LeaseDuration = time.Second
	workerConfig.LeaseSafetyMargin = 100 * time.Millisecond
	workerConfig.BaseDelay = 250 * time.Millisecond
	workerConfig.MaxDelay = 250 * time.Millisecond
	runtime, err := Build(RuntimeConfig{
		Enabled: true, Worker: workerConfig, RecoveryTemplates: map[notification.Channel]notification.TemplateRef{
			notification.ChannelEmail: template,
		}, IdleWait: 5 * time.Millisecond, ErrorBackoffBase: 10 * time.Millisecond,
		ErrorBackoffMax: 20 * time.Millisecond, MaxConsecutiveFailures: 5,
		SendTimeout: time.Second, ShutdownTimeout: time.Second,
	}, Dependencies{
		Store: store, MemberContacts: &testContactResolver{contact: "member@example.test"},
		Providers: map[notification.Channel]ProviderTransport{notification.ChannelEmail: provider},
	})
	if err != nil {
		t.Fatal(err)
	}
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(context.Background()) }()
	waitFor(t, time.Second, func() bool { return runtime.Health().WorkerRunning })
	waitForRuntimeReady(t, runtime, ctx, notification.ChannelSwitches{Email: true})

	results := []struct {
		name        string
		disposition notification.AnonymousDispatchResult
		wantStatus  string
	}{
		{
			name: "accepted",
			disposition: notification.AnonymousDispatchResult{
				Disposition: notification.AnonymousDispatchAccepted, Provider: "configured_email",
				ProviderDeliveryID: "anonymous-provider-1",
			},
			wantStatus: notification.OutboxAccepted,
		},
		{
			name: "unknown",
			disposition: notification.AnonymousDispatchResult{
				Disposition: notification.AnonymousDispatchUnknown, Provider: "configured_email",
			},
			wantStatus: notification.OutboxUnknown,
		},
	}
	dispatcher := &settlementRegistryDispatcher{
		results: make(map[uuid.UUID]notification.AnonymousDispatchResult, len(results)),
		calls:   make(map[uuid.UUID]int, len(results)),
	}
	outboxIDs := make(map[string]uuid.UUID, len(results))
	for _, item := range results {
		reference := uuid.New()
		tx, beginErr := pool.Begin(ctx)
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		enqueued, enqueueErr := store.EnqueueDispatchTx(ctx, tx, notification.DispatchEnqueueRequest{
			ScopeID: scopeID, SourceEventID: reference.String(), AnonymousDispatchReference: reference,
			Templates:      map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: template},
			AuditRequestID: "account-recovery-runtime-" + item.name,
		})
		if enqueueErr != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(enqueueErr)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if len(enqueued.Deliveries) != 1 {
			t.Fatalf("%s anonymous deliveries = %+v", item.name, enqueued.Deliveries)
		}
		outboxID := enqueued.Deliveries[0].OutboxID
		outboxIDs[item.name] = outboxID
		dispatcher.results[outboxID] = item.disposition
		waitFor(t, time.Second, func() bool {
			var status string
			var code *string
			return pool.QueryRow(ctx, `SELECT status,last_failure_code FROM notification_outbox WHERE id=$1`, outboxID).
				Scan(&status, &code) == nil && status == notification.OutboxPending && code != nil && *code == "dispatch_unregistered"
		})
	}
	registration, err := runtime.RegisterAnonymousDispatcher(ctx, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range results {
		outboxID := outboxIDs[item.name]
		waitFor(t, 2*time.Second, func() bool {
			var status string
			return pool.QueryRow(ctx, `SELECT status FROM notification_outbox WHERE id=$1`, outboxID).Scan(&status) == nil &&
				status == item.wantStatus
		})
		if calls := dispatcher.callCount(outboxID); calls != 1 {
			t.Fatalf("%s anonymous dispatcher calls = %d", item.name, calls)
		}
	}
	if messages, _ := provider.snapshot(); len(messages) != 0 {
		t.Fatalf("member provider received anonymous delivery: %+v", messages)
	}

	if err := runtime.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
	if err := registration.Close(context.Background()); err != nil {
		t.Fatalf("stale registration close = %v", err)
	}
}

func receiveProviderMessage(t *testing.T, calls <-chan ProviderMessage) ProviderMessage {
	t.Helper()
	select {
	case message := <-calls:
		return message
	case <-time.After(2 * time.Second):
		t.Fatal("provider message was not received")
		return ProviderMessage{}
	}
}

func waitForRuntimeReady(
	t *testing.T,
	runtime *Runtime,
	ctx context.Context,
	switches notification.ChannelSwitches,
) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		err := runtime.Ready(ctx, switches)
		if err == nil {
			return
		}
		if !errors.Is(err, ErrWorkerNotRunning) {
			t.Fatalf("Ready() = %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("notification runtime did not become ready after a successful batch")
}

func seedRuntimeMember(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	username := "notification-runtime-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO tenants(id,display_name) VALUES($1,'Notification Runtime')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'Runtime Member','unused')`,
		userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(),
		`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	return tenantID, scopeID, userID
}

func isolatedRuntimePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "notification_runtime_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^notification_runtime_test_[a-f0-9]{32}$`).MatchString(schema) {
		admin.Close()
		t.Fatalf("unsafe schema name %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		pool.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop runtime schema: %v", err)
		}
		admin.Close()
	})
	return pool
}
