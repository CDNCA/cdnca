package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNotificationRuntimeProcessPostgresSMTPTLS(t *testing.T) {
	pool := openNotificationRuntimeDatabase(t)
	server := newSMTPTestServer(t, smtpTestServerConfig{})
	template := notification.TemplateRef{ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail}
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTemplate(t.Context(), notification.TemplateDefinition{
		Ref: template, Subject: "账户通知", Body: "运行时消息", Variables: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	scopeID, userID := seedNotificationRuntimeMember(t, pool)
	if err := store.SetSubscription(
		t.Context(), scopeID, userID, "runtime.process", notification.Subscription{Email: true},
	); err != nil {
		t.Fatal(err)
	}

	config := notificationRuntimeConfig{
		Enabled: true, Worker: notification.WorkerConfig{
			BatchSize: 1, LeaseDuration: 2 * time.Second, LeaseSafetyMargin: 250 * time.Millisecond,
			MaxAttempts: 3, BaseDelay: 20 * time.Millisecond, MaxDelay: 100 * time.Millisecond,
		},
		RecoveryTemplates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: template},
		EmailProvider:     notificationEmailProviderSMTPTLS, SMTP: server.clientConfig(),
		IdleWait: 5 * time.Millisecond, ErrorBackoffBase: 10 * time.Millisecond,
		ErrorBackoffMax: 50 * time.Millisecond, MaxConsecutiveFailures: 3,
		SendTimeout: time.Second, StartupTimeout: time.Second, ShutdownTimeout: time.Second,
	}
	runtime, err := openNotificationProcessRuntime(t.Context(), config, pool, notificationRuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("Close() = %v", err)
		}
	})
	if health := runtime.Health(); !health.Ready || health.State != "ready" || health.EnabledChannels != 1 {
		t.Fatalf("startup health = %#v", health)
	}

	enqueued, err := store.Enqueue(t.Context(), notification.EnqueueRequest{
		ScopeID: scopeID, RecipientID: userID, SourceEventID: "notification-runtime-process-1",
		EventType: "runtime.process", Policy: notification.DeliveryTenantSubscribed,
		Templates:   map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: template},
		Contexts:    map[notification.Channel]notification.TemplateContext{notification.ChannelEmail: {}},
		ActorUserID: &userID, AuditRequestID: "notification-runtime-process-1",
	})
	if err != nil || len(enqueued.Deliveries) != 1 {
		t.Fatalf("Enqueue() deliveries=%+v error=%v", enqueued.Deliveries, err)
	}
	waitForCondition(t, 2*time.Second, func() bool { return len(server.messages()) == 1 })
	waitForNotificationRuntimeAcceptance(t, pool, enqueued.Deliveries[0].OutboxID, 2*time.Second)
}

func TestNotificationRuntimeResolverCommitPrecedesInFlightSMTP(t *testing.T) {
	pool := openNotificationRuntimeDatabase(t)
	server := newSMTPTestServer(t, smtpTestServerConfig{})
	template := notification.TemplateRef{ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail}
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTemplate(t.Context(), notification.TemplateDefinition{
		Ref: template, Subject: "账户通知", Body: "已解析发送", Variables: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	scopeID, userID := seedNotificationRuntimeMember(t, pool)
	if err := store.SetSubscription(
		t.Context(), scopeID, userID, "runtime.resolver-first", notification.Subscription{Email: true},
	); err != nil {
		t.Fatal(err)
	}

	sendEntered := make(chan struct{}, 1)
	sendRelease := make(chan struct{})
	config := notificationRuntimeConfig{
		Enabled: true, Worker: notification.WorkerConfig{
			BatchSize: 1, LeaseDuration: 3 * time.Second, LeaseSafetyMargin: 250 * time.Millisecond,
			MaxAttempts: 3, BaseDelay: 20 * time.Millisecond, MaxDelay: 100 * time.Millisecond,
		},
		RecoveryTemplates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: template},
		EmailProvider:     notificationEmailProviderSMTPTLS, SMTP: server.clientConfig(),
		IdleWait: 5 * time.Millisecond, ErrorBackoffBase: 10 * time.Millisecond,
		ErrorBackoffMax: 50 * time.Millisecond, MaxConsecutiveFailures: 3,
		SendTimeout: 2 * time.Second, StartupTimeout: time.Second, ShutdownTimeout: time.Second,
	}
	runtime, err := openNotificationProcessRuntime(t.Context(), config, pool, notificationRuntimeDependencies{
		NewSMTP: func(config smtpTLSConfig) (notificationruntime.ProviderTransport, error) {
			transport, err := newSMTPTLSTransport(config)
			if err != nil {
				return nil, err
			}
			return &smtpSendBarrierTransport{
				delegate: transport, entered: sendEntered, release: sendRelease,
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = runtime.Close()
		}
	}()

	enqueued, err := store.Enqueue(t.Context(), notification.EnqueueRequest{
		ScopeID: scopeID, RecipientID: userID, SourceEventID: "notification-runtime-resolver-first-1",
		EventType: "runtime.resolver-first", Policy: notification.DeliveryTenantSubscribed,
		Templates:   map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: template},
		Contexts:    map[notification.Channel]notification.TemplateContext{notification.ChannelEmail: {}},
		ActorUserID: &userID, AuditRequestID: "notification-runtime-resolver-first-1",
	})
	if err != nil || len(enqueued.Deliveries) != 1 {
		t.Fatalf("Enqueue() deliveries=%+v error=%v", enqueued.Deliveries, err)
	}
	select {
	case <-sendEntered:
	case <-time.After(time.Second):
		t.Fatal("SMTP provider Send was not entered")
	}

	suspender, err := pool.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer suspender.Release()
	suspendContext, cancelSuspend := context.WithTimeout(t.Context(), time.Second)
	command, err := suspender.Exec(suspendContext, `UPDATE tenants SET status='suspended'
		WHERE id=(SELECT tenant_id FROM access_scopes WHERE id=$1)`, scopeID)
	cancelSuspend()
	if err != nil {
		t.Fatalf("tenant suspension while SMTP Send was blocked = %v", err)
	}
	if command.RowsAffected() != 1 {
		t.Fatalf("tenant suspension rows = %d", command.RowsAffected())
	}
	sendRelease <- struct{}{}

	waitForCondition(t, 2*time.Second, func() bool { return len(server.messages()) == 1 })
	waitForNotificationRuntimeAcceptance(t, pool, enqueued.Deliveries[0].OutboxID, 2*time.Second)
	if messages := server.messages(); len(messages) != 1 {
		t.Fatalf("resolver-first SMTP messages = %d", len(messages))
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
}

func TestNotificationRuntimeProcessPostgresHTTPSJSONSMS(t *testing.T) {
	pool := openNotificationRuntimeDatabase(t)
	deliveries := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/ready":
			writer.WriteHeader(http.StatusNoContent)
		case "/v1/messages":
			if request.Header.Get("Authorization") != "Bearer process-sms-auth" ||
				request.Header.Get("Idempotency-Key") == "" {
				t.Errorf("SMS provider headers = %v", request.Header)
			}
			deliveries <- request.Header.Get("Idempotency-Key")
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusAccepted)
			_, _ = writer.Write([]byte(`{"delivery_id":"process-sms-delivery"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	template := notification.TemplateRef{ID: "account_recovery_sms", Version: 1, Channel: notification.ChannelSMS}
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTemplate(t.Context(), notification.TemplateDefinition{
		Ref: template, Body: "运行时短信", Variables: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{SMS: true}); err != nil {
		t.Fatal(err)
	}
	scopeID, userID := seedNotificationRuntimeMember(t, pool)
	if err := store.SetSubscription(
		t.Context(), scopeID, userID, "runtime.sms", notification.Subscription{SMS: true},
	); err != nil {
		t.Fatal(err)
	}
	config := notificationRuntimeConfig{
		Enabled: true, Worker: notification.WorkerConfig{
			BatchSize: 1, LeaseDuration: 2 * time.Second, LeaseSafetyMargin: 250 * time.Millisecond,
			MaxAttempts: 3, BaseDelay: 20 * time.Millisecond, MaxDelay: 100 * time.Millisecond,
		},
		RecoveryTemplates: map[notification.Channel]notification.TemplateRef{notification.ChannelSMS: template},
		SMSProvider:       notificationSMSProviderHTTPSJSON,
		SMS:               smsTestConfig(t, server, "process-sms-auth"),
		IdleWait:          5 * time.Millisecond, ErrorBackoffBase: 10 * time.Millisecond,
		ErrorBackoffMax: 50 * time.Millisecond, MaxConsecutiveFailures: 3,
		SendTimeout: time.Second, StartupTimeout: time.Second, ShutdownTimeout: time.Second,
	}
	runtime, err := openNotificationProcessRuntime(t.Context(), config, pool, notificationRuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	if health := runtime.Health(); !health.Ready || health.EnabledChannels != 1 {
		t.Fatalf("SMS startup health = %#v", health)
	}
	enqueued, err := store.Enqueue(t.Context(), notification.EnqueueRequest{
		ScopeID: scopeID, RecipientID: userID, SourceEventID: "notification-runtime-sms-1",
		EventType: "runtime.sms", Policy: notification.DeliveryTenantSubscribed,
		Templates:   map[notification.Channel]notification.TemplateRef{notification.ChannelSMS: template},
		Contexts:    map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: {}},
		ActorUserID: &userID, AuditRequestID: "notification-runtime-sms-1",
	})
	if err != nil || len(enqueued.Deliveries) != 1 {
		t.Fatalf("Enqueue() deliveries=%+v error=%v", enqueued.Deliveries, err)
	}
	select {
	case key := <-deliveries:
		if key == "" {
			t.Fatal("SMS provider received an empty idempotency key")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("SMS provider did not receive the notification")
	}
	waitForNotificationRuntimeAcceptance(t, pool, enqueued.Deliveries[0].OutboxID, 2*time.Second)
}

func TestPostgresMemberContactResolverTenantFenceLinearization(t *testing.T) {
	pool := openNotificationRuntimeDatabase(t)
	scopeID, userID := seedNotificationRuntimeMember(t, pool)
	resolver := &postgresMemberContactResolver{pool: pool}

	active := resolver.Resolve(t.Context(), scopeID, userID, notification.ChannelEmail)
	if active.Contact != "member@example.test" || active.Failure != nil {
		t.Fatalf("active tenant resolution = %+v", active)
	}
	activeSMS := resolver.Resolve(t.Context(), scopeID, userID, notification.ChannelSMS)
	if activeSMS.Contact != "+8613900000000" || activeSMS.Failure != nil {
		t.Fatalf("active tenant SMS resolution = %+v", activeSMS)
	}
	if err := resolver.Ready(t.Context(), notification.ChannelSMS); err != nil {
		t.Fatalf("SMS resolver readiness = %v", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE users SET phone=NULL WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	assertNotificationRecipientUnavailable(t, resolver.Resolve(
		t.Context(), scopeID, userID, notification.ChannelSMS,
	))
	if _, err := pool.Exec(t.Context(), `UPDATE users SET phone='+8613900000000' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}

	platformScopeID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platformScopeID, userID); err != nil {
		t.Fatal(err)
	}
	// 平台成员只会收到平台运维告警（入队侧白名单），解析放行（FX33）。
	if platformContact := resolver.Resolve(t.Context(), platformScopeID, userID, notification.ChannelEmail); platformContact.Contact != "member@example.test" || platformContact.Failure != nil {
		t.Fatalf("platform member resolution = %+v", platformContact)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, platformScopeID, userID); err != nil {
		t.Fatal(err)
	}
	assertNotificationRecipientUnavailable(t, resolver.Resolve(
		t.Context(), platformScopeID, userID, notification.ChannelEmail,
	))
	if _, err := pool.Exec(t.Context(), `UPDATE users SET status='disabled' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	assertNotificationRecipientUnavailable(t, resolver.Resolve(
		t.Context(), scopeID, userID, notification.ChannelEmail,
	))
	if _, err := pool.Exec(t.Context(), `UPDATE users SET status='active' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	assertNotificationRecipientUnavailable(t, resolver.Resolve(
		t.Context(), scopeID, userID, notification.ChannelEmail,
	))
	if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='active' WHERE scope_id=$1 AND user_id=$2`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	assertNotificationRecipientUnavailable(t, resolver.Resolve(
		t.Context(), uuid.New(), uuid.New(), notification.ChannelEmail,
	))

	var tenantID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, scopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	suspender, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = suspender.Rollback(context.Background()) }()
	if _, err := suspender.Exec(t.Context(), `UPDATE tenants SET status='suspended' WHERE id=$1`, tenantID); err != nil {
		t.Fatal(err)
	}

	resolution := make(chan notificationruntime.ContactResolution, 1)
	go func() {
		resolution <- resolver.Resolve(context.Background(), scopeID, userID, notification.ChannelEmail)
	}()
	select {
	case result := <-resolution:
		t.Fatalf("resolver returned before tenant suspension committed: %+v", result)
	case <-time.After(100 * time.Millisecond):
	}
	if err := suspender.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-resolution:
		assertNotificationRecipientUnavailable(t, result)
	case <-time.After(time.Second):
		t.Fatal("resolver remained blocked after tenant suspension committed")
	}

	if _, err := pool.Exec(t.Context(), `UPDATE tenants SET status='active' WHERE id=$1`, tenantID); err != nil {
		t.Fatal(err)
	}
	committed := resolver.Resolve(t.Context(), scopeID, userID, notification.ChannelEmail)
	if committed.Contact != "member@example.test" || committed.Failure != nil {
		t.Fatalf("reactivated tenant resolution = %+v", committed)
	}
	writeContext, cancelWrite := context.WithTimeout(t.Context(), time.Second)
	defer cancelWrite()
	if _, err := pool.Exec(writeContext, `UPDATE tenants SET status='suspended' WHERE id=$1`, tenantID); err != nil {
		t.Fatalf("tenant suspension after resolver commit = %v", err)
	}
}

func TestNotificationRuntimeTenantSuspensionPermanentlyStopsQueuedDelivery(t *testing.T) {
	pool := openNotificationRuntimeDatabase(t)
	server := newSMTPTestServer(t, smtpTestServerConfig{})
	template := notification.TemplateRef{ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail}
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTemplate(t.Context(), notification.TemplateDefinition{
		Ref: template, Subject: "账户通知", Body: "停用隔离", Variables: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	scopeID, userID := seedNotificationRuntimeMember(t, pool)
	if err := store.SetSubscription(
		t.Context(), scopeID, userID, "runtime.tenant-fence", notification.Subscription{Email: true},
	); err != nil {
		t.Fatal(err)
	}
	enqueued, err := store.Enqueue(t.Context(), notification.EnqueueRequest{
		ScopeID: scopeID, RecipientID: userID, SourceEventID: "notification-runtime-tenant-fence-1",
		EventType: "runtime.tenant-fence", Policy: notification.DeliveryTenantSubscribed,
		Templates:   map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: template},
		Contexts:    map[notification.Channel]notification.TemplateContext{notification.ChannelEmail: {}},
		ActorUserID: &userID, AuditRequestID: "notification-runtime-tenant-fence-1",
	})
	if err != nil || len(enqueued.Deliveries) != 1 {
		t.Fatalf("Enqueue() deliveries=%+v error=%v", enqueued.Deliveries, err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE tenants SET status='suspended'
		WHERE id=(SELECT tenant_id FROM access_scopes WHERE id=$1)`, scopeID); err != nil {
		t.Fatal(err)
	}

	config := notificationRuntimeConfig{
		Enabled: true, Worker: notification.WorkerConfig{
			BatchSize: 1, LeaseDuration: 2 * time.Second, LeaseSafetyMargin: 250 * time.Millisecond,
			MaxAttempts: 3, BaseDelay: 20 * time.Millisecond, MaxDelay: 100 * time.Millisecond,
		},
		RecoveryTemplates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: template},
		EmailProvider:     notificationEmailProviderSMTPTLS, SMTP: server.clientConfig(),
		IdleWait: 5 * time.Millisecond, ErrorBackoffBase: 10 * time.Millisecond,
		ErrorBackoffMax: 50 * time.Millisecond, MaxConsecutiveFailures: 3,
		SendTimeout: time.Second, StartupTimeout: time.Second, ShutdownTimeout: time.Second,
	}
	runtime, err := openNotificationProcessRuntime(t.Context(), config, pool, notificationRuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	waitForNotificationRuntimePermanentFailure(t, pool, enqueued.Deliveries[0].OutboxID, 2*time.Second)
	if messages := server.messages(); len(messages) != 0 {
		t.Fatalf("suspended tenant SMTP messages = %d", len(messages))
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := pool.Exec(t.Context(), `UPDATE tenants SET status='active'
		WHERE id=(SELECT tenant_id FROM access_scopes WHERE id=$1)`, scopeID); err != nil {
		t.Fatal(err)
	}
	restarted, err := openNotificationProcessRuntime(t.Context(), config, pool, notificationRuntimeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatal(err)
	}
	waitForNotificationRuntimePermanentFailure(t, pool, enqueued.Deliveries[0].OutboxID, time.Second)
	if messages := server.messages(); len(messages) != 0 {
		t.Fatalf("permanent failure revived after restart: SMTP messages = %d", len(messages))
	}
}

type smtpSendBarrierTransport struct {
	delegate notificationruntime.ProviderTransport
	entered  chan<- struct{}
	release  <-chan struct{}
}

func (transport *smtpSendBarrierTransport) Ready(ctx context.Context) error {
	return transport.delegate.Ready(ctx)
}

func (transport *smtpSendBarrierTransport) Send(
	ctx context.Context,
	message notificationruntime.ProviderMessage,
) (notificationruntime.ProviderResult, error) {
	select {
	case transport.entered <- struct{}{}:
	case <-ctx.Done():
		return notificationruntime.ProviderResult{}, ctx.Err()
	}
	select {
	case <-transport.release:
	case <-ctx.Done():
		return notificationruntime.ProviderResult{}, ctx.Err()
	}
	return transport.delegate.Send(ctx, message)
}

func (transport *smtpSendBarrierTransport) Close(ctx context.Context) error {
	return transport.delegate.Close(ctx)
}

func assertNotificationRecipientUnavailable(t *testing.T, resolution notificationruntime.ContactResolution) {
	t.Helper()
	if resolution.Contact != "" || resolution.Failure == nil ||
		resolution.Failure.Class != notification.FailurePermanent || resolution.Failure.Code != "recipient_unavailable" {
		t.Fatalf("recipient resolution = %+v", resolution)
	}
}

func waitForNotificationRuntimePermanentFailure(
	t *testing.T,
	pool *pgxpool.Pool,
	outboxID uuid.UUID,
	timeout time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var status, outboxFailure, attemptOutcome, attemptFailure string
	var attemptCount, attempts int
	for time.Now().Before(deadline) {
		err := pool.QueryRow(t.Context(), `
			SELECT outbox.status,outbox.last_failure_code,outbox.attempt_count,
			       count(attempt.outbox_id),coalesce(max(attempt.outcome),''),coalesce(max(attempt.failure_code),'')
			FROM notification_outbox outbox
			LEFT JOIN notification_attempts attempt ON attempt.outbox_id=outbox.id
			WHERE outbox.id=$1 GROUP BY outbox.id`, outboxID).Scan(
			&status, &outboxFailure, &attemptCount, &attempts, &attemptOutcome, &attemptFailure,
		)
		if err == nil && status == notification.OutboxPermanentFailed && outboxFailure == "recipient_unavailable" &&
			attemptCount == 1 && attempts == 1 && attemptOutcome == "permanent_failure" && attemptFailure == "recipient_unavailable" {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("permanent settlement timeout: status=%q outbox_failure=%q attempt_count=%d attempts=%d outcome=%q attempt_failure=%q",
		status, outboxFailure, attemptCount, attempts, attemptOutcome, attemptFailure)
}

func seedNotificationRuntimeMember(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	username := "notification-process-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'Notification Process')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO users(id,username,display_name,password_hash,email,phone)
		VALUES($1,$2,'Notification Member','unused','member@example.test','+8613900000000')`, userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	return scopeID, userID
}

func waitForNotificationRuntimeAcceptance(
	t *testing.T,
	pool *pgxpool.Pool,
	outboxID uuid.UUID,
	timeout time.Duration,
) {
	t.Helper()
	waitForNotificationRuntimeState(
		t, pool, outboxID, notification.OutboxAccepted, "accepted", timeout,
	)
}

func waitForNotificationRuntimeState(
	t *testing.T,
	pool *pgxpool.Pool,
	outboxID uuid.UUID,
	expectedStatus string,
	expectedOutcome string,
	timeout time.Duration,
) {
	t.Helper()
	type settlementState struct {
		status          string
		leaseTokenSet   bool
		leaseExpirySet  bool
		attemptCount    int
		activeAttempts  int
		matchedAttempts int
		completed       bool
	}
	deadline := time.Now().Add(timeout)
	var state settlementState
	var queryClass string
	for time.Now().Before(deadline) {
		err := pool.QueryRow(t.Context(), `
			SELECT outbox.status,
			       outbox.lease_token IS NOT NULL,
			       outbox.lease_expires_at IS NOT NULL,
			       count(attempt.outbox_id),
			       count(attempt.outbox_id) FILTER (
			           WHERE attempt.outcome='leased' OR attempt.completed_at IS NULL
			       ),
			       count(attempt.outbox_id) FILTER (WHERE attempt.outcome=$2),
			       coalesce(bool_and(attempt.completed_at IS NOT NULL) FILTER (
			           WHERE attempt.outbox_id IS NOT NULL
			       ), false)
			FROM notification_outbox outbox
			LEFT JOIN notification_attempts attempt ON attempt.outbox_id=outbox.id
			WHERE outbox.id=$1
			GROUP BY outbox.id`, outboxID, expectedOutcome).Scan(
			&state.status, &state.leaseTokenSet, &state.leaseExpirySet,
			&state.attemptCount, &state.activeAttempts, &state.matchedAttempts, &state.completed,
		)
		if err != nil {
			queryClass = "database_unavailable"
		} else {
			queryClass = ""
			if state.status == expectedStatus && !state.leaseTokenSet && !state.leaseExpirySet &&
				state.attemptCount == 1 && state.activeAttempts == 0 && state.matchedAttempts == 1 && state.completed {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf(
		"notification settlement timeout: state=%q lease_token_set=%t lease_expiry_set=%t "+
			"attempt_count=%d active_attempts=%d matched_attempts=%d completed=%t query_class=%q",
		state.status, state.leaseTokenSet, state.leaseExpirySet, state.attemptCount,
		state.activeAttempts, state.matchedAttempts, state.completed, queryClass,
	)
}

func openNotificationRuntimeDatabase(t *testing.T) *pgxpool.Pool {
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
	schema := "notification_process_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
			t.Errorf("drop notification process schema: %v", err)
		}
		admin.Close()
	})
	return pool
}
