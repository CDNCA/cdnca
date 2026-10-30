//go:build integration

package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/httpapi"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAnnouncementRuntimePostgreSQL043ProbeRouteWorkerRestartAndClose(t *testing.T) {
	missingPool := openAnnouncementRuntimeDatabase(t, 0)
	missingConfig := integrationAnnouncementRuntimeConfig()
	if _, err := openAnnouncementRuntime(t.Context(), missingPool, missingConfig); err == nil || !strings.Contains(err.Error(), "probe announcement schema") {
		t.Fatalf("missing 043 schema open error = %v", err)
	}

	pool := openAnnouncementRuntimeDatabase(t, 64)
	config := integrationAnnouncementRuntimeConfig()
	runtime, err := openAnnouncementRuntime(t.Context(), pool, config)
	if err != nil {
		t.Fatalf("open announcement runtime = %v", err)
	}
	if err := runtime.Ready(); err != nil {
		t.Fatalf("opened announcement runtime is not ready: %v", err)
	}
	workerDone := make(chan error, 1)
	go func() { workerDone <- runtime.Run(context.Background()) }()
	deadline := time.NewTimer(3 * time.Second)
	for runtime.publishAttempts.Load() == 0 {
		select {
		case <-deadline.C:
			t.Fatal("announcement worker did not call PublishDue")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	deadline.Stop()
	if err := runtime.Close(); err != nil {
		t.Fatalf("close announcement runtime = %v", err)
	}
	if err := <-workerDone; err != nil {
		t.Fatalf("announcement worker close error = %v", err)
	}
	if err := runtime.Ready(); err == nil {
		t.Fatal("closed announcement runtime remained ready")
	}

	restarted, err := openAnnouncementRuntime(t.Context(), pool, integrationAnnouncementRuntimeConfig())
	if err != nil {
		t.Fatalf("restart announcement runtime = %v", err)
	}
	if err := restarted.Close(); err != nil {
		t.Fatalf("close restarted announcement runtime = %v", err)
	}
}

func TestAnnouncementRuntimePostgreSQLWorkerFailureFailsReadinessAndReportsStableHealth(t *testing.T) {
	pool := openAnnouncementRuntimeDatabase(t, 64)
	config := integrationAnnouncementRuntimeConfig()
	runtime, err := openAnnouncementRuntime(t.Context(), pool, config)
	if err != nil {
		t.Fatalf("open announcement runtime = %v", err)
	}
	runtime.consecutiveFail.Store(announcementFailureThreshold - 1)
	pool.Close()
	failures := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		runRequiredAnnouncementRuntime(context.Background(), runtime, failures)
		close(done)
	}()
	select {
	case <-failures:
	case <-time.After(3 * time.Second):
		t.Fatal("announcement worker failure was not reported")
	}
	<-done
	if err := runtime.Ready(); err == nil {
		t.Fatal("failed announcement runtime remained ready")
	}
	if health := runtime.Health(); health.LastErrorCode != "publish_due_failed" || strings.Contains(health.LastErrorCode, "database") {
		t.Fatalf("unstable announcement health = %+v", health)
	}
	healthResponse := httptest.NewRecorder()
	withAnnouncementRuntimeHealth(http.NotFoundHandler(), runtime).ServeHTTP(
		healthResponse,
		httptest.NewRequest(http.MethodGet, "/health/announcements", nil),
	)
	if healthResponse.Code != http.StatusOK || !strings.Contains(healthResponse.Body.String(), `"last_error_code":"publish_due_failed"`) || strings.Contains(healthResponse.Body.String(), "closed pool") {
		t.Fatalf("announcement health response status=%d body=%q", healthResponse.Code, healthResponse.Body.String())
	}
	_ = runtime.Close()
}

func TestAnnouncementRuntimePostgreSQLWorkerPublishesDueAnnouncementAndCreatesInboxFacts(t *testing.T) {
	pool := openAnnouncementRuntimeDatabase(t, 64)
	scopeID, userID, _ := seedAnnouncementRuntimeSession(t, pool)
	notificationStore, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	saveAnnouncementPublishedTemplates(t, notificationStore)
	if err := notificationStore.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	if err := notificationStore.SetSubscription(
		t.Context(), scopeID, userID, announcementPublishedEventType,
		notification.Subscription{Email: true},
	); err != nil {
		t.Fatal(err)
	}
	fixedNow := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	announcementID := seedScheduledAnnouncement(t, pool, scopeID, userID, fixedNow, fixedNow.Add(-time.Minute))
	futureID := seedScheduledAnnouncement(t, pool, scopeID, userID, fixedNow, fixedNow.Add(time.Hour))
	config := integrationAnnouncementRuntimeConfig()
	config.Now = func() time.Time { return fixedNow }
	runtime, err := openAnnouncementRuntime(t.Context(), pool, config)
	if err != nil {
		t.Fatalf("open announcement runtime = %v", err)
	}
	workerDone := make(chan error, 1)
	go func() { workerDone <- runtime.Run(context.Background()) }()
	deadline := time.NewTimer(3 * time.Second)
	for runtime.published.Load() == 0 {
		select {
		case <-deadline.C:
			t.Fatal("announcement worker did not publish due announcement")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	deadline.Stop()
	if err := runtime.Close(); err != nil {
		t.Fatalf("close announcement runtime = %v", err)
	}
	if err := <-workerDone; err != nil {
		t.Fatalf("announcement worker close error = %v", err)
	}
	var status string
	if err := pool.QueryRow(t.Context(), `SELECT status FROM announcement_versions WHERE tenant_scope_id=$1 AND announcement_id=$2 AND version=1`, scopeID, announcementID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != announcement.StatusPublished {
		t.Fatalf("scheduled announcement status = %q, want published", status)
	}
	if err := pool.QueryRow(t.Context(), `SELECT status FROM announcement_versions WHERE tenant_scope_id=$1 AND announcement_id=$2 AND version=1`, scopeID, futureID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != announcement.StatusScheduled {
		t.Fatalf("future announcement status = %q, want scheduled", status)
	}
	var snapshots, events, states int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM announcement_recipient_snapshots WHERE tenant_scope_id=$1 AND announcement_id=$2),
		(SELECT count(*) FROM announcement_inbox_events WHERE tenant_scope_id=$1 AND announcement_id=$2),
		(SELECT count(*) FROM announcement_inbox_states state JOIN announcement_inbox_events event ON event.id=state.event_id WHERE event.tenant_scope_id=$1 AND event.announcement_id=$2)`, scopeID, announcementID).Scan(&snapshots, &events, &states); err != nil {
		t.Fatal(err)
	}
	if snapshots != 1 || events != 1 || states != 1 {
		t.Fatalf("published inbox facts snapshots=%d events=%d states=%d, want 1/1/1", snapshots, events, states)
	}

	sourceEventID := announcementPublicationSourceEventID(announcementID, 1)
	var notificationEvents, notificationOutbox int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM notification_events WHERE scope_id=$1 AND source_event_id=$2 AND event_type=$3),
		(SELECT count(*) FROM notification_outbox outbox JOIN notification_events event
		 ON event.scope_id=outbox.scope_id AND event.id=outbox.event_id
		 WHERE event.scope_id=$1 AND event.source_event_id=$2 AND event.event_type=$3)`,
		scopeID, sourceEventID, announcementPublishedEventType).Scan(&notificationEvents, &notificationOutbox); err != nil {
		t.Fatal(err)
	}
	if notificationEvents != 1 || notificationOutbox != 1 {
		t.Fatalf("published notification facts events=%d outbox=%d, want 1/1", notificationEvents, notificationOutbox)
	}
	var recipientID uuid.UUID
	var eventType string
	var policy notification.DeliveryPolicy
	var channel notification.Channel
	var templateID string
	var templateVersion uint64
	var subject, body, dedupKey, outboxStatus string
	if err := pool.QueryRow(t.Context(), `SELECT
		event.recipient_user_id,event.event_type,event.delivery_policy,
		outbox.channel,outbox.template_id,outbox.template_version,
		outbox.subject,outbox.body,outbox.dedup_key,outbox.status
		FROM notification_events event
		JOIN notification_outbox outbox ON outbox.scope_id=event.scope_id AND outbox.event_id=event.id
		WHERE event.scope_id=$1 AND event.source_event_id=$2 AND event.event_type=$3`,
		scopeID, sourceEventID, announcementPublishedEventType).Scan(
		&recipientID, &eventType, &policy, &channel, &templateID, &templateVersion,
		&subject, &body, &dedupKey, &outboxStatus,
	); err != nil {
		t.Fatal(err)
	}
	if recipientID != userID || eventType != announcementPublishedEventType ||
		policy != notification.DeliveryTenantSubscribed || channel != notification.ChannelEmail ||
		templateID != announcementPublishedTemplateID || templateVersion != 1 ||
		subject != "[公告] 运行时公告" || body != "运行时正文" ||
		!strings.HasPrefix(dedupKey, "notification-v1-") || outboxStatus != notification.OutboxPending {
		t.Fatalf("published notification contract recipient=%s event=%s policy=%s channel=%s template=%s/v%d subject=%q body=%q dedup=%q status=%s",
			recipientID, eventType, policy, channel, templateID, templateVersion, subject, body, dedupKey, outboxStatus)
	}
	var notificationAudit int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE scope_id=$1 AND actor_user_id IS NULL AND action='notification.event.enqueue'
		  AND resource_type='notification_event' AND request_id=$2 AND result='success'`,
		scopeID, announcementPublicationAuditRequestID(announcementID, 1, userID)).Scan(&notificationAudit); err != nil {
		t.Fatal(err)
	}
	if notificationAudit != 1 {
		t.Fatalf("published notification audit count = %d, want 1", notificationAudit)
	}
}

func TestAnnouncementRuntimePostgreSQLNotificationFailureRollsBackPublication(t *testing.T) {
	pool := openAnnouncementRuntimeDatabase(t, 64)
	scopeID, userID, _ := seedAnnouncementRuntimeSession(t, pool)
	notificationStore, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := notificationStore.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	if err := notificationStore.SetSubscription(
		t.Context(), scopeID, userID, announcementPublishedEventType,
		notification.Subscription{Email: true},
	); err != nil {
		t.Fatal(err)
	}
	fixedNow := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	announcementID := seedScheduledAnnouncement(t, pool, scopeID, userID, fixedNow, fixedNow.Add(-time.Minute))
	config := integrationAnnouncementRuntimeConfig()
	config.Now = func() time.Time { return fixedNow }
	runtime, err := openAnnouncementRuntime(t.Context(), pool, config)
	if err != nil {
		t.Fatalf("open announcement runtime = %v", err)
	}
	defer func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("close announcement runtime = %v", err)
		}
	}()

	published, err := runtime.store.PublishDue(t.Context(), 1)
	if !errors.Is(err, errAnnouncementNotificationEnqueueFailed) ||
		!errors.Is(err, notification.ErrTemplateSelection) {
		t.Fatalf("missing announcement notification template error = %v", err)
	}
	if len(published) != 0 {
		t.Fatalf("published announcements after notification failure = %d, want 0", len(published))
	}
	var status string
	var hasCurrentPublishedVersion bool
	if err := pool.QueryRow(t.Context(), `SELECT version.status,root.current_published_version IS NOT NULL
		FROM announcement_versions version
		JOIN announcements root ON root.tenant_scope_id=version.tenant_scope_id AND root.id=version.announcement_id
		WHERE version.tenant_scope_id=$1 AND version.announcement_id=$2 AND version.version=1`,
		scopeID, announcementID).Scan(&status, &hasCurrentPublishedVersion); err != nil {
		t.Fatal(err)
	}
	if status != announcement.StatusScheduled || hasCurrentPublishedVersion {
		t.Fatalf("announcement state after notification failure status=%q has_current=%t", status, hasCurrentPublishedVersion)
	}
	var snapshots, inboxEvents, inboxStates, notificationEvents, notificationOutbox, audits int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM announcement_recipient_snapshots WHERE tenant_scope_id=$1 AND announcement_id=$2),
		(SELECT count(*) FROM announcement_inbox_events WHERE tenant_scope_id=$1 AND announcement_id=$2),
		(SELECT count(*) FROM announcement_inbox_states state JOIN announcement_inbox_events event
		 ON event.tenant_scope_id=state.tenant_scope_id AND event.id=state.event_id
		 WHERE event.tenant_scope_id=$1 AND event.announcement_id=$2),
		(SELECT count(*) FROM notification_events WHERE scope_id=$1),
		(SELECT count(*) FROM notification_outbox WHERE scope_id=$1),
		(SELECT count(*) FROM audit_events WHERE scope_id=$1
		 AND action IN ('announcement.publish','notification.event.enqueue'))`, scopeID, announcementID).Scan(
		&snapshots, &inboxEvents, &inboxStates, &notificationEvents, &notificationOutbox, &audits,
	); err != nil {
		t.Fatal(err)
	}
	if snapshots != 0 || inboxEvents != 0 || inboxStates != 0 ||
		notificationEvents != 0 || notificationOutbox != 0 || audits != 0 {
		t.Fatalf("facts after notification failure snapshots=%d inbox=%d states=%d notification=%d outbox=%d audits=%d, want all zero",
			snapshots, inboxEvents, inboxStates, notificationEvents, notificationOutbox, audits)
	}
}

func TestAnnouncementRuntimePostgreSQLRouteUsesRealBearerSessionAndStableDeny(t *testing.T) {
	pool := openAnnouncementRuntimeDatabase(t, 64)
	scopeID, userID, sessionID := seedAnnouncementRuntimeSession(t, pool)
	runtimeConfig := integrationAnnouncementRuntimeConfig()
	runtime, err := openAnnouncementRuntime(t.Context(), pool, runtimeConfig)
	if err != nil {
		t.Fatalf("open announcement runtime = %v", err)
	}
	defer runtime.Close()
	tokens, err := identity.NewTokenManager(strings.Repeat("announcement-runtime-secret-", 2), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := tokens.Mint(userID, scopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	api := httpapi.New(pool, identityService, httpapi.Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnnouncementHandlerFactory: runtime.HandlerFactory()})
	if err := api.InitializationError(); err != nil {
		t.Fatalf("announcement API initialization = %v", err)
	}
	handler := api.Handler()
	if status := announcementRuntimeRouteStatus(handler, "Bearer "+token); status != http.StatusForbidden {
		t.Fatalf("real bearer without 043 role permission status = %d, want 403", status)
	}
	for name, ids := range map[string][3]uuid.UUID{
		"user":    {uuid.New(), scopeID, sessionID},
		"scope":   {userID, uuid.New(), sessionID},
		"session": {userID, scopeID, uuid.New()},
	} {
		tampered, _, err := tokens.Mint(ids[0], ids[1], ids[2])
		if err != nil {
			t.Fatal(err)
		}
		if status := announcementRuntimeRouteStatus(handler, "Bearer "+tampered); status != http.StatusUnauthorized {
			t.Errorf("%s-tampered bearer status = %d, want 401", name, status)
		}
	}
	if status := announcementRuntimeRouteStatus(handler, "CdncaKey workload-credential"); status != http.StatusUnauthorized {
		t.Errorf("CdncaKey status = %d, want 401", status)
	}
	for _, test := range []struct {
		name    string
		apply   string
		restore string
	}{
		{name: "disabled user", apply: `UPDATE users SET status='disabled' WHERE id=$1`, restore: `UPDATE users SET status='active' WHERE id=$1`},
		{name: "suspended membership", apply: `UPDATE memberships SET status='suspended' WHERE user_id=$1`, restore: `UPDATE memberships SET status='active' WHERE user_id=$1`},
		{name: "revoked session", apply: `UPDATE auth_sessions SET revoked_at=CURRENT_TIMESTAMP,revocation_reason='integration test' WHERE user_id=$1`, restore: `UPDATE auth_sessions SET revoked_at=NULL,revocation_reason=NULL WHERE user_id=$1`},
		{name: "expired session", apply: `UPDATE auth_sessions SET expires_at=created_at + interval '1 microsecond' WHERE user_id=$1`, restore: `UPDATE auth_sessions SET expires_at=CURRENT_TIMESTAMP + interval '1 hour' WHERE user_id=$1`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := pool.Exec(t.Context(), test.apply, userID); err != nil {
				t.Fatal(err)
			}
			if status := announcementRuntimeRouteStatus(handler, "Bearer "+token); status != http.StatusUnauthorized {
				t.Errorf("revoked identity status = %d, want 401", status)
			}
			if _, err := pool.Exec(t.Context(), test.restore, userID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAnnouncementRuntimePostgreSQL067TenantOwnerBearerCanCreateAndList(t *testing.T) {
	pool := openAnnouncementRuntimeDatabase(t, 67)
	scopeID, userID, sessionID := seedAnnouncementRuntimeSession(t, pool)
	roleID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'tenant_owner','announcement runtime owner',true)`, roleID, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scopeID, userID, roleID); err != nil {
		t.Fatal(err)
	}
	var permissionCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM role_permissions WHERE role_id=$1 AND permission_name IN ('announcements.read','announcements.manage')`, roleID).Scan(&permissionCount); err != nil {
		t.Fatal(err)
	}
	if permissionCount != 2 {
		t.Fatalf("067 projected announcement permissions = %d, want 2", permissionCount)
	}
	runtime, err := openAnnouncementRuntime(t.Context(), pool, integrationAnnouncementRuntimeConfig())
	if err != nil {
		t.Fatalf("open announcement runtime = %v", err)
	}
	defer runtime.Close()
	tokens, err := identity.NewTokenManager(strings.Repeat("announcement-runtime-secret-", 2), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identityService, err := identity.NewService(identity.NewStore(pool), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := tokens.Mint(userID, scopeID, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	api := httpapi.New(pool, identityService, httpapi.Config{APIKeyPepper: bytes.Repeat([]byte{0x52}, 32), AnnouncementHandlerFactory: runtime.HandlerFactory()})
	if err := api.InitializationError(); err != nil {
		t.Fatalf("announcement API initialization = %v", err)
	}
	handler := api.Handler()
	create := httptest.NewRequest(http.MethodPost, "/v1/admin/announcements", strings.NewReader(`{"title":"运行时创建","body":"运行时正文","all":true,"user_ids":[],"group_ids":[],"withdrawal_visibility":"retain"}`))
	create.Header.Set("Authorization", "Bearer "+token)
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("Idempotency-Key", "runtime-create-067")
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, create)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("tenant owner create status=%d body=%q", createResponse.Code, createResponse.Body.String())
	}
	list := httptest.NewRequest(http.MethodGet, "/v1/admin/announcements", nil)
	list.Header.Set("Authorization", "Bearer "+token)
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, list)
	if listResponse.Code != http.StatusOK || !strings.Contains(listResponse.Body.String(), "运行时创建") {
		t.Fatalf("tenant owner list status=%d body=%q", listResponse.Code, listResponse.Body.String())
	}
	if status := announcementRuntimeRouteStatus(handler, "Bearer "+token); status != http.StatusOK {
		t.Fatalf("tenant owner exact GET status=%d, want 200", status)
	}
	adjacent := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/announcements/adjacent/history", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(adjacent, request)
	if adjacent.Code != http.StatusNotFound {
		t.Fatalf("adjacent announcement route status=%d, want 404", adjacent.Code)
	}
}

func announcementRuntimeRouteStatus(handler http.Handler, authorization string) int {
	request := httptest.NewRequest(http.MethodGet, "/v1/admin/announcements", nil)
	request.Header.Set("Authorization", authorization)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response.Code
}

func integrationAnnouncementKeyring() announcement.CursorKeyring {
	return announcement.CursorKeyring{ActiveKID: "runtime", Keys: map[string][]byte{"runtime": bytes.Repeat([]byte{0x51}, 32)}}
}

func integrationAnnouncementRuntimeConfig() announcementRuntimeConfig {
	return announcementRuntimeConfig{
		Enabled: true, ExternalChannel: announcementExternalChannelDisabled,
		PollInterval: time.Second, OperationTimeout: time.Second,
		ShutdownTimeout: time.Second, StartupTimeout: time.Second, BatchSize: 10,
		CursorKeyring: integrationAnnouncementKeyring(),
	}
}

func seedAnnouncementRuntimeSession(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, scopeID, userID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, "announcement-runtime-tenant"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$3,$4)`, userID, "announcement-runtime-user", "Announcement Runtime", "unused"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), userID, scopeID, bytes.Repeat([]byte{0x34}, 32), now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return scopeID, userID, sessionID
}

func seedScheduledAnnouncement(
	t *testing.T,
	pool *pgxpool.Pool,
	scopeID, userID uuid.UUID,
	now, publishAt time.Time,
) uuid.UUID {
	t.Helper()
	announcementID := uuid.New()
	createdAt := now.Add(-2 * time.Minute)
	sealedAt := now.Add(-time.Minute)
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO announcements(id,tenant_scope_id,head_version,created_by_user_id,created_at,updated_at) VALUES($1,$2,1,$3,$4,$4)`, announcementID, scopeID, userID, createdAt); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO announcement_archive_254(tenant_scope_id,announcement_id,changed_at,changed_by_user_id) VALUES($1,$2,$3,$4)`, scopeID, announcementID, createdAt, userID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO announcement_lifecycle_facts_254(id,tenant_scope_id,announcement_id,revision,state,actor_user_id,occurred_at,request_id) VALUES($1,$2,$3,1,'active',$4,$5,$6)`, uuid.New(), scopeID, announcementID, userID, createdAt, "runtime-seed-"+announcementID.String()); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO announcement_versions(tenant_scope_id,announcement_id,version,revision,status,title,body,audience_mode,withdrawal_visibility,created_by_user_id,created_at,state_changed_at) VALUES($1,$2,1,1,'draft',$3,$4,'all','retain',$5,$6,$6)`, scopeID, announcementID, "运行时公告", "运行时正文", userID, createdAt); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE announcement_versions SET status='scheduled',revision=revision+1,scheduled_at=$3,sealed_at=$4,state_changed_at=$5 WHERE tenant_scope_id=$1 AND announcement_id=$2 AND version=1`, scopeID, announcementID, publishAt, sealedAt, now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return announcementID
}

func openAnnouncementRuntimeDatabase(t *testing.T, minimumVersion int) *pgxpool.Pool {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "announcement_runtime_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	admin.Close()
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, err := pgxpool.New(context.Background(), databaseURL)
		if err == nil {
			_, _ = cleanup.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
			cleanup.Close()
		}
	})
	if minimumVersion == 0 {
		return pool
	}
	// The runtime's notification adapter also requires the current schema.
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := pool.QueryRow(t.Context(), `SELECT max(version) FROM schema_migrations`).Scan(&version); err != nil || version < minimumVersion {
		t.Fatalf("schema version=%d minimum=%d err=%v", version, minimumVersion, err)
	}
	return pool
}
