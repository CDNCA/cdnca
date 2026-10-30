//go:build integration

package notification

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMigration049BackfillsMemberAndRefusesLossyDown(t *testing.T) {
	pool := isolatedAnonymousDispatchPool(t, 48)
	ctx := t.Context()
	_, scopeID, userID := seedAnonymousDispatchIdentity(t, pool, "migration")
	memberEventID := uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO notification_events (
			id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,request_digest,created_at
		) VALUES($1,$2,$3,'member-before-049','node.offline','system_required',$4,$5)`,
		memberEventID, scopeID, userID, make([]byte, 32), anonymousDispatchTestTime); err != nil {
		t.Fatal(err)
	}
	applyAnonymousDispatchMigration(t, pool, "049_notification_anonymous_dispatch.up.sql")
	var kind string
	var reference *uuid.UUID
	if err := pool.QueryRow(ctx, `
		SELECT recipient_kind,anonymous_dispatch_reference
		FROM notification_events WHERE id=$1`, memberEventID).Scan(&kind, &reference); err != nil {
		t.Fatal(err)
	}
	if kind != "member" || reference != nil {
		t.Fatalf("member backfill = %q/%v", kind, reference)
	}

	assertAnonymousDispatchSQLRejected(t, pool, `
		INSERT INTO notification_events(
			id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,
			request_digest,created_at,recipient_kind,anonymous_dispatch_reference
		) VALUES($1,$2,$3,'member-recovery','identity.account_recovery','system_required',
			$4,$5,'member',NULL)`, uuid.New(), scopeID, userID, make([]byte, 32), anonymousDispatchTestTime)
	assertAnonymousDispatchSQLRejected(t, pool, `
		INSERT INTO notification_events(
			id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,
			request_digest,created_at,recipient_kind,anonymous_dispatch_reference
		) VALUES($1,$2,$3,'both-targets','identity.account_recovery','system_required',
			$4,$5,'anonymous',$6)`, uuid.New(), scopeID, userID, make([]byte, 32), anonymousDispatchTestTime, uuid.New())
	assertAnonymousDispatchSQLRejected(t, pool, `
		INSERT INTO notification_events(
			id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,
			request_digest,created_at,recipient_kind,anonymous_dispatch_reference
		) VALUES($1,$2,NULL,'nil-reference','identity.account_recovery','system_required',
			$3,$4,'anonymous',$5)`, uuid.New(), scopeID, make([]byte, 32), anonymousDispatchTestTime, uuid.Nil)
	assertAnonymousDispatchSQLRejected(t, pool, `
		INSERT INTO notification_events(
			id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,
			request_digest,created_at,recipient_kind,anonymous_dispatch_reference
		) VALUES($1,$2,NULL,'wrong-policy','identity.account_recovery','tenant_subscribed',
			$3,$4,'anonymous',$5)`, uuid.New(), scopeID, make([]byte, 32), anonymousDispatchTestTime, uuid.New())
	assertAnonymousDispatchSQLRejected(t, pool, `
		INSERT INTO notification_events(
			id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,
			request_digest,created_at,recipient_kind,anonymous_dispatch_reference
		) VALUES($1,$2,NULL,'wrong-event','node.offline','system_required',
			$3,$4,'anonymous',$5)`, uuid.New(), scopeID, make([]byte, 32), anonymousDispatchTestTime, uuid.New())
	assertAnonymousDispatchSQLRejected(t, pool, `
		INSERT INTO notification_events(
			id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,
			request_digest,created_at,recipient_kind,anonymous_dispatch_reference
		) VALUES($1,$2,NULL,'neither-target','node.offline','system_required',
			$3,$4,'member',NULL)`, uuid.New(), scopeID, make([]byte, 32), anonymousDispatchTestTime)

	applyAnonymousDispatchMigration(t, pool, "049_notification_anonymous_dispatch.down.sql")
	applyAnonymousDispatchMigration(t, pool, "049_notification_anonymous_dispatch.up.sql")

	anonymousEventID, dispatchReference := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO notification_events(
			id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,
			request_digest,created_at,recipient_kind,anonymous_dispatch_reference
		) VALUES($1,$2,NULL,'anonymous-fact','identity.account_recovery','system_required',
			$3,$4,'anonymous',$5)`, anonymousEventID, scopeID, make([]byte, 32),
		anonymousDispatchTestTime, dispatchReference); err != nil {
		t.Fatal(err)
	}
	assertAnonymousDispatchSQLRejected(t, pool, `
		INSERT INTO notification_events(
			id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,
			request_digest,created_at,recipient_kind,anonymous_dispatch_reference
		) VALUES($1,$2,NULL,'anonymous-fact','identity.account_recovery','system_required',
			$3,$4,'anonymous',$5)`, uuid.New(), scopeID, make([]byte, 32), anonymousDispatchTestTime, uuid.New())
	assertAnonymousDispatchSQLRejected(t, pool, `
		INSERT INTO notification_events(
			id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,
			request_digest,created_at,recipient_kind,anonymous_dispatch_reference
		) VALUES($1,$2,NULL,'other-source','identity.account_recovery','system_required',
			$3,$4,'anonymous',$5)`, uuid.New(), scopeID, make([]byte, 32), anonymousDispatchTestTime, dispatchReference)
	if script, err := migrations.FS.ReadFile("049_notification_anonymous_dispatch.down.sql"); err != nil {
		t.Fatal(err)
	} else if _, err := pool.Exec(ctx, string(script)); err == nil ||
		!strings.Contains(err.Error(), "anonymous facts exist") {
		t.Fatalf("lossy 049 down error = %v", err)
	}
	var columnExists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='notification_events'
		  AND column_name='anonymous_dispatch_reference'
	)`).Scan(&columnExists); err != nil || !columnExists {
		t.Fatalf("049 down refusal was not atomic: exists=%v err=%v", columnExists, err)
	}
}

func TestAnonymousDispatchTransactionReplayAndNoopACK(t *testing.T) {
	pool := headMigratedNotificationPool(t)
	ctx := t.Context()
	_, scopeID, _ := seedAnonymousDispatchIdentity(t, pool, "dispatch")
	clock := &lockedClock{now: anonymousDispatchTestTime}
	store, err := NewStoreWithClock(pool, audit.New(pool), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	template := TemplateRef{ID: "account_recovery", Version: 1, Channel: ChannelSMS}
	if err := store.SaveTemplate(ctx, TemplateDefinition{
		Ref: template, Body: "重置地址：{{.recovery_url}}", Variables: []string{"recovery_url"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(ctx, ChannelSwitches{SMS: true}); err != nil {
		t.Fatal(err)
	}
	request := DispatchEnqueueRequest{
		ScopeID: scopeID, SourceEventID: "account-recovery-request-1",
		AnonymousDispatchReference: uuid.New(),
		Templates:                  map[Channel]TemplateRef{ChannelSMS: template},
		AuditRequestID:             "audit-account-recovery-request-1",
	}

	const writers = 8
	start := make(chan struct{})
	results := make(chan EnqueueResult, writers)
	errorsFound := make(chan error, writers)
	var wait sync.WaitGroup
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := enqueueAnonymousDispatch(t.Context(), pool, store, request)
			results <- result
			errorsFound <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	var eventID, outboxID uuid.UUID
	created, replayed := 0, 0
	for result := range results {
		if len(result.Deliveries) != 1 {
			t.Fatalf("dispatch deliveries = %+v", result.Deliveries)
		}
		if eventID == uuid.Nil {
			eventID, outboxID = result.EventID, result.Deliveries[0].OutboxID
		}
		if result.EventID != eventID || result.Deliveries[0].OutboxID != outboxID {
			t.Fatal("dispatch replay returned different identities")
		}
		if result.Replayed {
			replayed++
		} else {
			created++
		}
	}
	if created != 1 || replayed != writers-1 {
		t.Fatalf("dispatch created/replayed = %d/%d", created, replayed)
	}

	conflict := request
	conflict.AnonymousDispatchReference = uuid.New()
	if _, err := enqueueAnonymousDispatch(ctx, pool, store, conflict); !errors.Is(err, ErrEventConflict) {
		t.Fatalf("different reference replay error = %v", err)
	}
	var kind, eventType, sourceEventID, body string
	var recipientID *uuid.UUID
	var storedReference uuid.UUID
	if err := pool.QueryRow(ctx, `
		SELECT event.recipient_kind,event.recipient_user_id,event.anonymous_dispatch_reference,
		       event.event_type,event.source_event_id,outbox.body
		FROM notification_events event
		JOIN notification_outbox outbox ON outbox.scope_id=event.scope_id AND outbox.event_id=event.id
		WHERE event.id=$1`, eventID).Scan(
		&kind, &recipientID, &storedReference, &eventType, &sourceEventID, &body,
	); err != nil {
		t.Fatal(err)
	}
	if kind != "anonymous" || recipientID != nil || storedReference != request.AnonymousDispatchReference ||
		eventType != EventTypeAccountRecovery || sourceEventID != request.SourceEventID ||
		body != "重置地址：{{.recovery_url}}" {
		t.Fatalf("stored anonymous dispatch = %q/%v/%s/%q/%q/%q", kind, recipientID, storedReference, eventType, sourceEventID, body)
	}
	var auditPayload string
	if err := pool.QueryRow(ctx, `
		SELECT payload::text FROM audit_events
		WHERE action='notification.event.enqueue' AND resource_id=$1`, eventID.String()).Scan(&auditPayload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(auditPayload, request.AnonymousDispatchReference.String()) {
		t.Fatal("anonymous dispatch reference leaked into audit payload")
	}

	memberSender := &dispatchTestMemberSender{}
	dispatcher := &dispatchTestAnonymousDispatcher{
		result: AnonymousDispatchResult{Disposition: AnonymousDispatchNoopACK},
	}
	config := DefaultWorkerConfig()
	config.BatchSize = 1
	worker, err := NewWorkerWithAnonymousDispatcher(store, memberSender, dispatcher, config)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := worker.ProcessBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if batch.Claimed != 1 || batch.Succeeded != 1 || batch.NoopAcknowledged != 1 ||
		len(memberSender.calls) != 0 || len(dispatcher.calls) != 1 {
		t.Fatalf("anonymous noop batch=%+v member_calls=%d dispatch_calls=%d", batch, len(memberSender.calls), len(dispatcher.calls))
	}
	if dispatcher.calls[0].AnonymousDispatchReference != request.AnonymousDispatchReference ||
		dispatcher.calls[0].EventType != EventTypeAccountRecovery ||
		dispatcher.calls[0].SourceEventID != request.SourceEventID {
		t.Fatalf("claimed anonymous dispatch = %+v", dispatcher.calls[0])
	}
	assertOutboxStatusAttempt(t, pool, outboxID, OutboxSucceeded, 1)
	var outcome string
	if err := pool.QueryRow(ctx, `SELECT outcome FROM notification_attempts WHERE outbox_id=$1`, outboxID).Scan(&outcome); err != nil {
		t.Fatal(err)
	}
	if outcome != "succeeded" {
		t.Fatalf("noop attempt outcome = %q", outcome)
	}
}

func TestAnonymousDispatchAuditFailureRollsBackWithCaller(t *testing.T) {
	pool := headMigratedNotificationPool(t)
	ctx := t.Context()
	tenantID, scopeID, _ := seedAnonymousDispatchIdentity(t, pool, "rollback")
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	template := TemplateRef{ID: "account_recovery_rollback", Version: 1, Channel: ChannelSMS}
	if err := store.SaveTemplate(ctx, TemplateDefinition{
		Ref: template, Body: "recovery", Variables: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(ctx, ChannelSwitches{SMS: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		CREATE FUNCTION reject_anonymous_dispatch_audit_049()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action='notification.event.enqueue' AND NEW.payload->>'recipient_kind'='anonymous' THEN
				RAISE EXCEPTION 'injected anonymous dispatch audit failure';
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER reject_anonymous_dispatch_audit_049
		BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION reject_anonymous_dispatch_audit_049();`); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE tenants SET display_name='must rollback' WHERE id=$1`, tenantID); err != nil {
		t.Fatal(err)
	}
	request := DispatchEnqueueRequest{
		ScopeID: scopeID, SourceEventID: "rollback-request",
		AnonymousDispatchReference: uuid.New(),
		Templates:                  map[Channel]TemplateRef{ChannelSMS: template},
		AuditRequestID:             "audit-rollback-request",
	}
	if _, err := store.EnqueueDispatchTx(ctx, tx, request); err == nil {
		t.Fatal("anonymous dispatch audit failure was accepted")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var displayName string
	if err := pool.QueryRow(ctx, `SELECT display_name FROM tenants WHERE id=$1`, tenantID).Scan(&displayName); err != nil {
		t.Fatal(err)
	}
	if displayName == "must rollback" {
		t.Fatal("caller business mutation survived dispatch failure")
	}
	var events int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE source_event_id='rollback-request'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Fatalf("dispatch failure left %d notification events", events)
	}
}

func TestAnonymousDispatchFailureReusesRetryAndExhaustion(t *testing.T) {
	pool := headMigratedNotificationPool(t)
	ctx := t.Context()
	_, scopeID, _ := seedAnonymousDispatchIdentity(t, pool, "retry")
	clock := &lockedClock{now: anonymousDispatchTestTime}
	store, err := NewStoreWithClock(pool, audit.New(pool), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	template := TemplateRef{ID: "account_recovery_retry", Version: 1, Channel: ChannelSMS}
	if err := store.SaveTemplate(ctx, TemplateDefinition{
		Ref: template, Body: "recovery", Variables: []string{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(ctx, ChannelSwitches{SMS: true}); err != nil {
		t.Fatal(err)
	}
	request := DispatchEnqueueRequest{
		ScopeID: scopeID, SourceEventID: "retry-request",
		AnonymousDispatchReference: uuid.New(),
		Templates:                  map[Channel]TemplateRef{ChannelSMS: template},
		AuditRequestID:             "audit-retry-request",
	}
	enqueued, err := enqueueAnonymousDispatch(ctx, pool, store, request)
	if err != nil {
		t.Fatal(err)
	}
	outboxID := enqueued.Deliveries[0].OutboxID
	temporary := func() AnonymousDispatchResult {
		failure := Failure{Class: FailureTemporary, Code: "resolver_unavailable"}
		return AnonymousDispatchResult{Failure: &failure}
	}
	dispatcher := &dispatchTestAnonymousDispatcher{
		script: []AnonymousDispatchResult{temporary(), temporary()},
	}
	memberSender := &dispatchTestMemberSender{}
	config := DefaultWorkerConfig()
	config.BatchSize, config.MaxAttempts = 1, 2
	config.BaseDelay, config.MaxDelay = time.Second, time.Second
	worker, err := NewWorkerWithAnonymousDispatcher(store, memberSender, dispatcher, config)
	if err != nil {
		t.Fatal(err)
	}
	first, err := worker.ProcessBatch(ctx)
	if err != nil || first.Claimed != 1 || first.RetryScheduled != 1 {
		t.Fatalf("first anonymous retry = %+v, %v", first, err)
	}
	assertOutbox(t, pool, outboxID, OutboxPending, "resolver_unavailable", 1)
	if _, err := pool.Exec(ctx, `
		UPDATE notification_outbox SET available_at=clock_timestamp() WHERE id=$1`, outboxID); err != nil {
		t.Fatal(err)
	}
	second, err := worker.ProcessBatch(ctx)
	if err != nil || second.Claimed != 1 || second.Exhausted != 1 {
		t.Fatalf("anonymous exhaustion = %+v, %v", second, err)
	}
	assertOutbox(t, pool, outboxID, OutboxExhausted, "resolver_unavailable", 2)
	assertAttempt(t, pool, outboxID, 1, "temporary_failure", "resolver_unavailable")
	assertAttempt(t, pool, outboxID, 2, "exhausted", "resolver_unavailable")
	if len(memberSender.calls) != 0 || len(dispatcher.calls) != 2 {
		t.Fatalf("anonymous retry routes = member:%d anonymous:%d", len(memberSender.calls), len(dispatcher.calls))
	}
}

var anonymousDispatchTestTime = time.Date(2026, 7, 23, 3, 0, 0, 0, time.UTC)

func enqueueAnonymousDispatch(
	ctx context.Context,
	pool *pgxpool.Pool,
	store *Store,
	request DispatchEnqueueRequest,
) (EnqueueResult, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return EnqueueResult{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	result, err := store.EnqueueDispatchTx(ctx, tx, request)
	if err != nil {
		return EnqueueResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return EnqueueResult{}, err
	}
	return result, nil
}

func seedAnonymousDispatchIdentity(
	t *testing.T,
	pool *pgxpool.Pool,
	suffix string,
) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	username := "anonymous-dispatch-" + suffix + "-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`,
		tenantID, "Anonymous Dispatch "+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`,
		scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO users(id,username,display_name,password_hash)
		VALUES($1,$2,'Dispatch User','unused')`, userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`,
		scopeID, userID); err != nil {
		t.Fatal(err)
	}
	return tenantID, scopeID, userID
}

func assertAnonymousDispatchSQLRejected(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), sql, args...); err == nil {
		t.Fatal("invalid anonymous dispatch SQL was accepted")
	}
}

func applyAnonymousDispatchMigration(t *testing.T, pool *pgxpool.Pool, name string) {
	t.Helper()
	script, err := migrations.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(t.Context(), string(script)); err != nil {
		t.Fatalf("apply %s: %v", name, err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatalf("commit %s: %v", name, err)
	}
}

func isolatedAnonymousDispatchPool(t *testing.T, through int) *pgxpool.Pool {
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
	schema := "anonymous_dispatch_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^anonymous_dispatch_test_[a-f0-9]{32}$`).MatchString(schema) {
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
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
		t.Fatal(err)
	}
	if err := migrateAnonymousDispatchSchema(ctx, pool, through); err != nil {
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
			t.Errorf("drop anonymous dispatch schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func migrateAnonymousDispatchSchema(ctx context.Context, pool *pgxpool.Pool, through int) error {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	var names []string
	for _, entry := range entries {
		var version int
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		if _, err := fmt.Sscanf(entry.Name(), "%d_", &version); err == nil && version <= through {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) != through {
		return fmt.Errorf("migration count through %03d = %d", through, len(names))
	}
	for _, name := range names {
		script, err := migrations.FS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}
