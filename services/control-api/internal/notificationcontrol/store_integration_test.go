package notificationcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/notificationruntime"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var controlTestNow = time.Date(2026, 8, 3, 10, 0, 0, 123456000, time.UTC)

type notificationControlWriteCase struct {
	name, operation, successAction, requestID string
	actor                                     Actor
	denialErr, conflictErr                    error
	write                                     func(context.Context, *Store, bool, string) (any, error)
	revoke, grant                             func(*testing.T)
	assertRollback                            func(*testing.T)
}

type controlledNotificationProvider struct {
	messages chan notificationruntime.ProviderMessage
}

func (*controlledNotificationProvider) Ready(context.Context) error { return nil }

func (provider *controlledNotificationProvider) Send(
	_ context.Context,
	message notificationruntime.ProviderMessage,
) (notificationruntime.ProviderResult, error) {
	provider.messages <- message
	return notificationruntime.ProviderResult{
		Disposition:        notificationruntime.ProviderAccepted,
		ProviderDeliveryID: "controlled-delivery-" + string(message.Channel),
	}, nil
}

func (*controlledNotificationProvider) Close(context.Context) error { return nil }

type controlledContactResolver struct{}

func (controlledContactResolver) Ready(context.Context, notification.Channel) error { return nil }

func (controlledContactResolver) Resolve(
	_ context.Context,
	_ uuid.UUID,
	_ uuid.UUID,
	channel notification.Channel,
) notificationruntime.ContactResolution {
	if channel == notification.ChannelSMS {
		return notificationruntime.ContactResolution{Contact: "+8613800000000"}
	}
	return notificationruntime.ContactResolution{Contact: "member@example.test"}
}

func TestNotificationControlWriteDigestsBindSemanticInput(t *testing.T) {
	channels := UpdateChannelsRequest{
		ExpectedRevision: 4, SMSEnabled: false, EmailEnabled: true, RequestID: "channels-key",
	}
	channelDigest := updateChannelsRequestDigest(channels)
	for name, mutate := range map[string]func(*UpdateChannelsRequest){
		"revision": func(value *UpdateChannelsRequest) { value.ExpectedRevision++ },
		"sms":      func(value *UpdateChannelsRequest) { value.SMSEnabled = true },
		"email":    func(value *UpdateChannelsRequest) { value.EmailEnabled = false },
	} {
		changed := channels
		mutate(&changed)
		if updateChannelsRequestDigest(changed) == channelDigest {
			t.Fatalf("channels %s did not change digest", name)
		}
	}
	channels.RequestID = "other-key"
	if updateChannelsRequestDigest(channels) != channelDigest {
		t.Fatal("channels request key must not be duplicated in semantic digest")
	}

	template := TemplateInput{Subject: "subject", Body: "body", Variables: []string{"first", "second"}}
	templateDigest := putTemplateRequestDigest("template", 2, ChannelEmail, template)
	templateCases := map[string]struct {
		templateID string
		version    int64
		channel    string
		input      TemplateInput
	}{
		"template ID": {templateID: "other", version: 2, channel: ChannelEmail, input: template},
		"version":     {templateID: "template", version: 3, channel: ChannelEmail, input: template},
		"channel":     {templateID: "template", version: 2, channel: ChannelSMS, input: template},
		"subject": {templateID: "template", version: 2, channel: ChannelEmail,
			input: TemplateInput{Subject: "other", Body: "body", Variables: []string{"first", "second"}}},
		"body": {templateID: "template", version: 2, channel: ChannelEmail,
			input: TemplateInput{Subject: "subject", Body: "other", Variables: []string{"first", "second"}}},
		"variable order": {templateID: "template", version: 2, channel: ChannelEmail,
			input: TemplateInput{Subject: "subject", Body: "body", Variables: []string{"second", "first"}}},
	}
	for name, test := range templateCases {
		if putTemplateRequestDigest(test.templateID, test.version, test.channel, test.input) == templateDigest {
			t.Fatalf("template %s did not change digest", name)
		}
	}

	subscription := UpdateSubscriptionRequest{
		ExpectedRevision: 3, SMSEnabled: false, EmailEnabled: true, RequestID: "subscription-key",
	}
	subscriptionDigest := updateSubscriptionRequestDigest(EventTypeAnnouncementPublished, subscription)
	for name, test := range map[string]struct {
		eventType string
		request   UpdateSubscriptionRequest
	}{
		"event":    {eventType: "other.event", request: subscription},
		"revision": {eventType: EventTypeAnnouncementPublished, request: UpdateSubscriptionRequest{ExpectedRevision: 4, EmailEnabled: true}},
		"sms":      {eventType: EventTypeAnnouncementPublished, request: UpdateSubscriptionRequest{ExpectedRevision: 3, SMSEnabled: true, EmailEnabled: true}},
		"email":    {eventType: EventTypeAnnouncementPublished, request: UpdateSubscriptionRequest{ExpectedRevision: 3}},
	} {
		if updateSubscriptionRequestDigest(test.eventType, test.request) == subscriptionDigest {
			t.Fatalf("subscription %s did not change digest", name)
		}
	}
	subscription.RequestID = "other-key"
	if updateSubscriptionRequestDigest(EventTypeAnnouncementPublished, subscription) != subscriptionDigest {
		t.Fatal("subscription request key must not be duplicated in semantic digest")
	}
}

func TestNotificationControlAuthorizationPrecedesValidationAndLookup091(t *testing.T) {
	pool := notificationControlPool(t)
	store, err := NewStoreWithDependencies(
		pool,
		audit.NewWithClock(pool, func() time.Time { return controlTestNow }),
		func() time.Time { return controlTestNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	viewer := seedControlActor(t, pool, "platform", permissionRead)
	tenant := seedControlActor(t, pool, "tenant")
	revokedTenant := seedControlActor(t, pool, "tenant")
	if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions
		SET revoked_at=$2,revocation_reason='authorization-order-test' WHERE id=$1`,
		revokedTenant.SessionID, controlTestNow); err != nil {
		t.Fatal(err)
	}

	for range 2 {
		if _, err := store.UpdateChannels(t.Context(), viewer, UpdateChannelsRequest{
			ExpectedRevision: 0, RequestID: "authorization-first-channels",
		}); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("forbidden malformed channel update = %v, want permission denied", err)
		}
		if _, err := store.PutTemplate(t.Context(), viewer, "INVALID", 0, "invalid",
			TemplateInput{}, "authorization-first-template"); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("forbidden malformed template put = %v, want permission denied", err)
		}
		if _, err := store.GetSubscription(t.Context(), viewer, "private.unsupported"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("platform unsupported self subscription read = %v, want not found", err)
		}
		if _, err := store.UpdateSubscription(t.Context(), viewer, "private.unsupported", UpdateSubscriptionRequest{
			ExpectedRevision: 0, RequestID: "authorization-first-platform-subscription",
		}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("platform unsupported self subscription update = %v, want not found", err)
		}
		if _, err := store.ListDeliveryLogs(t.Context(), tenant, DeliveryLogQuery{Limit: "invalid"}); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("tenant malformed delivery list = %v, want permission denied", err)
		}
	}
	if _, err := store.GetSubscription(t.Context(), revokedTenant, "private.unsupported"); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked unsupported subscription read = %v, want unauthenticated", err)
	}
	if _, err := store.ListDeliveryLogs(t.Context(), revokedTenant, DeliveryLogQuery{Limit: "invalid"}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked malformed delivery list = %v, want unauthenticated", err)
	}
	if _, err := store.UpdateSubscription(t.Context(), revokedTenant, "private.unsupported", UpdateSubscriptionRequest{
		ExpectedRevision: -1, RequestID: "authorization-first-revoked-subscription",
	}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked malformed subscription update = %v, want unauthenticated", err)
	}

	var viewerRoleID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT role_id FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2`, viewer.ScopeID, viewer.UserID).Scan(&viewerRoleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,$2)`, viewerRoleID, permissionManage); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateChannels(t.Context(), viewer, UpdateChannelsRequest{
		ExpectedRevision: 0, RequestID: "authorized-invalid-channels",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("authorized malformed channel update = %v, want invalid input", err)
	}
	if _, err := store.PutTemplate(t.Context(), viewer, "INVALID", 0, "invalid",
		TemplateInput{}, "authorized-invalid-template"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("authorized malformed template put = %v, want invalid input", err)
	}
	if _, err := store.PutTemplate(t.Context(), viewer, "announcement_published", 1, ChannelSMS,
		TemplateInput{Body: "{{.body}}", Variables: []string{"body"}}, "authorized-invalid-sms-template"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("authorized invalid SMS template = %v, want invalid input", err)
	}
	if _, err := store.GetSubscription(t.Context(), tenant, "private.unsupported"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("authorized unsupported subscription read = %v, want not found", err)
	}
	if _, err := store.UpdateSubscription(t.Context(), tenant, "private.unsupported", UpdateSubscriptionRequest{
		ExpectedRevision: 0, RequestID: "authorized-unsupported-subscription",
	}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("authorized unsupported subscription update = %v, want not found", err)
	}
	if _, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
		ExpectedRevision: -1, SMSEnabled: true, RequestID: "authorized-negative-subscription",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("authorized negative subscription revision = %v, want invalid input", err)
	}
	if result, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
		ExpectedRevision: 0, SMSEnabled: true, RequestID: "authorized-sms-subscription",
	}); err != nil || !result.SMSEnabled || !result.SMSSupported || result.Revision != 1 {
		t.Fatalf("authorized SMS subscription = %+v, %v", result, err)
	}

	assertNotificationControlDeniedAudit091(t, pool, viewer, writeOperationChannelsUpdate,
		"authorization-first-channels", 1)
	assertNotificationControlDeniedAudit091(t, pool, viewer, writeOperationTemplatePut,
		"authorization-first-template", 1)
	assertNotificationControlDeniedAudit091(t, pool, viewer, "notification.subscription.get",
		viewer.SessionID.String(), 0)
	assertNotificationControlDeniedAudit091(t, pool, viewer, writeOperationSubscriptionUpdate,
		"authorization-first-platform-subscription", 0)
	assertNotificationControlDeniedAudit091(t, pool, revokedTenant, writeOperationSubscriptionUpdate,
		"authorization-first-revoked-subscription", 0)
}

func TestNotificationControlWritesReplayAuthorizationAndAudit091(t *testing.T) {
	pool := notificationControlPool(t)
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, func() time.Time { return controlTestNow }), func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range notificationControlWriteCases(t, pool, "matrix") {
		t.Run(test.name, func(t *testing.T) {
			test.grant(t)
			first, err := test.write(t.Context(), store, false, test.requestID)
			if err != nil {
				t.Fatalf("first write: %v", err)
			}
			assertNotificationControlChangedResult(t, first)
			replay, err := test.write(t.Context(), store, false, test.requestID)
			if err != nil || notificationControlResultJSON(t, replay) != notificationControlResultJSON(t, first) {
				t.Fatalf("exact replay = %+v, %v, want %+v", replay, err, first)
			}
			if _, err := test.write(t.Context(), store, true, test.requestID); !errors.Is(err, test.conflictErr) {
				t.Fatalf("changed digest = %v, want %v", err, test.conflictErr)
			}
			before := notificationControlReceiptFacts(t, pool, test)
			assertNotificationControlReceiptAuditIdentity(t, pool, test, 1, 1, 0)

			test.revoke(t)
			if _, err := test.write(t.Context(), store, false, test.requestID); !errors.Is(err, test.denialErr) {
				t.Fatalf("revoked exact replay = %v, want %v", err, test.denialErr)
			}
			if after := notificationControlReceiptFacts(t, pool, test); after != before {
				t.Fatalf("denied replay changed receipt: before=%q after=%q", before, after)
			}
			assertNotificationControlReceiptAuditIdentity(t, pool, test, 1, 1, 1)
		})
	}
}

func TestNotificationControlAuditFailureRollsBackAllWrites091(t *testing.T) {
	pool := notificationControlPool(t)
	injected := errors.New("injected notification control audit failure")
	failing, err := NewStoreWithDependencies(pool, notificationControlFailingAuditor{err: injected}, func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	retry, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, func() time.Time { return controlTestNow }), func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range notificationControlWriteCases(t, pool, "audit-failure") {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.write(t.Context(), failing, false, test.requestID); !errors.Is(err, injected) {
				t.Fatalf("audit failure = %v", err)
			}
			test.assertRollback(t)
			assertNotificationControlReceiptAuditIdentity(t, pool, test, 0, 0, 0)
			result, err := test.write(t.Context(), retry, false, test.requestID)
			if err != nil {
				t.Fatalf("retry after rollback: %v", err)
			}
			assertNotificationControlChangedResult(t, result)
			assertNotificationControlReceiptAuditIdentity(t, pool, test, 1, 1, 0)
		})
	}
}

func TestNotificationControlDeniedAuditSerialConcurrentAndGrant091(t *testing.T) {
	pool := notificationControlPool(t)
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, func() time.Time { return controlTestNow }), func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	tests := notificationControlWriteCases(t, pool, "denied-serial")
	for _, test := range tests {
		t.Run("serial/"+test.name, func(t *testing.T) {
			test.revoke(t)
			for range 2 {
				if _, err := test.write(t.Context(), store, false, test.requestID); !errors.Is(err, test.denialErr) {
					t.Fatalf("serial denial = %v, want %v", err, test.denialErr)
				}
			}
			assertNotificationControlReceiptAuditIdentity(t, pool, test, 0, 0, 1)
			test.assertRollback(t)
			test.grant(t)
			result, err := test.write(t.Context(), store, false, test.requestID)
			if err != nil {
				t.Fatalf("same-key success after grant: %v", err)
			}
			assertNotificationControlChangedResult(t, result)
			assertNotificationControlReceiptAuditIdentity(t, pool, test, 1, 1, 1)
		})
	}

	for _, test := range tests {
		t.Run("concurrent/"+test.name, func(t *testing.T) {
			test.requestID = strings.Replace(test.requestID, "denied-serial", "denied-concurrent", 1)
			test.revoke(t)
			start := make(chan struct{})
			errorsSeen := make(chan error, 2)
			var workers sync.WaitGroup
			for range 2 {
				workers.Add(1)
				go func() {
					defer workers.Done()
					<-start
					_, err := test.write(context.Background(), store, false, test.requestID)
					errorsSeen <- err
				}()
			}
			close(start)
			workers.Wait()
			close(errorsSeen)
			for err := range errorsSeen {
				if !errors.Is(err, test.denialErr) {
					t.Fatalf("concurrent denial = %v, want %v", err, test.denialErr)
				}
			}
			assertNotificationControlReceiptAuditIdentity(t, pool, test, 0, 0, 1)
		})
	}
}

func TestNotificationControlDeniedAuditCommitsBeforeConcurrentGrant091(t *testing.T) {
	pool := notificationControlPool(t)
	actor := seedControlActor(t, pool, "platform", permissionRead)
	manageRoleID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,$3,'Notification atomic grant role',true)`, manageRoleID, actor.ScopeID,
		"notification-atomic-grant-"+strings.ReplaceAll(manageRoleID.String(), "-", "")); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name)
		VALUES($1,$2)`, manageRoleID, permissionManage); err != nil {
		t.Fatal(err)
	}
	releaseAudit := make(chan struct{})
	auditEntered := make(chan int32, 1)
	blockingAuditor := &notificationControlBlockingAuditor091{
		delegate: audit.NewWithClock(pool, func() time.Time { return controlTestNow }),
		entered:  auditEntered,
		release:  releaseAudit,
	}
	store, err := NewStoreWithDependencies(pool, blockingAuditor, func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	requestID := "denial-atomic-grant"
	workerContext, stopWorker := context.WithTimeout(context.Background(), 15*time.Second)
	defer stopWorker()
	denialResult := make(chan error, 1)
	go func() {
		_, err := store.UpdateChannels(workerContext, actor, UpdateChannelsRequest{
			ExpectedRevision: 0, RequestID: requestID,
		})
		denialResult <- err
	}()

	var denialPID int32
	select {
	case denialPID = <-auditEntered:
	case err := <-denialResult:
		t.Fatalf("permission denial returned before its audit entered the authorization transaction: %v", err)
	case <-workerContext.Done():
		t.Fatalf("permission denial audit did not enter: %v", workerContext.Err())
	}

	grantConnection, err := pool.Acquire(workerContext)
	if err != nil {
		t.Fatal(err)
	}
	grantTx, err := grantConnection.Begin(workerContext)
	if err != nil {
		grantConnection.Release()
		t.Fatal(err)
	}
	var grantPID int32
	if err := grantTx.QueryRow(workerContext, `SELECT pg_backend_pid()`).Scan(&grantPID); err != nil {
		_ = grantTx.Rollback(context.Background())
		grantConnection.Release()
		t.Fatal(err)
	}
	grantResult := make(chan error, 1)
	go func() {
		defer grantConnection.Release()
		_, grantErr := grantTx.Exec(workerContext, `INSERT INTO role_assignments(scope_id,user_id,role_id)
			VALUES($1,$2,$3)`, actor.ScopeID, actor.UserID, manageRoleID)
		if grantErr == nil {
			grantErr = grantTx.Commit(workerContext)
		} else {
			_ = grantTx.Rollback(context.Background())
		}
		grantResult <- grantErr
	}()
	waitNotificationControlIAMConflict091(t, pool, denialPID, grantPID, grantResult)
	select {
	case err := <-denialResult:
		t.Fatalf("permission denial returned before audit release and commit: %v", err)
	default:
	}
	close(releaseAudit)
	if err := <-denialResult; !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("permission denial after audit commit = %v, want permission denied", err)
	}
	assertNotificationControlDeniedAudit091(t, pool, actor, writeOperationChannelsUpdate, requestID, 1)
	if err := <-grantResult; err != nil {
		t.Fatalf("concurrent grant after denial commit: %v", err)
	}
	if _, err := store.UpdateChannels(t.Context(), actor, UpdateChannelsRequest{
		ExpectedRevision: 0, RequestID: requestID,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("same request after grant = %v, want invalid input", err)
	}
	assertNotificationControlDeniedAudit091(t, pool, actor, writeOperationChannelsUpdate, requestID, 1)
}

func TestNotificationControlDeniedAuditIdentityRedactionAndUniqueDefense091(t *testing.T) {
	pool := notificationControlPool(t)
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, func() time.Time { return controlTestNow }), func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	actor := seedControlActor(t, pool, "tenant")
	foreign := seedControlActor(t, pool, "tenant")
	for name, candidate := range map[string]Actor{
		"fake session":       {UserID: actor.UserID, ScopeID: actor.ScopeID, SessionID: uuid.New(), ScopeKind: "tenant"},
		"mismatched session": {UserID: foreign.UserID, ScopeID: actor.ScopeID, SessionID: actor.SessionID, ScopeKind: "tenant"},
	} {
		t.Run(name, func(t *testing.T) {
			requestID := "unverifiable-" + strings.ReplaceAll(name, " ", "-")
			_, err := store.UpdateSubscription(t.Context(), candidate, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
				ExpectedRevision: 0, EmailEnabled: true, RequestID: requestID,
			})
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("write error = %v, want unauthenticated", err)
			}
			var audits, receipts int
			if err := pool.QueryRow(t.Context(), `SELECT
				(SELECT count(*) FROM audit_events WHERE request_id=$1),
				(SELECT count(*) FROM notification_control_idempotency_receipts WHERE request_key=$1)`, requestID).Scan(&audits, &receipts); err != nil {
				t.Fatal(err)
			}
			if audits != 0 || receipts != 0 {
				t.Fatalf("unverifiable identity audits/receipts = %d/%d", audits, receipts)
			}
		})
	}

	requestID := "verifiable-revoked-session"
	if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='test' WHERE id=$1`, actor.SessionID, controlTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateSubscription(t.Context(), actor, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
		ExpectedRevision: 0, EmailEnabled: true, RequestID: requestID,
	}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revoked exact session = %v, want unauthenticated", err)
	}
	assertNotificationControlDeniedAudit091(t, pool, actor, writeOperationSubscriptionUpdate, requestID, 0)

	directID := "direct-denied-duplicate"
	event := audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: writeOperationSubscriptionUpdate,
		ResourceType: "notification_control", ResourceID: writeOperationSubscriptionUpdate,
		RequestID: directID, Result: "denied",
		Payload: map[string]any{"reason_code": "permission_denied", "operation": writeOperationSubscriptionUpdate},
	}
	logger := audit.NewWithClock(pool, func() time.Time { return controlTestNow })
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error { return logger.Append(t.Context(), tx, event) }); err != nil {
		t.Fatal(err)
	}
	err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error { return logger.Append(t.Context(), tx, event) })
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("direct duplicate error = %v, want unique violation", err)
	}
}

func TestNotificationControlPlatformWritesAuthenticateBeforeScopeDenial091(t *testing.T) {
	pool := notificationControlPool(t)
	store, err := NewStoreWithDependencies(
		pool,
		audit.NewWithClock(pool, func() time.Time { return controlTestNow }),
		func() time.Time { return controlTestNow },
	)
	if err != nil {
		t.Fatal(err)
	}
	valid := seedControlActor(t, pool, "tenant")
	fake := valid
	fake.SessionID = uuid.New()
	mismatched := valid
	mismatched.ScopeKind = "platform"
	revoked := seedControlActor(t, pool, "tenant")
	if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions
		SET revoked_at=$2,revocation_reason='platform-write-auth-test' WHERE id=$1`,
		revoked.SessionID, controlTestNow); err != nil {
		t.Fatal(err)
	}
	expired := seedControlActor(t, pool, "tenant")
	if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET expires_at=$2 WHERE id=$1`,
		expired.SessionID, controlTestNow); err != nil {
		t.Fatal(err)
	}

	actors := []struct {
		name       string
		actor      Actor
		wantErr    error
		wantAudits int
	}{
		{name: "valid", actor: valid, wantErr: ErrPermissionDenied, wantAudits: 1},
		{name: "fake", actor: fake, wantErr: ErrUnauthenticated},
		{name: "mismatched", actor: mismatched, wantErr: ErrUnauthenticated},
		{name: "revoked", actor: revoked, wantErr: ErrUnauthenticated},
		{name: "expired", actor: expired, wantErr: ErrUnauthenticated},
	}
	for _, test := range actors {
		t.Run(test.name, func(t *testing.T) {
			writes := []struct {
				name, operation string
				write           func(string) error
			}{
				{
					name: "channels", operation: writeOperationChannelsUpdate,
					write: func(requestID string) error {
						_, writeErr := store.UpdateChannels(t.Context(), test.actor, UpdateChannelsRequest{
							ExpectedRevision: 1, EmailEnabled: true, RequestID: requestID,
						})
						return writeErr
					},
				},
				{
					name: "template", operation: writeOperationTemplatePut,
					write: func(requestID string) error {
						_, writeErr := store.PutTemplate(t.Context(), test.actor,
							"announcement_published", 1, ChannelEmail,
							TemplateInput{Subject: "[公告] {{.title}}", Body: "{{.body}}", Variables: []string{"title", "body"}},
							requestID)
						return writeErr
					},
				},
			}
			for _, write := range writes {
				t.Run(write.name, func(t *testing.T) {
					requestID := "platform-write-auth-" + test.name + "-" + write.name
					if err := write.write(requestID); !errors.Is(err, test.wantErr) {
						t.Fatalf("write error = %v, want %v", err, test.wantErr)
					}
					assertNotificationControlDeniedAudit091(
						t, pool, test.actor, write.operation, requestID, test.wantAudits,
					)
					var receipts int
					if err := pool.QueryRow(t.Context(), `SELECT count(*)
						FROM notification_control_idempotency_receipts
						WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND request_key=$4`,
						test.actor.ScopeID, test.actor.UserID, write.operation, requestID,
					).Scan(&receipts); err != nil {
						t.Fatal(err)
					}
					if receipts != 0 {
						t.Fatalf("write receipts = %d, want 0", receipts)
					}
				})
			}
		})
	}
}

func TestNotificationControlTenantActiveFencePostgreSQL(t *testing.T) {
	pool := notificationControlPool(t)
	tenant := seedControlActor(t, pool, "tenant")
	platform := seedControlActor(t, pool, "platform", "system_configuration.read")
	store, err := NewStoreWithDependencies(
		pool,
		audit.NewWithClock(pool, func() time.Time { return controlTestNow }),
		func() time.Time { return controlTestNow },
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.GetSubscription(t.Context(), tenant, EventTypeAnnouncementPublished); err != nil {
		t.Fatalf("active tenant GET: %v", err)
	}
	if _, err := store.GetChannels(t.Context(), platform); err != nil {
		t.Fatalf("platform GET before tenant suspension: %v", err)
	}
	request := UpdateSubscriptionRequest{
		ExpectedRevision: 0, EmailEnabled: true, RequestID: "tenant-active-fence-replay",
	}
	if _, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, request); err != nil {
		t.Fatalf("active tenant PUT: %v", err)
	}

	var tenantID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, tenant.ScopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE tenants SET status='suspended' WHERE id=$1`, tenantID); err != nil {
		t.Fatal(err)
	}

	if _, err := store.GetSubscription(t.Context(), tenant, EventTypeAnnouncementPublished); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("suspended tenant GET = %v, want permission denied", err)
	}
	for range 2 {
		if _, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, request); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("suspended tenant completed replay = %v, want permission denied", err)
		}
	}
	fresh := UpdateSubscriptionRequest{
		ExpectedRevision: 1, EmailEnabled: false, RequestID: "tenant-active-fence-fresh",
	}
	for range 2 {
		if _, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, fresh); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("suspended tenant fresh PUT = %v, want permission denied", err)
		}
	}
	for _, requestID := range []string{request.RequestID, fresh.RequestID} {
		var denied int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
			WHERE scope_id=$1 AND actor_user_id=$2 AND action=$3 AND request_id=$4 AND result='denied'`,
			tenant.ScopeID, tenant.UserID, writeOperationSubscriptionUpdate, requestID).Scan(&denied); err != nil {
			t.Fatal(err)
		}
		if denied != 1 {
			t.Fatalf("denied audits for %q = %d, want 1", requestID, denied)
		}
	}
	if _, err := store.GetChannels(t.Context(), platform); err != nil {
		t.Fatalf("platform GET after tenant suspension: %v", err)
	}
}

func TestNotificationControlTenantActiveFenceLinearizationPostgreSQL(t *testing.T) {
	pool := notificationControlPool(t)

	t.Run("authorization first", func(t *testing.T) {
		actor := seedControlActor(t, pool, "tenant")
		var tenantID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, actor.ScopeID).Scan(&tenantID); err != nil {
			t.Fatal(err)
		}
		authorizer, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer authorizer.Rollback(t.Context())
		if err := authorize(t.Context(), authorizer, actor, "", controlTestNow); err != nil {
			t.Fatalf("authorize active tenant: %v", err)
		}

		suspender, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer suspender.Rollback(t.Context())
		if _, err := suspender.Exec(t.Context(), `SET LOCAL lock_timeout='100ms'`); err != nil {
			t.Fatal(err)
		}
		_, err = suspender.Exec(t.Context(), `UPDATE tenants SET status='suspended' WHERE id=$1`, tenantID)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
			t.Fatalf("suspend while authorization is open = %v, want lock timeout", err)
		}
		if err := suspender.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := authorizer.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `UPDATE tenants SET status='suspended' WHERE id=$1`, tenantID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("suspension first", func(t *testing.T) {
		actor := seedControlActor(t, pool, "tenant")
		var tenantID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, actor.ScopeID).Scan(&tenantID); err != nil {
			t.Fatal(err)
		}
		suspender, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer suspender.Rollback(t.Context())
		if _, err := suspender.Exec(t.Context(), `UPDATE tenants SET status='suspended' WHERE id=$1`, tenantID); err != nil {
			t.Fatal(err)
		}

		authorizer, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer authorizer.Rollback(t.Context())
		if _, err := authorizer.Exec(t.Context(), `SET LOCAL lock_timeout='100ms'`); err != nil {
			t.Fatal(err)
		}
		err = authorize(t.Context(), authorizer, actor, "", controlTestNow)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
			t.Fatalf("authorize while suspension is open = %v, want lock timeout", err)
		}
		if err := authorizer.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		if err := suspender.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}

		err = pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			return authorize(t.Context(), tx, actor, "", controlTestNow)
		})
		if !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("authorization after suspension commit = %v, want permission denied", err)
		}
	})
}

func TestChannelTemplateAndSubscriptionControlPostgreSQL(t *testing.T) {
	pool := notificationControlPool(t)
	platform := seedControlActor(t, pool, "platform", "system_configuration.read", "system_configuration.manage")
	tenant := seedControlActor(t, pool, "tenant")
	foreign := seedControlActor(t, pool, "tenant")
	store, err := NewStoreWithDependencies(pool, audit.New(pool), func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}

	channels, err := store.GetChannels(t.Context(), platform)
	if err != nil || channels.Revision != 1 || channels.SMSEnabled || channels.EmailEnabled || !channels.SMSSupported || !channels.EmailSupported {
		t.Fatalf("initial channels = %+v, %v", channels, err)
	}
	changed, err := store.UpdateChannels(t.Context(), platform, UpdateChannelsRequest{
		ExpectedRevision: 1, SMSEnabled: true, EmailEnabled: true, RequestID: "channels-enable-email",
	})
	if err != nil || !changed.Changed || changed.Revision != 2 || !changed.SMSEnabled || !changed.EmailEnabled || !changed.SMSSupported {
		t.Fatalf("changed channels = %+v, %v", changed, err)
	}
	committedReplay, err := store.UpdateChannels(t.Context(), platform, UpdateChannelsRequest{
		ExpectedRevision: 1, SMSEnabled: true, EmailEnabled: true, RequestID: "channels-enable-email",
	})
	if err != nil || committedReplay != changed {
		t.Fatalf("committed channel replay = %+v, %v, want %+v", committedReplay, err, changed)
	}
	if _, err := store.UpdateChannels(t.Context(), platform, UpdateChannelsRequest{
		ExpectedRevision: 1, SMSEnabled: false, EmailEnabled: false, RequestID: "channels-enable-email",
	}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("changed channel payload with same request key = %v", err)
	}
	replay, err := store.UpdateChannels(t.Context(), platform, UpdateChannelsRequest{
		ExpectedRevision: 2, SMSEnabled: true, EmailEnabled: true, RequestID: "channels-replay",
	})
	if err != nil || replay.Changed || replay.Revision != 2 {
		t.Fatalf("natural replay = %+v, %v", replay, err)
	}
	for name, revision := range map[string]int64{"stale": 1, "future": 3} {
		if _, err := store.UpdateChannels(t.Context(), platform, UpdateChannelsRequest{
			ExpectedRevision: revision, SMSEnabled: true, EmailEnabled: true, RequestID: "channels-" + name,
		}); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("channels %s no-change revision = %v", name, err)
		}
	}
	if _, err := store.UpdateChannels(t.Context(), platform, UpdateChannelsRequest{
		ExpectedRevision: 1, SMSEnabled: false, EmailEnabled: false, RequestID: "channels-conflict",
	}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("channels conflict = %v", err)
	}
	template := TemplateInput{Subject: "[公告] {{.title}}", Body: "{{.body}}", Variables: []string{"title", "body"}}
	created, err := store.PutTemplate(t.Context(), platform, "announcement_published", 1, ChannelEmail, template, "template-create")
	if err != nil || !created.Changed || !created.CreatedAt.Equal(controlTestNow) {
		t.Fatalf("create template = %+v, %v", created, err)
	}
	committedTemplateReplay, err := store.PutTemplate(
		t.Context(), platform, "announcement_published", 1, ChannelEmail, template, "template-create",
	)
	if err != nil || notificationControlResultJSON(t, committedTemplateReplay) != notificationControlResultJSON(t, created) {
		t.Fatalf("committed template replay = %+v, %v, want %+v", committedTemplateReplay, err, created)
	}
	changedTemplate := template
	changedTemplate.Subject = "changed {{.title}}"
	if _, err := store.PutTemplate(
		t.Context(), platform, "announcement_published", 1, ChannelEmail, changedTemplate, "template-create",
	); !errors.Is(err, ErrTemplateVersionConflict) {
		t.Fatalf("changed template payload with same request key = %v", err)
	}
	templateReplay, err := store.PutTemplate(t.Context(), platform, "announcement_published", 1, ChannelEmail, template, "template-replay")
	if err != nil || templateReplay.Changed {
		t.Fatalf("template replay = %+v, %v", templateReplay, err)
	}
	conflicting := template
	conflicting.Subject = "private-different-subject {{.title}}"
	if _, err := store.PutTemplate(t.Context(), platform, "announcement_published", 1, ChannelEmail, conflicting, "template-conflict"); !errors.Is(err, ErrTemplateVersionConflict) {
		t.Fatalf("template conflict = %v", err)
	}
	createdV2, err := store.PutTemplate(t.Context(), platform, "announcement_published", 2, ChannelEmail,
		TemplateInput{Subject: "[公告 v2] {{.title}}", Body: "{{.body}}", Variables: []string{"title", "body"}}, "template-create-v2")
	if err != nil || !createdV2.Changed || createdV2.Version != 2 {
		t.Fatalf("create template v2 = %+v, %v", createdV2, err)
	}
	smsTemplate := TemplateInput{Body: "短信：{{.title}}\n{{.body}}", Variables: []string{"title", "body"}}
	createdSMS, err := store.PutTemplate(t.Context(), platform, "announcement_published", 1, ChannelSMS,
		smsTemplate, "template-create-sms")
	if err != nil || !createdSMS.Changed || createdSMS.Channel != ChannelSMS || createdSMS.Subject != "" {
		t.Fatalf("create SMS template = %+v, %v", createdSMS, err)
	}
	invalidAnnouncementTemplates := []struct {
		name  string
		input TemplateInput
	}{
		{name: "missing variable", input: TemplateInput{Subject: "公告", Body: "{{.body}}", Variables: []string{"body"}}},
		{name: "extra variable", input: TemplateInput{Subject: "{{.title}}", Body: "{{.body}}{{.foo}}", Variables: []string{"title", "body", "foo"}}},
		{name: "unknown variable", input: TemplateInput{Subject: "{{.foo}}", Body: "公告", Variables: []string{"foo"}}},
		{name: "maximum context overflow", input: TemplateInput{Subject: "{{.title}}", Body: "{{.body}}{{.body}}", Variables: []string{"title", "body"}}},
		{name: "conditional branch", input: TemplateInput{
			Subject: `{{if eq .title "trigger"}}{{.body}}{{else}}{{.title}}{{end}}`,
			Body:    "{{.body}}", Variables: []string{"title", "body"},
		}},
		{name: "body transform", input: TemplateInput{
			Subject: "{{.title}}", Body: "{{urlquery .body}}", Variables: []string{"title", "body"},
		}},
	}
	for index, test := range invalidAnnouncementTemplates {
		if _, err := store.PutTemplate(t.Context(), platform, "announcement_published", int64(index+3), ChannelEmail,
			test.input, "template-invalid-"+fmt.Sprint(index)); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s = %v", test.name, err)
		}
	}
	var invalidTemplateCount int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_templates
		WHERE template_id='announcement_published' AND version >= 3`).Scan(&invalidTemplateCount); err != nil {
		t.Fatal(err)
	}
	if invalidTemplateCount != 0 {
		t.Fatalf("invalid announcement templates persisted = %d", invalidTemplateCount)
	}
	genericTemplate, err := store.PutTemplate(t.Context(), platform, "generic_event", 1, ChannelEmail,
		TemplateInput{Subject: "{{.foo}}", Body: "generic", Variables: []string{"foo"}}, "generic-template-create")
	if err != nil || !genericTemplate.Changed {
		t.Fatalf("generic template = %+v, %v", genericTemplate, err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		refs, err := ActiveTemplateRefs(t.Context(), tx, "announcement_published")
		if err != nil {
			return err
		}
		if len(refs) != 2 || refs[notification.ChannelEmail].Version != 2 ||
			refs[notification.ChannelEmail].ID != "announcement_published" ||
			refs[notification.ChannelSMS].Version != 1 {
			t.Fatalf("active template refs = %+v", refs)
		}
		missing, err := ActiveTemplateRefs(t.Context(), tx, "missing_template")
		if err != nil || len(missing) != 0 {
			t.Fatalf("missing active template refs = %+v, %v", missing, err)
		}
		generic, err := ActiveTemplateRefs(t.Context(), tx, "generic_event")
		if err != nil || len(generic) != 1 || generic[notification.ChannelEmail].Version != 1 {
			t.Fatalf("generic active template refs = %+v, %v", generic, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	poisonedTemplates := []TemplateInput{
		{Subject: "{{.foo}}", Body: "poison", Variables: []string{"foo"}},
		{Subject: "{{.title}}", Body: "{{.body}}{{.body}}", Variables: []string{"title", "body"}},
		{
			Subject: `{{if eq .title "trigger"}}{{.body}}{{else}}{{.title}}{{end}}`,
			Body:    "{{.body}}", Variables: []string{"title", "body"},
		},
	}
	for index, input := range poisonedTemplates {
		version := int64(100 + index)
		if _, err := pool.Exec(t.Context(), `INSERT INTO notification_templates(
			template_id,version,channel,subject,body,variables,created_at
		) VALUES('announcement_published',$1,'email',$2,$3,$4,$5)`,
			version, input.Subject, input.Body, input.Variables, controlTestNow); err != nil {
			t.Fatal(err)
		}
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			_, err := ActiveTemplateRefs(t.Context(), tx, "announcement_published")
			return err
		}); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("poisoned active template v%d = %v", version, err)
		}
	}
	unavailable, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := unavailable.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := ActiveTemplateRefs(t.Context(), unavailable, "announcement_published"); err == nil {
		t.Fatal("active template selection must fail when its transaction is unavailable")
	}

	subscription, err := store.GetSubscription(t.Context(), tenant, EventTypeAnnouncementPublished)
	// fix-notifsub: a member who never chose has every reminder on.
	if err != nil || subscription.Revision != 0 || !subscription.SMSEnabled || !subscription.EmailEnabled || !subscription.SMSSupported {
		t.Fatalf("default subscription = %+v, %v", subscription, err)
	}
	// Writing the default back is a no-op: no row, revision stays 0.
	if same, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
		ExpectedRevision: 0, SMSEnabled: true, EmailEnabled: true, RequestID: "subscription-default",
	}); err != nil || same.Changed || same.Revision != 0 {
		t.Fatalf("default write-back = %+v, %v", same, err)
	}
	updated, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
		ExpectedRevision: 0, SMSEnabled: true, EmailEnabled: false, RequestID: "subscription-enable",
	})
	if err != nil || !updated.Changed || updated.Revision != 1 || !updated.SMSEnabled || updated.EmailEnabled || !updated.SMSSupported {
		t.Fatalf("subscription update = %+v, %v", updated, err)
	}
	committedSubscriptionReplay, err := store.UpdateSubscription(
		t.Context(), tenant, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
			ExpectedRevision: 0, SMSEnabled: true, EmailEnabled: false, RequestID: "subscription-enable",
		},
	)
	if err != nil || committedSubscriptionReplay != updated {
		t.Fatalf("committed subscription replay = %+v, %v, want %+v", committedSubscriptionReplay, err, updated)
	}
	if _, err := store.UpdateSubscription(
		t.Context(), tenant, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
			ExpectedRevision: 0, SMSEnabled: false, EmailEnabled: false, RequestID: "subscription-enable",
		},
	); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("changed subscription payload with same request key = %v", err)
	}
	unchanged, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
		ExpectedRevision: 1, SMSEnabled: true, EmailEnabled: false, RequestID: "subscription-replay",
	})
	if err != nil || unchanged.Changed || unchanged.Revision != 1 {
		t.Fatalf("subscription replay = %+v, %v", unchanged, err)
	}
	if _, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
		ExpectedRevision: 0, SMSEnabled: false, EmailEnabled: false, RequestID: "subscription-conflict",
	}); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("subscription conflict = %v", err)
	}
	for name, revision := range map[string]int64{"stale": 0, "future": 2} {
		if _, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
			ExpectedRevision: revision, SMSEnabled: true, EmailEnabled: false, RequestID: "subscription-" + name,
		}); !errors.Is(err, ErrVersionConflict) {
			t.Fatalf("subscription %s no-change revision = %v", name, err)
		}
	}
	if value, err := store.GetSubscription(t.Context(), platform, EventTypeAnnouncementPublished); err != nil || value.Revision != 0 {
		t.Fatalf("platform self subscription read = %+v, %v", value, err)
	}
	if value, err := store.UpdateSubscription(t.Context(), platform, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
		ExpectedRevision: 0, SMSEnabled: true, EmailEnabled: false, RequestID: "platform-subscription-sms",
	}); err != nil || !value.SMSEnabled || value.EmailEnabled || value.Revision != 1 || !value.Changed {
		t.Fatalf("platform self SMS subscription = %+v, %v", value, err)
	}
	crossTenant := tenant
	crossTenant.ScopeID = foreign.ScopeID
	if _, err := store.GetSubscription(t.Context(), crossTenant, EventTypeAnnouncementPublished); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("cross-tenant read = %v", err)
	}

	if _, err := pool.Exec(t.Context(), `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`,
		platform.ScopeID, platform.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateChannels(t.Context(), platform, UpdateChannelsRequest{
		ExpectedRevision: 2, SMSEnabled: false, EmailEnabled: false, RequestID: "channels-revoked",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("live permission revoke = %v", err)
	}
	if _, err := store.UpdateChannels(t.Context(), platform, UpdateChannelsRequest{
		ExpectedRevision: 2, SMSEnabled: true, EmailEnabled: true, RequestID: "channels-revoked-sms",
	}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("live permission revoke before unsupported channel = %v", err)
	}
	if _, err := store.PutTemplate(t.Context(), platform, "announcement_published", 2, ChannelSMS,
		TemplateInput{Body: "{{.body}}", Variables: []string{"body"}}, "template-revoked-sms"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("live permission revoke before unsupported template = %v", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='test'
		WHERE id=$1`, tenant.SessionID, controlTestNow); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
		ExpectedRevision: 1, SMSEnabled: true, EmailEnabled: true, RequestID: "subscription-revoked-sms",
	}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("live session revoke before unsupported channel = %v", err)
	}
	if _, err := store.GetSubscription(t.Context(), tenant, EventTypeAnnouncementPublished); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("live session revoke = %v", err)
	}

	var payloads string
	if err := pool.QueryRow(t.Context(), `SELECT string_agg(payload::text,' ') FROM audit_events
		WHERE action IN ('notification.channels.update','notification.template.create','notification.subscription.update')`).Scan(&payloads); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private-different-subject", "[公告]", "{{.body}}", "@example.test", "provider", "credential"} {
		if strings.Contains(payloads, forbidden) {
			t.Fatalf("audit payload leaked %q: %s", forbidden, payloads)
		}
	}
	for _, requestID := range []string{"channels-enable-email", "template-create", "subscription-enable"} {
		var count int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE request_id=$1`, requestID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("audit events for %q = %d, want 1", requestID, count)
		}
	}
}

func TestControlledChannelsAndSubscriptionReachEmailAndSMSProviders(t *testing.T) {
	pool := notificationControlPool(t)
	platform := seedControlActor(t, pool, "platform", permissionRead, permissionManage)
	tenant := seedControlActor(t, pool, "tenant")
	control, err := NewStoreWithDependencies(pool, audit.New(pool), func() time.Time { return controlTestNow })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := control.UpdateChannels(t.Context(), platform, UpdateChannelsRequest{
		ExpectedRevision: 1, SMSEnabled: true, EmailEnabled: true, RequestID: "provider-channels",
	}); err != nil {
		t.Fatal(err)
	}
	refs := map[notification.Channel]notification.TemplateRef{
		notification.ChannelEmail: {ID: announcementPublishedTemplateID, Version: 1, Channel: notification.ChannelEmail},
		notification.ChannelSMS:   {ID: announcementPublishedTemplateID, Version: 1, Channel: notification.ChannelSMS},
	}
	if _, err := control.PutTemplate(t.Context(), platform, announcementPublishedTemplateID, 1, ChannelEmail,
		TemplateInput{Subject: "[公告] {{.title}}", Body: "{{.body}}", Variables: []string{"title", "body"}},
		"provider-email-template"); err != nil {
		t.Fatal(err)
	}
	if _, err := control.PutTemplate(t.Context(), platform, announcementPublishedTemplateID, 1, ChannelSMS,
		TemplateInput{Body: "{{.title}}\n{{.body}}", Variables: []string{"title", "body"}},
		"provider-sms-template"); err != nil {
		t.Fatal(err)
	}
	if _, err := control.UpdateSubscription(t.Context(), tenant, EventTypeAnnouncementPublished,
		UpdateSubscriptionRequest{
			ExpectedRevision: 0, SMSEnabled: true, EmailEnabled: true, RequestID: "provider-subscription",
		}); err != nil {
		t.Fatal(err)
	}

	notificationStore, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	emailProvider := &controlledNotificationProvider{messages: make(chan notificationruntime.ProviderMessage, 1)}
	smsProvider := &controlledNotificationProvider{messages: make(chan notificationruntime.ProviderMessage, 1)}
	config := notificationruntime.DefaultRuntimeConfig()
	config.Enabled = true
	config.Worker.BatchSize = 2
	config.Worker.LeaseDuration = time.Second
	config.Worker.LeaseSafetyMargin = 100 * time.Millisecond
	config.Worker.BaseDelay = 10 * time.Millisecond
	config.Worker.MaxDelay = 20 * time.Millisecond
	config.RecoveryTemplates = refs
	config.IdleWait = 5 * time.Millisecond
	config.ErrorBackoffBase = 5 * time.Millisecond
	config.ErrorBackoffMax = 20 * time.Millisecond
	config.SendTimeout = time.Second
	config.ShutdownTimeout = time.Second
	runtime, err := notificationruntime.Build(config, notificationruntime.Dependencies{
		Store: notificationStore, MemberContacts: controlledContactResolver{},
		Providers: map[notification.Channel]notificationruntime.ProviderTransport{
			notification.ChannelEmail: emailProvider,
			notification.ChannelSMS:   smsProvider,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	runContext, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- runtime.Run(runContext) }()

	result, err := notificationStore.Enqueue(t.Context(), notification.EnqueueRequest{
		ScopeID: tenant.ScopeID, RecipientID: tenant.UserID, SourceEventID: "controlled-provider-announcement",
		EventType: EventTypeAnnouncementPublished, Policy: notification.DeliveryTenantSubscribed,
		Templates: refs,
		Contexts: map[notification.Channel]notification.TemplateContext{
			notification.ChannelEmail: {"title": notification.PublicValue("维护"), "body": notification.PublicValue("正文")},
			notification.ChannelSMS:   {"title": notification.PublicValue("维护"), "body": notification.PublicValue("正文")},
		},
		ActorUserID: &tenant.UserID, AuditRequestID: "controlled-provider-announcement",
	})
	if err != nil || len(result.Deliveries) != 2 {
		t.Fatalf("enqueue result = %+v, %v", result, err)
	}
	for channel, calls := range map[notification.Channel]<-chan notificationruntime.ProviderMessage{
		notification.ChannelEmail: emailProvider.messages,
		notification.ChannelSMS:   smsProvider.messages,
	} {
		select {
		case message := <-calls:
			if message.Channel != channel || message.IdempotencyKey == "" || message.AttemptNumber != 1 {
				t.Fatalf("%s provider message = %+v", channel, message)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s provider was not called", channel)
		}
	}
	// The provider is called before the worker settles its answer; stopping the runtime
	// right away would turn an in-flight accepted send into unknown, so wait for both
	// deliveries to leave dispatching first.
	settled := false
	for deadline := time.Now().Add(5 * time.Second); !settled && time.Now().Before(deadline); {
		page, err := control.ListDeliveryLogs(t.Context(), platform, DeliveryLogQuery{
			ScopeID: tenant.ScopeID.String(), Limit: "100",
		})
		if err != nil {
			t.Fatal(err)
		}
		settled = len(page.Items) == 2
		for _, item := range page.Items {
			settled = settled && item.State != "dispatching" && item.State != "pending"
		}
		if !settled {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !settled {
		t.Fatal("provider answers were not settled")
	}
	cancelRun()
	if err := <-runDone; err != nil {
		t.Fatalf("runtime run = %v", err)
	}
	if err := runtime.Close(t.Context()); err != nil {
		t.Fatalf("runtime close = %v", err)
	}
	page, err := control.ListDeliveryLogs(t.Context(), platform, DeliveryLogQuery{
		ScopeID: tenant.ScopeID.String(), Limit: "100",
	})
	if err != nil || len(page.Items) != 2 || page.NextCursor != "" {
		t.Fatalf("delivery page = %+v, %v", page, err)
	}
	for _, item := range page.Items {
		if item.ScopeID != tenant.ScopeID || item.State != "accepted" || item.AttemptCount != 1 ||
			item.Provider == nil || item.FailureCode != nil || item.TemplateID != announcementPublishedTemplateID {
			t.Fatalf("delivery item = %+v", item)
		}
		attempts, err := control.ListDeliveryAttempts(t.Context(), platform, item.OutboxID.String())
		if err != nil || attempts.OutboxID != item.OutboxID || len(attempts.Items) != 1 ||
			attempts.Items[0].Outcome != "accepted" || attempts.Items[0].FailureCode != nil {
			t.Fatalf("delivery attempts = %+v, %v", attempts, err)
		}
	}
}

func TestTemplateVersionConcurrentWritersHaveOneWinner(t *testing.T) {
	pool := notificationControlPool(t)
	actor := seedControlActor(t, pool, "platform", "system_configuration.read", "system_configuration.manage")
	store, _ := NewStoreWithDependencies(pool, audit.New(pool), func() time.Time { return controlTestNow })
	inputs := []TemplateInput{
		{Subject: "first {{.title}}", Body: "{{.body}}", Variables: []string{"title", "body"}},
		{Subject: "second {{.title}}", Body: "{{.body}}", Variables: []string{"title", "body"}},
	}
	start := make(chan struct{})
	errorsSeen := make(chan error, 2)
	var wg sync.WaitGroup
	for index := range inputs {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			_, err := store.PutTemplate(context.Background(), actor, "announcement_published", 2, ChannelEmail, inputs[index], "template-race")
			errorsSeen <- err
		}(index)
	}
	close(start)
	wg.Wait()
	close(errorsSeen)
	var success, conflict int
	for err := range errorsSeen {
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrTemplateVersionConflict):
			conflict++
		default:
			t.Fatalf("unexpected race error = %v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("race outcomes success=%d conflict=%d", success, conflict)
	}
}

type notificationControlFailingAuditor struct{ err error }

func (auditor notificationControlFailingAuditor) Append(context.Context, pgx.Tx, audit.Event) error {
	return auditor.err
}

type notificationControlBlockingAuditor091 struct {
	delegate AuditAppender
	entered  chan<- int32
	release  <-chan struct{}
}

func (auditor *notificationControlBlockingAuditor091) Append(
	ctx context.Context,
	tx pgx.Tx,
	event audit.Event,
) error {
	if err := auditor.delegate.Append(ctx, tx, event); err != nil {
		return err
	}
	if event.Result != "denied" {
		return nil
	}
	var pid int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		return err
	}
	select {
	case auditor.entered <- pid:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-auditor.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func waitNotificationControlIAMConflict091(
	t *testing.T,
	pool *pgxpool.Pool,
	denialPID, grantPID int32,
	grantReturned <-chan error,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		select {
		case err := <-grantReturned:
			t.Fatalf("IAM grant returned before the denial transaction committed: %v", err)
		default:
		}
		var exactBlocker, grantInsert bool
		err := pool.QueryRow(ctx, `SELECT
			$1 = ANY(pg_blocking_pids($2)),
			EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$2
				AND query LIKE '%INSERT INTO role_assignments%')`, denialPID, grantPID).
			Scan(&exactBlocker, &grantInsert)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			t.Fatal(err)
		}
		if exactBlocker && grantInsert {
			return
		}
	}
	t.Fatal("IAM grant did not expose the denial transaction as its exact blocker")
}

func assertNotificationControlDeniedAudit091(
	t *testing.T,
	pool *pgxpool.Pool,
	actor Actor,
	action, requestID string,
	want int,
) {
	t.Helper()
	var exact, total int
	if err := pool.QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE result='denied'
			AND resource_type='notification_control' AND resource_id=$3
			AND payload=jsonb_build_object('reason_code','permission_denied','operation',$3::text)),
		count(*)
		FROM audit_events WHERE scope_id=$1 AND actor_user_id=$2 AND action=$3 AND request_id=$4`,
		actor.ScopeID, actor.UserID, action, requestID).Scan(&exact, &total); err != nil {
		t.Fatal(err)
	}
	if exact != want || total != want {
		t.Fatalf("denied audit %s/%s exact/total=%d/%d want=%d/%d",
			action, requestID, exact, total, want, want)
	}
}

func notificationControlWriteCases(t *testing.T, pool *pgxpool.Pool, prefix string) []notificationControlWriteCase {
	t.Helper()
	platformActor := seedControlActor(t, pool, "platform", "system_configuration.read", "system_configuration.manage")
	channelsActor := platformActor
	templateActor := platformActor
	subscriptionActor := seedControlActor(t, pool, "tenant")

	platformAuthority := func(actor Actor) (func(*testing.T), func(*testing.T)) {
		var roleID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT role_id FROM role_assignments
			WHERE scope_id=$1 AND user_id=$2`, actor.ScopeID, actor.UserID).Scan(&roleID); err != nil {
			t.Fatal(err)
		}
		return func(t *testing.T) {
				t.Helper()
				if _, err := pool.Exec(t.Context(), `DELETE FROM role_assignments
				WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, actor.ScopeID, actor.UserID, roleID); err != nil {
					t.Fatal(err)
				}
			}, func(t *testing.T) {
				t.Helper()
				if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id)
				VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, actor.ScopeID, actor.UserID, roleID); err != nil {
					t.Fatal(err)
				}
			}
	}
	channelsRevoke, channelsGrant := platformAuthority(channelsActor)
	templateRevoke, templateGrant := platformAuthority(templateActor)
	subscriptionRevoke := func(t *testing.T) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='suspended'
			WHERE scope_id=$1 AND user_id=$2`, subscriptionActor.ScopeID, subscriptionActor.UserID); err != nil {
			t.Fatal(err)
		}
	}
	subscriptionGrant := func(t *testing.T) {
		t.Helper()
		if _, err := pool.Exec(t.Context(), `UPDATE memberships SET status='active'
			WHERE scope_id=$1 AND user_id=$2`, subscriptionActor.ScopeID, subscriptionActor.UserID); err != nil {
			t.Fatal(err)
		}
	}

	return []notificationControlWriteCase{
		{
			name: "channels", operation: writeOperationChannelsUpdate,
			successAction: "notification.channels.update", requestID: prefix + "-channels",
			actor: channelsActor, denialErr: ErrPermissionDenied, conflictErr: ErrVersionConflict,
			write: func(ctx context.Context, store *Store, changed bool, requestID string) (any, error) {
				return store.UpdateChannels(ctx, channelsActor, UpdateChannelsRequest{
					ExpectedRevision: 1, EmailEnabled: !changed, RequestID: requestID,
				})
			},
			revoke: channelsRevoke, grant: channelsGrant,
			assertRollback: func(t *testing.T) {
				var revision int64
				var enabled bool
				if err := pool.QueryRow(t.Context(), `SELECT revision,email_enabled FROM notification_channel_settings WHERE singleton`).Scan(&revision, &enabled); err != nil {
					t.Fatal(err)
				}
				if revision != 1 || enabled {
					t.Fatalf("channels committed after audit failure: revision=%d enabled=%t", revision, enabled)
				}
			},
		},
		{
			name: "template", operation: writeOperationTemplatePut,
			successAction: "notification.template.create", requestID: prefix + "-template",
			actor: templateActor, denialErr: ErrPermissionDenied, conflictErr: ErrTemplateVersionConflict,
			write: func(ctx context.Context, store *Store, changed bool, requestID string) (any, error) {
				subject := "[公告] {{.title}}"
				if changed {
					subject = "[变更] {{.title}}"
				}
				return store.PutTemplate(ctx, templateActor, "announcement_published", 1, ChannelEmail,
					TemplateInput{Subject: subject, Body: "{{.body}}", Variables: []string{"title", "body"}}, requestID)
			},
			revoke: templateRevoke, grant: templateGrant,
			assertRollback: func(t *testing.T) {
				var count int
				if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_templates
					WHERE template_id='announcement_published' AND version=1 AND channel='email'`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("template rows after audit failure = %d", count)
				}
			},
		},
		{
			name: "subscription", operation: writeOperationSubscriptionUpdate,
			successAction: "notification.subscription.update", requestID: prefix + "-subscription",
			actor: subscriptionActor, denialErr: ErrPermissionDenied, conflictErr: ErrVersionConflict,
			write: func(ctx context.Context, store *Store, changed bool, requestID string) (any, error) {
				return store.UpdateSubscription(ctx, subscriptionActor, EventTypeAnnouncementPublished, UpdateSubscriptionRequest{
					ExpectedRevision: 0, EmailEnabled: !changed, RequestID: requestID,
				})
			},
			revoke: subscriptionRevoke, grant: subscriptionGrant,
			assertRollback: func(t *testing.T) {
				var count int
				if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_subscriptions
					WHERE scope_id=$1 AND user_id=$2 AND event_type=$3`, subscriptionActor.ScopeID,
					subscriptionActor.UserID, EventTypeAnnouncementPublished).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("subscription rows after audit failure = %d", count)
				}
			},
		},
	}
}

func notificationControlResultJSON(t *testing.T, result any) string {
	t.Helper()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func assertNotificationControlChangedResult(t *testing.T, result any) {
	t.Helper()
	switch value := result.(type) {
	case ChannelSettings:
		if !value.Changed || value.Revision != 2 || !value.EmailEnabled {
			t.Fatalf("channel result = %+v", value)
		}
	case Template:
		if !value.Changed || value.Version != 1 || value.TemplateID != "announcement_published" {
			t.Fatalf("template result = %+v", value)
		}
	case Subscription:
		if !value.Changed || value.Revision != 1 || !value.EmailEnabled {
			t.Fatalf("subscription result = %+v", value)
		}
	default:
		t.Fatalf("unexpected notification result %T", result)
	}
}

func notificationControlReceiptFacts(t *testing.T, pool *pgxpool.Pool, test notificationControlWriteCase) string {
	t.Helper()
	var facts string
	if err := pool.QueryRow(t.Context(), `SELECT concat_ws('|',id::text,actor_scope_id::text,
		actor_user_id::text,operation,request_key,encode(request_digest,'hex'),response_body::text,
		created_at::text,completed_at::text) FROM notification_control_idempotency_receipts
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND request_key=$4`,
		test.actor.ScopeID, test.actor.UserID, test.operation, test.requestID).Scan(&facts); err != nil {
		t.Fatal(err)
	}
	return facts
}

func assertNotificationControlReceiptAuditIdentity(
	t *testing.T,
	pool *pgxpool.Pool,
	test notificationControlWriteCase,
	wantReceipts, wantSuccess, wantDenied int,
) {
	t.Helper()
	var receipts, success, denied, total int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM notification_control_idempotency_receipts
		 WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND request_key=$4),
		(SELECT count(*) FROM audit_events
		 WHERE scope_id=$1 AND actor_user_id=$2 AND action=$5 AND request_id=$4 AND result='success'),
		(SELECT count(*) FROM audit_events
		 WHERE scope_id=$1 AND actor_user_id=$2 AND action=$3 AND request_id=$4 AND result='denied'
		   AND payload=jsonb_build_object('reason_code',$6::text,'operation',$3::text)),
		(SELECT count(*) FROM audit_events WHERE request_id=$4)`, test.actor.ScopeID, test.actor.UserID,
		test.operation, test.requestID, test.successAction, notificationControlDenialReason(test.denialErr)).Scan(
		&receipts, &success, &denied, &total,
	); err != nil {
		t.Fatal(err)
	}
	if receipts != wantReceipts || success != wantSuccess || denied != wantDenied || total != wantSuccess+wantDenied {
		t.Fatalf("%s receipt/success/denied/total=%d/%d/%d/%d want=%d/%d/%d/%d", test.name,
			receipts, success, denied, total, wantReceipts, wantSuccess, wantDenied, wantSuccess+wantDenied)
	}
}

func notificationControlDenialReason(err error) string {
	if errors.Is(err, ErrUnauthenticated) {
		return "unauthenticated"
	}
	return "permission_denied"
}

func notificationControlPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "notification_control_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^notification_control_[a-f0-9]{32}$`).MatchString(schema) {
		t.Fatalf("unsafe schema %q", schema)
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	// 同生产 database.Open 的连接池上限（订阅页并发用例依赖它）；不走
	// TEST_DATABASE_URL 的 pool_max_conns：pgx.Connect/psql 不认这个参数。
	config.MaxConns = 20
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, stop := databasetest.CleanupContext()
		defer stop()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	return pool
}

func seedControlActor(t *testing.T, pool *pgxpool.Pool, kind string, permissions ...string) Actor {
	t.Helper()
	scopeID := uuid.New()
	var tenantID *uuid.UUID
	if kind == "tenant" {
		value := uuid.New()
		tenantID = &value
		if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, value, "Notification tenant "+value.String()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,$2,$3)`, scopeID, kind, tenantID); err != nil {
		t.Fatal(err)
	}
	return seedControlMember(t, pool, scopeID, kind, permissions...)
}

// seedControlMember adds a user with its own role and session to an existing
// scope (the platform scope is unique: access_scopes_single_platform_idx).
func seedControlMember(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, kind string, permissions ...string) Actor {
	t.Helper()
	userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New()
	roleName := "notification-role-" + strings.ReplaceAll(roleID.String(), "-", "")
	username := "notification-" + strings.ReplaceAll(userID.String(), "-", "")
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash,email)
		VALUES($1,$2,'Notification Actor','unused',$3)`, userID, username, username+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,$3,'Notification control test role',true)`, roleID, scopeID, roleName); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scopeID, userID, roleID); err != nil {
		t.Fatal(err)
	}
	for _, permission := range permissions {
		if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permission); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(sessionID[:])
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), userID, scopeID, digest[:], controlTestNow.Add(-time.Hour), controlTestNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return Actor{UserID: userID, ScopeID: scopeID, SessionID: sessionID, ScopeKind: kind}
}
