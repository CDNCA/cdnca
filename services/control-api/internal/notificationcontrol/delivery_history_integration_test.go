package notificationcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type historyTestSender struct{ retry, unknown uuid.UUID }

func (sender historyTestSender) Send(_ context.Context, attempt notification.DeliveryAttempt) notification.SendResult {
	if attempt.OutboxID == sender.unknown {
		return notification.SendResult{Disposition: notification.SendUnknown, Provider: "history-test"}
	}
	if attempt.OutboxID == sender.retry {
		if attempt.AttemptNumber == 1 {
			return notification.SendResult{Failure: &notification.Failure{Class: notification.FailureTemporary, Code: "provider_unavailable"}}
		}
		return notification.SendResult{Disposition: notification.SendAccepted, Provider: "history-test", ProviderDeliveryID: "private-provider-delivery"}
	}
	return notification.SendResult{Disposition: notification.SendDelivered, Provider: "history-test"}
}

func (historyTestSender) Dispatch(context.Context, notification.AnonymousDeliveryAttempt) notification.AnonymousDispatchResult {
	return notification.AnonymousDispatchResult{Disposition: notification.AnonymousDispatchDelivered, Provider: "history-test"}
}

func TestDeliveryHistoryPostgreSQLFactsFiltersAuthorizationAndRedaction(t *testing.T) {
	pool := notificationControlPool(t)
	admin := seedControlActor(t, pool, "platform", permissionRead, permissionManage)
	denied := Actor{ScopeID: admin.ScopeID, UserID: uuid.New(), SessionID: uuid.New(), ScopeKind: "platform"}
	digest := sha256.Sum256(denied.SessionID[:])
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'history-denied','History denied','unused');
		INSERT INTO memberships(scope_id,user_id) VALUES($2,$1);
		INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		 VALUES($3,$3,$1,$2,$4,clock_timestamp(),clock_timestamp()+interval '1 hour')`,
		pgx.QueryExecModeSimpleProtocol, denied.UserID, denied.ScopeID, denied.SessionID, digest[:]); err != nil {
		t.Fatal(err)
	}
	tenantA, tenantB := seedControlActor(t, pool, "tenant"), seedControlActor(t, pool, "tenant")
	if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	control, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	deliveries, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := deliveries.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true, SMS: true}); err != nil {
		t.Fatal(err)
	}
	refs := map[notification.Channel]notification.TemplateRef{}
	for _, channel := range []notification.Channel{notification.ChannelEmail, notification.ChannelSMS} {
		ref := notification.TemplateRef{ID: "history_test", Version: 1, Channel: channel}
		definition := notification.TemplateDefinition{Ref: ref, Body: "private-history-body", Variables: []string{}}
		if channel == notification.ChannelEmail {
			definition.Subject = "private-history-title"
		}
		if err := deliveries.SaveTemplate(t.Context(), definition); err != nil {
			t.Fatal(err)
		}
		refs[channel] = ref
	}
	enqueue := func(actor Actor, source string, channel notification.Channel) notification.EnqueueResult {
		t.Helper()
		if err := deliveries.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: channel == notification.ChannelEmail, SMS: channel == notification.ChannelSMS}); err != nil {
			t.Fatal(err)
		}
		result, err := deliveries.Enqueue(t.Context(), notification.EnqueueRequest{
			ScopeID: actor.ScopeID, RecipientID: actor.UserID, SourceEventID: source, EventType: EventTypeAnnouncementPublished,
			Policy: notification.DeliverySystemRequired, Templates: map[notification.Channel]notification.TemplateRef{channel: refs[channel]},
			ActorUserID: &actor.UserID, AuditRequestID: source,
		})
		if err != nil || len(result.Deliveries) != 1 {
			t.Fatalf("enqueue=%+v err=%v", result, err)
		}
		return result
	}
	retry := enqueue(tenantA, "history-retry", notification.ChannelEmail)
	unknown := enqueue(tenantA, "history-unknown", notification.ChannelSMS)
	foreign := enqueue(tenantB, "history-foreign", notification.ChannelEmail)
	var anonymous notification.EnqueueResult
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var err error
		anonymous, err = deliveries.EnqueueDispatchTx(t.Context(), tx, notification.DispatchEnqueueRequest{
			ScopeID: tenantA.ScopeID, SourceEventID: "history-anonymous", AnonymousDispatchReference: uuid.New(),
			EventType:      notification.EventTypeAccountRecovery,
			Templates:      map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: refs[notification.ChannelEmail]},
			AuditRequestID: "history-anonymous",
		})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := deliveries.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true, SMS: true}); err != nil {
		t.Fatal(err)
	}
	sender := historyTestSender{retry: retry.Deliveries[0].OutboxID, unknown: unknown.Deliveries[0].OutboxID}
	config := notification.DefaultWorkerConfig()
	config.BatchSize, config.MaxAttempts = 4, 2
	config.BaseDelay, config.MaxDelay = time.Hour, time.Hour
	worker, err := notification.NewWorkerWithAnonymousDispatcher(deliveries, sender, sender, config)
	if err != nil {
		t.Fatal(err)
	}
	if batch, err := worker.ProcessBatch(t.Context()); err != nil || batch.RetryScheduled != 1 || batch.Unknown != 1 || batch.Succeeded != 2 {
		t.Fatalf("initial worker batch=%+v err=%v", batch, err)
	}
	// Make only the isolated retry due; dispatch and settlement still run through the real worker.
	if _, err := pool.Exec(t.Context(), `UPDATE notification_outbox SET available_at=clock_timestamp() WHERE id=$1`, sender.retry); err != nil {
		t.Fatal(err)
	}
	if batch, err := worker.ProcessBatch(t.Context()); err != nil || batch.Accepted != 1 || batch.Claimed != 1 {
		t.Fatalf("retry worker batch=%+v err=%v", batch, err)
	}
	before, err := control.ListDeliveryHistory(t.Context(), admin, DeliveryHistoryQuery{MessageID: retry.EventID.String()})
	if err != nil || len(before.Items) != 4 || before.Items[0].State != "accepted" || before.Items[0].FailureCount != 1 {
		t.Fatalf("before receipt=%+v err=%v", before, err)
	}
	receipt := notification.ProviderReceipt{
		ScopeID: tenantA.ScopeID, OutboxID: sender.retry, Provider: "history-test", ProviderEventKey: "private-provider-event",
		ProviderDeliveryID: "private-provider-delivery", State: notification.DeliveryPermanentFailed,
		FailureCode: "recipient_rejected", ObservedAt: time.Now().UTC(),
	}
	for _, replayed := range []bool{false, true} {
		if result, err := deliveries.RecordProviderReceipt(t.Context(), receipt); err != nil || result.Replayed != replayed {
			t.Fatalf("receipt=%+v err=%v", result, err)
		}
	}
	var attemptOutcome string
	if err := pool.QueryRow(t.Context(), `SELECT outcome FROM notification_attempts WHERE outbox_id=$1 AND attempt_number=2`, sender.retry).Scan(&attemptOutcome); err != nil || attemptOutcome != "accepted" {
		t.Fatalf("receipt must leave historical attempt accepted: outcome=%q err=%v", attemptOutcome, err)
	}
	settlementActor := notification.SettlementActor{UserID: admin.UserID, ScopeID: admin.ScopeID, SessionID: admin.SessionID, ScopeKind: admin.ScopeKind}
	replay, err := deliveries.ReplayDelivery(t.Context(), settlementActor, notification.DeliveryCommand{
		ScopeID: tenantA.ScopeID, OutboxID: sender.retry, RequestID: "history-replay",
	})
	if err != nil {
		t.Fatal(err)
	}
	if batch, err := worker.ProcessBatch(t.Context()); err != nil || batch.Succeeded != 1 {
		t.Fatalf("replay worker batch=%+v err=%v", batch, err)
	}
	cancelled := enqueue(tenantA, "history-cancel", notification.ChannelEmail)
	if _, err := deliveries.CancelDelivery(t.Context(), settlementActor, notification.DeliveryCommand{
		ScopeID: tenantA.ScopeID, OutboxID: cancelled.Deliveries[0].OutboxID, RequestID: "history-cancel-command",
	}); err != nil {
		t.Fatal(err)
	}
	all, err := control.ListDeliveryHistory(t.Context(), admin, DeliveryHistoryQuery{Limit: "300"})
	if err != nil || all.Schema != "cdnca.notification-delivery-history/v1" || all.TotalCount != 15 || len(all.Items) != 15 || all.NextCursor != "" {
		t.Fatalf("all history=%+v err=%v", all, err)
	}
	for _, item := range all.Items {
		wantFailures := int64(0)
		if item.OutboxID == sender.retry {
			wantFailures = []int64{0, 1, 1, 1, 2}[item.Sequence-1]
		}
		if item.FailureCount != wantFailures || item.RecipientAddress != nil || item.RecipientAddressState != "unavailable" {
			t.Fatalf("historical failure count/contact=%+v", item)
		}
		if item.OutboxID == anonymous.Deliveries[0].OutboxID && (item.RecipientUserID != nil || item.RecipientUserDisplayID != nil || item.RecipientKind != "anonymous") {
			t.Fatalf("anonymous identity fabricated: %+v", item)
		}
		if item.OutboxID == replay.NewOutboxID && (item.Generation != 2 || item.ReplayOfOutboxID == nil || *item.ReplayOfOutboxID != sender.retry || item.MessageID != retry.EventID) {
			t.Fatalf("replay identity=%+v", item)
		}
	}
	encoded, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"@example.test", "private-history", "private-provider", "subject", "body", "dedup_key", "lease_token", "anonymous_dispatch_reference"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("history leaked %q", secret)
		}
	}
	var displayID string
	if err := pool.QueryRow(t.Context(), `SELECT display_id::text FROM users WHERE id=$1`, tenantA.UserID).Scan(&displayID); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		query DeliveryHistoryQuery
		want  int64
	}{
		{"scope", DeliveryHistoryQuery{ScopeID: tenantB.ScopeID.String()}, 2},
		{"user UUID", DeliveryHistoryQuery{UserID: tenantA.UserID.String()}, 11},
		{"user display", DeliveryHistoryQuery{UserID: displayID}, 11},
		{"channel", DeliveryHistoryQuery{Channel: "sms"}, 2},
		{"message", DeliveryHistoryQuery{MessageID: retry.EventID.String()}, 8},
		{"event type", DeliveryHistoryQuery{EventType: notification.EventTypeAccountRecovery}, 2},
		{"state", DeliveryHistoryQuery{State: "accepted"}, 1},
		{"success", DeliveryHistoryQuery{Result: "success"}, 3},
		{"failure", DeliveryHistoryQuery{Result: "failure"}, 2},
		{"result and state", DeliveryHistoryQuery{State: "accepted", Result: "success"}, 0},
		{"combined mismatch", DeliveryHistoryQuery{ScopeID: tenantB.ScopeID.String(), UserID: tenantA.UserID.String()}, 0},
		{"absent message", DeliveryHistoryQuery{MessageID: uuid.NewString()}, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			page, err := control.ListDeliveryHistory(t.Context(), admin, test.query)
			if err != nil || page.TotalCount != test.want || len(page.Items) != int(test.want) {
				t.Fatalf("filter=%+v page=%+v err=%v", test.query, page, err)
			}
		})
	}
	pageQuery := DeliveryHistoryQuery{Limit: "2"}
	index := 0
	for {
		page, err := control.ListDeliveryHistory(t.Context(), admin, pageQuery)
		if err != nil || page.TotalCount != all.TotalCount {
			t.Fatalf("page=%+v err=%v", page, err)
		}
		for _, row := range page.Items {
			if index >= len(all.Items) || row.ID != all.Items[index].ID {
				t.Fatalf("pagination mismatch at %d: %+v", index, row)
			}
			index++
		}
		if page.NextCursor == "" {
			break
		}
		pageQuery.Cursor = page.NextCursor
	}
	if index != len(all.Items) {
		t.Fatalf("pagination rows=%d want=%d", index, len(all.Items))
	}
	boundary := all.Items[len(all.Items)-1]
	page, err := control.ListDeliveryHistory(t.Context(), admin, DeliveryHistoryQuery{Cursor: boundary.ID})
	if err != nil || len(page.Items) != 0 || page.TotalCount != all.TotalCount {
		t.Fatalf("empty final page=%+v err=%v", page, err)
	}
	for _, query := range []DeliveryHistoryQuery{
		{ScopeID: tenantA.ScopeID.String(), Cursor: foreign.Deliveries[0].OutboxID.String() + ":1"},
		{Result: "success", Cursor: sender.unknown.String() + ":2"},
		{Cursor: sender.retry.String() + ":" + strconv.Itoa(99)},
		{Cursor: boundary.ID, From: boundary.ObservedAt.Add(time.Microsecond).Format(time.RFC3339Nano)},
	} {
		if _, err := control.ListDeliveryHistory(t.Context(), admin, query); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("cursor query=%+v err=%v", query, err)
		}
	}
	for _, test := range []struct {
		actor Actor
		want  error
	}{{Actor{}, ErrUnauthenticated}, {denied, ErrPermissionDenied}, {tenantA, ErrPermissionDenied}} {
		if _, err := control.ListDeliveryHistory(t.Context(), test.actor, DeliveryHistoryQuery{Invalid: true}); !errors.Is(err, test.want) {
			t.Fatalf("authorization before validation=%v want=%v", err, test.want)
		}
	}
	// merge-p6: platform.admin alone also reads delivery history (a second member of the one platform scope).
	// The store reads the real clock: extend this member's session like the ones above.
	platformAdmin := seedControlMember(t, pool, admin.ScopeID, "platform", permissionPlatformAdmin)
	if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1`,
		platformAdmin.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := control.ListDeliveryHistory(t.Context(), platformAdmin, DeliveryHistoryQuery{}); err != nil {
		t.Fatalf("platform.admin only=%v", err)
	}
	if _, err := pool.Exec(t.Context(), `DELETE FROM role_assignments WHERE scope_id=$1 AND user_id=$2`, admin.ScopeID, admin.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := control.ListDeliveryHistory(t.Context(), admin, DeliveryHistoryQuery{}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("permission revoked=%v", err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=clock_timestamp(),revocation_reason='test' WHERE id=$1`, admin.SessionID); err != nil {
		t.Fatal(err)
	}
	if _, err := control.ListDeliveryHistory(t.Context(), admin, DeliveryHistoryQuery{Invalid: true}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("session revoked=%v", err)
	}
}
