//go:build integration

package notification

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNotificationRepeatPolicyPersistsWindowIntervalAndReplay(t *testing.T) {
	for _, test := range []struct {
		name, mode, now, first string
		interval               int
	}{
		{"before_window", "custom", "2026-09-27T07:30:00+08:00", "2026-09-27T08:00:00+08:00", 24},
		{"after_window", "custom", "2026-09-27T23:30:00+08:00", "2026-09-28T08:00:00+08:00", 24},
		{"all_day", "all_day", "2026-09-27T07:30:00+08:00", "2026-09-27T07:30:00+08:00", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newNotificationRepeatFixture(t)
			fixture.clock.now, _ = time.Parse(time.RFC3339, test.now)
			first, _ := time.Parse(time.RFC3339, test.first)
			if _, err := fixture.pool.Exec(t.Context(), `UPDATE notification_delivery_policy SET
				window_mode=$1,window_start_minute=480,window_end_minute=1320 WHERE singleton`, test.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.pool.Exec(t.Context(), `UPDATE notification_event_policies SET interval_hours=$1
				WHERE event_type='node.offline'`, test.interval); err != nil {
				t.Fatal(err)
			}
			request := fixture.request(fixture.scopeA, test.name, DeliveryTenantSubscribed)
			result, err := fixture.store.Enqueue(t.Context(), request)
			if err != nil || result.Replayed || len(result.Deliveries) != 6 {
				t.Fatalf("repeat=3 enqueue result=%+v err=%v", result, err)
			}
			rows, err := fixture.pool.Query(t.Context(), `SELECT id,channel,dedup_key,generation,
				replay_of_outbox_id,available_at,status,attempt_count FROM notification_outbox
				WHERE event_id=$1 ORDER BY channel,generation`, result.EventID)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			persisted := make(map[uuid.UUID]EnqueuedDelivery, 6)
			firstIDs := make(map[Channel]uuid.UUID, 2)
			for rows.Next() {
				var delivery EnqueuedDelivery
				var generation, attempts int
				var source *uuid.UUID
				var available time.Time
				if err := rows.Scan(&delivery.OutboxID, &delivery.Channel, &delivery.DedupKey, &generation,
					&source, &available, &delivery.Status, &attempts); err != nil {
					t.Fatal(err)
				}
				wantAt := first.Add(time.Duration(test.interval*(generation-1)) * time.Hour)
				if generation < 1 || generation > 3 || !available.Equal(wantAt) || delivery.Status != OutboxPending || attempts != 0 {
					t.Fatalf("generation=%d available=%v want=%v delivery=%+v attempts=%d", generation, available, wantAt, delivery, attempts)
				}
				if generation == 1 {
					firstIDs[delivery.Channel] = delivery.OutboxID
					wantKey, err := DedupKey(EventIdentity{TenantID: request.ScopeID.String(), RecipientID: request.RecipientID.String(),
						EventID: request.SourceEventID, EventType: request.EventType}, request.Templates[delivery.Channel])
					if err != nil || source != nil || delivery.DedupKey != wantKey {
						t.Fatalf("generation 1 identity changed: delivery=%+v source=%v err=%v", delivery, source, err)
					}
				} else if source == nil || *source != firstIDs[delivery.Channel] ||
					!regexp.MustCompile(`^notification-v2-[0-9a-f]{64}$`).MatchString(delivery.DedupKey) {
					t.Fatalf("repeat identity=%+v generation=%d source=%v", delivery, generation, source)
				}
				persisted[delivery.OutboxID] = delivery
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			rows.Close()
			if len(persisted) != 6 {
				t.Fatalf("persisted outbox count=%d", len(persisted))
			}
			for _, delivery := range result.Deliveries {
				if persisted[delivery.OutboxID] != delivery {
					t.Fatalf("returned delivery differs from persisted fact: %+v", delivery)
				}
			}
			if _, err := fixture.pool.Exec(t.Context(), `UPDATE notification_event_policies SET repeat_count=1,interval_hours=1
				WHERE event_type='node.offline'`); err != nil {
				t.Fatal(err)
			}
			for range 3 {
				replay, err := fixture.store.Enqueue(t.Context(), request)
				if err != nil || !replay.Replayed || replay.EventID != result.EventID || len(replay.Deliveries) != 6 {
					t.Fatalf("event replay=%+v err=%v", replay, err)
				}
				for _, delivery := range replay.Deliveries {
					if persisted[delivery.OutboxID] != delivery {
						t.Fatalf("replay identity changed: %+v", delivery)
					}
				}
			}
			request.Contexts[ChannelSMS]["name"] = PublicValue("different-node")
			if _, err := fixture.store.Enqueue(t.Context(), request); !errors.Is(err, ErrEventConflict) {
				t.Fatalf("conflicting replay error=%v", err)
			}
			assertNotificationRepeatCounts(t, fixture, 1, 6, 1)
			var auditedOutboxCount int
			if err := fixture.pool.QueryRow(t.Context(), `SELECT (payload->>'outbox_count')::int
				FROM audit_events WHERE action='notification.event.enqueue' AND resource_id=$1`, result.EventID.String()).Scan(&auditedOutboxCount); err != nil {
				t.Fatal(err)
			}
			if auditedOutboxCount != 6 {
				t.Fatalf("audited outbox count=%d", auditedOutboxCount)
			}
		})
	}
}

func TestNotificationRepeatPolicyRollsBackPartialOutboxAndAuditFailure(t *testing.T) {
	for _, test := range []struct{ name, table, condition string }{
		{"third_generation", "notification_outbox", "NEW.generation=3"},
		{"audit", "audit_events", "NEW.action='notification.event.enqueue'"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newNotificationRepeatFixture(t)
			if _, err := fixture.pool.Exec(t.Context(), fmt.Sprintf(`CREATE FUNCTION reject_repeat_insert()
				RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF %s THEN
				RAISE EXCEPTION 'injected repeat transaction failure'; END IF; RETURN NEW; END; $$;
				CREATE TRIGGER reject_repeat_insert BEFORE INSERT ON %s
				FOR EACH ROW EXECUTE FUNCTION reject_repeat_insert()`, test.condition, test.table)); err != nil {
				t.Fatal(err)
			}
			request := fixture.request(fixture.scopeA, test.name, DeliveryTenantSubscribed)
			if _, err := fixture.store.Enqueue(t.Context(), request); err == nil || !strings.Contains(err.Error(), "injected repeat transaction failure") {
				t.Fatalf("expected injected failure, got %v", err)
			}
			assertNotificationRepeatCounts(t, fixture, 0, 0, 0)
			if _, err := fixture.pool.Exec(t.Context(), "DROP TRIGGER reject_repeat_insert ON "+pgx.Identifier{test.table}.Sanitize()); err != nil {
				t.Fatal(err)
			}
			tx, err := fixture.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(t.Context()) }()
			if _, err := fixture.store.EnqueueTx(t.Context(), tx, request); err != nil {
				t.Fatal(err)
			}
			if err := tx.Rollback(t.Context()); err != nil {
				t.Fatal(err)
			}
			assertNotificationRepeatCounts(t, fixture, 0, 0, 0)
			if result, err := fixture.store.Enqueue(t.Context(), request); err != nil || result.Replayed || len(result.Deliveries) != 6 {
				t.Fatalf("retry after rollback=%+v err=%v", result, err)
			}
			assertNotificationRepeatCounts(t, fixture, 1, 6, 1)
		})
	}
}

func TestNotificationRepeatPolicyManualReplayUsesNextGeneration(t *testing.T) {
	fixture := newNotificationRepeatFixture(t)
	config := fixture.pool.Config()
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	actorPool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer actorPool.Close()
	actor := seedSettlementActor108(t, actorPool, "platform", "system_configuration.manage")
	if _, err := actorPool.Exec(t.Context(), `UPDATE auth_sessions SET expires_at=now()+interval '1 hour' WHERE id=$1`, actor.SessionID); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.store.Enqueue(t.Context(), fixture.request(fixture.scopeA, "manual-replay", DeliveryTenantSubscribed))
	if err != nil || len(result.Deliveries) != 6 {
		t.Fatalf("automatic repeat=%+v err=%v", result, err)
	}
	source := result.Deliveries[0]
	command := DeliveryCommand{ScopeID: fixture.scopeA, OutboxID: source.OutboxID, RequestID: "cancel-before-replay"}
	if cancelled, err := fixture.store.CancelDelivery(t.Context(), actor, command); err != nil || cancelled.State != DeliveryCancelled {
		t.Fatalf("cancelled=%+v err=%v", cancelled, err)
	}
	command.RequestID = "manual-replay-after-repeat"
	replay, err := fixture.store.ReplayDelivery(t.Context(), actor, command)
	if err != nil || replay.Replayed || replay.NewOutboxID == uuid.Nil {
		t.Fatalf("manual replay=%+v err=%v", replay, err)
	}
	var generation int
	var replayOf uuid.UUID
	var key string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT generation,replay_of_outbox_id,dedup_key
		FROM notification_outbox WHERE id=$1`, replay.NewOutboxID).Scan(&generation, &replayOf, &key); err != nil {
		t.Fatal(err)
	}
	wantKey := replayDedupKey(source.DedupKey, deliveryCommandDigest("notification.delivery.replay", command), 4)
	if generation != 4 || replayOf != source.OutboxID || key != wantKey {
		t.Fatalf("manual replay generation=%d source=%v key=%s", generation, replayOf, key)
	}
	again, err := fixture.store.ReplayDelivery(t.Context(), actor, command)
	if err != nil || !again.Replayed || again.NewOutboxID != replay.NewOutboxID {
		t.Fatalf("manual replay retry=%+v err=%v", again, err)
	}
	assertNotificationRepeatCounts(t, fixture, 1, 7, 1)
	assertCommandCounts108(t, fixture.pool, command.RequestID, 1, 1, 1)
}

func TestNotificationRepeatWindowUsesPreviousScheduledDelivery(t *testing.T) {
	for _, test := range []struct {
		name, now            string
		policy               DeliveryPolicy
		start, end, interval int
		want                 [3]string
	}{
		{"overnight", "2026-09-27T07:00:00+08:00", DeliveryTenantSubscribed, 1350, 495, 6,
			[3]string{"2026-09-27T07:00:00+08:00", "2026-09-27T22:30:00+08:00", "2026-09-28T04:30:00+08:00"}},
		{"narrow_window", "2026-09-27T08:00:00+08:00", DeliveryTenantSubscribed, 480, 540, 2,
			[3]string{"2026-09-27T08:00:00+08:00", "2026-09-28T08:00:00+08:00", "2026-09-29T08:00:00+08:00"}},
		{"system_required_bypasses_window", "2026-09-27T10:00:00+08:00", DeliverySystemRequired, 1350, 495, 6,
			[3]string{"2026-09-27T10:00:00+08:00", "2026-09-27T16:00:00+08:00", "2026-09-27T22:00:00+08:00"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newNotificationRepeatFixture(t)
			fixture.clock.now, _ = time.Parse(time.RFC3339, test.now)
			if _, err := fixture.pool.Exec(t.Context(), `UPDATE notification_delivery_policy SET
				window_mode='custom',window_start_minute=$1,window_end_minute=$2 WHERE singleton`, test.start, test.end); err != nil {
				t.Fatal(err)
			}
			if _, err := fixture.pool.Exec(t.Context(), `UPDATE notification_event_policies SET interval_hours=$1
				WHERE event_type='node.offline'`, test.interval); err != nil {
				t.Fatal(err)
			}
			result, err := fixture.store.Enqueue(t.Context(), fixture.request(fixture.scopeA, test.name, test.policy))
			if err != nil || len(result.Deliveries) != 6 {
				t.Fatalf("repeat enqueue=%+v err=%v", result, err)
			}
			rows, err := fixture.pool.Query(t.Context(), `SELECT channel,generation,available_at
				FROM notification_outbox WHERE event_id=$1 ORDER BY channel,generation`, result.EventID)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			count := 0
			for rows.Next() {
				var channel Channel
				var generation int
				var scheduled time.Time
				if err := rows.Scan(&channel, &generation, &scheduled); err != nil {
					t.Fatal(err)
				}
				if generation < 1 || generation > len(test.want) {
					t.Fatalf("unexpected generation=%d", generation)
				}
				want, _ := time.Parse(time.RFC3339, test.want[generation-1])
				if !scheduled.Equal(want) {
					t.Errorf("channel=%s generation=%d scheduled=%s want=%s", channel, generation,
						scheduled.Format(time.RFC3339), want.Format(time.RFC3339))
				}
				count++
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if count != 6 {
				t.Fatalf("persisted schedule rows=%d", count)
			}
		})
	}
}

func newNotificationRepeatFixture(t *testing.T) *notificationFixture {
	t.Helper()
	fixture := newNotificationFixture(t)
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO notification_event_policies
		(event_type,enabled,sms_enabled,email_enabled,repeat_count,interval_hours,supported,updated_at)
		VALUES('node.offline',true,true,true,3,24,true,now())`); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.SetChannelSwitches(t.Context(), ChannelSwitches{SMS: true, Email: true}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.SetSubscription(t.Context(), fixture.scopeA, fixture.userID, "node.offline", Subscription{SMS: true, Email: true}); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func assertNotificationRepeatCounts(t *testing.T, fixture *notificationFixture, events, outbox, audits int) {
	t.Helper()
	var gotEvents, gotOutbox, gotAudits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM notification_events),
		(SELECT count(*) FROM notification_outbox),
		(SELECT count(*) FROM audit_events WHERE action='notification.event.enqueue')`).Scan(&gotEvents, &gotOutbox, &gotAudits); err != nil {
		t.Fatal(err)
	}
	if gotEvents != events || gotOutbox != outbox || gotAudits != audits {
		t.Fatalf("events/outbox/audits=%d/%d/%d want=%d/%d/%d", gotEvents, gotOutbox, gotAudits, events, outbox, audits)
	}
}
