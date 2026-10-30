//go:build integration

package notification

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FX41: 预排的重复投递在源事件已过期（续费、恢复、订阅失效）后不得再发。
func TestNotificationReplayGuardWithdrawsStaleRepeatsBeforeSend(t *testing.T) {
	fixture := newReplayGuardFixture(t)
	result, err := fixture.store.Enqueue(t.Context(), fixture.request(fixture.scopeA, "guard-stale", DeliverySystemRequired))
	if err != nil || len(result.Deliveries) != 6 {
		t.Fatalf("enqueue=%+v err=%v", result, err)
	}
	makeReplayGuardOutboxDue(t, fixture, result.EventID)

	var seen []ReplayCandidate
	if err := fixture.store.RegisterReplayGuard("node.offline", func(_ context.Context, _ pgx.Tx, candidate ReplayCandidate) (bool, error) {
		seen = append(seen, candidate)
		return false, nil
	}); err != nil {
		t.Fatal(err)
	}
	sender := &recordingSender{}
	worker := newReplayGuardWorker(t, fixture, sender)
	batch, err := worker.ProcessBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if batch.Withdrawn != 4 || batch.Succeeded != 2 || batch.Claimed != 2 {
		t.Fatalf("batch=%+v", batch)
	}
	calls, unique := sender.snapshot()
	if calls != 2 || unique != 2 {
		t.Fatalf("sender calls=%d unique=%d", calls, unique)
	}
	for _, candidate := range seen {
		if candidate.Generation < 2 || candidate.EventType != "node.offline" || candidate.SourceEventID != "guard-stale" ||
			candidate.ScopeID != fixture.scopeA || candidate.EventID != result.EventID {
			t.Fatalf("guard candidate=%+v", candidate)
		}
	}
	rows, err := fixture.pool.Query(t.Context(), `SELECT outbox.generation,outbox.status,outbox.last_failure_code,
		settlement.state,fact.fact_kind,fact.failure_code,fact.operation
		FROM notification_outbox outbox
		LEFT JOIN notification_delivery_settlements_108 settlement ON settlement.outbox_id=outbox.id
		LEFT JOIN notification_delivery_facts_108 fact ON fact.outbox_id=outbox.id AND fact.sequence=settlement.revision
		WHERE outbox.event_id=$1 ORDER BY outbox.channel,outbox.generation`, result.EventID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	withdrawn := 0
	for rows.Next() {
		var generation int
		var status string
		var failure, state, kind, factFailure, operation *string
		if err := rows.Scan(&generation, &status, &failure, &state, &kind, &factFailure, &operation); err != nil {
			t.Fatal(err)
		}
		if generation == 1 {
			if status != OutboxSucceeded {
				t.Fatalf("generation 1 status=%s", status)
			}
			continue
		}
		if status != "cancelled" || failure == nil || *failure != ReplayWithdrawnCode || state == nil || *state != "cancelled" ||
			kind == nil || *kind != "cancelled" || factFailure == nil || *factFailure != ReplayWithdrawnCode || operation != nil {
			t.Fatalf("generation=%d status=%s failure=%v state=%v kind=%v factFailure=%v operation=%v",
				generation, status, failure, state, kind, factFailure, operation)
		}
		withdrawn++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if withdrawn != 4 {
		t.Fatalf("withdrawn rows=%d", withdrawn)
	}
	var audits int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
		WHERE action='notification.delivery.withdraw' AND actor_user_id IS NULL`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 4 {
		t.Fatalf("withdraw audits=%d", audits)
	}
	again, err := worker.ProcessBatch(t.Context())
	if err != nil || again != (WorkerBatchResult{}) {
		t.Fatalf("second batch=%+v err=%v", again, err)
	}
}

func TestNotificationReplayGuardKeepsCurrentRepeatsAndFirstDelivery(t *testing.T) {
	fixture := newReplayGuardFixture(t)
	result, err := fixture.store.Enqueue(t.Context(), fixture.request(fixture.scopeA, "guard-current", DeliverySystemRequired))
	if err != nil || len(result.Deliveries) != 6 {
		t.Fatalf("enqueue=%+v err=%v", result, err)
	}
	makeReplayGuardOutboxDue(t, fixture, result.EventID)
	calls := 0
	if err := fixture.store.RegisterReplayGuard("node.offline", func(_ context.Context, _ pgx.Tx, candidate ReplayCandidate) (bool, error) {
		calls++
		if candidate.Generation < 2 {
			t.Fatalf("guard consulted for first delivery: %+v", candidate)
		}
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
	sender := &recordingSender{}
	batch, err := newReplayGuardWorker(t, fixture, sender).ProcessBatch(t.Context())
	if err != nil || batch.Succeeded != 6 || batch.Withdrawn != 0 || calls != 4 {
		t.Fatalf("batch=%+v calls=%d err=%v", batch, calls, err)
	}
}

func TestNotificationReplayGuardRegistrationRejectsInvalidInput(t *testing.T) {
	fixture := newReplayGuardFixture(t)
	guard := func(context.Context, pgx.Tx, ReplayCandidate) (bool, error) { return true, nil }
	if err := fixture.store.RegisterReplayGuard("Bad Type", guard); err == nil {
		t.Fatal("invalid event type accepted")
	}
	if err := fixture.store.RegisterReplayGuard("node.offline", nil); err == nil {
		t.Fatal("nil guard accepted")
	}
	if err := fixture.store.RegisterReplayGuard("node.offline", guard); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.RegisterReplayGuard("node.offline", guard); err == nil {
		t.Fatal("duplicate guard accepted")
	}
}

func newReplayGuardFixture(t *testing.T) *notificationFixture {
	t.Helper()
	fixture := newNotificationFixture(t)
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO notification_event_policies
		(event_type,enabled,sms_enabled,email_enabled,repeat_count,interval_hours,supported,updated_at)
		VALUES('node.offline',true,true,true,3,1,true,now())
		ON CONFLICT (event_type) DO UPDATE SET enabled=true,sms_enabled=true,email_enabled=true,
		repeat_count=3,interval_hours=1,supported=true`); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.SetChannelSwitches(t.Context(), ChannelSwitches{SMS: true, Email: true}); err != nil {
		t.Fatal(err)
	}
	return fixture
}

// 预排的 replay 在未来；把整组时间平移到过去，模拟“到点”。
func makeReplayGuardOutboxDue(t *testing.T, fixture *notificationFixture, eventID uuid.UUID) {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE notification_outbox
		SET available_at=available_at-interval '30 days'
		WHERE event_id=$1`, eventID); err != nil {
		t.Fatal(err)
	}
}

func newReplayGuardWorker(t *testing.T, fixture *notificationFixture, sender Sender) *Worker {
	t.Helper()
	config := DefaultWorkerConfig()
	config.BatchSize = 16
	config.BaseDelay, config.MaxDelay = time.Second, time.Minute
	worker, err := NewWorker(fixture.store, sender, config)
	if err != nil {
		t.Fatal(err)
	}
	return worker
}

// 没有任何 guard 时，自动预排的 replay 也必须能正常投递（settlement 投影要带 replay_of_outbox_id）。
func TestNotificationAutomaticRepeatDispatchesWithoutGuard(t *testing.T) {
	fixture := newReplayGuardFixture(t)
	result, err := fixture.store.Enqueue(t.Context(), fixture.request(fixture.scopeA, "repeat-dispatch", DeliverySystemRequired))
	if err != nil || len(result.Deliveries) != 6 {
		t.Fatalf("enqueue=%+v err=%v", result, err)
	}
	makeReplayGuardOutboxDue(t, fixture, result.EventID)
	batch, err := newReplayGuardWorker(t, fixture, &recordingSender{}).ProcessBatch(t.Context())
	if err != nil || batch.Succeeded != 6 {
		t.Fatalf("batch=%+v err=%v", batch, err)
	}
	var mismatched int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM notification_outbox outbox
		JOIN notification_delivery_settlements_108 settlement ON settlement.outbox_id=outbox.id
		WHERE outbox.event_id=$1 AND (settlement.state<>'delivered' OR
		settlement.replay_of_outbox_id IS DISTINCT FROM outbox.replay_of_outbox_id)`, result.EventID).Scan(&mismatched); err != nil {
		t.Fatal(err)
	}
	if mismatched != 0 {
		t.Fatalf("settlements not delivered or replay source mismatched: %d", mismatched)
	}
}
