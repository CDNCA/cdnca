//go:build integration

package notificationcontrol

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDeliveryPolicyCloudSaveReplayAndReadback(t *testing.T) {
	pool := deliveryPolicyMigrationPool(t, 250)
	now := func() time.Time { return controlTestNow }
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, now), now)
	if err != nil {
		t.Fatal(err)
	}
	actor := seedControlActor(t, pool, "platform", permissionRead, permissionManage)
	initial, err := store.GetDeliveryPolicy(t.Context(), actor)
	if err != nil {
		t.Fatal(err)
	}
	request := UpdateDeliveryPolicyRequest{
		ExpectedRevision: initial.Revision,
		WindowMode:       "custom",
		WindowStart:      "22:30",
		WindowEnd:        "08:15",
		Timezone:         initial.Timezone,
		Events:           initial.Events,
		RequestID:        "policy-cloud-save",
	}
	found := false
	for index := range request.Events {
		event := &request.Events[index]
		if event.EventType == "package.monitor.traffic.triggered" {
			event.Enabled, event.EmailEnabled, event.SMSEnabled = true, true, false
			event.RepeatCount, event.IntervalHours = 3, 6
			found = true
		}
	}
	if !found {
		t.Fatal("traffic notification policy was not seeded")
	}
	updated, err := store.UpdateDeliveryPolicy(t.Context(), actor, request)
	if err != nil {
		t.Fatalf("save overnight traffic notification policy: %v", err)
	}
	if !updated.Changed || updated.Revision != initial.Revision+1 ||
		updated.WindowMode != request.WindowMode || updated.WindowStart != request.WindowStart ||
		updated.WindowEnd != request.WindowEnd || updated.Timezone != request.Timezone ||
		!reflect.DeepEqual(updated.Events, request.Events) {
		t.Fatalf("saved policy = %+v, request = %+v", updated, request)
	}
	replayed, err := store.UpdateDeliveryPolicy(t.Context(), actor, request)
	if err != nil || !reflect.DeepEqual(replayed, updated) {
		t.Fatalf("exact replay = %+v, %v; want %+v", replayed, err, updated)
	}
	readback, err := store.GetDeliveryPolicy(t.Context(), actor)
	updated.Changed = false
	if err != nil || !reflect.DeepEqual(readback, updated) {
		t.Fatalf("readback = %+v, %v; want %+v", readback, err, updated)
	}
	assertDeliveryPolicyWriteCounts(t, pool, 1, 1, 0)

	conflict := request
	conflict.WindowEnd = "09:15"
	if _, err := store.UpdateDeliveryPolicy(t.Context(), actor, conflict); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("changed request replay = %v, want version conflict", err)
	}
	conflict = request
	conflict.RequestID = "policy-stale-revision"
	if _, err := store.UpdateDeliveryPolicy(t.Context(), actor, conflict); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale revision = %v, want version conflict", err)
	}
	invalid := request
	invalid.RequestID, invalid.ExpectedRevision, invalid.WindowEnd = "policy-invalid-time", updated.Revision, "25:00"
	if _, err := store.UpdateDeliveryPolicy(t.Context(), actor, invalid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid time = %v, want invalid input", err)
	}
	assertDeliveryPolicyWriteCounts(t, pool, 1, 1, 0)

	request.ExpectedRevision, request.RequestID = updated.Revision, "policy-no-op"
	noOp, err := store.UpdateDeliveryPolicy(t.Context(), actor, request)
	if err != nil || !reflect.DeepEqual(noOp, updated) {
		t.Fatalf("no-op = %+v, %v; want %+v", noOp, err, updated)
	}
	viewer := seedControlActor(t, pool, "tenant")
	for range 2 {
		if _, err := store.UpdateDeliveryPolicy(t.Context(), viewer, request); !errors.Is(err, ErrPermissionDenied) {
			t.Fatalf("viewer write = %v, want permission denied", err)
		}
	}
	assertDeliveryPolicyWriteCounts(t, pool, 2, 1, 1)

	for _, statement := range []string{
		`UPDATE notification_control_idempotency_receipts SET response_body='{}' WHERE operation='notification.policy.update'`,
		`DELETE FROM notification_control_idempotency_receipts WHERE operation='notification.policy.update'`,
	} {
		_, err := pool.Exec(t.Context(), statement)
		assertDeliveryPolicySQLState(t, err, "P9102")
	}
	before := deliveryPolicyPersistenceSnapshot(t, pool)
	assertDeliveryPolicySQLState(t, migrateNotificationControlVersion091(t.Context(), pool, "down", 250), "P2501")
	if after := deliveryPolicyPersistenceSnapshot(t, pool); after != before {
		t.Fatal("rejected rollback changed policy, receipts, audit or migration ledger")
	}
	if replay, err := store.UpdateDeliveryPolicy(t.Context(), actor, request); err != nil || !reflect.DeepEqual(replay, noOp) {
		t.Fatalf("receipt replay after rejected rollback = %+v, %v", replay, err)
	}
}

func TestDeliveryPolicyAuditFailureRollsBackAndRetries(t *testing.T) {
	pool := deliveryPolicyMigrationPool(t, 250)
	now := func() time.Time { return controlTestNow }
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, now), now)
	if err != nil {
		t.Fatal(err)
	}
	actor := seedControlActor(t, pool, "platform", permissionRead, permissionManage)
	initial, err := store.GetDeliveryPolicy(t.Context(), actor)
	if err != nil {
		t.Fatal(err)
	}
	request := UpdateDeliveryPolicyRequest{
		ExpectedRevision: initial.Revision, WindowMode: "custom", WindowStart: "22:30",
		WindowEnd: "08:15", Timezone: initial.Timezone, Events: initial.Events, RequestID: "policy-audit-retry",
	}
	injected := errors.New("injected policy audit failure")
	failing, err := NewStoreWithDependencies(pool, notificationControlFailingAuditor{err: injected}, now)
	if err != nil {
		t.Fatal(err)
	}
	before := deliveryPolicyPersistenceSnapshot(t, pool)
	if _, err := failing.UpdateDeliveryPolicy(t.Context(), actor, request); !errors.Is(err, injected) {
		t.Fatalf("audit failure = %v, want injected failure", err)
	}
	if after := deliveryPolicyPersistenceSnapshot(t, pool); after != before {
		t.Fatal("audit failure persisted partial policy, receipt or audit")
	}
	updated, err := store.UpdateDeliveryPolicy(t.Context(), actor, request)
	if err != nil || !updated.Changed || updated.Revision != initial.Revision+1 {
		t.Fatalf("retry after audit recovery = %+v, %v", updated, err)
	}
	assertDeliveryPolicyWriteCounts(t, pool, 1, 1, 0)
}

func TestDeliveryPolicyMigration250RoundTrip(t *testing.T) {
	pool := deliveryPolicyMigrationPool(t, 250)
	now := func() time.Time { return controlTestNow }
	store, err := NewStoreWithDependencies(pool, audit.NewWithClock(pool, now), now)
	if err != nil {
		t.Fatal(err)
	}
	actor := seedControlActor(t, pool, "platform", permissionRead, permissionManage)
	channels, err := store.GetChannels(t.Context(), actor)
	if err != nil {
		t.Fatal(err)
	}
	channelRequest := UpdateChannelsRequest{ExpectedRevision: channels.Revision,
		SMSEnabled: channels.SMSEnabled, EmailEnabled: !channels.EmailEnabled, RequestID: "channel-before-policy-down"}
	savedChannels, err := store.UpdateChannels(t.Context(), actor, channelRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrateNotificationControlVersion091(t.Context(), pool, "down", 250); err != nil {
		t.Fatalf("250 down without policy receipts: %v", err)
	}
	var head int
	if err := pool.QueryRow(t.Context(), `SELECT max(version) FROM schema_migrations`).Scan(&head); err != nil || head != 249 {
		t.Fatalf("down migration head = %d, %v; want 249", head, err)
	}
	if replay, err := store.UpdateChannels(t.Context(), actor, channelRequest); err != nil || replay != savedChannels {
		t.Fatalf("existing channel receipt after down = %+v, %v", replay, err)
	}
	initial, err := store.GetDeliveryPolicy(t.Context(), actor)
	if err != nil {
		t.Fatal(err)
	}
	request := UpdateDeliveryPolicyRequest{
		ExpectedRevision: initial.Revision, WindowMode: initial.WindowMode, WindowStart: initial.WindowStart,
		WindowEnd: initial.WindowEnd, Timezone: initial.Timezone, Events: initial.Events, RequestID: "policy-after-roundtrip",
	}
	_, err = store.UpdateDeliveryPolicy(t.Context(), actor, request)
	assertDeliveryPolicySQLState(t, err, "23514")
	if err := migrateNotificationControlVersion091(t.Context(), pool, "up", 250); err != nil {
		t.Fatalf("reapply 250: %v", err)
	}
	if result, err := store.UpdateDeliveryPolicy(t.Context(), actor, request); err != nil || result.Changed || result.Revision != initial.Revision {
		t.Fatalf("policy after reapplying 250 = %+v, %v", result, err)
	}
	if replay, err := store.UpdateChannels(t.Context(), actor, channelRequest); err != nil || replay != savedChannels {
		t.Fatalf("existing channel receipt after up = %+v, %v", replay, err)
	}
}

func TestDeliveryPolicyMigration250Contract(t *testing.T) {
	for filename, fragments := range map[string][]string{
		"250_notification_policy_write_receipts.up.sql": {
			"migration 250 requires the exact verified 249 release head",
			"notification.channels.update", "notification.template.put", "notification.subscription.update", "notification.policy.update",
			"notification_control_idempotency_receipts_operation_check",
		},
		"250_notification_policy_write_receipts.down.sql": {
			"IN ACCESS EXCLUSIVE MODE", "WHERE operation = 'notification.policy.update'", "ERRCODE = 'P2501'",
			"retain migration 250 during binary rollback to preserve notification policy write receipts",
		},
	} {
		contents, err := controlmigrations.FS.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		for _, fragment := range fragments {
			if !strings.Contains(string(contents), fragment) {
				t.Errorf("%s missing %q", filename, fragment)
			}
		}
	}
}

func assertDeliveryPolicySQLState(t *testing.T, err error, code string) {
	t.Helper()
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != code {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, code)
	}
}

func assertDeliveryPolicyWriteCounts(t *testing.T, pool *pgxpool.Pool, receipts, success, denied int) {
	t.Helper()
	var actualReceipts, actualSuccess, actualDenied int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM notification_control_idempotency_receipts WHERE operation='notification.policy.update' AND completed_at IS NOT NULL),
		(SELECT count(*) FROM audit_events WHERE action='notification.policy.update' AND result='success'),
		(SELECT count(*) FROM audit_events WHERE action='notification.policy.update' AND result='denied')`).Scan(
		&actualReceipts, &actualSuccess, &actualDenied); err != nil {
		t.Fatal(err)
	}
	if actualReceipts != receipts || actualSuccess != success || actualDenied != denied {
		t.Fatalf("receipt/success/denied counts = %d/%d/%d, want %d/%d/%d", actualReceipts, actualSuccess, actualDenied, receipts, success, denied)
	}
}

func deliveryPolicyPersistenceSnapshot(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var snapshot string
	if err := pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
		'policy', (SELECT jsonb_agg(to_jsonb(p)) FROM notification_delivery_policy p),
		'events', (SELECT jsonb_agg(to_jsonb(e) ORDER BY event_type) FROM notification_event_policies e),
		'receipts', (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM notification_control_idempotency_receipts r),
		'audit', (SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM audit_events a),
		'migrations', (SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM schema_migrations m))::text`).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// deliveryPolicyMigrationPool stops the schema at 250/251 for the delivery
// policy cases; today's audit writer needs 361's unified columns, added on
// their own.
func deliveryPolicyMigrationPool(t *testing.T, maximum int64) *pgxpool.Pool {
	t.Helper()
	pool := notificationControlMigrationPool091(t, maximum)
	databasetest.AddUnifiedAuditColumns(t, pool)
	return pool
}
