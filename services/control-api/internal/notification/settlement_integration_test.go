//go:build integration

package notification

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNotificationProviderSettlementAcceptedUnknownRetryAndReceipts108(t *testing.T) {
	fixture := newSettlementFixture108(t)
	fixture.enableSMS(t)

	acceptedID := mustEnqueue(t, fixture.notificationFixture, "settlement-accepted")
	unknownID := mustEnqueue(t, fixture.notificationFixture, "settlement-unknown")
	retryID := mustEnqueue(t, fixture.notificationFixture, "settlement-retry-after")
	sender := &recordingSender{scripts: map[uuid.UUID][]SendResult{
		acceptedID: {{Disposition: SendAccepted, Provider: "smtp", ProviderDeliveryID: "smtp-accepted-1"}},
		unknownID:  {{Disposition: SendUnknown, Provider: "smtp"}},
		retryID:    {failedSendAfter(FailureTemporary, "provider_rate_limited", 37*time.Second)},
	}}
	config := DefaultWorkerConfig()
	config.BatchSize = 3
	config.BaseDelay, config.MaxDelay = time.Second, time.Minute
	worker, err := NewWorker(fixture.store, sender, config)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := worker.ProcessBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if batch.Claimed != 3 || batch.Accepted != 1 || batch.Unknown != 1 || batch.RetryScheduled != 1 || batch.Succeeded != 0 {
		t.Fatalf("settlement batch=%+v", batch)
	}
	assertSettlement108(t, fixture.pool, acceptedID, "accepted", 2)
	assertSettlement108(t, fixture.pool, unknownID, "unknown", 2)
	assertSettlement108(t, fixture.pool, retryID, "retry_wait", 2)
	assertOutboxStatusAttempt(t, fixture.pool, acceptedID, OutboxAccepted, 1)
	assertOutboxStatusAttempt(t, fixture.pool, unknownID, OutboxUnknown, 1)
	assertOutboxStatusAttempt(t, fixture.pool, retryID, OutboxPending, 1)
	assertAttemptNoFailure108(t, fixture.pool, acceptedID, "accepted")
	assertAttempt108(t, fixture.pool, unknownID, "unknown", "provider_outcome_unknown")

	var availableAt time.Time
	if err := fixture.pool.QueryRow(t.Context(), `SELECT available_at FROM notification_outbox WHERE id=$1`, retryID).Scan(&availableAt); err != nil {
		t.Fatal(err)
	}
	var firstFactAt time.Time
	if err := fixture.pool.QueryRow(t.Context(), `SELECT created_at FROM notification_delivery_facts_108
		WHERE outbox_id=$1 AND result_state='retry_wait'`, retryID).Scan(&firstFactAt); err != nil {
		t.Fatal(err)
	}
	if availableAt.Before(firstFactAt.Add(37 * time.Second)) {
		t.Fatalf("Retry-After lost: available=%v fact=%v", availableAt, firstFactAt)
	}

	// Settlement facts are stamped with the database clock (settlementDatabaseNow) and the 108 fact
	// guard requires non-decreasing observed_at, so the provider receipt is observed after them.
	var receiptObservedAt time.Time
	if err := fixture.pool.QueryRow(t.Context(), `SELECT clock_timestamp()`).Scan(&receiptObservedAt); err != nil {
		t.Fatal(err)
	}
	receipt := ProviderReceipt{
		ScopeID: fixture.scopeA, OutboxID: acceptedID, Provider: "smtp",
		ProviderEventKey: "smtp-event-accepted-1", ProviderDeliveryID: "smtp-accepted-1",
		State: DeliveryDelivered, ObservedAt: receiptObservedAt,
	}
	first, err := fixture.store.RecordProviderReceipt(t.Context(), receipt)
	if err != nil || first.Replayed || first.State != DeliveryDelivered {
		t.Fatalf("first receipt=%+v err=%v", first, err)
	}
	replayed, err := fixture.store.RecordProviderReceipt(t.Context(), receipt)
	if err != nil || !replayed.Replayed || replayed.State != DeliveryDelivered {
		t.Fatalf("replayed receipt=%+v err=%v", replayed, err)
	}
	conflict := receipt
	conflict.ProviderEventKey = "smtp-event-conflict"
	conflict.State = DeliveryPermanentFailed
	conflict.FailureCode = "recipient_rejected"
	if _, err := fixture.store.RecordProviderReceipt(t.Context(), conflict); !errors.Is(err, ErrSettlementConflict) {
		t.Fatalf("terminal conflict err=%v", err)
	}
	assertOutboxStatusAttempt(t, fixture.pool, acceptedID, OutboxSucceeded, 1)
	assertSettlement108(t, fixture.pool, acceptedID, "delivered", 3)

	second, err := worker.ProcessBatch(t.Context())
	if err != nil || second.Claimed != 0 {
		t.Fatalf("unknown was automatically resent: batch=%+v err=%v", second, err)
	}
	if calls, unique := sender.snapshot(); calls != 3 || unique != 3 {
		t.Fatalf("provider calls=%d unique=%d", calls, unique)
	}
}

func TestNotificationProviderSettlementPartialRecipientsAndExpiredDispatchUnknown108(t *testing.T) {
	fixture := newSettlementFixture108(t)
	if err := fixture.store.SetChannelSwitches(t.Context(), ChannelSwitches{SMS: true, Email: true}); err != nil {
		t.Fatal(err)
	}
	request := fixture.request(fixture.scopeA, "settlement-partial", DeliverySystemRequired)
	result, err := fixture.store.Enqueue(t.Context(), request)
	if err != nil || len(result.Deliveries) != 2 {
		t.Fatalf("enqueue=%+v err=%v", result, err)
	}
	sender := &recordingSender{scripts: map[uuid.UUID][]SendResult{
		result.Deliveries[0].OutboxID: {{Disposition: SendDelivered, Provider: "test"}},
		result.Deliveries[1].OutboxID: {{Disposition: SendAccepted, Provider: "smtp"}},
	}}
	config := DefaultWorkerConfig()
	config.BatchSize = 2
	worker, err := NewWorker(fixture.store, sender, config)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := worker.ProcessBatch(t.Context())
	if err != nil || batch.Succeeded != 1 || batch.Accepted != 1 {
		t.Fatalf("partial batch=%+v err=%v", batch, err)
	}
	assertOutboxStateCount(t, fixture.pool, OutboxSucceeded, 1)
	assertOutboxStateCount(t, fixture.pool, OutboxAccepted, 1)

	// mustEnqueue relies on the SMS subscription; since 316 an unsubscribed member gets the event's
	// default channels (none for node.offline), not the system-required pair used above.
	fixture.enableSMS(t)
	crashID := mustEnqueue(t, fixture.notificationFixture, "settlement-crash-window")
	claim, err := fixture.store.claim(t.Context(), WorkerConfig{
		BatchSize: 1, LeaseDuration: 2 * time.Second, LeaseSafetyMargin: time.Second,
		MaxAttempts: 3, BaseDelay: time.Second, MaxDelay: time.Minute,
	})
	if err != nil || len(claim.deliveries) != 1 || claim.deliveries[0].OutboxID != crashID {
		t.Fatalf("crash claim=%+v err=%v", claim, err)
	}
	if err := fixture.store.beginDispatch(t.Context(), claim.deliveries[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE notification_outbox
		SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, crashID); err != nil {
		t.Fatal(err)
	}
	recovered, err := fixture.store.claim(t.Context(), DefaultWorkerConfig())
	if err != nil || recovered.unknown != 1 || len(recovered.deliveries) != 0 {
		t.Fatalf("expired dispatch recovery=%+v err=%v", recovered, err)
	}
	assertOutboxStatusAttempt(t, fixture.pool, crashID, OutboxUnknown, 1)
	assertSettlement108(t, fixture.pool, crashID, "unknown", 2)
}

func TestNotificationProviderSettlementCancelReplayAuthorizationAuditAndIdempotency108(t *testing.T) {
	fixture := newSettlementFixture108(t)
	fixture.enableSMS(t)
	pendingID := mustEnqueue(t, fixture.notificationFixture, "settlement-cancel")
	platform := seedSettlementActor108(t, fixture.pool, "platform", "system_configuration.manage")
	tenant := seedSettlementActor108(t, fixture.pool, "tenant")

	denied := DeliveryCommand{ScopeID: fixture.scopeA, OutboxID: pendingID, RequestID: "tenant-cancel-1"}
	if _, err := fixture.store.CancelDelivery(t.Context(), tenant, denied); !errors.Is(err, ErrSettlementPermissionDenied) {
		t.Fatalf("tenant cancel err=%v", err)
	}
	assertCommandCounts108(t, fixture.pool, "tenant-cancel-1", 1, 0, 0)

	cancel := DeliveryCommand{ScopeID: fixture.scopeA, OutboxID: pendingID, RequestID: "platform-cancel-1"}
	cancelled, err := fixture.store.CancelDelivery(t.Context(), platform, cancel)
	if err != nil || cancelled.Replayed || cancelled.State != DeliveryCancelled {
		t.Fatalf("cancelled=%+v err=%v", cancelled, err)
	}
	cancelReplay, err := fixture.store.CancelDelivery(t.Context(), platform, cancel)
	if err != nil || !cancelReplay.Replayed || cancelReplay.State != DeliveryCancelled {
		t.Fatalf("cancel replay=%+v err=%v", cancelReplay, err)
	}
	assertCommandCounts108(t, fixture.pool, "platform-cancel-1", 1, 1, 1)

	replay := DeliveryCommand{ScopeID: fixture.scopeA, OutboxID: pendingID, RequestID: "platform-replay-1"}
	replayed, err := fixture.store.ReplayDelivery(t.Context(), platform, replay)
	if err != nil || replayed.Replayed || replayed.NewOutboxID == uuid.Nil || replayed.NewOutboxID == pendingID {
		t.Fatalf("replay=%+v err=%v", replayed, err)
	}
	replayAgain, err := fixture.store.ReplayDelivery(t.Context(), platform, replay)
	if err != nil || !replayAgain.Replayed || replayAgain.NewOutboxID != replayed.NewOutboxID {
		t.Fatalf("replay again=%+v err=%v", replayAgain, err)
	}
	var generation int
	var replayOf *uuid.UUID
	var dedup string
	if err := fixture.pool.QueryRow(t.Context(), `SELECT generation,replay_of_outbox_id,dedup_key
		FROM notification_outbox WHERE id=$1`, replayed.NewOutboxID).Scan(&generation, &replayOf, &dedup); err != nil {
		t.Fatal(err)
	}
	if generation != 2 || replayOf == nil || *replayOf != pendingID || dedup == "" {
		t.Fatalf("replay identity generation=%d replayOf=%v dedup=%q", generation, replayOf, dedup)
	}
	assertCommandCounts108(t, fixture.pool, "platform-replay-1", 1, 1, 1)

	acceptedID := mustEnqueue(t, fixture.notificationFixture, "settlement-no-cancel-accepted")
	config := DefaultWorkerConfig()
	config.BatchSize = 1
	worker, err := NewWorker(fixture.store, &recordingSender{scripts: map[uuid.UUID][]SendResult{
		acceptedID: {{Disposition: SendAccepted, Provider: "smtp"}},
	}}, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.ProcessBatch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.CancelDelivery(t.Context(), platform, DeliveryCommand{
		ScopeID: fixture.scopeA, OutboxID: acceptedID, RequestID: "accepted-cancel",
	}); !errors.Is(err, ErrSettlementConflict) {
		t.Fatalf("accepted cancel err=%v", err)
	}
}

type settlementFixture108 struct {
	*notificationFixture
}

func newSettlementFixture108(t *testing.T) *settlementFixture108 {
	t.Helper()
	pool := settlementPool108(t)
	clock := &lockedClock{now: notificationIntegrationTime}
	store, err := NewStoreWithClock(pool, audit.New(pool), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	tenantA, tenantB := uuid.New(), uuid.New()
	scopeA, scopeB, userID := uuid.New(), uuid.New(), uuid.New()
	username := "settlement-" + strings.ReplaceAll(userID.String(), "-", "")
	// Several statements with parameters: the extended protocol rejects them (42601).
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'Settlement A'),($2,'Settlement B');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($3,'tenant',$1),($4,'tenant',$2);
		INSERT INTO users(id,username,display_name,password_hash) VALUES($5,$6,'Settlement User','unused');
		INSERT INTO memberships(scope_id,user_id) VALUES($3,$5),($4,$5)`, pgx.QueryExecModeSimpleProtocol,
		tenantA, tenantB, scopeA, scopeB, userID, username); err != nil {
		t.Fatal(err)
	}
	sms := TemplateRef{ID: "node_offline", Version: 1, Channel: ChannelSMS}
	email := TemplateRef{ID: "node_offline", Version: 1, Channel: ChannelEmail}
	if err := store.SaveTemplate(t.Context(), TemplateDefinition{Ref: sms, Body: "node {{.name}} offline", Variables: []string{"name"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTemplate(t.Context(), TemplateDefinition{Ref: email, Subject: "offline", Body: "node {{.name}} offline", Variables: []string{"name"}}); err != nil {
		t.Fatal(err)
	}
	return &settlementFixture108{&notificationFixture{
		pool: pool, store: store, clock: clock, scopeA: scopeA, scopeB: scopeB,
		userID: userID, sms: sms, email: email,
	}}
}

func seedSettlementActor108(t *testing.T, pool *pgxpool.Pool, kind string, permissions ...string) SettlementActor {
	t.Helper()
	scopeID, userID, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	var tenantID *uuid.UUID
	if kind == "tenant" {
		value := uuid.New()
		tenantID = &value
		if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, value, "Settlement "+value.String()); err != nil {
			t.Fatal(err)
		}
	}
	username := "settlement-actor-" + strings.ReplaceAll(userID.String(), "-", "")
	roleName := "settlement-role-" + strings.ReplaceAll(roleID.String(), "-", "")
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,$2,$3);
		INSERT INTO users(id,username,display_name,password_hash) VALUES($4,$5,'Settlement Actor','unused');
		INSERT INTO memberships(scope_id,user_id) VALUES($1,$4);
		INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($6,$1,$7,'Settlement role',true);
		INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$4,$6)`, pgx.QueryExecModeSimpleProtocol,
		scopeID, kind, tenantID, userID, username, roleID, roleName); err != nil {
		t.Fatal(err)
	}
	for _, permission := range permissions {
		if _, err := pool.Exec(t.Context(), `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2)`, roleID, permission); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(sessionID[:])
	// Settlement commands check the session against the database clock (authorizeSettlementCommand).
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour')`,
		sessionID, uuid.New(), userID, scopeID, digest[:]); err != nil {
		t.Fatal(err)
	}
	return SettlementActor{UserID: userID, ScopeID: scopeID, SessionID: sessionID, ScopeKind: kind}
}

func failedSendAfter(class FailureClass, code string, retryAfter time.Duration) SendResult {
	failure := Failure{Class: class, Code: code, RetryAfter: retryAfter}
	return SendResult{Failure: &failure}
}

func assertSettlement108(t *testing.T, pool *pgxpool.Pool, outboxID uuid.UUID, state string, revision int) {
	t.Helper()
	var gotState string
	var gotRevision int
	var facts int
	if err := pool.QueryRow(t.Context(), `SELECT settlement.state,settlement.revision,
		(SELECT count(*) FROM notification_delivery_facts_108 fact WHERE fact.outbox_id=settlement.outbox_id)
		FROM notification_delivery_settlements_108 settlement WHERE outbox_id=$1`, outboxID).
		Scan(&gotState, &gotRevision, &facts); err != nil {
		t.Fatal(err)
	}
	if gotState != state || gotRevision != revision || facts != revision {
		t.Fatalf("settlement=%s/%d facts=%d want=%s/%d", gotState, gotRevision, facts, state, revision)
	}
}

func assertAttemptNoFailure108(t *testing.T, pool *pgxpool.Pool, outboxID uuid.UUID, outcome string) {
	t.Helper()
	var got string
	var code *string
	if err := pool.QueryRow(t.Context(), `SELECT outcome,failure_code FROM notification_attempts WHERE outbox_id=$1`, outboxID).Scan(&got, &code); err != nil {
		t.Fatal(err)
	}
	if got != outcome || code != nil {
		t.Fatalf("attempt=%s/%v want=%s/nil", got, code, outcome)
	}
}

func assertAttempt108(t *testing.T, pool *pgxpool.Pool, outboxID uuid.UUID, outcome, failure string) {
	t.Helper()
	var got, code string
	if err := pool.QueryRow(t.Context(), `SELECT outcome,failure_code FROM notification_attempts WHERE outbox_id=$1`, outboxID).Scan(&got, &code); err != nil {
		t.Fatal(err)
	}
	if got != outcome || code != failure {
		t.Fatalf("attempt=%s/%s want=%s/%s", got, code, outcome, failure)
	}
}

func assertCommandCounts108(t *testing.T, pool *pgxpool.Pool, requestID string, audits, receipts, facts int) {
	t.Helper()
	var gotAudits, gotReceipts, gotFacts int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM audit_events WHERE request_id=$1),
		(SELECT count(*) FROM notification_delivery_command_receipts_108 WHERE request_id=$1),
		(SELECT count(*) FROM notification_delivery_facts_108 WHERE request_id=$1)`, requestID).
		Scan(&gotAudits, &gotReceipts, &gotFacts); err != nil {
		t.Fatal(err)
	}
	if gotAudits != audits || gotReceipts != receipts || gotFacts != facts {
		t.Fatalf("request %s audits/receipts/facts=%d/%d/%d want=%d/%d/%d",
			requestID, gotAudits, gotReceipts, gotFacts, audits, receipts, facts)
	}
}

// settlementPool108 is a release-head schema: the worker, store and settlement code under test
// read tables added after 108 (notification_delivery_policy and later), so tests no longer stop
// at the 108 prefix (1.0.35 is the initial release).
func settlementPool108(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return headMigratedNotificationPool(t)
}
