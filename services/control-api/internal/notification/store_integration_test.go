//go:build integration

package notification

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
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

var notificationIntegrationTime = time.Date(2026, 7, 22, 6, 0, 0, 0, time.UTC)

type lockedClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *lockedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *lockedClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

type notificationFixture struct {
	pool   *pgxpool.Pool
	store  *Store
	clock  *lockedClock
	scopeA uuid.UUID
	scopeB uuid.UUID
	userID uuid.UUID
	sms    TemplateRef
	email  TemplateRef
}

func TestNotificationEnqueueRoutingDedupAndTenantIsolation(t *testing.T) {
	fixture := newNotificationFixture(t)
	ctx := context.Background()
	if err := fixture.store.SetChannelSwitches(ctx, ChannelSwitches{SMS: true, Email: true}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.SetSubscription(ctx, fixture.scopeA, fixture.userID, "node.offline", Subscription{SMS: true}); err != nil {
		t.Fatal(err)
	}

	request := fixture.request(fixture.scopeA, "duplicate-event", DeliveryTenantSubscribed)
	const writers = 16
	start := make(chan struct{})
	results := make(chan EnqueueResult, writers)
	errorsFound := make(chan error, writers)
	var wait sync.WaitGroup
	for range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := fixture.store.Enqueue(ctx, request)
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
		if len(result.Deliveries) != 1 || result.Deliveries[0].Channel != ChannelSMS {
			t.Fatalf("duplicate result = %+v", result)
		}
		if eventID == uuid.Nil {
			eventID, outboxID = result.EventID, result.Deliveries[0].OutboxID
		}
		if result.EventID != eventID || result.Deliveries[0].OutboxID != outboxID {
			t.Fatal("duplicate event returned different persisted identities")
		}
		if result.Replayed {
			replayed++
		} else {
			created++
		}
	}
	if created != 1 || replayed != writers-1 {
		t.Fatalf("created=%d replayed=%d", created, replayed)
	}
	assertCounts(t, fixture.pool, 1, 1, 0)
	var auditCount int
	if err := fixture.pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_events WHERE action = 'notification.event.enqueue'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("enqueue audit count = %d", auditCount)
	}

	if err := fixture.store.SetChannelSwitches(ctx, ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.SetSubscription(ctx, fixture.scopeA, fixture.userID, "node.offline", Subscription{SMS: true, Email: true}); err != nil {
		t.Fatal(err)
	}
	emailOnly, err := fixture.store.Enqueue(ctx, fixture.request(fixture.scopeA, "email-only", DeliveryTenantSubscribed))
	if err != nil {
		t.Fatal(err)
	}
	if len(emailOnly.Deliveries) != 1 || emailOnly.Deliveries[0].Channel != ChannelEmail {
		t.Fatalf("email-only result = %+v", emailOnly)
	}
	replayedOriginal, err := fixture.store.Enqueue(ctx, request)
	if err != nil || !replayedOriginal.Replayed || replayedOriginal.Deliveries[0].Channel != ChannelSMS {
		t.Fatalf("replay after switch change = %+v, %v", replayedOriginal, err)
	}

	if err := fixture.store.SetChannelSwitches(ctx, ChannelSwitches{}); err != nil {
		t.Fatal(err)
	}
	disabled, err := fixture.store.Enqueue(ctx, fixture.request(fixture.scopeA, "all-disabled", DeliverySystemRequired))
	if err != nil {
		t.Fatal(err)
	}
	if len(disabled.Deliveries) != 0 {
		t.Fatalf("disabled deliveries = %+v", disabled.Deliveries)
	}

	if err := fixture.store.SetChannelSwitches(ctx, ChannelSwitches{SMS: true, Email: true}); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.SetSubscription(ctx, fixture.scopeA, fixture.userID, "node.offline", Subscription{}); err != nil {
		t.Fatal(err)
	}
	requiredA, err := fixture.store.Enqueue(ctx, fixture.request(fixture.scopeA, "shared-event", DeliverySystemRequired))
	if err != nil {
		t.Fatal(err)
	}
	if len(requiredA.Deliveries) != 2 {
		t.Fatalf("required deliveries = %+v", requiredA.Deliveries)
	}
	requiredB, err := fixture.store.Enqueue(ctx, fixture.request(fixture.scopeB, "shared-event", DeliverySystemRequired))
	if err != nil {
		t.Fatal(err)
	}
	if len(requiredB.Deliveries) != 2 || requiredA.EventID == requiredB.EventID ||
		requiredA.Deliveries[0].DedupKey == requiredB.Deliveries[0].DedupKey {
		t.Fatalf("tenant-isolated results = %+v / %+v", requiredA, requiredB)
	}

	conflict := request
	conflict.Contexts = cloneContexts(request.Contexts)
	conflict.Contexts[ChannelSMS]["name"] = PublicValue("changed")
	if _, err := fixture.store.Enqueue(ctx, conflict); !errors.Is(err, ErrEventConflict) {
		t.Fatalf("conflicting replay error = %v", err)
	}
}

func TestNotificationRegistrationSuccessEventRendersPublishedUsername(t *testing.T) {
	fixture := newNotificationFixture(t)
	ctx := context.Background()
	if err := fixture.store.SetChannelSwitches(ctx, ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	ref := TemplateRef{ID: "platform_user_registration_success", Version: 1, Channel: ChannelEmail}
	if err := fixture.store.SaveTemplate(ctx, TemplateDefinition{
		Ref: ref, Subject: "注册成功", Body: "您好，{{.username}}，账户已创建。", Variables: []string{"username"},
	}); err != nil {
		t.Fatal(err)
	}
	result, err := fixture.store.Enqueue(ctx, EnqueueRequest{
		ScopeID:        fixture.scopeA,
		RecipientID:    fixture.userID,
		SourceEventID:  "account-registration-success:integration",
		EventType:      EventTypeAccountRegistrationSuccess,
		Policy:         DeliverySystemRequired,
		Templates:      map[Channel]TemplateRef{ChannelEmail: ref},
		Contexts:       map[Channel]TemplateContext{ChannelEmail: {"username": PublicValue("integration-user")}},
		AuditRequestID: "registration-success-integration",
	})
	if err != nil || len(result.Deliveries) != 1 {
		t.Fatalf("registration success enqueue=(%#v,%v)", result, err)
	}
	var subject, body string
	if err := fixture.pool.QueryRow(ctx, `SELECT subject,body FROM notification_outbox WHERE id=$1`, result.Deliveries[0].OutboxID).Scan(&subject, &body); err != nil {
		t.Fatal(err)
	}
	if subject != "注册成功" || body != "您好，integration-user，账户已创建。" {
		t.Fatalf("rendered registration success=(%q,%q)", subject, body)
	}
}

func TestNotificationWorkersClaimEachOutboxOnce(t *testing.T) {
	fixture := newNotificationFixture(t)
	ctx := context.Background()
	fixture.enableSMS(t)
	const eventCount = 24
	for index := 0; index < eventCount; index++ {
		if _, err := fixture.store.Enqueue(ctx, fixture.request(
			fixture.scopeA, fmt.Sprintf("claim-%02d", index), DeliveryTenantSubscribed,
		)); err != nil {
			t.Fatal(err)
		}
	}
	sender := &recordingSender{}
	config := DefaultWorkerConfig()
	config.BatchSize = eventCount
	first, err := NewWorker(fixture.store, sender, config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewWorker(fixture.store, sender, config)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan WorkerBatchResult, 2)
	errorsFound := make(chan error, 2)
	var wait sync.WaitGroup
	for _, worker := range []*Worker{first, second} {
		wait.Add(1)
		go func(worker *Worker) {
			defer wait.Done()
			<-start
			result, err := worker.ProcessBatch(ctx)
			results <- result
			errorsFound <- err
		}(worker)
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
	claimed, succeeded := 0, 0
	for result := range results {
		claimed += result.Claimed
		succeeded += result.Succeeded
	}
	if claimed != eventCount || succeeded != eventCount {
		t.Fatalf("claimed=%d succeeded=%d", claimed, succeeded)
	}
	if calls, unique := sender.snapshot(); calls != eventCount || unique != eventCount {
		t.Fatalf("sender calls=%d unique=%d", calls, unique)
	}
	assertOutboxStateCount(t, fixture.pool, OutboxSucceeded, eventCount)
	assertAttemptCount(t, fixture.pool, eventCount)
}

func TestNotificationWorkerLeaseUsesDatabaseClockAcrossInstances(t *testing.T) {
	fixture := newNotificationFixture(t)
	fixture.enableSMS(t)
	mustEnqueue(t, fixture, "clock-skew-lease")

	config := DefaultWorkerConfig()
	config.BatchSize = 1
	config.LeaseDuration = 30 * time.Second
	config.LeaseSafetyMargin = time.Second
	blocking := newBlockingSender()
	first, err := NewWorker(fixture.store, blocking, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	firstDone := make(chan error, 1)
	go func() {
		_, runErr := first.ProcessBatch(ctx)
		firstDone <- runErr
	}()
	<-blocking.started

	aheadClock := &lockedClock{now: time.Now().UTC().Add(24 * time.Hour)}
	aheadStore, err := NewStoreWithClock(fixture.pool, audit.New(fixture.pool), aheadClock.Now)
	if err != nil {
		t.Fatal(err)
	}
	secondSender := &recordingSender{}
	second, err := NewWorker(aheadStore, secondSender, config)
	if err != nil {
		t.Fatal(err)
	}
	result, err := second.ProcessBatch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Claimed != 0 || result.Succeeded != 0 {
		t.Fatalf("ahead-clock worker stole live lease: %+v", result)
	}
	if calls, _ := secondSender.snapshot(); calls != 0 {
		t.Fatalf("ahead-clock sender calls = %d", calls)
	}
	cancel()
	if err := <-firstDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("first worker error = %v", err)
	}
}

func TestNotificationSlowSenderStopsBeforeLeaseAndDoesNotClaimNext(t *testing.T) {
	fixture := newNotificationFixture(t)
	fixture.enableSMS(t)
	ctx := context.Background()
	firstID := mustEnqueue(t, fixture, "slow-first")
	secondID := mustEnqueue(t, fixture, "slow-second")
	sender := newBlockingSender()
	config := DefaultWorkerConfig()
	config.BatchSize = 2
	config.LeaseDuration = 300 * time.Millisecond
	config.LeaseSafetyMargin = 100 * time.Millisecond
	worker, err := NewWorker(fixture.store, sender, config)
	if err != nil {
		t.Fatal(err)
	}
	type workerResult struct {
		batch WorkerBatchResult
		err   error
	}
	done := make(chan workerResult, 1)
	go func() {
		batch, err := worker.ProcessBatch(ctx)
		done <- workerResult{batch: batch, err: err}
	}()
	observation := <-sender.started
	if !observation.hasDeadline {
		t.Fatal("sender context had no lease deadline")
	}
	deadlineBudget := time.Until(observation.deadline)
	if deadlineBudget <= 0 || deadlineBudget > config.LeaseDuration-config.LeaseSafetyMargin+50*time.Millisecond {
		t.Fatalf("sender deadline budget = %v", deadlineBudget)
	}
	result := <-done
	if !errors.Is(result.err, context.DeadlineExceeded) || result.batch.Claimed != 1 ||
		result.batch.Unknown != 1 || result.batch.Succeeded != 0 {
		t.Fatalf("slow sender result = %+v, %v", result.batch, result.err)
	}
	if calls, _ := sender.snapshot(); calls != 1 {
		t.Fatalf("slow sender calls = %d", calls)
	}
	assertOutboxStatusAttempt(t, fixture.pool, observation.delivery.OutboxID, OutboxUnknown, 1)
	assertAttempt(t, fixture.pool, observation.delivery.OutboxID, 1, "unknown", "provider_outcome_unknown")
	otherID := firstID
	if otherID == observation.delivery.OutboxID {
		otherID = secondID
	}
	assertOutboxStatusAttempt(t, fixture.pool, otherID, OutboxPending, 0)
	assertAttemptCount(t, fixture.pool, 1)
}

func TestNotificationWorkerContextCancellationStopsAfterCurrentClaim(t *testing.T) {
	fixture := newNotificationFixture(t)
	fixture.enableSMS(t)
	firstID := mustEnqueue(t, fixture, "cancel-first")
	secondID := mustEnqueue(t, fixture, "cancel-second")
	sender := newBlockingSender()
	config := DefaultWorkerConfig()
	config.BatchSize = 2
	worker, err := NewWorker(fixture.store, sender, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	type workerResult struct {
		batch WorkerBatchResult
		err   error
	}
	done := make(chan workerResult, 1)
	go func() {
		batch, err := worker.ProcessBatch(ctx)
		done <- workerResult{batch: batch, err: err}
	}()
	observation := <-sender.started
	cancel()
	result := <-done
	if !errors.Is(result.err, context.Canceled) || result.batch.Claimed != 1 ||
		result.batch.Unknown != 1 || result.batch.Succeeded != 0 {
		t.Fatalf("canceled worker result = %+v, %v", result.batch, result.err)
	}
	assertOutboxStatusAttempt(t, fixture.pool, observation.delivery.OutboxID, OutboxUnknown, 1)
	assertAttempt(t, fixture.pool, observation.delivery.OutboxID, 1, "unknown", "provider_outcome_unknown")
	otherID := firstID
	if otherID == observation.delivery.OutboxID {
		otherID = secondID
	}
	assertOutboxStatusAttempt(t, fixture.pool, otherID, OutboxPending, 0)
	assertAttemptCount(t, fixture.pool, 1)
}

func TestNotificationWorkerRefusesLeaseWithoutSafetyMargin(t *testing.T) {
	fixture := newNotificationFixture(t)
	fixture.enableSMS(t)
	outboxID := mustEnqueue(t, fixture, "unsafe-lease")
	config := DefaultWorkerConfig()
	config.BatchSize = 1
	config.LeaseDuration = 10 * time.Second
	config.LeaseSafetyMargin = 2 * time.Second
	claim, err := fixture.store.claim(context.Background(), config)
	if err != nil || len(claim.deliveries) != 1 {
		t.Fatalf("claim = %+v, %v", claim, err)
	}
	if err := fixture.pool.QueryRow(context.Background(), `
		UPDATE notification_outbox
		SET lease_expires_at = clock_timestamp() + interval '1 second'
		WHERE id = $1
		RETURNING lease_expires_at`, outboxID,
	).Scan(&claim.deliveries[0].LeaseExpiresAt); err != nil {
		t.Fatal(err)
	}
	sender := &recordingSender{}
	worker, err := NewWorker(fixture.store, sender, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := worker.processDelivery(context.Background(), claim.deliveries[0]); !errors.Is(err, ErrLeaseUnsafe) {
		t.Fatalf("unsafe lease error = %v", err)
	}
	if calls, _ := sender.snapshot(); calls != 0 {
		t.Fatalf("sender called %d times for unsafe lease", calls)
	}
	assertOutboxStatusAttempt(t, fixture.pool, outboxID, OutboxLeased, 1)
}

func TestNotificationSettlementUsesDatabaseClock(t *testing.T) {
	t.Run("valid lease ignores ahead process clock", func(t *testing.T) {
		fixture := newNotificationFixture(t)
		fixture.enableSMS(t)
		outboxID := mustEnqueue(t, fixture, "settle-ahead-clock")
		config := DefaultWorkerConfig()
		config.BatchSize = 1
		claim, err := fixture.store.claim(context.Background(), config)
		if err != nil || len(claim.deliveries) != 1 {
			t.Fatalf("claim = %+v, %v", claim, err)
		}
		aheadClock := &lockedClock{now: time.Now().UTC().Add(24 * time.Hour)}
		aheadStore, err := NewStoreWithClock(fixture.pool, audit.New(fixture.pool), aheadClock.Now)
		if err != nil {
			t.Fatal(err)
		}
		if err := aheadStore.beginDispatch(context.Background(), claim.deliveries[0]); err != nil {
			t.Fatal(err)
		}
		if err := aheadStore.settleSendResult(context.Background(), claim.deliveries[0],
			SendResult{Disposition: SendDelivered}, "", "", 0); err != nil {
			t.Fatalf("valid database lease settlement = %v", err)
		}
		assertOutboxStatusAttempt(t, fixture.pool, outboxID, OutboxSucceeded, 1)
	})

	t.Run("expired lease ignores behind process clock", func(t *testing.T) {
		fixture := newNotificationFixture(t)
		fixture.enableSMS(t)
		outboxID := mustEnqueue(t, fixture, "settle-behind-clock")
		config := DefaultWorkerConfig()
		config.BatchSize = 1
		claim, err := fixture.store.claim(context.Background(), config)
		if err != nil || len(claim.deliveries) != 1 {
			t.Fatalf("claim = %+v, %v", claim, err)
		}
		if err := fixture.store.beginDispatch(context.Background(), claim.deliveries[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(context.Background(), `
			UPDATE notification_outbox
			SET lease_expires_at = clock_timestamp() - interval '1 second'
			WHERE id = $1`, outboxID); err != nil {
			t.Fatal(err)
		}
		behindClock := &lockedClock{now: time.Unix(0, 0).UTC()}
		behindStore, err := NewStoreWithClock(fixture.pool, audit.New(fixture.pool), behindClock.Now)
		if err != nil {
			t.Fatal(err)
		}
		if err := behindStore.settleSendResult(context.Background(), claim.deliveries[0],
			SendResult{Disposition: SendDelivered}, "", "", 0); !errors.Is(err, ErrClaimLost) {
			t.Fatalf("expired database lease settlement error = %v", err)
		}
		assertOutboxStatusAttempt(t, fixture.pool, outboxID, OutboxLeased, 1)
	})
}

func TestNotificationConcurrentSettlementSucceedsOnce(t *testing.T) {
	fixture := newNotificationFixture(t)
	fixture.enableSMS(t)
	outboxID := mustEnqueue(t, fixture, "concurrent-settle")
	config := DefaultWorkerConfig()
	config.BatchSize = 1
	claim, err := fixture.store.claim(context.Background(), config)
	if err != nil || len(claim.deliveries) != 1 {
		t.Fatalf("claim = %+v, %v", claim, err)
	}
	if err := fixture.store.beginDispatch(context.Background(), claim.deliveries[0]); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			results <- fixture.store.settleSendResult(context.Background(), claim.deliveries[0],
				SendResult{Disposition: SendDelivered}, "", "", 0)
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	succeeded, lost := 0, 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrClaimLost):
			lost++
		default:
			t.Fatalf("settlement error = %v", err)
		}
	}
	if succeeded != 1 || lost != 1 {
		t.Fatalf("settlement success/lost = %d/%d", succeeded, lost)
	}
	assertOutboxStatusAttempt(t, fixture.pool, outboxID, OutboxSucceeded, 1)
	var completedAttempts int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM notification_attempts
		WHERE outbox_id = $1 AND outcome = 'succeeded'`, outboxID).Scan(&completedAttempts); err != nil {
		t.Fatal(err)
	}
	if completedAttempts != 1 {
		t.Fatalf("completed attempts = %d", completedAttempts)
	}
}

func TestNotificationPersistsAndSelectsExactTemplateVersion(t *testing.T) {
	fixture := newNotificationFixture(t)
	ctx := context.Background()
	fixture.enableSMS(t)
	versionTwo := TemplateRef{ID: fixture.sms.ID, Version: 2, Channel: ChannelSMS}
	definition := TemplateDefinition{
		Ref: versionTwo, Body: "版本二：{{.name}}", Variables: []string{"name"},
	}
	if err := fixture.store.SaveTemplate(ctx, definition); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.SaveTemplate(ctx, definition); !errors.Is(err, ErrTemplateExists) {
		t.Fatalf("duplicate template error = %v", err)
	}
	request := fixture.request(fixture.scopeA, "template-v2", DeliveryTenantSubscribed)
	request.Templates[ChannelSMS] = versionTwo
	result, err := fixture.store.Enqueue(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	var version uint64
	var body string
	if err := fixture.pool.QueryRow(ctx, `
		SELECT template_version, body FROM notification_outbox WHERE id = $1`,
		result.Deliveries[0].OutboxID).Scan(&version, &body); err != nil {
		t.Fatal(err)
	}
	if version != 2 || body != "版本二：edge-1" {
		t.Fatalf("persisted template = v%d %q", version, body)
	}
}

func TestNotificationLeaseRecoveryAndCrashExhaustion(t *testing.T) {
	fixture := newNotificationFixture(t)
	ctx := context.Background()
	fixture.enableSMS(t)
	firstEvent, err := fixture.store.Enqueue(ctx, fixture.request(fixture.scopeA, "crash-retry", DeliveryTenantSubscribed))
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultWorkerConfig()
	config.BatchSize, config.MaxAttempts, config.LeaseDuration = 1, 3, 10*time.Second
	firstClaim, err := fixture.store.claim(ctx, config)
	if err != nil || len(firstClaim.deliveries) != 1 {
		t.Fatalf("first claim = %+v, %v", firstClaim, err)
	}
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE notification_outbox
		SET lease_expires_at = clock_timestamp() - interval '1 second'
		WHERE id = $1`, firstEvent.Deliveries[0].OutboxID); err != nil {
		t.Fatal(err)
	}
	secondClaim, err := fixture.store.claim(ctx, config)
	if err != nil || len(secondClaim.deliveries) != 1 {
		t.Fatalf("recovered claim = %+v, %v", secondClaim, err)
	}
	if secondClaim.deliveries[0].OutboxID != firstEvent.Deliveries[0].OutboxID ||
		secondClaim.deliveries[0].AttemptNumber != 2 ||
		secondClaim.deliveries[0].LeaseToken == firstClaim.deliveries[0].LeaseToken {
		t.Fatalf("recovered delivery = %+v", secondClaim.deliveries[0])
	}
	assertAttempt(t, fixture.pool, firstEvent.Deliveries[0].OutboxID, 1, "lease_expired", expiredLeaseFailureCode)
	if err := fixture.store.beginDispatch(ctx, secondClaim.deliveries[0]); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.settleSendResult(ctx, secondClaim.deliveries[0],
		SendResult{Disposition: SendDelivered}, "", "", 0); err != nil {
		t.Fatal(err)
	}

	crashedFinal, err := fixture.store.Enqueue(ctx, fixture.request(fixture.scopeA, "crash-final", DeliveryTenantSubscribed))
	if err != nil {
		t.Fatal(err)
	}
	config.MaxAttempts = 1
	claim, err := fixture.store.claim(ctx, config)
	if err != nil || len(claim.deliveries) != 1 || claim.deliveries[0].OutboxID != crashedFinal.Deliveries[0].OutboxID {
		t.Fatalf("final claim = %+v, %v", claim, err)
	}
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE notification_outbox
		SET lease_expires_at = clock_timestamp() - interval '1 second'
		WHERE id = $1`, crashedFinal.Deliveries[0].OutboxID); err != nil {
		t.Fatal(err)
	}
	reaped, err := fixture.store.claim(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if reaped.exhausted != 1 || len(reaped.deliveries) != 0 {
		t.Fatalf("reaped claim = %+v", reaped)
	}
	assertOutbox(t, fixture.pool, crashedFinal.Deliveries[0].OutboxID, OutboxExhausted, expiredLeaseFailureCode, 1)
}

func TestNotificationWorkerFailureClassificationAndRetryExhaustion(t *testing.T) {
	fixture := newNotificationFixture(t)
	ctx := context.Background()
	fixture.enableSMS(t)
	temporary := mustEnqueue(t, fixture, "temporary")
	permanent := mustEnqueue(t, fixture, "permanent")
	unsafe := mustEnqueue(t, fixture, "unsafe-provider-detail")
	sender := &recordingSender{scripts: map[uuid.UUID][]SendResult{
		temporary: {
			failedSend(FailureTemporary, "provider_unavailable"),
			failedSend(FailureTemporary, "provider_unavailable"),
		},
		permanent: {failedSend(FailurePermanent, "recipient_invalid")},
		unsafe:    {failedSend(FailureTemporary, "raw provider secret value")},
	}}
	config := DefaultWorkerConfig()
	config.BatchSize, config.MaxAttempts = 3, 2
	config.BaseDelay, config.MaxDelay = 5*time.Second, 5*time.Second
	worker, err := NewWorker(fixture.store, sender, config)
	if err != nil {
		t.Fatal(err)
	}
	var databaseBefore time.Time
	if err := fixture.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&databaseBefore); err != nil {
		t.Fatal(err)
	}
	first, err := worker.ProcessBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var databaseAfter time.Time
	if err := fixture.pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&databaseAfter); err != nil {
		t.Fatal(err)
	}
	if first.Claimed != 3 || first.RetryScheduled != 1 || first.PermanentFailed != 2 {
		t.Fatalf("first batch = %+v", first)
	}
	assertOutbox(t, fixture.pool, temporary, OutboxPending, "provider_unavailable", 1)
	assertOutbox(t, fixture.pool, permanent, OutboxPermanentFailed, "recipient_invalid", 1)
	assertOutbox(t, fixture.pool, unsafe, OutboxPermanentFailed, "sender_contract_invalid", 1)
	var availableAt, nextAttemptAt time.Time
	if err := fixture.pool.QueryRow(ctx, `
		SELECT outbox.available_at, attempt.next_attempt_at
		FROM notification_outbox outbox
		JOIN notification_attempts attempt ON attempt.outbox_id = outbox.id AND attempt.attempt_number = 1
		WHERE outbox.id = $1`, temporary).Scan(&availableAt, &nextAttemptAt); err != nil {
		t.Fatal(err)
	}
	if !availableAt.Equal(nextAttemptAt) || availableAt.Before(databaseBefore.Add(5*time.Second)) ||
		availableAt.After(databaseAfter.Add(5*time.Second)) {
		t.Fatalf("temporary retry available_at = %v, database window = %v..%v", availableAt, databaseBefore, databaseAfter)
	}
	aheadClock := &lockedClock{now: time.Now().UTC().Add(24 * time.Hour)}
	aheadStore, err := NewStoreWithClock(fixture.pool, audit.New(fixture.pool), aheadClock.Now)
	if err != nil {
		t.Fatal(err)
	}
	premature, err := aheadStore.claim(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if len(premature.deliveries) != 0 || premature.exhausted != 0 {
		t.Fatalf("ahead-clock worker skipped retry delay: %+v", premature)
	}
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE notification_outbox SET available_at = clock_timestamp() WHERE id = $1`, temporary); err != nil {
		t.Fatal(err)
	}
	second, err := worker.ProcessBatch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.Claimed != 1 || second.Exhausted != 1 {
		t.Fatalf("second batch = %+v", second)
	}
	assertOutbox(t, fixture.pool, temporary, OutboxExhausted, "provider_unavailable", 2)
	assertAttempt(t, fixture.pool, temporary, 1, "temporary_failure", "provider_unavailable")
	assertAttempt(t, fixture.pool, temporary, 2, "exhausted", "provider_unavailable")
	if _, err := fixture.pool.Exec(ctx, `
		UPDATE notification_attempts SET outcome = 'lease_expired', next_attempt_at = NULL
		WHERE outbox_id = $1 AND attempt_number = 2`, temporary); err == nil {
		t.Fatal("terminal notification attempt was mutable")
	}
	var leaked int
	if err := fixture.pool.QueryRow(ctx, `
		SELECT count(*)
		FROM (
			SELECT last_failure_code AS value FROM notification_outbox
			UNION ALL
			SELECT failure_code FROM notification_attempts
		) codes
		WHERE value LIKE '%secret%' OR value LIKE '%raw%'`).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked != 0 {
		t.Fatal("unsafe provider detail reached persistence")
	}
}

func TestNotificationEnqueueRollbackAndSensitiveContext(t *testing.T) {
	fixture := newNotificationFixture(t)
	ctx := context.Background()
	fixture.enableSMS(t)
	if _, err := fixture.pool.Exec(ctx, `
		CREATE FUNCTION fail_notification_enqueue_audit()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF NEW.action = 'notification.event.enqueue' THEN
				RAISE EXCEPTION 'injected notification audit failure';
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER fail_notification_enqueue_audit_trigger
		BEFORE INSERT ON audit_events
		FOR EACH ROW EXECUTE FUNCTION fail_notification_enqueue_audit();`); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Enqueue(ctx, fixture.request(fixture.scopeA, "audit-failure", DeliveryTenantSubscribed)); err == nil {
		t.Fatal("audit failure was accepted")
	}
	assertCounts(t, fixture.pool, 0, 0, 0)
	var failedAuditRows int
	if err := fixture.pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_events WHERE action = 'notification.event.enqueue'`).Scan(&failedAuditRows); err != nil {
		t.Fatal(err)
	}
	if failedAuditRows != 0 {
		t.Fatalf("audit failure left %d audit rows", failedAuditRows)
	}
	if _, err := fixture.pool.Exec(ctx, `
		DROP TRIGGER fail_notification_enqueue_audit_trigger ON audit_events;
		DROP FUNCTION fail_notification_enqueue_audit();`); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.pool.Exec(ctx, `
		CREATE FUNCTION fail_notification_outbox_insert()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected notification outbox failure'; END;
		$$;
		CREATE TRIGGER fail_notification_outbox_insert_trigger
		BEFORE INSERT ON notification_outbox
		FOR EACH ROW EXECUTE FUNCTION fail_notification_outbox_insert();`); err != nil {
		t.Fatal(err)
	}
	tx, err := fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE tenants SET display_name = 'Changed in business tx' WHERE id = (
		SELECT tenant_id FROM access_scopes WHERE id = $1
	)`, fixture.scopeA); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.EnqueueTx(ctx, tx, fixture.request(fixture.scopeA, "outbox-failure", DeliveryTenantSubscribed)); err == nil {
		t.Fatal("outbox failure was accepted")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	assertCounts(t, fixture.pool, 0, 0, 0)
	if _, err := fixture.pool.Exec(ctx, `
		DROP TRIGGER fail_notification_outbox_insert_trigger ON notification_outbox;
		DROP FUNCTION fail_notification_outbox_insert();`); err != nil {
		t.Fatal(err)
	}

	tx, err = fixture.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE tenants SET display_name = 'Committed with notification' WHERE id = (
		SELECT tenant_id FROM access_scopes WHERE id = $1
	)`, fixture.scopeA); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.EnqueueTx(ctx, tx, fixture.request(fixture.scopeA, "tx-success", DeliveryTenantSubscribed)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assertCounts(t, fixture.pool, 1, 1, 0)

	sensitive := fixture.request(fixture.scopeA, "sensitive", DeliveryTenantSubscribed)
	sensitive.Contexts[ChannelSMS]["name"] = SensitiveValue("must-never-be-persisted")
	if _, err := fixture.store.Enqueue(ctx, sensitive); !errors.Is(err, ErrSensitiveContext) ||
		strings.Contains(err.Error(), "must-never-be-persisted") {
		t.Fatalf("sensitive enqueue error = %v", err)
	}
	var sensitiveRows int
	if err := fixture.pool.QueryRow(ctx, `
		SELECT count(*) FROM notification_events WHERE source_event_id = 'sensitive'`).Scan(&sensitiveRows); err != nil {
		t.Fatal(err)
	}
	if sensitiveRows != 0 {
		t.Fatal("sensitive context produced a persisted event")
	}
}

func TestNotificationPersistedFactsRejectDirectMutationAndTruncate(t *testing.T) {
	fixture := newNotificationFixture(t)
	fixture.enableSMS(t)
	result, err := fixture.store.Enqueue(context.Background(), fixture.request(
		fixture.scopeA, "immutable-facts", DeliveryTenantSubscribed,
	))
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewWorker(fixture.store, &recordingSender{}, DefaultWorkerConfig())
	if err != nil {
		t.Fatal(err)
	}
	if batch, err := worker.ProcessBatch(context.Background()); err != nil || batch.Succeeded != 1 {
		t.Fatalf("complete immutable outbox = %+v, %v", batch, err)
	}
	outboxID := result.Deliveries[0].OutboxID
	operations := []struct {
		name string
		sql  string
		args []any
	}{
		{name: "template update", sql: `UPDATE notification_templates SET body = 'changed' WHERE template_id = $1 AND version = $2 AND channel = $3`, args: []any{fixture.sms.ID, fixture.sms.Version, fixture.sms.Channel}},
		{name: "template delete", sql: `DELETE FROM notification_templates WHERE template_id = $1 AND version = $2 AND channel = $3`, args: []any{fixture.sms.ID, fixture.sms.Version, fixture.sms.Channel}},
		{name: "template truncate", sql: `TRUNCATE notification_templates CASCADE`},
		{name: "event update", sql: `UPDATE notification_events SET source_event_id = 'changed' WHERE id = $1`, args: []any{result.EventID}},
		{name: "event delete", sql: `DELETE FROM notification_events WHERE id = $1`, args: []any{result.EventID}},
		{name: "event truncate", sql: `TRUNCATE notification_events CASCADE`},
		{name: "outbox body update", sql: `UPDATE notification_outbox SET body = 'changed' WHERE id = $1`, args: []any{outboxID}},
		{name: "outbox template update", sql: `UPDATE notification_outbox SET template_version = template_version + 1 WHERE id = $1`, args: []any{outboxID}},
		{name: "outbox dedup update", sql: `UPDATE notification_outbox SET dedup_key = 'notification-v1-' || repeat('0', 64) WHERE id = $1`, args: []any{outboxID}},
		{name: "outbox terminal state update", sql: `UPDATE notification_outbox SET status = 'pending', completed_at = NULL, available_at = CURRENT_TIMESTAMP WHERE id = $1`, args: []any{outboxID}},
		{name: "outbox delete", sql: `DELETE FROM notification_outbox WHERE id = $1`, args: []any{outboxID}},
		{name: "outbox truncate", sql: `TRUNCATE notification_outbox CASCADE`},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			if _, err := fixture.pool.Exec(context.Background(), operation.sql, operation.args...); err == nil {
				t.Fatal("direct mutation was accepted")
			} else if !strings.Contains(err.Error(), "immutable") {
				t.Fatalf("unexpected mutation error = %v", err)
			}
		})
	}
	var templateVersion uint64
	var dedupKey, body, status string
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT template_version, dedup_key, body, status FROM notification_outbox WHERE id = $1`, outboxID,
	).Scan(&templateVersion, &dedupKey, &body, &status); err != nil {
		t.Fatal(err)
	}
	if templateVersion != fixture.sms.Version || dedupKey != result.Deliveries[0].DedupKey ||
		body != "节点 edge-1 已离线" || status != OutboxSucceeded {
		t.Fatalf("persisted facts changed: v%d %s %q %s", templateVersion, dedupKey, body, status)
	}
}

func TestNotificationMigration029UpDownUp(t *testing.T) {
	pool := isolatedNotificationPoolThrough(t, 29)
	ctx := context.Background()
	down, err := migrations.FS.ReadFile("029_notification_outbox.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, err := migrations.FS.ReadFile("029_notification_outbox.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, string(down)); err != nil {
		t.Fatalf("029 down: %v", err)
	}
	var table *string
	if err := pool.QueryRow(ctx, `SELECT to_regclass('notification_outbox')::text`).Scan(&table); err != nil {
		t.Fatal(err)
	}
	if table != nil {
		t.Fatalf("notification_outbox survived down: %s", *table)
	}
	if _, err := pool.Exec(ctx, string(up)); err != nil {
		t.Fatalf("029 reapply: %v", err)
	}
	var settings int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM notification_channel_settings`).Scan(&settings); err != nil {
		t.Fatal(err)
	}
	if settings != 1 {
		t.Fatalf("settings rows after reapply = %d", settings)
	}
}

type recordingSender struct {
	mu      sync.Mutex
	scripts map[uuid.UUID][]SendResult
	calls   []uuid.UUID
}

type sendObservation struct {
	delivery    DeliveryAttempt
	deadline    time.Time
	hasDeadline bool
}

type blockingSender struct {
	mu      sync.Mutex
	calls   []uuid.UUID
	started chan sendObservation
}

func newBlockingSender() *blockingSender {
	return &blockingSender{started: make(chan sendObservation, 1)}
}

func (s *blockingSender) Send(ctx context.Context, delivery DeliveryAttempt) SendResult {
	deadline, hasDeadline := ctx.Deadline()
	s.mu.Lock()
	s.calls = append(s.calls, delivery.OutboxID)
	s.mu.Unlock()
	s.started <- sendObservation{
		delivery: delivery, deadline: deadline, hasDeadline: hasDeadline,
	}
	<-ctx.Done()
	return SendResult{Disposition: SendUnknown, Provider: "test"}
}

func (s *blockingSender) snapshot() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unique := make(map[uuid.UUID]struct{}, len(s.calls))
	for _, id := range s.calls {
		unique[id] = struct{}{}
	}
	return len(s.calls), len(unique)
}

func (s *recordingSender) Send(_ context.Context, delivery DeliveryAttempt) SendResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, delivery.OutboxID)
	if len(s.scripts[delivery.OutboxID]) == 0 {
		return SendResult{Disposition: SendDelivered}
	}
	result := s.scripts[delivery.OutboxID][0]
	s.scripts[delivery.OutboxID] = s.scripts[delivery.OutboxID][1:]
	return result
}

func (s *recordingSender) snapshot() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unique := make(map[uuid.UUID]struct{}, len(s.calls))
	for _, id := range s.calls {
		unique[id] = struct{}{}
	}
	return len(s.calls), len(unique)
}

func failedSend(class FailureClass, code string) SendResult {
	failure := Failure{Class: class, Code: code}
	return SendResult{Failure: &failure}
}

func newNotificationFixture(t *testing.T) *notificationFixture {
	t.Helper()
	return seedNotificationFixture(t, settlementPool108(t))
}

func seedNotificationFixture(t *testing.T, pool *pgxpool.Pool) *notificationFixture {
	t.Helper()
	clock := &lockedClock{now: notificationIntegrationTime}
	store, err := NewStoreWithClock(pool, audit.New(pool), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	tenantA, tenantB := uuid.New(), uuid.New()
	scopeA, scopeB := uuid.New(), uuid.New()
	userID := uuid.New()
	username := "notify-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id, display_name) VALUES ($1, 'Notification A'), ($2, 'Notification B')`,
		tenantA, tenantB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1, 'tenant', $2), ($3, 'tenant', $4)`,
		scopeA, tenantA, scopeB, tenantB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id, username, display_name, password_hash)
		VALUES ($1, $2, 'Notification User', 'unused')`, userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO memberships (scope_id, user_id) VALUES ($1, $3), ($2, $3)`,
		scopeA, scopeB, userID); err != nil {
		t.Fatal(err)
	}
	sms := TemplateRef{ID: "node_offline", Version: 1, Channel: ChannelSMS}
	email := TemplateRef{ID: "node_offline", Version: 1, Channel: ChannelEmail}
	if err := store.SaveTemplate(ctx, TemplateDefinition{
		Ref: sms, Body: "节点 {{.name}} 已离线", Variables: []string{"name"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveTemplate(ctx, TemplateDefinition{
		Ref: email, Subject: "节点离线", Body: "节点 {{.name}} 已离线", Variables: []string{"name"},
	}); err != nil {
		t.Fatal(err)
	}
	return &notificationFixture{
		pool: pool, store: store, clock: clock, scopeA: scopeA, scopeB: scopeB,
		userID: userID, sms: sms, email: email,
	}
}

func (f *notificationFixture) request(scopeID uuid.UUID, eventID string, policy DeliveryPolicy) EnqueueRequest {
	actor := f.userID
	return EnqueueRequest{
		ScopeID: scopeID, RecipientID: f.userID, SourceEventID: eventID,
		EventType: "node.offline", Policy: policy,
		Templates: map[Channel]TemplateRef{ChannelSMS: f.sms, ChannelEmail: f.email},
		Contexts: map[Channel]TemplateContext{
			ChannelSMS: {"name": PublicValue("edge-1")}, ChannelEmail: {"name": PublicValue("edge-1")},
		},
		ActorUserID: &actor, AuditRequestID: "notify-" + eventID,
	}
}

func (f *notificationFixture) enableSMS(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if err := f.store.SetChannelSwitches(ctx, ChannelSwitches{SMS: true}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetSubscription(ctx, f.scopeA, f.userID, "node.offline", Subscription{SMS: true}); err != nil {
		t.Fatal(err)
	}
}

func mustEnqueue(t *testing.T, fixture *notificationFixture, eventID string) uuid.UUID {
	t.Helper()
	result, err := fixture.store.Enqueue(context.Background(), fixture.request(fixture.scopeA, eventID, DeliveryTenantSubscribed))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Deliveries) != 1 {
		t.Fatalf("deliveries = %+v", result.Deliveries)
	}
	return result.Deliveries[0].OutboxID
}

func cloneContexts(source map[Channel]TemplateContext) map[Channel]TemplateContext {
	cloned := make(map[Channel]TemplateContext, len(source))
	for channel, context := range source {
		cloned[channel] = make(TemplateContext, len(context))
		for name, value := range context {
			cloned[channel][name] = value
		}
	}
	return cloned
}

func assertCounts(t *testing.T, pool *pgxpool.Pool, events, outbox, attempts int) {
	t.Helper()
	var gotEvents, gotOutbox, gotAttempts int
	if err := pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM notification_events),
		       (SELECT count(*) FROM notification_outbox),
		       (SELECT count(*) FROM notification_attempts)`).Scan(&gotEvents, &gotOutbox, &gotAttempts); err != nil {
		t.Fatal(err)
	}
	if gotEvents != events || gotOutbox != outbox || gotAttempts != attempts {
		t.Fatalf("counts = %d/%d/%d, want %d/%d/%d", gotEvents, gotOutbox, gotAttempts, events, outbox, attempts)
	}
}

func assertOutboxStateCount(t *testing.T, pool *pgxpool.Pool, status string, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM notification_outbox WHERE status = $1`, status).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("outbox status %s count = %d, want %d", status, got, want)
	}
}

func assertOutboxStatusAttempt(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, status string, attempts int) {
	t.Helper()
	var gotStatus string
	var gotAttempts int
	if err := pool.QueryRow(context.Background(), `
		SELECT status, attempt_count FROM notification_outbox WHERE id = $1`, id,
	).Scan(&gotStatus, &gotAttempts); err != nil {
		t.Fatal(err)
	}
	if gotStatus != status || gotAttempts != attempts {
		t.Fatalf("outbox = %s/%d, want %s/%d", gotStatus, gotAttempts, status, attempts)
	}
}

func assertAttemptCount(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM notification_attempts`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("attempt count = %d, want %d", got, want)
	}
}

func assertAttempt(t *testing.T, pool *pgxpool.Pool, outboxID uuid.UUID, attempt int, outcome, code string) {
	t.Helper()
	var gotOutcome string
	var gotCode *string
	if err := pool.QueryRow(context.Background(), `
		SELECT outcome, failure_code FROM notification_attempts
		WHERE outbox_id = $1 AND attempt_number = $2`, outboxID, attempt).Scan(&gotOutcome, &gotCode); err != nil {
		t.Fatal(err)
	}
	if gotOutcome != outcome || gotCode == nil || *gotCode != code {
		t.Fatalf("attempt = %s/%v, want %s/%s", gotOutcome, gotCode, outcome, code)
	}
}

func assertOutbox(t *testing.T, pool *pgxpool.Pool, id uuid.UUID, status, failure string, attempts int) {
	t.Helper()
	var gotStatus string
	var gotFailure *string
	var gotAttempts int
	if err := pool.QueryRow(context.Background(), `
		SELECT status, last_failure_code, attempt_count FROM notification_outbox WHERE id = $1`, id,
	).Scan(&gotStatus, &gotFailure, &gotAttempts); err != nil {
		t.Fatal(err)
	}
	if gotStatus != status || gotFailure == nil || *gotFailure != failure || gotAttempts != attempts {
		t.Fatalf("outbox = %s/%v/%d, want %s/%s/%d", gotStatus, gotFailure, gotAttempts, status, failure, attempts)
	}
}

func isolatedNotificationPoolThrough(t *testing.T, through int) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "notification_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if !regexp.MustCompile(`^notification_test_[a-f0-9]{32}$`).MatchString(schema) {
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
	if err := migrateNotificationSchema(ctx, pool, through); err != nil {
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
			t.Errorf("drop notification schema: %v", err)
		}
		admin.Close()
	})
	return pool
}

func migrateNotificationSchema(ctx context.Context, pool *pgxpool.Pool, through int) error {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	for _, entry := range entries {
		var version int
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		if _, err := fmt.Sscanf(entry.Name(), "%d_", &version); err != nil || version > through {
			continue
		}
		script, err := migrations.FS.ReadFile(entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %d: %w", version, err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %d: %w", version, err)
		}
		if _, err := tx.Exec(ctx, string(script)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %d: %w", version, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %d: %w", version, err)
		}
	}
	return nil
}
