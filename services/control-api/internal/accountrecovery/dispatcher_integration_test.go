package accountrecovery

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var errInjectedDispatch = errors.New("injected account recovery dispatch failure")

type recordingRecoverySender struct {
	mu         sync.Mutex
	calls      int
	deliveries map[string]RecoveryDelivery
	failure    *notification.Failure
	result     notification.SendResult
}

func (s *recordingRecoverySender) SendRecovery(_ context.Context, delivery RecoveryDelivery) notification.SendResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.failure != nil {
		failure := *s.failure
		return notification.SendResult{Failure: &failure}
	}
	if s.deliveries == nil {
		s.deliveries = make(map[string]RecoveryDelivery)
	}
	if _, exists := s.deliveries[delivery.IdempotencyKey]; !exists {
		s.deliveries[delivery.IdempotencyKey] = delivery
	}
	if s.result.Disposition != "" || s.result.Provider != "" || s.result.ProviderDeliveryID != "" {
		return s.result
	}
	return notification.SendResult{Disposition: notification.SendDelivered}
}

func (s *recordingRecoverySender) snapshot() (int, []RecoveryDelivery) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := make([]RecoveryDelivery, 0, len(s.deliveries))
	for _, delivery := range s.deliveries {
		items = append(items, delivery)
	}
	return s.calls, items
}

type rejectingMemberSender struct{}

func (rejectingMemberSender) Send(context.Context, notification.DeliveryAttempt) notification.SendResult {
	return notification.SendResult{Failure: &notification.Failure{
		Class: notification.FailurePermanent, Code: "member_route_forbidden",
	}}
}

type failAfterEnqueue struct {
	inner DispatchEnqueuer
}

func (f failAfterEnqueue) EnqueueDispatchTx(
	ctx context.Context,
	tx pgx.Tx,
	request notification.DispatchEnqueueRequest,
) (notification.EnqueueResult, error) {
	if _, err := f.inner.EnqueueDispatchTx(ctx, tx, request); err != nil {
		return notification.EnqueueResult{}, err
	}
	return notification.EnqueueResult{}, errInjectedDispatch
}

func TestTransactionalDispatchSurvivesProcessRestartAndKeepsSecretsIsolated(t *testing.T) {
	f := seedFixture(t, isolatedPool(t, true), 20, 20)
	key := "crash-recovery"
	if _, err := f.service.Request(t.Context(), requestInput(f, f.username, key, "198.51.100.80")); err != nil {
		t.Fatal(err)
	}
	if events, outbox, claims := recoveryDispatchCounts(t, f.pool); events != 1 || outbox != 1 || claims != 1 {
		t.Fatalf("committed dispatch facts = %d/%d/%d, want 1/1/1", events, outbox, claims)
	}
	expected := recoveryDeliveryForRequest(t, f, key)

	sender := &recordingRecoverySender{}
	dispatcher := newTestDispatcher(t, f, f.keyring, sender)
	worker, err := notification.NewWorkerWithAnonymousDispatcher(
		f.store, rejectingMemberSender{}, dispatcher, notification.DefaultWorkerConfig(),
	)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := worker.ProcessBatch(t.Context())
	if err != nil || batch.Succeeded != 1 || batch.NoopAcknowledged != 0 {
		t.Fatalf("restarted worker batch = %+v, %v", batch, err)
	}
	calls, deliveries := sender.snapshot()
	if calls != 1 || len(deliveries) != 1 {
		t.Fatalf("recovery sender calls/deliveries = %d/%d", calls, len(deliveries))
	}
	delivery := deliveries[0]
	parsed, err := url.Parse(delivery.RecoveryURL)
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := url.ParseQuery(parsed.Fragment)
	if err != nil {
		t.Fatal(err)
	}
	if delivery.Contact != f.username || parsed.Scheme != "https" || parsed.Host != "control.example.test" ||
		parsed.Path != "/forget-password" || parsed.RawQuery != "" || fragment.Get("token") != expected.Token ||
		fragment.Get("recovery_context") == "" ||
		delivery.IdempotencyKey == "" || delivery.AttemptNumber != 1 {
		t.Fatalf("recovery delivery metadata invalid: contact_match=%t scheme=%q host=%q path=%q key_present=%t attempt=%d",
			delivery.Contact == f.username, parsed.Scheme, parsed.Host, parsed.Path,
			delivery.IdempotencyKey != "", delivery.AttemptNumber)
	}
	scope, err := VerifyRecoveryContext(testDigestKey, expected.Token,
		fragment.Get("recovery_context"), f.clock.Now())
	if err != nil || scope.TenantID != f.tenantID || scope.ScopeID != f.scopeID {
		t.Fatalf("verify recovery context = (%+v, %v)", scope, err)
	}
	assertDispatchSecretsIsolated(t, f, key, expected.Token)
}

func TestPublishedSystemUserRecoveryTemplateRendersAtDispatch(t *testing.T) {
	f := newFixture(t, 20, 20)
	published := notification.TemplateRef{
		ID: "platform_user_account_recovery", Version: 9, Channel: notification.ChannelEmail,
	}
	if err := f.store.SaveTemplate(t.Context(), notification.TemplateDefinition{
		Ref: published, Subject: "找回密码：{{.username}}", Body: "<p>您好，{{.username}}。</p>",
		Variables: []string{"username"},
	}); err != nil {
		t.Fatal(err)
	}
	config := testConfig(f)
	config.TemplateResolver = recoveryTemplateResolver{email: published}
	service, err := NewServiceWithDependencies(f.pool, config, audit.New(f.pool))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Request(t.Context(), requestInput(f, f.username, "published-dispatch", "198.51.100.45")); err != nil {
		t.Fatal(err)
	}
	sender := &recordingRecoverySender{}
	dispatcher := newTestDispatcher(t, f, f.keyring, sender)
	result := dispatcher.Dispatch(t.Context(), dispatchAttemptForRequest(t, f, "published-dispatch"))
	if result.Disposition != notification.AnonymousDispatchDelivered || result.Failure != nil {
		t.Fatalf("published template dispatch result=%+v", result)
	}
	_, deliveries := sender.snapshot()
	if len(deliveries) != 1 || deliveries[0].Subject != "找回密码："+f.username ||
		deliveries[0].Body != "<p>您好，"+f.username+"。</p>" || strings.Contains(deliveries[0].Body, "{{") {
		t.Fatalf("published recovery delivery=%#v", deliveries)
	}
}

func TestDispatcherNoopAcknowledgesInvalidatedClaims(t *testing.T) {
	f := newFixture(t, 20, 20)
	sender := &recordingRecoverySender{}
	dispatcher := newTestDispatcher(t, f, f.keyring, sender)

	if _, err := f.service.Request(t.Context(), requestInput(f, "missing@example.test", "noop-missing", "198.51.100.81")); err != nil {
		t.Fatal(err)
	}
	assertNoopDispatch(t, dispatcher, dispatchAttemptForRequest(t, f, "noop-missing"))

	if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "noop-revoked", "198.51.100.82")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "noop-replacement", "198.51.100.83")); err != nil {
		t.Fatal(err)
	}
	assertNoopDispatch(t, dispatcher, dispatchAttemptForRequest(t, f, "noop-revoked"))

	if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "noop-contact", "198.51.100.84")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE users SET email='changed@example.test' WHERE id=$1`, f.userID); err != nil {
		t.Fatal(err)
	}
	assertNoopDispatch(t, dispatcher, dispatchAttemptForRequest(t, f, "noop-contact"))

	if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "noop-principal", "198.51.100.85")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE users SET revision=revision+1 WHERE id=$1`, f.userID); err != nil {
		t.Fatal(err)
	}
	assertNoopDispatch(t, dispatcher, dispatchAttemptForRequest(t, f, "noop-principal"))

	if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "noop-consumed", "198.51.100.86")); err != nil {
		t.Fatal(err)
	}
	token := recoveryDeliveryForRequest(t, f, "noop-consumed").Token
	if _, err := f.service.Reset(t.Context(), resetInput(f, token, "noop-consume-reset", "Changed-password-1234")); err != nil {
		t.Fatal(err)
	}
	assertNoopDispatch(t, dispatcher, dispatchAttemptForRequest(t, f, "noop-consumed"))

	if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "noop-expired", "198.51.100.87")); err != nil {
		t.Fatal(err)
	}
	expiresAt := recoveryDeliveryForRequest(t, f, "noop-expired").ExpiresAt
	f.clock.Set(expiresAt)
	assertNoopDispatch(t, dispatcher, dispatchAttemptForRequest(t, f, "noop-expired"))

	calls, deliveries := sender.snapshot()
	if calls != 0 || len(deliveries) != 0 {
		t.Fatalf("noop claims reached sender: calls=%d deliveries=%d", calls, len(deliveries))
	}
}

func TestDispatcherSupportsKEKRotationAndClassifiesSenderFailures(t *testing.T) {
	f := newFixture(t, 20, 20)
	if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "rotation-old", "198.51.100.88")); err != nil {
		t.Fatal(err)
	}
	newOnly, err := NewDispatchKeyring("recovery-test-v2", map[string][]byte{
		"recovery-test-v2": bytes.Repeat([]byte{0x6c}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	oldAttempt := dispatchAttemptForRequest(t, f, "rotation-old")
	missingKey := newTestDispatcher(t, f, newOnly, &recordingRecoverySender{}).
		Dispatch(t.Context(), oldAttempt)
	if missingKey.Failure == nil || missingKey.Failure.Class != notification.FailureTemporary ||
		missingKey.Failure.Code != "account_recovery_key_unavailable" {
		t.Fatalf("missing old KEK classification = %+v", missingKey)
	}
	rotated, err := NewDispatchKeyring("recovery-test-v2", map[string][]byte{
		"recovery-test-v1": bytes.Repeat([]byte{0x5b}, 32),
		"recovery-test-v2": bytes.Repeat([]byte{0x6c}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	sender := &recordingRecoverySender{}
	dispatcher := newTestDispatcher(t, f, rotated, sender)
	result := dispatcher.Dispatch(t.Context(), oldAttempt)
	if result.Disposition != notification.AnonymousDispatchDelivered || result.Failure != nil {
		t.Fatalf("old KEK dispatch after rotation = %+v", result)
	}

	config := testConfig(f)
	config.DispatchKeyring = rotated
	rotatedService, err := NewServiceWithDependencies(f.pool, config, audit.New(f.pool))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotatedService.Request(t.Context(), requestInput(f, f.username, "rotation-new", "198.51.100.89")); err != nil {
		t.Fatal(err)
	}
	var keyID string
	if err := f.pool.QueryRow(t.Context(), `SELECT claim.kek_key_id
		FROM account_recovery_dispatch_claims claim
		JOIN account_recovery_challenges challenge ON challenge.id=claim.challenge_id
		JOIN account_recovery_write_requests write_request ON write_request.id=challenge.issued_by_write_id
		WHERE write_request.idempotency_key='rotation-new'`).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	if keyID != "recovery-test-v2" {
		t.Fatalf("new claim KEK = %q", keyID)
	}

	newAttempt := dispatchAttemptForRequest(t, f, "rotation-new")
	for _, test := range []struct {
		class notification.FailureClass
		code  string
	}{
		{notification.FailureTemporary, "mail_transport_unavailable"},
		{notification.FailurePermanent, "recipient_rejected"},
	} {
		failureSender := &recordingRecoverySender{failure: &notification.Failure{Class: test.class, Code: test.code}}
		failureDispatcher := newTestDispatcher(t, f, rotated, failureSender)
		failure := failureDispatcher.Dispatch(t.Context(), newAttempt).Failure
		if failure == nil || failure.Class != test.class || failure.Code != test.code {
			t.Fatalf("sender failure classification = %+v, want %s/%s", failure, test.class, test.code)
		}
	}
}

func TestDispatcherPropagatesProviderAcceptedAndUnknown(t *testing.T) {
	observation := notification.NewDispatchObservation(notification.ChannelEmail, "member@example.test", time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC))
	for _, test := range []struct {
		name string
		send notification.SendResult
		want notification.AnonymousDispatchResult
	}{
		{
			name: "accepted",
			send: notification.SendResult{
				Disposition: notification.SendAccepted, Provider: "configured_email",
				ProviderDeliveryID: "provider-delivery-1",
				Observation:        observation,
			},
			want: notification.AnonymousDispatchResult{
				Disposition: notification.AnonymousDispatchAccepted, Provider: "configured_email",
				ProviderDeliveryID: "provider-delivery-1",
				Observation:        observation,
			},
		},
		{
			name: "unknown",
			send: notification.SendResult{
				Disposition: notification.SendUnknown, Provider: "configured_email",
				Observation: observation,
			},
			want: notification.AnonymousDispatchResult{
				Disposition: notification.AnonymousDispatchUnknown, Provider: "configured_email",
				Observation: observation,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newFixture(t, 20, 20)
			key := "provider-" + test.name
			if _, err := f.service.Request(t.Context(), requestInput(f, f.username, key, "198.51.100.96")); err != nil {
				t.Fatal(err)
			}
			sender := &recordingRecoverySender{result: test.send}
			got := newTestDispatcher(t, f, f.keyring, sender).
				Dispatch(t.Context(), dispatchAttemptForRequest(t, f, key))
			if got != test.want {
				t.Fatalf("dispatch result = %+v, want %+v", got, test.want)
			}
			if calls, deliveries := sender.snapshot(); calls != 1 || len(deliveries) != 1 {
				t.Fatalf("sender calls/deliveries = %d/%d", calls, len(deliveries))
			}
		})
	}
}

func TestDispatcherRejectsPersistedCiphertextTampering(t *testing.T) {
	f := newFixture(t, 20, 20)
	if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "tampered-claim", "198.51.100.90")); err != nil {
		t.Fatal(err)
	}
	attempt := dispatchAttemptForRequest(t, f, "tampered-claim")
	if _, err := f.pool.Exec(t.Context(), `ALTER TABLE account_recovery_dispatch_claims
		DISABLE TRIGGER account_recovery_dispatch_claims_protected_050`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `UPDATE account_recovery_dispatch_claims
		SET sealed_token=set_byte(sealed_token,20,get_byte(sealed_token,20) # 255)
		WHERE reference=$1`, attempt.AnonymousDispatchReference); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(t.Context(), `ALTER TABLE account_recovery_dispatch_claims
		ENABLE TRIGGER account_recovery_dispatch_claims_protected_050`); err != nil {
		t.Fatal(err)
	}
	result := newTestDispatcher(t, f, f.keyring, &recordingRecoverySender{}).Dispatch(t.Context(), attempt)
	if result.Failure == nil || result.Failure.Class != notification.FailurePermanent ||
		result.Failure.Code != "account_recovery_claim_invalid" || result.Disposition != "" {
		t.Fatalf("tampered claim dispatch = %+v", result)
	}
}

func TestDispatcherRejectsForgedAndStaleNotificationAttempts(t *testing.T) {
	f := newFixture(t, 20, 20)
	if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "forged-attempt", "198.51.100.95")); err != nil {
		t.Fatal(err)
	}
	valid := dispatchAttemptForRequest(t, f, "forged-attempt")
	sender := &recordingRecoverySender{}
	dispatcher := newTestDispatcher(t, f, f.keyring, sender)
	for _, test := range []struct {
		name   string
		mutate func(*notification.AnonymousDeliveryAttempt)
	}{
		{"outbox ID", func(item *notification.AnonymousDeliveryAttempt) { item.OutboxID = uuid.New() }},
		{"event ID", func(item *notification.AnonymousDeliveryAttempt) { item.EventID = uuid.New() }},
		{"channel", func(item *notification.AnonymousDeliveryAttempt) { item.Channel = notification.ChannelSMS }},
		{"dedup key", func(item *notification.AnonymousDeliveryAttempt) { item.DedupKey += "-forged" }},
		{"body", func(item *notification.AnonymousDeliveryAttempt) { item.Body += " forged" }},
		{"lease token", func(item *notification.AnonymousDeliveryAttempt) { item.LeaseToken = uuid.New() }},
		{"lease expiry", func(item *notification.AnonymousDeliveryAttempt) {
			item.LeaseExpiresAt = item.LeaseExpiresAt.Add(time.Second)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			forged := valid
			test.mutate(&forged)
			assertInvalidDispatch(t, dispatcher, forged)
		})
	}
	f.clock.Set(valid.LeaseExpiresAt)
	assertInvalidDispatch(t, dispatcher, valid)
	if calls, deliveries := sender.snapshot(); calls != 0 || len(deliveries) != 0 {
		t.Fatalf("forged/stale attempts reached sender: calls=%d deliveries=%d", calls, len(deliveries))
	}
}

func TestConcurrentNotificationWorkersDispatchOnce(t *testing.T) {
	f := seedFixture(t, isolatedPool(t, true), 20, 20)
	if _, err := f.service.Request(t.Context(), requestInput(f, f.username, "concurrent-dispatch", "198.51.100.91")); err != nil {
		t.Fatal(err)
	}
	sender := &recordingRecoverySender{}
	dispatcher := newTestDispatcher(t, f, f.keyring, sender)
	workers := make([]*notification.Worker, 2)
	for index := range workers {
		worker, err := notification.NewWorkerWithAnonymousDispatcher(
			f.store, rejectingMemberSender{}, dispatcher, notification.DefaultWorkerConfig(),
		)
		if err != nil {
			t.Fatal(err)
		}
		workers[index] = worker
	}
	start := make(chan struct{})
	results := make(chan notification.WorkerBatchResult, 2)
	errs := make(chan error, 2)
	for _, worker := range workers {
		go func(worker *notification.Worker) {
			<-start
			result, err := worker.ProcessBatch(context.Background())
			results <- result
			errs <- err
		}(worker)
	}
	close(start)
	var succeeded int
	for range workers {
		result := <-results
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
		succeeded += result.Succeeded
	}
	calls, deliveries := sender.snapshot()
	if succeeded != 1 || calls != 1 || len(deliveries) != 1 {
		t.Fatalf("concurrent dispatch succeeded/calls/deliveries = %d/%d/%d", succeeded, calls, len(deliveries))
	}
}

func TestRequestRollsBackChallengeClaimAndOutboxFailures(t *testing.T) {
	f := newFixture(t, 20, 20)

	for _, test := range []struct {
		name  string
		table string
		key   string
	}{
		{"challenge", "account_recovery_challenges", "rollback-challenge"},
		{"claim", "account_recovery_dispatch_claims", "rollback-claim"},
	} {
		t.Run(test.name, func(t *testing.T) {
			function := "reject_account_recovery_" + test.name + "_test"
			trigger := function + "_trigger"
			if _, err := f.pool.Exec(t.Context(), fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RAISE EXCEPTION 'injected account recovery persistence failure'; END $$;
				CREATE TRIGGER %s BEFORE INSERT ON %s FOR EACH ROW EXECUTE FUNCTION %s()`,
				function, trigger, test.table, function)); err != nil {
				t.Fatal(err)
			}
			before := tableCounts(t, f.pool)
			_, requestErr := f.service.Request(t.Context(), requestInput(f, f.username, test.key, "198.51.100.92"))
			if requestErr == nil {
				t.Fatal("injected persistence failure succeeded")
			}
			after := tableCounts(t, f.pool)
			if fmt.Sprint(before) != fmt.Sprint(after) {
				t.Fatalf("rollback counts before=%v after=%v", before, after)
			}
			if _, err := f.pool.Exec(t.Context(), fmt.Sprintf(`DROP TRIGGER %s ON %s; DROP FUNCTION %s()`,
				trigger, test.table, function)); err != nil {
				t.Fatal(err)
			}
		})
	}

	config := testConfig(f)
	config.DispatchEnqueuer = failAfterEnqueue{inner: f.store}
	failing, err := NewServiceWithDependencies(f.pool, config, audit.New(f.pool))
	if err != nil {
		t.Fatal(err)
	}
	before := tableCounts(t, f.pool)
	if _, err := failing.Request(t.Context(), requestInput(f, f.username, "rollback-outbox", "198.51.100.93")); !errors.Is(err, ErrDispatchUnavailable) {
		t.Fatalf("outbox failure error = %v", err)
	}
	after := tableCounts(t, f.pool)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("outbox rollback counts before=%v after=%v", before, after)
	}

	failingNotificationStore, err := notification.NewStoreWithClock(f.pool, failingAudit{}, f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	config = testConfig(f)
	config.DispatchEnqueuer = failingNotificationStore
	failingNotification, err := NewServiceWithDependencies(f.pool, config, audit.New(f.pool))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failingNotification.Request(t.Context(), requestInput(f, f.username, "rollback-notification-audit", "198.51.100.94")); !errors.Is(err, ErrDispatchUnavailable) {
		t.Fatalf("notification audit failure error = %v", err)
	}
	if after = tableCounts(t, f.pool); fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("notification audit rollback counts before=%v after=%v", before, after)
	}
}

func newTestDispatcher(
	t *testing.T,
	f *fixture,
	keyring *DispatchKeyring,
	sender RecoverySender,
) *Dispatcher {
	t.Helper()
	dispatcher, err := NewDispatcher(f.pool, DispatcherConfig{
		Clock: f.clock.Now, DigestKey: testDigestKey, Keyring: keyring,
		RecoveryURL: "https://control.example.test/forget-password", Sender: sender,
	})
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher
}

func dispatchAttemptForRequest(t *testing.T, f *fixture, key string) notification.AnonymousDeliveryAttempt {
	t.Helper()
	var attempt notification.AnonymousDeliveryAttempt
	err := f.pool.QueryRow(t.Context(), `SELECT outbox.id,outbox.scope_id,event.id,
		event.anonymous_dispatch_reference,event.event_type,event.source_event_id,outbox.channel,
		outbox.template_id,outbox.template_version,outbox.subject,outbox.body,outbox.dedup_key
		FROM notification_outbox outbox
		JOIN notification_events event ON event.id=outbox.event_id
		JOIN audit_events audit_event ON audit_event.resource_id=event.id::text
		WHERE audit_event.action='notification.event.enqueue' AND audit_event.request_id=$1`,
		key+"-request-id").Scan(
		&attempt.OutboxID, &attempt.ScopeID, &attempt.EventID, &attempt.AnonymousDispatchReference,
		&attempt.EventType, &attempt.SourceEventID, &attempt.Channel, &attempt.Template.ID,
		&attempt.Template.Version, &attempt.Subject, &attempt.Body, &attempt.DedupKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	attempt.Template.Channel = attempt.Channel
	attempt.LeaseToken = uuid.New()
	attempt.LeaseExpiresAt = storeTime(f.clock.Now().Add(time.Minute))
	err = pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(t.Context(), `UPDATE notification_outbox
			SET status='leased',attempt_count=attempt_count+1,lease_token=$2,
			    lease_expires_at=$3,updated_at=$4
			WHERE id=$1 AND status='pending'
			RETURNING attempt_count`, attempt.OutboxID, attempt.LeaseToken,
			attempt.LeaseExpiresAt, storeTime(f.clock.Now())).Scan(&attempt.AttemptNumber); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO notification_attempts(
			outbox_id,scope_id,attempt_number,lease_token,lease_expires_at,outcome,claimed_at
		) VALUES($1,$2,$3,$4,$5,'leased',$6)`, attempt.OutboxID, attempt.ScopeID,
			attempt.AttemptNumber, attempt.LeaseToken, attempt.LeaseExpiresAt, storeTime(f.clock.Now()))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return attempt
}

func assertNoopDispatch(t *testing.T, dispatcher *Dispatcher, attempt notification.AnonymousDeliveryAttempt) {
	t.Helper()
	result := dispatcher.Dispatch(t.Context(), attempt)
	if result.Disposition != notification.AnonymousDispatchNoopACK || result.Failure != nil {
		t.Fatalf("noop dispatch = %+v", result)
	}
}

func assertInvalidDispatch(t *testing.T, dispatcher *Dispatcher, attempt notification.AnonymousDeliveryAttempt) {
	t.Helper()
	result := dispatcher.Dispatch(t.Context(), attempt)
	if result.Disposition != "" || result.Failure == nil ||
		result.Failure.Class != notification.FailurePermanent ||
		result.Failure.Code != "account_recovery_dispatch_invalid" {
		t.Fatalf("invalid dispatch result = %+v", result)
	}
}

func assertDispatchSecretsIsolated(t *testing.T, f *fixture, key, token string) {
	t.Helper()
	var challengeID uuid.UUID
	var tokenDigest, emailDigest []byte
	if err := f.pool.QueryRow(t.Context(), `SELECT challenge.id,challenge.token_digest,claim.email_digest
		FROM account_recovery_challenges challenge
		JOIN account_recovery_dispatch_claims claim ON claim.challenge_id=challenge.id
		JOIN account_recovery_write_requests write_request ON write_request.id=challenge.issued_by_write_id
		WHERE write_request.idempotency_key=$1`, key).Scan(&challengeID, &tokenDigest, &emailDigest); err != nil {
		t.Fatal(err)
	}
	rows, err := f.pool.Query(t.Context(), `SELECT source_event_id || ' ' ||
		coalesce(anonymous_dispatch_reference::text,'') || ' ' || encode(request_digest,'hex')
		FROM notification_events WHERE event_type='identity.account_recovery'
		UNION ALL
		SELECT subject || ' ' || body || ' ' || dedup_key FROM notification_outbox
		UNION ALL
		SELECT resource_id || ' ' || payload::text FROM audit_events
		WHERE action IN ('notification.event.enqueue','identity.account_recovery.request')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var persisted string
		if err := rows.Scan(&persisted); err != nil {
			t.Fatal(err)
		}
		for _, sensitive := range []string{
			token, f.username, challengeID.String(), hex.EncodeToString(tokenDigest), hex.EncodeToString(emailDigest),
		} {
			if sensitive != "" && strings.Contains(persisted, sensitive) {
				t.Fatalf("notification/audit leaked sensitive recovery value")
			}
		}
	}
}
