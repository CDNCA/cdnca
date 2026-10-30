package accountrecoveryhttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/accountrecovery"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errHTTPIntegrationFailure = errors.New("injected HTTP integration failure")

type integrationClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *integrationClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *integrationClock) Set(value time.Time) {
	clock.mu.Lock()
	clock.now = value
	clock.mu.Unlock()
}

type integrationFixture struct {
	pool       *pgxpool.Pool
	store      *notification.Store
	service    *accountrecovery.Service
	handler    *Handler
	dispatcher *accountrecovery.Dispatcher
	sender     *integrationRecoverySender
	clock      *integrationClock
	keyring    *accountrecovery.DispatchKeyring
	tenantID   uuid.UUID
	scopeID    uuid.UUID
	userID     uuid.UUID
	username   string
	password   string
}

type integrationRecoverySender struct {
	mu         sync.Mutex
	deliveries []accountrecovery.RecoveryDelivery
}

func (sender *integrationRecoverySender) SendRecovery(
	_ context.Context,
	delivery accountrecovery.RecoveryDelivery,
) notification.SendResult {
	sender.mu.Lock()
	sender.deliveries = append(sender.deliveries, delivery)
	sender.mu.Unlock()
	return notification.SendResult{}
}

func (sender *integrationRecoverySender) count() int {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	return len(sender.deliveries)
}

func (sender *integrationRecoverySender) latest() accountrecovery.RecoveryDelivery {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	return sender.deliveries[len(sender.deliveries)-1]
}

type integrationFailingAudit struct{}

func (integrationFailingAudit) Append(context.Context, pgx.Tx, audit.Event) error {
	return errHTTPIntegrationFailure
}

type integrationFailingEnqueuer struct{}

func (integrationFailingEnqueuer) EnqueueDispatchTx(
	context.Context,
	pgx.Tx,
	notification.DispatchEnqueueRequest,
) (notification.EnqueueResult, error) {
	return notification.EnqueueResult{}, errHTTPIntegrationFailure
}

func TestAccountRecoveryHTTPPostgresVerticalSlice(t *testing.T) {
	fixture := newIntegrationFixture(t)

	t.Run("enumeration safe request", func(t *testing.T) {
		existing := postRecoveryRequest(t, fixture.handler, fixture.username, "enum-existing")
		if existing.Code != http.StatusAccepted {
			t.Fatalf("existing status=%d body=%s", existing.Code, existing.Body.String())
		}
		expectedBody := existing.Body.String()

		missing := postRecoveryRequest(t, fixture.handler, "missing@example.test", "enum-missing")
		setIntegrationUserStatus(t, fixture, "disabled")
		disabled := postRecoveryRequest(t, fixture.handler, fixture.username, "enum-disabled")
		setIntegrationUserStatus(t, fixture, "active")
		setIntegrationMembershipStatus(t, fixture, "suspended")
		suspended := postRecoveryRequest(t, fixture.handler, fixture.username, "enum-suspended")
		setIntegrationMembershipStatus(t, fixture, "active")

		for name, response := range map[string]*httptest.ResponseRecorder{
			"missing": missing, "disabled": disabled, "suspended": suspended,
		} {
			if response.Code != http.StatusAccepted || response.Body.String() != expectedBody {
				t.Fatalf("%s response status=%d body=%s, want exact %s", name, response.Code, response.Body.String(), expectedBody)
			}
		}
		var events, outbox, claims int
		if err := fixture.pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM notification_events WHERE event_type='identity.account_recovery'),
			(SELECT count(*) FROM notification_outbox outbox JOIN notification_events event ON event.id=outbox.event_id
			 WHERE event.event_type='identity.account_recovery'),
			(SELECT count(*) FROM account_recovery_dispatch_claims)`).Scan(&events, &outbox, &claims); err != nil {
			t.Fatal(err)
		}
		if events != 4 || outbox != 4 || claims != 1 {
			t.Fatalf("enumeration facts events/outbox/claims=%d/%d/%d", events, outbox, claims)
		}
		conflict := postRecoveryRequest(t, fixture.handler, "other@example.test", "enum-existing")
		if conflict.Code != http.StatusConflict || responseCode(t, conflict) != "account_recovery_idempotency_conflict" {
			t.Fatalf("request idempotency conflict status=%d body=%s", conflict.Code, conflict.Body.String())
		}
	})

	t.Run("rate limit returns bounded retry without dimension", func(t *testing.T) {
		config := integrationServiceConfig(fixture, fixture.store)
		config.SubjectLimit = 1
		limitedService, err := accountrecovery.NewServiceWithDependencies(fixture.pool, config, audit.New(fixture.pool))
		if err != nil {
			t.Fatal(err)
		}
		limitedHandler := newIntegrationHandler(t, fixture, limitedService)
		if response := postRecoveryRequest(t, limitedHandler, "rate-limited@example.test", "limit-first"); response.Code != http.StatusAccepted {
			t.Fatalf("first limited request status=%d body=%s", response.Code, response.Body.String())
		}
		response := postRecoveryRequest(t, limitedHandler, "rate-limited@example.test", "limit-second")
		if response.Code != http.StatusTooManyRequests || responseCode(t, response) != "account_recovery_rate_limited" ||
			response.Header().Get("Retry-After") != "900" ||
			strings.Contains(response.Body.String(), "subject") || strings.Contains(response.Body.String(), "source") {
			t.Fatalf("limited response status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
		}
	})

	t.Run("invalid revoked and expired", func(t *testing.T) {
		invalid := postRecoveryConfirmation(t, fixture.handler, "invalid", "invalid", "invalid-token")
		if invalid.Code != http.StatusBadRequest || responseCode(t, invalid) != "account_recovery_invalid_token" {
			t.Fatalf("invalid response status=%d body=%s", invalid.Code, invalid.Body.String())
		}

		first := requestAndDispatchLink(t, fixture, "revoked-first")
		_ = postRecoveryRequest(t, fixture.handler, fixture.username, "revoked-replacement")
		revoked := postRecoveryConfirmation(t, fixture.handler, first.token, first.recoveryContext, "revoked-confirm")
		if revoked.Code != http.StatusBadRequest || responseCode(t, revoked) != "account_recovery_invalid_token" {
			t.Fatalf("revoked response status=%d body=%s", revoked.Code, revoked.Body.String())
		}

		changed := requestAndDispatchLink(t, fixture, "principal-changed-request")
		if _, err := fixture.pool.Exec(t.Context(), `UPDATE users SET revision=revision+1 WHERE id=$1`, fixture.userID); err != nil {
			t.Fatal(err)
		}
		changedResponse := postRecoveryConfirmation(t, fixture.handler,
			changed.token, changed.recoveryContext, "principal-changed-confirm")
		if changedResponse.Code != http.StatusConflict ||
			responseCode(t, changedResponse) != "account_recovery_principal_changed" {
			t.Fatalf("principal changed response status=%d body=%s", changedResponse.Code, changedResponse.Body.String())
		}

		expired := requestAndDispatchLink(t, fixture, "expired-request")
		fixture.clock.Set(fixture.clock.Now().Add(10 * time.Minute))
		expiredResponse := postRecoveryConfirmation(t, fixture.handler, expired.token, expired.recoveryContext, "expired-confirm")
		if expiredResponse.Code != http.StatusBadRequest || responseCode(t, expiredResponse) != "account_recovery_invalid_token" {
			t.Fatalf("expired response status=%d body=%s", expiredResponse.Code, expiredResponse.Body.String())
		}
	})

	t.Run("concurrent winner idempotent replay and consumed token", func(t *testing.T) {
		link := requestAndDispatchLink(t, fixture, "race-request")
		start := make(chan struct{})
		responses := make(chan struct {
			key      string
			response *httptest.ResponseRecorder
		}, 2)
		for index := 0; index < 2; index++ {
			go func(index int) {
				key := fmt.Sprintf("race-confirm-%d", index)
				<-start
				responses <- struct {
					key      string
					response *httptest.ResponseRecorder
				}{key: key, response: postRecoveryConfirmation(t, fixture.handler, link.token, link.recoveryContext, key)}
			}(index)
		}
		close(start)
		var successKey string
		var successes, invalid int
		for index := 0; index < 2; index++ {
			result := <-responses
			switch result.response.Code {
			case http.StatusNoContent:
				successes++
				successKey = result.key
			case http.StatusBadRequest:
				if responseCode(t, result.response) != "account_recovery_invalid_token" {
					t.Fatalf("loser body=%s", result.response.Body.String())
				}
				invalid++
			default:
				t.Fatalf("race status=%d body=%s", result.response.Code, result.response.Body.String())
			}
		}
		if successes != 1 || invalid != 1 {
			t.Fatalf("race successes/invalid=%d/%d", successes, invalid)
		}

		replay := postRecoveryConfirmation(t, fixture.handler, link.token, link.recoveryContext, successKey)
		if replay.Code != http.StatusNoContent || replay.Header().Get("Idempotency-Replayed") != "true" {
			t.Fatalf("replay status=%d headers=%v body=%s", replay.Code, replay.Header(), replay.Body.String())
		}
		consumed := postRecoveryConfirmation(t, fixture.handler, link.token, link.recoveryContext, "consumed-new-key")
		if consumed.Code != http.StatusBadRequest || responseCode(t, consumed) != "account_recovery_invalid_token" {
			t.Fatalf("consumed response status=%d body=%s", consumed.Code, consumed.Body.String())
		}
	})

	t.Run("audit and notification failures roll back", func(t *testing.T) {
		resetLink := requestAndDispatchLink(t, fixture, "rollback-reset-request")
		before := integrationTableCounts(t, fixture.pool)
		badAudit, err := accountrecovery.NewServiceWithDependencies(
			fixture.pool, integrationServiceConfig(fixture, fixture.store), integrationFailingAudit{},
		)
		if err != nil {
			t.Fatal(err)
		}
		badAuditHandler := newIntegrationHandler(t, fixture, badAudit)
		response := postRecoveryRequest(t, badAuditHandler, fixture.username, "rollback-audit")
		if response.Code != http.StatusServiceUnavailable || responseCode(t, response) != "account_recovery_unavailable" {
			t.Fatalf("audit failure status=%d body=%s", response.Code, response.Body.String())
		}
		if after := integrationTableCounts(t, fixture.pool); fmt.Sprint(after) != fmt.Sprint(before) {
			t.Fatalf("audit rollback before=%v after=%v", before, after)
		}
		var oldHash string
		var oldRevision int64
		if err := fixture.pool.QueryRow(t.Context(), `SELECT password_hash,revision FROM users WHERE id=$1`,
			fixture.userID).Scan(&oldHash, &oldRevision); err != nil {
			t.Fatal(err)
		}
		response = postRecoveryConfirmationWithPassword(t, badAuditHandler,
			resetLink.token, resetLink.recoveryContext, "rollback-reset-confirm", "Rollback-password-1234")
		if response.Code != http.StatusServiceUnavailable || responseCode(t, response) != "account_recovery_unavailable" {
			t.Fatalf("reset audit failure status=%d body=%s", response.Code, response.Body.String())
		}
		var currentHash string
		var currentRevision int64
		if err := fixture.pool.QueryRow(t.Context(), `SELECT password_hash,revision FROM users WHERE id=$1`,
			fixture.userID).Scan(&currentHash, &currentRevision); err != nil {
			t.Fatal(err)
		}
		if currentHash != oldHash || currentRevision != oldRevision {
			t.Fatalf("reset audit rollback hash_changed=%t revision=%d/%d",
				currentHash != oldHash, currentRevision, oldRevision)
		}
		if after := integrationTableCounts(t, fixture.pool); fmt.Sprint(after) != fmt.Sprint(before) {
			t.Fatalf("reset audit rollback before=%v after=%v", before, after)
		}

		badNotification, err := accountrecovery.NewServiceWithDependencies(
			fixture.pool, integrationServiceConfig(fixture, integrationFailingEnqueuer{}), audit.New(fixture.pool),
		)
		if err != nil {
			t.Fatal(err)
		}
		badNotificationHandler := newIntegrationHandler(t, fixture, badNotification)
		response = postRecoveryRequest(t, badNotificationHandler, fixture.username, "rollback-notification")
		if response.Code != http.StatusServiceUnavailable || responseCode(t, response) != "account_recovery_unavailable" {
			t.Fatalf("notification failure status=%d body=%s", response.Code, response.Body.String())
		}
		if after := integrationTableCounts(t, fixture.pool); fmt.Sprint(after) != fmt.Sprint(before) {
			t.Fatalf("notification rollback before=%v after=%v", before, after)
		}
	})
}

type recoveryLink struct {
	token           string
	recoveryContext string
}

func requestAndDispatchLink(t *testing.T, fixture *integrationFixture, key string) recoveryLink {
	t.Helper()
	response := postRecoveryRequest(t, fixture.handler, fixture.username, key)
	if response.Code != http.StatusAccepted {
		t.Fatalf("request %s status=%d body=%s", key, response.Code, response.Body.String())
	}
	before := fixture.sender.count()
	attempt := integrationDispatchAttempt(t, fixture, key)
	result := fixture.dispatcher.Dispatch(t.Context(), attempt)
	if result.Disposition != notification.AnonymousDispatchDelivered || result.Failure != nil ||
		fixture.sender.count() != before+1 {
		t.Fatalf("dispatch %s = %+v sender before/after=%d/%d", key, result, before, fixture.sender.count())
	}
	delivery := fixture.sender.latest()
	parsed, err := url.Parse(delivery.RecoveryURL)
	if err != nil {
		t.Fatal(err)
	}
	fragment, err := url.ParseQuery(parsed.Fragment)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.RawQuery != "" {
		t.Fatalf("recovery URL query must be empty: %q", parsed.RawQuery)
	}
	link := recoveryLink{token: fragment.Get("token"), recoveryContext: fragment.Get("recovery_context")}
	if link.token == "" || link.recoveryContext == "" || strings.Contains(delivery.Subject+delivery.Body, link.token) {
		t.Fatal("dispatcher did not isolate the recovery link")
	}
	return link
}

func postRecoveryRequest(t *testing.T, handler http.Handler, username, key string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"username":` + strconv.Quote(username) + `}`
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, jsonRequest(t, requestPath, body, key))
	return response
}

func postRecoveryConfirmation(
	t *testing.T,
	handler http.Handler,
	token, recoveryContext, key string,
) *httptest.ResponseRecorder {
	return postRecoveryConfirmationWithPassword(t, handler, token, recoveryContext, key, "Changed-password-1234")
}

func postRecoveryConfirmationWithPassword(
	t *testing.T,
	handler http.Handler,
	token, recoveryContext, key, password string,
) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	body := strings.ReplaceAll(confirmationJSON(token, recoveryContext), "Changed-password-1234", password)
	handler.ServeHTTP(response, jsonRequest(t, confirmationPath, body, key))
	return response
}

func newIntegrationFixture(t *testing.T) *integrationFixture {
	t.Helper()
	// The HTTP handler and services under test run against the release head.
	pool := databasetest.MigratedPool(t, nil)
	clock := &integrationClock{now: time.Date(2026, 7, 23, 5, 0, 0, 0, time.UTC)}
	store, err := notification.NewStoreWithClock(pool, audit.New(pool), clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{Email: true}); err != nil {
		t.Fatal(err)
	}
	template := notification.TemplateRef{ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail}
	if err := store.SaveTemplate(t.Context(), notification.TemplateDefinition{
		Ref: template, Subject: "重置密码", Body: "请使用安全链接重置密码", Variables: []string{},
	}); err != nil && !errors.Is(err, notification.ErrTemplateExists) {
		t.Fatal(err)
	}
	keyring, err := accountrecovery.NewDispatchKeyring("http-integration-v1", map[string][]byte{
		"http-integration-v1": bytes.Repeat([]byte{0x72}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture := &integrationFixture{
		pool: pool, store: store, clock: clock, keyring: keyring,
		username: "recover-http@example.test", password: "Initial-password-1234",
	}
	fixture.tenantID, fixture.scopeID = integrationSeedTenant(t, pool)
	fixture.userID = uuid.New()
	hash, err := identity.HashPassword(fixture.password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(
		id,username,display_name,email,password_hash,status,revision,created_at,updated_at
	) VALUES($1,$2,'Recovery HTTP User',$2,$3,'active',1,$4,$4)`,
		fixture.userID, fixture.username, hash, clock.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id,status)
		VALUES($1,$2,'active')`, fixture.scopeID, fixture.userID); err != nil {
		t.Fatal(err)
	}
	fixture.service, err = accountrecovery.NewServiceWithDependencies(
		pool, integrationServiceConfig(fixture, store), audit.New(pool),
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.handler = newIntegrationHandler(t, fixture, fixture.service)
	fixture.sender = &integrationRecoverySender{}
	fixture.dispatcher, err = accountrecovery.NewDispatcher(pool, accountrecovery.DispatcherConfig{
		Clock: clock.Now, DigestKey: handlerTestKey, Keyring: keyring,
		RecoveryURL: "https://control.example.test/forget-password", Sender: fixture.sender,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func integrationServiceConfig(fixture *integrationFixture, enqueuer accountrecovery.DispatchEnqueuer) accountrecovery.Config {
	template := notification.TemplateRef{ID: "account_recovery", Version: 1, Channel: notification.ChannelEmail}
	return accountrecovery.Config{
		Clock: fixture.clock.Now, DigestKey: handlerTestKey, TokenTTL: 10 * time.Minute,
		RateWindow: 15 * time.Minute, SubjectLimit: 100, SourceLimit: 100,
		DispatchKeyring: fixture.keyring, DispatchEnqueuer: enqueuer,
		DispatchTemplates: map[notification.Channel]notification.TemplateRef{notification.ChannelEmail: template},
	}
}

func newIntegrationHandler(t *testing.T, fixture *integrationFixture, service RecoveryService) *Handler {
	t.Helper()
	handler, err := NewHandler(service, func(request *http.Request) (TrustedContext, error) {
		key := request.Header.Get("Idempotency-Key")
		return TrustedContext{
			TenantID: fixture.tenantID, ScopeID: fixture.scopeID, RequestID: "http-" + key,
			TraceID: "trace-" + key, SourceIP: "198.51.100.20",
		}, nil
	}, Config{
		DigestKey: handlerTestKey, Clock: fixture.clock.Now,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func integrationDispatchAttempt(
	t *testing.T,
	fixture *integrationFixture,
	key string,
) notification.AnonymousDeliveryAttempt {
	t.Helper()
	var attempt notification.AnonymousDeliveryAttempt
	err := fixture.pool.QueryRow(t.Context(), `SELECT outbox.id,outbox.scope_id,event.id,
		event.anonymous_dispatch_reference,event.event_type,event.source_event_id,outbox.channel,
		outbox.template_id,outbox.template_version,outbox.subject,outbox.body,outbox.dedup_key
		FROM notification_outbox outbox
		JOIN notification_events event ON event.id=outbox.event_id
		JOIN audit_events audit_event ON audit_event.resource_id=event.id::text
		WHERE audit_event.action='notification.event.enqueue' AND audit_event.request_id=$1`, "http-"+key).Scan(
		&attempt.OutboxID, &attempt.ScopeID, &attempt.EventID, &attempt.AnonymousDispatchReference,
		&attempt.EventType, &attempt.SourceEventID, &attempt.Channel, &attempt.Template.ID,
		&attempt.Template.Version, &attempt.Subject, &attempt.Body, &attempt.DedupKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	attempt.Template.Channel = attempt.Channel
	attempt.LeaseToken = uuid.New()
	attempt.LeaseExpiresAt = fixture.clock.Now().UTC().Truncate(time.Microsecond).Add(time.Minute)
	err = pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(t.Context(), `UPDATE notification_outbox
			SET status='leased',attempt_count=attempt_count+1,lease_token=$2,
			    lease_expires_at=$3,updated_at=$4
			WHERE id=$1 AND status='pending'
			RETURNING attempt_count`, attempt.OutboxID, attempt.LeaseToken, attempt.LeaseExpiresAt,
			fixture.clock.Now().UTC().Truncate(time.Microsecond)).Scan(&attempt.AttemptNumber); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO notification_attempts(
			outbox_id,scope_id,attempt_number,lease_token,lease_expires_at,outcome,claimed_at
		) VALUES($1,$2,$3,$4,$5,'leased',$6)`, attempt.OutboxID, attempt.ScopeID,
			attempt.AttemptNumber, attempt.LeaseToken, attempt.LeaseExpiresAt,
			fixture.clock.Now().UTC().Truncate(time.Microsecond))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return attempt
}

func setIntegrationUserStatus(t *testing.T, fixture *integrationFixture, status string) {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE users SET status=$2 WHERE id=$1`, fixture.userID, status); err != nil {
		t.Fatal(err)
	}
}

func setIntegrationMembershipStatus(t *testing.T, fixture *integrationFixture, status string) {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE memberships SET status=$3
		WHERE scope_id=$1 AND user_id=$2`, fixture.scopeID, fixture.userID, status); err != nil {
		t.Fatal(err)
	}
}

func integrationTableCounts(t *testing.T, pool *pgxpool.Pool) []int {
	t.Helper()
	tables := []string{
		"account_recovery_challenges", "account_recovery_dispatch_claims", "account_recovery_rate_windows",
		"account_recovery_write_requests", "notification_events", "notification_outbox", "audit_events",
	}
	counts := make([]int, len(tables))
	for index, table := range tables {
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM `+pgx.Identifier{table}.Sanitize()).Scan(&counts[index]); err != nil {
			t.Fatal(err)
		}
	}
	return counts
}

func integrationSeedTenant(t *testing.T, pool *pgxpool.Pool) (uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, scopeID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants(id,display_name) VALUES($1,'Recovery HTTP tenant')`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes(id,kind,tenant_id)
		VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	return tenantID, scopeID
}
