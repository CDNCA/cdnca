//go:build integration

package acmeruntime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/acme"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/acmeworker"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestACMERuntimePostgreSQL17(t *testing.T) {
	// The runtime under test (dispatcher, issuer store, audit log) runs against
	// the release head; a hand-made ledger replayed through 106 lacks the
	// unified-log audit columns (361) and every later runtime table. The
	// dispatcher claims the oldest due outbox row of the whole database, so
	// each subtest gets a database of its own (rows another subtest left
	// retryable would otherwise be claimed in its place).
	var pool *pgxpool.Pool
	run := func(name string, test func(t *testing.T)) {
		t.Run(name, func(t *testing.T) {
			pool = databasetest.MigratedPool(t, nil)
			test(t)
		})
	}

	run("request keys and account replay survive retry", func(t *testing.T) {
		fixture := seedRuntimeOrder(t, pool, "dns-01", providerVerified, payloadValid)
		issuer := &scriptedIssuer{failures: []error{context.DeadlineExceeded}}
		dispatcher, keys := newRuntimeDispatcher(t, pool, issuer, 3, 20*time.Millisecond)
		dispatcher.config.RetryBase = time.Hour
		dispatcher.config.RetryMaximum = time.Hour
		result, err := dispatcher.DispatchOne(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if result.Outcome != OutcomeRetry || result.Attempt != 1 || issuer.callCount() != 1 {
			t.Fatalf("dispatch result=%+v calls=%d", result, issuer.callCount())
		}
		request := issuer.request(0)
		if request.TenantID != fixture.tenantID || request.ScopeID != fixture.scopeID ||
			request.ProviderID != fixture.providerID || request.ZoneID != fixture.zoneID ||
			request.ActorUserID != fixture.actorID ||
			request.CertificateOrderID != fixture.orderID || request.OperationID != fixture.orderID.String() ||
			request.ProviderRef != fixture.providerID.String() || !request.AcceptTerms ||
			request.ChallengeType != acmeworker.ChallengeDNS01 {
			t.Fatalf("issue request = %+v", request)
		}
		assertOutbox(t, pool, fixture.outboxID, "failed", 1, string(acmeworker.CodeTimeout))
		assertRuntimeOrder(t, pool, fixture.orderID, "validating", 2)
		// FX10: while the order retries, the list shows why.
		orders, err := dnsacme.NewStore(pool).ListOrders(t.Context(), dnsacme.Actor{ScopeID: fixture.scopeID, ScopeKind: "tenant"})
		if err != nil {
			t.Fatal(err)
		}
		retrying := false
		for _, order := range orders {
			if order.ID == fixture.orderID {
				retrying = order.RetryErrorCode != nil && *order.RetryErrorCode == string(acmeworker.CodeTimeout)
			}
		}
		if !retrying {
			t.Fatalf("retrying order does not expose its retry reason: %+v", orders)
		}
		for _, keyRef := range []string{request.AccountKeyRef, request.CertificateKeyRef} {
			signer, err := keys.Signer(t.Context(), keyRef)
			if err != nil || signer == nil {
				t.Fatalf("Signer(%q) = %T, %v", keyRef, signer, err)
			}
		}
		restartedKeys, err := NewKeyStore(pool, runtimeWrappingKeyID, bytesOf(32, 7))
		if err != nil {
			t.Fatal(err)
		}
		if signer, err := restartedKeys.Signer(t.Context(), request.CertificateKeyRef); err != nil || signer == nil {
			t.Fatalf("restarted signer=%T error=%v", signer, err)
		}
		result, err = dispatcher.DispatchOne(t.Context())
		if err != nil || result.Outcome != OutcomeIdle || issuer.callCount() != 1 {
			t.Fatalf("retry delay result=%+v calls=%d error=%v", result, issuer.callCount(), err)
		}
		var keyCount int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM acme_tenant_key_facts
			WHERE tenant_scope_id=$1`, fixture.scopeID).Scan(&keyCount); err != nil || keyCount != 2 {
			t.Fatalf("key count=%d error=%v", keyCount, err)
		}

		accounts, err := NewAccountStore(pool, true)
		if err != nil {
			t.Fatal(err)
		}
		account := acmeworker.AccountRegistration{
			URI:     "https://ca.example/acct/" + fixture.orderID.String(),
			Contact: []string{"mailto:ops@example.test"},
		}
		if err := accounts.SaveAccount(t.Context(), runtimeDirectoryURL, request.AccountKeyRef, account); err != nil {
			t.Fatal(err)
		}
		if err := accounts.SaveAccount(t.Context(), runtimeDirectoryURL, request.AccountKeyRef, account); err != nil {
			t.Fatalf("exact account replay: %v", err)
		}
		conflict := account
		conflict.URI += "/forged"
		if err := accounts.SaveAccount(t.Context(), runtimeDirectoryURL, request.AccountKeyRef, conflict); !errors.Is(err, ErrConflict) {
			t.Fatalf("conflicting account replay error = %v", err)
		}
		loaded, found, err := accounts.LoadAccount(t.Context(), runtimeDirectoryURL, request.AccountKeyRef)
		if err != nil || !found || loaded.URI != account.URI || len(loaded.Contact) != 1 {
			t.Fatalf("loaded account=%+v found=%t error=%v", loaded, found, err)
		}
	})

	// B-D1: an account registered without contacts (Let's Encrypt no longer
	// echoes them) is the empty array, not NULL, which 048 rejects.
	run("account without contacts is stored as empty array", func(t *testing.T) {
		fixture := seedRuntimeOrder(t, pool, "http-01", providerNone, payloadValid)
		issuer := &scriptedIssuer{failures: []error{context.DeadlineExceeded}}
		dispatcher, _ := newRuntimeDispatcher(t, pool, issuer, 3, 20*time.Millisecond)
		dispatcher.config.RetryBase = time.Hour
		dispatcher.config.RetryMaximum = time.Hour
		if _, err := dispatcher.DispatchOne(t.Context()); err != nil {
			t.Fatal(err)
		}
		request := issuer.request(0)
		accounts, err := NewAccountStore(pool, true)
		if err != nil {
			t.Fatal(err)
		}
		account := acmeworker.AccountRegistration{URI: "https://ca.example/acct/" + fixture.orderID.String()}
		if err := accounts.SaveAccount(t.Context(), runtimeDirectoryURL, request.AccountKeyRef, account); err != nil {
			t.Fatalf("save account without contacts: %v", err)
		}
		if err := accounts.SaveAccount(t.Context(), runtimeDirectoryURL, request.AccountKeyRef,
			acmeworker.AccountRegistration{URI: account.URI, Contact: []string{}}); err != nil {
			t.Fatalf("empty-contacts replay: %v", err)
		}
		loaded, found, err := accounts.LoadAccount(t.Context(), runtimeDirectoryURL, request.AccountKeyRef)
		if err != nil || !found || loaded.URI != account.URI || loaded.Contact == nil || len(loaded.Contact) != 0 {
			t.Fatalf("loaded account=%+v found=%t error=%v", loaded, found, err)
		}
	})

	run("issuer success cannot complete before issued database fact", func(t *testing.T) {
		fixture := seedRuntimeOrder(t, pool, "http-01", providerNone, payloadValid)
		dispatcher, _ := newRuntimeDispatcher(t, pool, &scriptedIssuer{}, 3, 20*time.Millisecond)
		result, err := dispatcher.DispatchOne(t.Context())
		if !errors.Is(err, ErrConflict) || result.Outcome != OutcomeRetry {
			t.Fatalf("uncommitted issuer success result=%+v error=%v", result, err)
		}
		assertOutbox(t, pool, fixture.outboxID, "processing", 1, "")
		assertRuntimeOrder(t, pool, fixture.orderID, "validating", 2)
	})

	run("concurrent claim takeover stale fence and exhaustion", func(t *testing.T) {
		concurrentFixture := seedRuntimeOrder(t, pool, "http-01", providerNone, payloadValid)
		issuer := &scriptedIssuer{}
		dispatcher, _ := newRuntimeDispatcher(t, pool, issuer, 3, 20*time.Millisecond)
		dispatcher.config.LeaseDuration = time.Hour

		const contenders = 8
		start := make(chan struct{})
		leases := make(chan Lease, contenders)
		errorsSeen := make(chan error, contenders)
		var wait sync.WaitGroup
		for range contenders {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				lease, found, err := dispatcher.claim(t.Context())
				if err != nil {
					errorsSeen <- err
					return
				}
				if found && lease.OutboxID == concurrentFixture.outboxID {
					leases <- lease
				}
			}()
		}
		close(start)
		wait.Wait()
		close(leases)
		close(errorsSeen)
		for err := range errorsSeen {
			t.Fatal(err)
		}
		claimed := make([]Lease, 0, contenders)
		for lease := range leases {
			claimed = append(claimed, lease)
		}
		if len(claimed) != 1 {
			t.Fatalf("claim winners=%d, want 1", len(claimed))
		}

		takeoverFixture := seedRuntimeOrder(t, pool, "http-01", providerNone, payloadValid)
		dispatcher.config.LeaseDuration = 80 * time.Millisecond
		first, found, err := dispatcher.claim(t.Context())
		if err != nil || !found || first.OutboxID != takeoverFixture.outboxID || first.Attempt != 1 {
			t.Fatalf("first takeover claim=%+v found=%t error=%v", first, found, err)
		}
		time.Sleep(120 * time.Millisecond)
		dispatcher.config.LeaseDuration = 30 * time.Second
		second, found, err := dispatcher.claim(t.Context())
		if err != nil || !found || second.Attempt != 2 || second.Token == first.Token {
			t.Fatalf("takeover=%+v found=%t error=%v", second, found, err)
		}
		if err := dispatcher.complete(t.Context(), first); !errors.Is(err, ErrLeaseLost) {
			t.Fatalf("stale completion error=%v", err)
		}
		dispatcher.config.RetryBase = time.Hour
		dispatcher.config.RetryMaximum = time.Hour
		if err := dispatcher.fail(t.Context(), second, "acme_timeout", 0); err != nil {
			t.Fatal(err)
		}
		if _, found, err := dispatcher.claim(t.Context()); err != nil || found {
			t.Fatalf("claim before retry found=%t error=%v", found, err)
		}

		exhaustionFixture := seedRuntimeOrder(t, pool, "http-01", providerNone, payloadValid)
		dispatcher.config.RetryBase = 20 * time.Millisecond
		dispatcher.config.RetryMaximum = 100 * time.Millisecond
		for attempt := 1; attempt <= 3; attempt++ {
			lease, found, err := dispatcher.claim(t.Context())
			if err != nil || !found || lease.OutboxID != exhaustionFixture.outboxID || lease.Attempt != attempt {
				t.Fatalf("exhaustion claim %d=%+v found=%t error=%v", attempt, lease, found, err)
			}
			if err := dispatcher.fail(t.Context(), lease, "acme_timeout", 0); err != nil {
				t.Fatal(err)
			}
			if attempt < 3 {
				time.Sleep(150 * time.Millisecond)
			}
		}
		time.Sleep(150 * time.Millisecond)
		if _, found, err := dispatcher.claim(t.Context()); err != nil || found {
			t.Fatalf("exhausted claim found=%t error=%v", found, err)
		}
		assertOutbox(t, pool, exhaustionFixture.outboxID, "failed", 3, "acme_timeout")
	})

	run("rate limit retry schedule survives restart", func(t *testing.T) {
		fixture := seedRuntimeOrder(t, pool, "http-01", providerNone, payloadValid)
		issuer := &scriptedIssuer{failures: []error{
			&acmeworker.Error{Code: acmeworker.CodeRateLimited, Temporary: true, RetryAfter: 30 * time.Millisecond},
			context.DeadlineExceeded,
		}}
		dispatcher, _ := newRuntimeDispatcher(t, pool, issuer, 3, 20*time.Millisecond)
		result, err := dispatcher.DispatchOne(t.Context())
		if err != nil || result.Outcome != OutcomeRetry || result.ErrorCode != string(acmeworker.CodeRateLimited) {
			t.Fatalf("first dispatch=%+v error=%v", result, err)
		}
		assertOutbox(t, pool, fixture.outboxID, "failed", 1, string(acmeworker.CodeRateLimited))
		time.Sleep(50 * time.Millisecond)
		restarted, _ := newRuntimeDispatcher(t, pool, issuer, 3, 20*time.Millisecond)
		result, err = restarted.DispatchOne(t.Context())
		if err != nil || result.Outcome != OutcomeRetry || result.Attempt != 2 ||
			result.ErrorCode != string(acmeworker.CodeTimeout) {
			t.Fatalf("second dispatch=%+v error=%v", result, err)
		}
		assertOutbox(t, pool, fixture.outboxID, "failed", 2, string(acmeworker.CodeTimeout))
		var keyCount int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM acme_tenant_key_facts
			WHERE tenant_scope_id=$1`, fixture.scopeID).Scan(&keyCount); err != nil || keyCount != 2 {
			t.Fatalf("retry key count=%d error=%v", keyCount, err)
		}
	})

	run("last failure is exhausted without immediate retry", func(t *testing.T) {
		fixture := seedRuntimeOrder(t, pool, "http-01", providerNone, payloadValid)
		issuer := &scriptedIssuer{failures: []error{context.DeadlineExceeded}}
		dispatcher, _ := newRuntimeDispatcher(t, pool, issuer, 1, 20*time.Millisecond)
		dispatcher.config.RetryBase = time.Hour
		dispatcher.config.RetryMaximum = time.Hour
		result, err := dispatcher.DispatchOne(t.Context())
		if err != nil || result.Outcome != OutcomeExhausted || result.Attempt != 1 ||
			result.ErrorCode != string(acmeworker.CodeTimeout) {
			t.Fatalf("dispatch=%+v error=%v", result, err)
		}
		assertOutbox(t, pool, fixture.outboxID, "failed", 1, string(acmeworker.CodeTimeout))
		assertRuntimeOrder(t, pool, fixture.orderID, "failed", 3)
		var transitionAudits int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events
			WHERE scope_id=$1 AND resource_id=$2::text AND action='certificate.order.transition'`,
			fixture.scopeID, fixture.orderID).Scan(&transitionAudits); err != nil || transitionAudits != 2 {
			t.Fatalf("terminal transition audits=%d error=%v", transitionAudits, err)
		}
		if next, found, err := dispatcher.claim(t.Context()); err != nil || found {
			t.Fatalf("exhausted follow-up claim=%+v found=%t error=%v", next, found, err)
		}
	})

	// FX05③: a terminal ACME error fails the order at once instead of running
	// out the whole retry budget (about four hours with production settings).
	run("terminal failure fails the order on the first attempt", func(t *testing.T) {
		for _, code := range []acmeworker.ErrorCode{acmeworker.CodeAuthorizationInvalid, acmeworker.CodeOrderRejected,
			acmeworker.CodeHTTP01NodeAggregateRequired} {
			t.Run(string(code), func(t *testing.T) {
				fixture := seedRuntimeOrder(t, pool, "http-01", providerNone, payloadValid)
				issuer := &scriptedIssuer{failures: []error{&acmeworker.Error{Code: code}}}
				dispatcher, _ := newRuntimeDispatcher(t, pool, issuer, 10, 20*time.Millisecond)
				result, err := dispatcher.DispatchOne(t.Context())
				if err != nil || result.Outcome != OutcomeExhausted || result.Attempt != 1 || result.ErrorCode != string(code) {
					t.Fatalf("dispatch=%+v error=%v", result, err)
				}
				assertOutbox(t, pool, fixture.outboxID, "failed", 1, string(code))
				assertRuntimeOrder(t, pool, fixture.orderID, "failed", 3)
				// Other subtests leave retryable rows behind; this order's row must
				// never be claimed again.
				for {
					next, found, err := dispatcher.claim(t.Context())
					if err != nil || found && next.OutboxID == fixture.outboxID {
						t.Fatalf("terminal follow-up claim=%+v found=%t error=%v", next, found, err)
					}
					if !found {
						break
					}
					if err := dispatcher.fail(t.Context(), next, "acme_timeout", time.Hour); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	})

	// 订单失败时与分类码一起记下 CA 原因（已脱敏）。
	run("terminal failure records the redacted CA reason", func(t *testing.T) {
		fixture := seedRuntimeOrder(t, pool, "http-01", providerNone, payloadValid)
		cause := &acme.Error{StatusCode: 403, ProblemType: "urn:ietf:params:acme:error:unauthorized",
			Detail: "Invalid response from http://a.example.test/.well-known/acme-challenge/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789: 404"}
		issuer := &scriptedIssuer{failures: []error{acmeworker.TerminalFailure(acmeworker.CodeAuthorizationInvalid, cause)}}
		dispatcher, _ := newRuntimeDispatcher(t, pool, issuer, 10, 20*time.Millisecond)
		if result, err := dispatcher.DispatchOne(t.Context()); err != nil || result.Outcome != OutcomeExhausted {
			t.Fatalf("dispatch=%+v error=%v", result, err)
		}
		var orderReason, outboxReason *string
		if err := pool.QueryRow(t.Context(), `SELECT failure_reason,(SELECT last_error_reason FROM dns_acme_outbox WHERE id=$2)
			FROM certificate_orders WHERE id=$1`, fixture.orderID, fixture.outboxID).Scan(&orderReason, &outboxReason); err != nil {
			t.Fatal(err)
		}
		want := "Invalid response from [url]: 404"
		if orderReason == nil || *orderReason != want || outboxReason == nil || *outboxReason != want {
			t.Fatalf("order reason=%v outbox reason=%v", orderReason, outboxReason)
		}
		for {
			next, found, err := dispatcher.claim(t.Context())
			if err != nil || !found {
				break
			}
			if err := dispatcher.fail(t.Context(), next, "acme_timeout", time.Hour); err != nil {
				t.Fatal(err)
			}
		}
	})

	// fix-certstuck（73 订单 01a178e0）：worker 已把操作落终态（证书公钥不是本单密钥），
	// 订单要立即转 failed 带 failure_code，不再按 acme_certificate_invalid 退避到 10 次。
	run("worker terminal failure fails the order on the first attempt", func(t *testing.T) {
		fixture := seedRuntimeOrder(t, pool, "http-01", providerNone, payloadValid)
		issuer := &scriptedIssuer{failures: []error{&acmeworker.Error{Code: acmeworker.CodeCertificateInvalid, Terminal: true}}}
		dispatcher, _ := newRuntimeDispatcher(t, pool, issuer, 10, 20*time.Millisecond)
		result, err := dispatcher.DispatchOne(t.Context())
		if err != nil || result.Outcome != OutcomeExhausted || result.Attempt != 1 ||
			result.ErrorCode != string(acmeworker.CodeCertificateInvalid) {
			t.Fatalf("dispatch=%+v error=%v", result, err)
		}
		assertOutbox(t, pool, fixture.outboxID, "failed", 1, string(acmeworker.CodeCertificateInvalid))
		assertRuntimeOrder(t, pool, fixture.orderID, "failed", 3)
		var failureCode string
		if err := pool.QueryRow(t.Context(), `SELECT failure_code FROM certificate_orders WHERE id=$1`,
			fixture.orderID).Scan(&failureCode); err != nil || failureCode != string(acmeworker.CodeCertificateInvalid) {
			t.Fatalf("failure_code=%q error=%v", failureCode, err)
		}
		for {
			next, found, err := dispatcher.claim(t.Context())
			if err != nil || found && next.OutboxID == fixture.outboxID {
				t.Fatalf("terminal follow-up claim=%+v found=%t error=%v", next, found, err)
			}
			if !found {
				break
			}
			if err := dispatcher.fail(t.Context(), next, "acme_timeout", time.Hour); err != nil {
				t.Fatal(err)
			}
		}
	})

	run("invalid success cancellation and SQL failure settle without completion", func(t *testing.T) {
		tests := []struct {
			name       string
			issuer     *scriptedIssuer
			installSQL bool
			wantCode   string
		}{
			{"invalid-success", &scriptedIssuer{invalidResult: true}, false, "acme_issue_result_invalid"},
			{"cancelled", &scriptedIssuer{failures: []error{context.Canceled}}, false, string(acmeworker.CodeCancelled)},
			{"sql-rollback", &scriptedIssuer{}, true, "acme_runtime_failed"},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				fixture := seedRuntimeOrder(t, pool, "http-01", providerNone, payloadValid)
				if test.installSQL {
					if _, err := pool.Exec(t.Context(), `CREATE FUNCTION reject_test_certificate_key()
						RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
						IF NEW.purpose='certificate' THEN RAISE EXCEPTION 'test rejection'; END IF;
						RETURN NEW; END $$;
						CREATE TRIGGER reject_test_certificate_key_trigger
						BEFORE INSERT ON acme_tenant_key_facts FOR EACH ROW
						EXECUTE FUNCTION reject_test_certificate_key()`); err != nil {
						t.Fatal(err)
					}
					defer func() {
						if _, err := pool.Exec(context.Background(), `DROP TRIGGER reject_test_certificate_key_trigger
							ON acme_tenant_key_facts; DROP FUNCTION reject_test_certificate_key()`); err != nil {
							t.Errorf("drop SQL failure trigger: %v", err)
						}
					}()
				}
				dispatcher, _ := newRuntimeDispatcher(t, pool, test.issuer, 2, 20*time.Millisecond)
				dispatcher.config.RetryBase = time.Hour
				dispatcher.config.RetryMaximum = time.Hour
				result, err := dispatcher.DispatchOne(t.Context())
				if err != nil || result.Outcome != OutcomeRetry || result.ErrorCode != test.wantCode {
					t.Fatalf("dispatch=%+v error=%v", result, err)
				}
				assertOutbox(t, pool, fixture.outboxID, "failed", 1, test.wantCode)
				if test.installSQL {
					var keyCount int
					if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM acme_tenant_key_facts
						WHERE tenant_scope_id=$1`, fixture.scopeID).Scan(&keyCount); err != nil || keyCount != 0 {
						t.Fatalf("rolled back key count=%d error=%v", keyCount, err)
					}
				}
			})
		}
	})

	run("payload actor and provider facts fail closed", func(t *testing.T) {
		tests := []struct {
			name     string
			provider providerState
			payload  payloadState
			disable  bool
			wantCode string
		}{
			{"payload", providerVerified, payloadForgedDomains, false, "acme_outbox_payload_conflict"},
			{"actor", providerVerified, payloadValid, true, "acme_order_unavailable"},
			{"provider", providerDisabled, payloadValid, false, "acme_dns_provider_unavailable"},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				fixture := seedRuntimeOrder(t, pool, "dns-01", test.provider, test.payload)
				if test.disable {
					if _, err := pool.Exec(t.Context(), `UPDATE users SET status='disabled',revision=revision+1,
						updated_at=statement_timestamp() WHERE id=$1`, fixture.actorID); err != nil {
						t.Fatal(err)
					}
				}
				issuer := &scriptedIssuer{}
				dispatcher, _ := newRuntimeDispatcher(t, pool, issuer, 2, 20*time.Millisecond)
				dispatcher.config.RetryBase = time.Hour
				dispatcher.config.RetryMaximum = time.Hour
				result, err := dispatcher.DispatchOne(t.Context())
				if err != nil || result.Outcome != OutcomeRetry || result.ErrorCode != test.wantCode || issuer.callCount() != 0 {
					t.Fatalf("dispatch=%+v calls=%d error=%v", result, issuer.callCount(), err)
				}
				var keyCount int
				if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM acme_tenant_key_facts
					WHERE tenant_scope_id=$1`, fixture.scopeID).Scan(&keyCount); err != nil || keyCount != 0 {
					t.Fatalf("key count=%d error=%v", keyCount, err)
				}
			})
		}
	})

	run("ciphertext aad tenant purpose and external material fail closed", func(t *testing.T) {
		fixture := seedRuntimeIdentity(t, pool)
		keys, err := NewKeyStore(pool, runtimeWrappingKeyID, bytesOf(32, 7))
		if err != nil {
			t.Fatal(err)
		}
		externalRef, err := CertificateKeyRef(fixture.scopeID, uuid.New())
		if err != nil {
			t.Fatal(err)
		}
		insertRawKey(t, pool, fixture, externalRef, "certificate", bytesOf(32, 41), true)
		if _, err := keys.Signer(t.Context(), externalRef); !errors.Is(err, ErrUnsupportedKeyMaterial) {
			t.Fatalf("external signer error=%v", err)
		}
		wrappedRef, err := CertificateKeyRef(fixture.scopeID, uuid.New())
		if err != nil {
			t.Fatal(err)
		}
		insertRawKey(t, pool, fixture, wrappedRef, "certificate", bytesOf(32, 42), false)
		if _, err := keys.Signer(t.Context(), wrappedRef); !errors.Is(err, ErrConflict) {
			t.Fatalf("tampered wrapped signer error=%v", err)
		}
		otherTenantRef, err := CertificateKeyRef(uuid.New(), uuid.New())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := keys.Signer(t.Context(), otherTenantRef); !errors.Is(err, ErrConflict) {
			t.Fatalf("cross-tenant signer error=%v", err)
		}
		accountRef, err := AccountKeyRef(fixture.scopeID, runtimeDirectoryURL)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := keys.Signer(t.Context(), strings.Replace(accountRef, ":account:", ":certificate:", 1)); !errors.Is(err, ErrConflict) && !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("purpose-tampered signer error=%v", err)
		}
	})
}

func assertRuntimeOrder(t *testing.T, pool *pgxpool.Pool, orderID uuid.UUID, status string, revision int64) {
	t.Helper()
	var actualStatus string
	var actualRevision int64
	if err := pool.QueryRow(t.Context(), `SELECT status,revision FROM certificate_orders WHERE id=$1`, orderID).
		Scan(&actualStatus, &actualRevision); err != nil {
		t.Fatal(err)
	}
	if actualStatus != status || actualRevision != revision {
		t.Fatalf("order status=%s revision=%d, want %s/%d",
			actualStatus, actualRevision, status, revision)
	}
}

const (
	runtimeDirectoryURL  = "https://ca.example/directory"
	runtimeWrappingKeyID = "runtime-kek-v1"
)

type providerState int

const (
	providerNone providerState = iota
	providerVerified
	providerDisabled
)

type payloadState int

const (
	payloadValid payloadState = iota
	payloadForgedDomains
)

type runtimeFixture struct {
	tenantID   uuid.UUID
	scopeID    uuid.UUID
	actorID    uuid.UUID
	providerID uuid.UUID
	zoneID     uuid.UUID
	orderID    uuid.UUID
	outboxID   uuid.UUID
}

func seedRuntimeIdentity(t *testing.T, pool *pgxpool.Pool) runtimeFixture {
	t.Helper()
	fixture := runtimeFixture{tenantID: uuid.New(), scopeID: uuid.New(), actorID: uuid.New()}
	username := "runtime-" + strings.ReplaceAll(fixture.actorID.String(), "-", "")[:16]
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Runtime tenant')`, []any{fixture.tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, []any{fixture.scopeID, fixture.tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash)
		 VALUES($1,$2,'Runtime actor','test-hash')`, []any{fixture.actorID, username}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, []any{fixture.scopeID, fixture.actorID}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	return fixture
}

func seedRuntimeOrder(
	t *testing.T,
	pool *pgxpool.Pool,
	challengeType string,
	provider providerState,
	payloadState payloadState,
) runtimeFixture {
	t.Helper()
	fixture := seedRuntimeIdentity(t, pool)
	fixture.orderID = uuid.New()
	fixture.outboxID = uuid.New()
	domains := []string{"example.test", "www.example.test"}
	var providerID *uuid.UUID
	if provider != providerNone {
		fixture.providerID = uuid.New()
		providerID = &fixture.providerID
		status := "verified"
		if provider == providerDisabled {
			status = "disabled"
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO dns_providers(
			id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,status,
			created_by_user_id,updated_by_user_id
		) VALUES($1,$2,'Runtime DNS','cloudflare','credential-key',$3,$4,$5,$5)`,
			fixture.providerID, fixture.scopeID, bytesOf(32, 19), status, fixture.actorID); err != nil {
			t.Fatal(err)
		}
		fixture.zoneID = uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO dns_zones(
			id,scope_id,provider_id,name,created_by_user_id,updated_by_user_id
		) VALUES($1,$2,$3,'example.test',$4,$4)`, fixture.zoneID, fixture.scopeID,
			fixture.providerID, fixture.actorID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO certificate_orders(
		id,scope_id,dns_provider_id,domains,challenge_type,auto_renew,
		created_by_user_id,updated_by_user_id
	) VALUES($1,$2,$3,$4,$5,true,$6,$6)`, fixture.orderID, fixture.scopeID,
		providerID, domains, challengeType, fixture.actorID); err != nil {
		t.Fatal(err)
	}
	payloadDomains := domains
	if payloadState == payloadForgedDomains {
		payloadDomains = []string{"forged.example.test"}
	}
	payload, err := json.Marshal(outboxPayload{
		OrderID: fixture.orderID, ChallengeType: challengeType,
		Domains: payloadDomains, DNSProviderID: providerID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_acme_outbox(
		id,scope_id,aggregate_type,aggregate_id,event_type,payload
	) VALUES($1,$2,'certificate_order',$3,'certificate.order.requested',$4)`,
		fixture.outboxID, fixture.scopeID, fixture.orderID, payload); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func insertRawKey(
	t *testing.T,
	pool *pgxpool.Pool,
	fixture runtimeFixture,
	keyRef, purpose string,
	digest []byte,
	external bool,
) {
	t.Helper()
	if external {
		_, err := pool.Exec(t.Context(), `INSERT INTO acme_tenant_key_facts(
			tenant_scope_id,id,key_ref,purpose,algorithm,public_key_spki_sha256,
			external_key_reference,created_by_user_id
		) VALUES($1,$2,$3,$4,'ecdsa',$5,$6,$7)`, fixture.scopeID, uuid.New(), keyRef,
			purpose, digest, "kms://runtime/"+uuid.NewString(), fixture.actorID)
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	_, err := pool.Exec(t.Context(), `INSERT INTO acme_tenant_key_facts(
		tenant_scope_id,id,key_ref,purpose,algorithm,public_key_spki_sha256,
		wrapped_key_ciphertext,wrapping_key_id,wrapping_nonce,wrapping_aad_sha256,
		created_by_user_id
	) VALUES($1,$2,$3,$4,'ecdsa',$5,$6,$7,$8,$9,$10)`, fixture.scopeID, uuid.New(),
		keyRef, purpose, digest, bytesOf(48, 51), runtimeWrappingKeyID,
		bytesOf(12, 52), bytesOf(32, 53), fixture.actorID)
	if err != nil {
		t.Fatal(err)
	}
}

type scriptedIssuer struct {
	mu            sync.Mutex
	requests      []acmeworker.IssueRequest
	failures      []error
	invalidResult bool
}

func (i *scriptedIssuer) Issue(
	_ context.Context,
	request acmeworker.IssueRequest,
) (acmeworker.IssueResult, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	call := len(i.requests)
	i.requests = append(i.requests, request)
	if call < len(i.failures) && i.failures[call] != nil {
		return acmeworker.IssueResult{}, i.failures[call]
	}
	if i.invalidResult {
		return acmeworker.IssueResult{}, nil
	}
	return scriptedIssuedCertificate(request)
}

// scriptedIssuedCertificate is a well-formed issuer success for request: a
// self-signed leaf for exactly the requested names, so the dispatcher's own
// result checks (validIssueResult) pass and what is under test is the
// durable issued fact, not a malformed result.
func scriptedIssuedCertificate(request acmeworker.IssueRequest) (acmeworker.IssueResult, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return acmeworker.IssueResult{}, err
	}
	notBefore := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: request.Domains[0]},
		DNSNames: slices.Clone(request.Domains), NotBefore: notBefore, NotAfter: notBefore.Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return acmeworker.IssueResult{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return acmeworker.IssueResult{}, err
	}
	fingerprint, spki := sha256.Sum256(leaf.Raw), sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return acmeworker.IssueResult{Certificate: acmeworker.IssuedCertificate{
		RequestDigest: "sha256:request", CertificateKeyRef: request.CertificateKeyRef,
		PublicKeySPKISHA256: "sha256:" + hex.EncodeToString(spki[:]),
		LeafDER:             slices.Clone(leaf.Raw), ChainDER: [][]byte{slices.Clone(leaf.Raw)},
		CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}),
		SerialNumber:   leaf.SerialNumber.String(), DNSNames: slices.Clone(request.Domains),
		CertificateURL:  "https://ca.example/cert/" + request.CertificateOrderID.String(),
		LeafFingerprint: "sha256:" + hex.EncodeToString(fingerprint[:]),
		NotBefore:       leaf.NotBefore, NotAfter: leaf.NotAfter,
	}}, nil
}

func (i *scriptedIssuer) callCount() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.requests)
}

func (i *scriptedIssuer) request(index int) acmeworker.IssueRequest {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.requests[index]
}

func newRuntimeDispatcher(
	t *testing.T,
	pool *pgxpool.Pool,
	issuer Issuer,
	maxAttempts int,
	retryBase time.Duration,
) (*Dispatcher, *KeyStore) {
	t.Helper()
	keys, err := NewKeyStore(pool, runtimeWrappingKeyID, bytesOf(32, 7))
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig(runtimeDirectoryURL, []string{"mailto:ops@example.test"})
	config.LeaseDuration = time.Second
	config.SettleTimeout = time.Second
	config.RetryBase = retryBase
	config.RetryMaximum = 100 * time.Millisecond
	config.MaxAttempts = maxAttempts
	dispatcher, err := NewDispatcher(pool, issuer, keys, config)
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher, keys
}

func assertOutbox(
	t *testing.T,
	pool *pgxpool.Pool,
	outboxID uuid.UUID,
	wantStatus string,
	wantAttempts int,
	wantCode string,
) {
	t.Helper()
	var status string
	var attempts int
	var code *string
	if err := pool.QueryRow(t.Context(), `SELECT status,attempts,last_error_code
		FROM dns_acme_outbox WHERE id=$1`, outboxID).Scan(&status, &attempts, &code); err != nil {
		t.Fatal(err)
	}
	gotCode := ""
	if code != nil {
		gotCode = *code
	}
	if status != wantStatus || attempts != wantAttempts || gotCode != wantCode {
		t.Fatalf("outbox status=%q attempts=%d code=%q", status, attempts, gotCode)
	}
}
