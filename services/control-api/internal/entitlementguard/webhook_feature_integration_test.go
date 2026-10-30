package entitlementguard

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCheckFeatureSignedLeaseAndQuota(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	lease := fixture.lease(1)
	encoded := fixture.install(t, lease, fixture.now)
	revocation, err := NewRevocationService(fixture.pool, fixture.trust).Restore(t.Context(), fixture.now)
	if err != nil {
		t.Fatalf("Restore(revocation) error = %v", err)
	}

	featureOnly := fixture.check("feature-only")
	featureTx := fixture.begin(t)
	decision, err := fixture.guard().CheckFeature(t.Context(), featureTx, featureOnly)
	if err != nil {
		t.Fatalf("CheckFeature(feature only) error = %v", err)
	}
	wantDigest := sha256.Sum256(encoded)
	if decision.TargetScopeID != featureOnly.TargetScopeID ||
		decision.ActorScopeID != featureOnly.ActorScopeID || decision.ActorUserID != featureOnly.ActorUserID ||
		decision.ResourceType != featureOnly.ResourceType || decision.ResourceID != featureOnly.ResourceID ||
		decision.Operation != featureOnly.Operation || decision.Feature != featureOnly.Feature ||
		decision.LeaseSerial != lease.Serial || decision.LeaseSHA256 != wantDigest ||
		!decision.EvaluatedAt.Equal(fixture.now) ||
		!decision.NotBefore.Equal(time.Unix(lease.NotBefore, 0).UTC()) ||
		!decision.ExpiresAt.Equal(time.Unix(lease.ExpiresAt, 0).UTC()) ||
		!decision.GraceUntil.Equal(time.Unix(lease.GraceUntil, 0).UTC()) ||
		decision.RevocationRevision != revocation.Revision ||
		decision.RevocationSHA256 != revocation.ArtifactSHA256 ||
		decision.RevocationKeyID != revocation.KeyID ||
		!decision.RevocationIssuedAt.Equal(revocation.IssuedAt) ||
		!decision.RevocationExpiresAt.Equal(revocation.ExpiresAt) ||
		decision.Current != 0 || decision.Limit != 0 {
		t.Fatalf("feature decision = %#v", decision)
	}
	if err := featureTx.Rollback(t.Context()); err != nil {
		t.Fatalf("rollback feature transaction: %v", err)
	}

	quotaCheck := fixture.check("quota")
	quotaCheck.Quota = QuotaExtensionsWebhooksCount
	quotaCheck.Count = func(context.Context, pgx.Tx) (int64, error) { return 2, nil }
	quotaTx := fixture.begin(t)
	decision, err = fixture.guard().CheckFeature(t.Context(), quotaTx, quotaCheck)
	if err != nil {
		t.Fatalf("CheckFeature(quota) error = %v", err)
	}
	if decision.Quota != QuotaExtensionsWebhooksCount || decision.Current != 2 || decision.Limit != 3 {
		t.Fatalf("quota decision = %#v", decision)
	}
	if err := quotaTx.Rollback(t.Context()); err != nil {
		t.Fatalf("rollback quota transaction: %v", err)
	}

	quotaWithoutCount := fixture.check("quota-without-count")
	quotaWithoutCount.Quota = QuotaExtensionsWebhooksCount
	quotaWithoutCountTx := fixture.begin(t)
	decision, err = fixture.guard().CheckFeature(t.Context(), quotaWithoutCountTx, quotaWithoutCount)
	if err == nil {
		t.Fatalf("CheckFeature(quota without Count) = %#v, want error", decision)
	}
	if err := quotaWithoutCountTx.Rollback(t.Context()); err != nil {
		t.Fatalf("rollback quota-without-count transaction: %v", err)
	}
}

func TestCheckFeatureDeniesInvalidLeaseStatesAndQuota(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	tests := []struct {
		name    string
		prepare func(*testing.T, uint64) *Guard
		mutate  func(*FeatureCheck)
		want    error
	}{
		{name: "missing cache", prepare: fixture.missingCache, want: ErrUnavailable},
		{name: "missing trust", prepare: fixture.missingTrust, want: ErrUnavailable},
		{name: "invalid envelope", prepare: fixture.invalidEnvelope, want: ErrInvalid},
		{name: "invalid signature", prepare: fixture.invalidSignature, want: ErrInvalid},
		{name: "not yet valid", prepare: fixture.notYetValid, want: ErrStateDenied},
		// Grace is usable (lease_states_integration_test.go). The stale revocation
		// list is kept as last-known-good, so the lease window decides.
		{name: "expired", prepare: fixture.expired, want: ErrStateDenied},
		{name: "revoked", prepare: fixture.revoked, want: ErrStateDenied},
		{name: "missing feature", prepare: fixture.missingFeature, want: ErrFeatureDenied},
		{name: "missing quota", prepare: fixture.valid, mutate: func(check *FeatureCheck) {
			check.Quota = QuotaNodesCount
			check.Count = func(context.Context, pgx.Tx) (int64, error) { return 0, nil }
		}, want: ErrQuotaDenied},
		{name: "zero quota", prepare: fixture.zeroQuota, mutate: withWebhookCount(0), want: ErrQuotaExceeded},
		{name: "quota full", prepare: fixture.valid, mutate: withWebhookCount(3), want: ErrQuotaExceeded},
		{name: "quota exceeded", prepare: fixture.valid, mutate: withWebhookCount(4), want: ErrQuotaExceeded},
	}

	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serial := uint64(index + 10)
			guard := test.prepare(t, serial)
			check := fixture.check(fmt.Sprintf("deny-%d", serial))
			if test.mutate != nil {
				test.mutate(&check)
			}
			tx := fixture.begin(t)
			t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
			if _, err := guard.CheckFeature(t.Context(), tx, check); !errors.Is(err, test.want) || !IsDenial(err) {
				t.Fatalf("CheckFeature() error = %v, want %v", err, test.want)
			}
			var actorScope, targetScope string
			if err := tx.QueryRow(t.Context(), `
				SELECT payload->>'actor_scope_id', payload->>'target_scope_id'
				FROM audit_events WHERE request_id=$1`, check.RequestID).Scan(&actorScope, &targetScope); err != nil {
				t.Fatalf("read denial audit: %v", err)
			}
			if actorScope != check.ActorScopeID.String() || targetScope != check.TargetScopeID.String() {
				t.Fatalf("denial audit scopes = (%q, %q)", actorScope, targetScope)
			}
			if err := tx.Rollback(t.Context()); err != nil {
				t.Fatalf("rollback denial transaction: %v", err)
			}
		})
	}
}

func TestCheckFeatureEvaluatesAfterLockAcquisition(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	fixture.install(t, fixture.lease(45), fixture.now)

	holder := fixture.begin(t)
	if _, err := holder.Exec(t.Context(), `SELECT singleton FROM control_installation_entitlement WHERE singleton FOR UPDATE`); err != nil {
		t.Fatalf("lock entitlement singleton: %v", err)
	}
	waiter := fixture.begin(t)
	var waiterPID int
	if err := waiter.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&waiterPID); err != nil {
		t.Fatalf("read waiter backend PID: %v", err)
	}
	var released atomic.Bool
	guard := NewGuard(fixture.pool, func() time.Time {
		if released.Load() {
			return fixture.now.Add(3 * time.Hour)
		}
		return fixture.now
	}, fixture.trust)
	done := make(chan error, 1)
	go func() {
		_, err := guard.CheckFeature(context.Background(), waiter, fixture.check("post-lock-clock"))
		done <- err
	}()
	waitForEntitlementBlock(t, fixture.pool, waiterPID)
	released.Store(true)
	if err := holder.Commit(t.Context()); err != nil {
		t.Fatalf("commit lock holder: %v", err)
	}
	select {
	case err := <-done:
		// now+3h is past grace_until (now+2h): the clock read after the lock decides.
		if !errors.Is(err, ErrStateDenied) {
			t.Fatalf("CheckFeature(post-lock clock) error = %v, want ErrStateDenied", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CheckFeature post-lock clock waiter did not resume")
	}
	if err := waiter.Rollback(t.Context()); err != nil {
		t.Fatalf("rollback waiter: %v", err)
	}
}

func TestCheckFeatureLocksBeforeCount(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	fixture.install(t, fixture.lease(40), fixture.now)

	holder := fixture.begin(t)
	if _, err := holder.Exec(t.Context(), `SELECT singleton FROM control_installation_entitlement WHERE singleton FOR UPDATE`); err != nil {
		t.Fatalf("lock entitlement singleton: %v", err)
	}
	waiter := fixture.begin(t)
	var waiterPID int
	if err := waiter.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&waiterPID); err != nil {
		t.Fatalf("read waiter backend PID: %v", err)
	}
	countCalled := make(chan struct{}, 1)
	done := make(chan error, 1)
	check := fixture.check("lock-order")
	check.Quota = QuotaExtensionsWebhooksCount
	check.Count = func(context.Context, pgx.Tx) (int64, error) {
		countCalled <- struct{}{}
		return 0, nil
	}
	go func() {
		_, err := fixture.guard().CheckFeature(context.Background(), waiter, check)
		done <- err
	}()
	waitForEntitlementBlock(t, fixture.pool, waiterPID)
	select {
	case <-countCalled:
		t.Fatal("Count ran before the singleton entitlement row lock was acquired")
	default:
	}
	if err := holder.Commit(t.Context()); err != nil {
		t.Fatalf("commit lock holder: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("CheckFeature(waiter) error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CheckFeature waiter did not resume")
	}
	select {
	case <-countCalled:
	default:
		t.Fatal("Count was not called after singleton lock acquisition")
	}
	if err := waiter.Rollback(t.Context()); err != nil {
		t.Fatalf("rollback waiter: %v", err)
	}
}

func TestCheckFeatureRollbackRemovesValidationAndAudit(t *testing.T) {
	fixture := newWebhookFeatureFixture(t)
	fixture.invalidSignature(t, 50)
	check := fixture.check("rollback")
	tx := fixture.begin(t)
	if _, err := fixture.guard().CheckFeature(t.Context(), tx, check); !errors.Is(err, ErrInvalid) {
		t.Fatalf("CheckFeature() error = %v, want ErrInvalid", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	var status string
	var errorCode *string
	var verifiedAt time.Time
	var auditCount int
	if err := fixture.pool.QueryRow(t.Context(), `
		SELECT last_status, last_error_code, last_verified_at,
		       (SELECT count(*) FROM audit_events WHERE request_id=$1)
		FROM control_installation_entitlement WHERE singleton`, check.RequestID).Scan(&status, &errorCode, &verifiedAt, &auditCount); err != nil {
		t.Fatalf("read rollback state: %v", err)
	}
	if status != string(entitlement.StatusValid) || errorCode != nil || !verifiedAt.Equal(fixture.now) || auditCount != 0 {
		t.Fatalf("rollback left status=%q error=%v verified_at=%s audit_count=%d", status, errorCode, verifiedAt, auditCount)
	}
}

type webhookFeatureFixture struct {
	pool        *pgxpool.Pool
	now         time.Time
	signer      integrationSigner
	trust       *TrustStore
	targetScope uuid.UUID
	actorScope  uuid.UUID
	actorUser   uuid.UUID
	resourceID  uuid.UUID
}

func newWebhookFeatureFixture(t *testing.T) webhookFeatureFixture {
	t.Helper()
	return newWebhookFeatureFixtureWithKeyWindow(t, 24*time.Hour)
}

// newWebhookFeatureFixtureWithKeyWindow lets outage tests move the clock past
// the default one-day signing key verification window.
func newWebhookFeatureFixtureWithKeyWindow(t *testing.T, keyVerifyFor time.Duration) webhookFeatureFixture {
	t.Helper()
	pool := isolatedEntitlementPool(t)
	var now time.Time
	if err := pool.QueryRow(t.Context(), `SELECT date_trunc('second',clock_timestamp())`).Scan(&now); err != nil {
		t.Fatalf("read database clock: %v", err)
	}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	verifyUntil := now.Add(keyVerifyFor)
	fixture := webhookFeatureFixture{
		pool: pool, now: now,
		signer: integrationSigner{id: "webhook-feature-key", private: private},
		trust: mustTrustStore(t, VerificationKey{KeyID: "webhook-feature-key", PublicKey: public,
			NotBefore: now.Add(-24 * time.Hour), SignUntil: &verifyUntil, VerifyUntil: &verifyUntil}),
		targetScope: uuid.New(), actorScope: uuid.New(),
		actorUser: uuid.New(), resourceID: uuid.New(),
	}
	tenant := uuid.New()
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Webhook target')`, []any{tenant}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$3),($2,'platform',NULL)`, []any{fixture.targetScope, fixture.actorScope, tenant}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'webhook-feature-actor','Webhook actor','unused')`, []any{fixture.actorUser}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(t.Context(), statement.query, statement.args...); err != nil {
			t.Fatalf("seed feature fixture: %v", err)
		}
	}
	acceptIntegrationRevocation(t, pool, fixture.trust, fixture.signer, now, now.Add(-5*time.Minute), 1, nil)
	return fixture
}

func (fixture webhookFeatureFixture) lease(serial uint64) entitlement.Lease {
	lease := integrationLease(fixture.now, serial)
	lease.Features = []entitlement.Feature{{Code: FeatureExtensionsWebhooks}}
	lease.Quotas = []entitlement.Quota{{Code: QuotaExtensionsWebhooksCount, Limit: 3}}
	return lease
}

func (fixture webhookFeatureFixture) install(t *testing.T, lease entitlement.Lease, at time.Time) []byte {
	t.Helper()
	signed := signIntegrationLease(t, lease, fixture.signer)
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	service := NewService(fixture.pool, fixture.trust)
	if _, err := service.Install(t.Context(), InstallBundle{InstallationID: lease.InstallationID, SignedLease: signed}, at); err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	return encoded
}

func (fixture webhookFeatureFixture) guard() *Guard {
	return NewGuard(fixture.pool, func() time.Time { return fixture.now }, fixture.trust)
}

func (fixture webhookFeatureFixture) check(suffix string) FeatureCheck {
	return FeatureCheck{
		TargetScopeID: fixture.targetScope,
		ActorScopeID:  fixture.actorScope, ActorUserID: fixture.actorUser,
		ResourceType: "plugin_webhook_subscription", ResourceID: fixture.resourceID,
		RequestID: "webhook-feature-" + suffix, Operation: "plugin_webhook.subscription.create",
		Feature: FeatureExtensionsWebhooks,
	}
}

func (fixture webhookFeatureFixture) begin(t *testing.T) pgx.Tx {
	t.Helper()
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	return tx
}

func (fixture webhookFeatureFixture) valid(t *testing.T, serial uint64) *Guard {
	t.Helper()
	fixture.install(t, fixture.lease(serial), fixture.now)
	return fixture.guard()
}

func (fixture webhookFeatureFixture) missingCache(t *testing.T, serial uint64) *Guard {
	t.Helper()
	if _, err := fixture.pool.Exec(t.Context(), `
		INSERT INTO control_installation_entitlement(singleton,installation_id)
		VALUES(true,$1) ON CONFLICT(singleton) DO UPDATE SET current_serial=NULL,last_status='uninstalled',last_error_code=NULL`,
		integrationInstallationID); err != nil {
		t.Fatalf("clear cached lease: %v", err)
	}
	return fixture.guard()
}

func (fixture webhookFeatureFixture) missingTrust(t *testing.T, serial uint64) *Guard {
	t.Helper()
	fixture.install(t, fixture.lease(serial), fixture.now)
	return NewGuard(fixture.pool, func() time.Time { return fixture.now }, nil)
}

func (fixture webhookFeatureFixture) invalidEnvelope(t *testing.T, serial uint64) *Guard {
	t.Helper()
	fixture.install(t, fixture.lease(serial), fixture.now)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE entitlement_cached_leases SET signed_lease='{}' WHERE serial=$1`, serial); err != nil {
		t.Fatalf("damage cached envelope: %v", err)
	}
	return fixture.guard()
}

func (fixture webhookFeatureFixture) invalidSignature(t *testing.T, serial uint64) *Guard {
	t.Helper()
	fixture.install(t, fixture.lease(serial), fixture.now)
	var encoded []byte
	if err := fixture.pool.QueryRow(t.Context(), `SELECT signed_lease FROM entitlement_cached_leases WHERE serial=$1`, serial).Scan(&encoded); err != nil {
		t.Fatalf("read cached lease: %v", err)
	}
	signed, err := entitlement.Decode(encoded)
	if err != nil {
		t.Fatalf("decode cached lease for damage: %v", err)
	}
	signed.Signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	damaged, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("encode damaged lease: %v", err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE entitlement_cached_leases SET signed_lease=$2 WHERE serial=$1`, serial, damaged); err != nil {
		t.Fatalf("damage cached signature: %v", err)
	}
	return fixture.guard()
}

func (fixture webhookFeatureFixture) notYetValid(t *testing.T, serial uint64) *Guard {
	t.Helper()
	lease := fixture.lease(serial)
	fixture.install(t, lease, fixture.now)
	// Verify tolerates a signer clock lead of VerifierClockSkew on not_before;
	// stand just beyond it so the lease is genuinely not yet valid.
	return NewGuard(fixture.pool, func() time.Time {
		return time.Unix(lease.NotBefore, 0).Add(-entitlement.VerifierClockSkew - time.Second).UTC()
	}, fixture.trust)
}

func (fixture webhookFeatureFixture) expired(t *testing.T, serial uint64) *Guard {
	t.Helper()
	lease := fixture.lease(serial)
	fixture.install(t, lease, fixture.now)
	return NewGuard(fixture.pool, func() time.Time { return time.Unix(lease.GraceUntil, 0).UTC() }, fixture.trust)
}

func (fixture webhookFeatureFixture) revoked(t *testing.T, serial uint64) *Guard {
	t.Helper()
	fixture.install(t, fixture.lease(serial), fixture.now)
	if _, err := fixture.pool.Exec(t.Context(),
		`UPDATE entitlement_cached_leases SET status='revoked' WHERE serial=$1`, serial); err != nil {
		t.Fatalf("revoke cached lease: %v", err)
	}
	if _, err := fixture.pool.Exec(t.Context(),
		`UPDATE control_installation_entitlement SET last_status='revoked' WHERE singleton`); err != nil {
		t.Fatalf("record revoked lease status: %v", err)
	}
	return fixture.guard()
}

func (fixture webhookFeatureFixture) missingFeature(t *testing.T, serial uint64) *Guard {
	t.Helper()
	lease := fixture.lease(serial)
	lease.Features = []entitlement.Feature{{Code: FeatureSitesManage}}
	fixture.install(t, lease, fixture.now)
	return fixture.guard()
}

func (fixture webhookFeatureFixture) zeroQuota(t *testing.T, serial uint64) *Guard {
	t.Helper()
	lease := fixture.lease(serial)
	lease.Quotas[0].Limit = 0
	fixture.install(t, lease, fixture.now)
	return fixture.guard()
}

func withWebhookCount(current int64) func(*FeatureCheck) {
	return func(check *FeatureCheck) {
		check.Quota = QuotaExtensionsWebhooksCount
		check.Count = func(context.Context, pgx.Tx) (int64, error) { return current, nil }
	}
}

func waitForEntitlementBlock(t *testing.T, pool *pgxpool.Pool, waiterPID int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var blockers []int32
		if err := pool.QueryRow(t.Context(), `SELECT pg_blocking_pids($1)`, waiterPID).Scan(&blockers); err != nil {
			t.Fatalf("read blocking PIDs: %v", err)
		}
		if len(blockers) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("waiter never blocked on the entitlement singleton row")
}
