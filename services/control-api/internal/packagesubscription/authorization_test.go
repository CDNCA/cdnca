package packagesubscription

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/google/uuid"
)

func TestSubscriptionAuthorizationRequiresLiveSessionAndActionPermission(t *testing.T) {
	source, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"protocol.AcquireShared",
		"auth_sessions",
		"role_permissions",
		"package_subscriptions.read",
		"package_subscriptions.manage",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("subscription authorization is missing %q", required)
		}
	}
}

func TestPostgresSubscriptionAuthorizationRejectsInvalidSessionsAndMissingPermissions(t *testing.T) {
	pool := isolatedSubscriptionPool(t)
	now := time.Date(2026, time.August, 7, 9, 0, 0, 0, time.UTC)
	owner := insertPlatformActor(t, pool, "package-auth-owner")
	tenantA := insertSubscriptionTenant(t, pool, "Auth A", "package-auth-a")
	tenantB := insertSubscriptionTenant(t, pool, "Auth B", "package-auth-b")
	productID := insertPackageProductVersion(t, pool, owner, 1, 10, 1_000)
	service := NewService(NewStoreWithClock(pool, func() time.Time { return now }))
	factor, err := packageperiod.NewTrafficFactor(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	month := packageperiod.DurationMonth
	opened, err := service.Open(t.Context(), owner, OpenRequest{
		TenantScopeID: tenantA.scopeID, OwnerUserID: tenantA.userID,
		ProductID: productID, ProductRevision: 1,
		SiteLimit: 1, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "UTC",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "auth-baseline", RequestID: "auth-baseline",
	})
	if err != nil {
		t.Fatal(err)
	}

	newPlatformMember := func(name string) Actor {
		userID := uuid.New()
		insertSubscriptionUser(t, pool, owner.ScopeID, userID, name)
		return Actor{UserID: userID, ScopeID: owner.ScopeID,
			SessionID: insertSubscriptionSession(t, pool, owner.ScopeID, userID), ScopeKind: ScopePlatform}
	}
	withoutPermission := newPlatformMember("package-auth-no-permission")
	revoked := newPlatformMember("package-auth-revoked")
	if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=$2, revocation_reason=$3 WHERE id=$1`,
		revoked.SessionID, now, "authorization-test-revoked"); err != nil {
		t.Fatal(err)
	}
	expired := newPlatformMember("package-auth-expired")
	if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET expires_at=$2 WHERE id=$1`, expired.SessionID, now); err != nil {
		t.Fatal(err)
	}
	fake := withoutPermission
	fake.SessionID = uuid.New()
	mismatched := owner
	mismatched.ScopeKind = ScopeTenant
	crossTenant := Actor{UserID: tenantA.userID, ScopeID: tenantA.scopeID,
		SessionID: tenantA.sessionID, ScopeKind: ScopeTenant}

	assertDenied := func(name string, actor Actor, targetScopeID uuid.UUID, want error) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			operations := []struct {
				name string
				run  func() error
			}{
				{name: "get", run: func() error {
					_, err := service.Get(context.Background(), actor, targetScopeID, opened.Subscription.ID)
					return err
				}},
				{name: "open", run: func() error {
					_, err := service.Open(context.Background(), actor, OpenRequest{
						TenantScopeID: targetScopeID, OwnerUserID: tenantA.userID,
						ProductID: productID, ProductRevision: 1,
						SiteLimit: 1, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "UTC",
						CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
						IdempotencyKey: "auth-" + name + "-open", RequestID: "auth-" + name + "-open",
					})
					return err
				}},
				{name: "renew", run: func() error {
					_, err := service.Renew(context.Background(), actor, RenewRequest{
						TenantScopeID: targetScopeID, SubscriptionID: opened.Subscription.ID,
						ExpectedRevision: 1, Terms: packageperiod.Terms{Duration: &month},
						IdempotencyKey: "auth-" + name + "-renew", RequestID: "auth-" + name + "-renew",
					})
					return err
				}},
				{name: "cancel", run: func() error {
					_, err := service.Cancel(context.Background(), actor, CancelRequest{
						TenantScopeID: targetScopeID, SubscriptionID: opened.Subscription.ID,
						ExpectedRevision: 1, IdempotencyKey: "auth-" + name + "-cancel",
						RequestID: "auth-" + name + "-cancel",
					})
					return err
				}},
			}
			for _, operation := range operations {
				t.Run(operation.name, func(t *testing.T) {
					if err := operation.run(); !errors.Is(err, want) {
						t.Fatalf("error = %v, want %v", err, want)
					}
				})
			}
		})
	}

	assertDenied("missing_permission", withoutPermission, tenantA.scopeID, ErrPermissionDenied)
	assertDenied("fake_session", fake, tenantA.scopeID, ErrUnauthenticated)
	assertDenied("revoked_session", revoked, tenantA.scopeID, ErrUnauthenticated)
	assertDenied("expired_session", expired, tenantA.scopeID, ErrUnauthenticated)
	assertDenied("scope_kind_mismatch", mismatched, tenantA.scopeID, ErrUnauthenticated)
	assertDenied("wrong_tenant_scope", crossTenant, tenantB.scopeID, ErrPermissionDenied)

	var subscriptions, versions, writes, audits int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM package_subscriptions),
		(SELECT count(*) FROM package_subscription_versions),
		(SELECT count(*) FROM package_subscription_write_requests),
		(SELECT count(*) FROM audit_events WHERE action LIKE 'package.subscription.%')`,
	).Scan(&subscriptions, &versions, &writes, &audits); err != nil {
		t.Fatal(err)
	}
	if [4]int{subscriptions, versions, writes, audits} != [4]int{1, 1, 1, 1} {
		t.Fatalf("denied facts = %d/%d/%d/%d, want 1/1/1/1", subscriptions, versions, writes, audits)
	}
}
