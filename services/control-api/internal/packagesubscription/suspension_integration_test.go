package packagesubscription

import (
	"context"
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// bb03 (ADR 0019 §5, migration 555), 合并任务跑:
//
//	TEST_DATABASE_URL=... go -C services/control-api test -count=1 -p 1 \
//	  -run 'TestPostgresSubscriptionSuspend|TestPostgresResellerCancel' ./internal/packagesubscription/

// resellerOf makes tenant a reseller (active profile, reseller.customers.manage
// in a fresh session) with customer under it.
func resellerOf(t *testing.T, pool *pgxpool.Pool, platform Actor, reseller, customer tenantFixture) Actor {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO reseller_profiles(scope_id,status,revision,created_by_user_id,created_at,
		updated_by_user_id,updated_at) VALUES($1,'active',1,$2,clock_timestamp(),$2,clock_timestamp())`,
		reseller.scopeID, platform.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE tenants SET parent_scope_id=$1 WHERE id=(SELECT tenant_id FROM access_scopes WHERE id=$2)`,
		reseller.scopeID, customer.scopeID); err != nil {
		t.Fatal(err)
	}
	// Reseller permissions live on the owner role (480).
	makeOwner(t, pool, reseller, PermissionResellerCustomersManage)
	return Actor{UserID: reseller.userID, ScopeID: reseller.scopeID, SessionID: reseller.sessionID, ScopeKind: ScopeTenant}
}

// makeOwner gives the fixture tenant's user the tenant_owner role with
// permissions; 079 keeps owner apart from the fixture's tenant_viewer, so
// that assignment goes first.
func makeOwner(t *testing.T, pool *pgxpool.Pool, tenant tenantFixture, permissions ...string) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `DELETE FROM role_assignments assignment USING roles role
		WHERE assignment.role_id=role.id AND role.name='tenant_viewer' AND assignment.scope_id=$1 AND assignment.user_id=$2`,
		tenant.scopeID, tenant.userID); err != nil {
		t.Fatal(err)
	}
	assignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "tenant_owner", permissions...)
}

func openForSuspension(t *testing.T, service *Service, actor Actor, tenant tenantFixture, productID uuid.UUID, key string) Subscription {
	t.Helper()
	factor, err := packageperiod.NewTrafficFactor(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	duration := packageperiod.DurationMonth
	opened, err := service.Open(context.Background(), actor, OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: productID, ProductRevision: 1,
		SiteLimit: 1, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &duration}, TimeZone: "UTC",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: key, RequestID: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	return opened.Subscription
}

// Suspend keeps the term, advances the revision with a suspend version, is
// idempotent, touches only that subscription and is audited; the customer's
// reseller may do it, another reseller and the customer itself may not.
// Unsuspend clears it. Republication runs in the same transaction.
func TestPostgresSubscriptionSuspendUnsuspend(t *testing.T) {
	pool := isolatedSubscriptionPool(t)
	platform := insertPlatformActor(t, pool, "bb03-platform")
	customer := insertSubscriptionTenant(t, pool, "Customer", "bb03-customer")
	reseller := insertSubscriptionTenant(t, pool, "Reseller", "bb03-reseller")
	foreign := insertSubscriptionTenant(t, pool, "Foreign", "bb03-foreign")
	direct := insertSubscriptionTenant(t, pool, "Direct", "bb03-direct")
	resellerActor := resellerOf(t, pool, platform, reseller, customer)
	foreignActor := resellerOf(t, pool, platform, foreign, direct)
	productID := insertPackageProductVersion(t, pool, platform, 1, 10, 1_000)
	var republished []bool
	store := NewStore(pool).WithSuspensionRepublishTx(func(_ context.Context, tx pgx.Tx, scope, subscription uuid.UUID,
		from int64, suspend bool, _ string) error {
		if scope != customer.scopeID || from < 1 {
			return errors.New("unexpected republication")
		}
		republished = append(republished, suspend)
		return nil
	})
	service := NewService(store)
	first := openForSuspension(t, service, platform, customer, productID, "bb03-open-1")
	second := openForSuspension(t, service, platform, customer, productID, "bb03-open-2")
	request := func(key string, suspend bool) SuspendRequest {
		reason := ""
		if suspend {
			reason = "财务系统停用"
		}
		return SuspendRequest{TenantScopeID: customer.scopeID, SubscriptionID: first.ID, Suspend: suspend,
			Reason: reason, IdempotencyKey: key, RequestID: key}
	}
	// Another reseller, and a plain tenant on its own scope's neighbour, are refused.
	if _, err := service.Suspend(context.Background(), foreignActor, request("bb03-foreign", true)); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("foreign reseller suspend = %v", err)
	}
	customerActor := Actor{UserID: customer.userID, ScopeID: customer.scopeID, SessionID: customer.sessionID, ScopeKind: ScopeTenant}
	if _, err := service.Suspend(context.Background(), customerActor, request("bb03-self", true)); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("customer suspend without manage = %v", err)
	}
	suspended, err := service.Suspend(context.Background(), resellerActor, request("bb03-suspend", true))
	if err != nil {
		t.Fatal(err)
	}
	s := suspended.Subscription
	if s.SuspendedAt == nil || s.SuspendReason != "财务系统停用" || s.Revision != first.Revision+1 ||
		!s.Period.EndsAt.Equal(first.Period.EndsAt) || len(republished) != 1 || !republished[0] {
		t.Fatalf("suspended = %#v republished %v", s, republished)
	}
	// Replay and an already-suspended request both succeed without a write.
	if replay, err := service.Suspend(context.Background(), resellerActor, request("bb03-suspend", true)); err != nil || !replay.Replayed {
		t.Fatalf("replay = %#v, %v", replay, err)
	}
	if again, err := service.Suspend(context.Background(), platform, request("bb03-suspend-again", true)); err != nil ||
		again.Subscription.Revision != s.Revision || len(republished) != 1 {
		t.Fatalf("suspend again = %#v, %v (republished %v)", again.Subscription, err, republished)
	}
	var otherSuspended bool
	var versions, audits int
	if err := pool.QueryRow(t.Context(), `SELECT suspended_at IS NOT NULL FROM package_subscriptions WHERE id=$1`, second.ID).
		Scan(&otherSuspended); err != nil || otherSuspended {
		t.Fatalf("other subscription suspended=%v err=%v", otherSuspended, err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM package_subscription_versions WHERE subscription_id=$1 AND operation='suspend'`,
		first.ID).Scan(&versions); err != nil || versions != 1 {
		t.Fatalf("suspend versions = %d, %v", versions, err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='package_subscription.suspended' AND resource_id=$1`,
		first.ID.String()).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("suspend audits = %d, %v", audits, err)
	}
	// A direct write that changes the suspension without a version is refused.
	if _, err := pool.Exec(t.Context(), `UPDATE package_subscriptions SET suspended_at=NULL,suspend_reason=NULL,revision=revision+1,
		updated_at=clock_timestamp() WHERE id=$1`, first.ID); err == nil {
		t.Fatal("suspension change without a version was accepted")
	}
	resumed, err := service.Suspend(context.Background(), platform, request("bb03-unsuspend", false))
	if err != nil || resumed.Subscription.SuspendedAt != nil || resumed.Subscription.Revision != s.Revision+1 ||
		len(republished) != 2 || republished[1] {
		t.Fatalf("unsuspended = %#v, %v (republished %v)", resumed.Subscription, err, republished)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='package_subscription.unsuspended' AND resource_id=$1`,
		first.ID.String()).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("unsuspend audits = %d, %v", audits, err)
	}
	if _, err := service.Suspend(context.Background(), platform, SuspendRequest{TenantScopeID: customer.scopeID,
		SubscriptionID: first.ID, Suspend: true, IdempotencyKey: "bb03-noreason", RequestID: "bb03-noreason"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("suspend without reason = %v", err)
	}
}

// A reseller cancels its customer's subscription as the platform would; a
// tenant still cannot cancel another tenant's, nor a reseller a foreign one.
func TestPostgresResellerCancel(t *testing.T) {
	pool := isolatedSubscriptionPool(t)
	platform := insertPlatformActor(t, pool, "bb03c-platform")
	customer := insertSubscriptionTenant(t, pool, "Customer", "bb03c-customer")
	reseller := insertSubscriptionTenant(t, pool, "Reseller", "bb03c-reseller")
	foreign := insertSubscriptionTenant(t, pool, "Foreign", "bb03c-foreign")
	direct := insertSubscriptionTenant(t, pool, "Direct", "bb03c-direct")
	resellerActor := resellerOf(t, pool, platform, reseller, customer)
	foreignActor := resellerOf(t, pool, platform, foreign, direct)
	makeOwner(t, pool, direct, permissionManage) // package_subscriptions.manage is the owner role's (084)
	directActor := Actor{UserID: direct.userID, ScopeID: direct.scopeID, SessionID: direct.sessionID, ScopeKind: ScopeTenant}
	productID := insertPackageProductVersion(t, pool, platform, 1, 10, 1_000)
	service := NewService(NewStore(pool))
	subscription := openForSuspension(t, service, platform, customer, productID, "bb03c-open")
	cancel := func(actor Actor, key string) error {
		_, err := service.Cancel(context.Background(), actor, CancelRequest{TenantScopeID: customer.scopeID,
			SubscriptionID: subscription.ID, ExpectedRevision: subscription.Revision, IdempotencyKey: key, RequestID: key})
		return err
	}
	if err := cancel(directActor, "bb03c-tenant"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("other tenant cancel = %v", err)
	}
	if err := cancel(foreignActor, "bb03c-foreign"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("foreign reseller cancel = %v", err)
	}
	if err := cancel(resellerActor, "bb03c-reseller"); err != nil {
		t.Fatalf("reseller cancel = %v", err)
	}
	var status string
	if err := pool.QueryRow(t.Context(), `SELECT lifecycle_status FROM package_subscriptions WHERE id=$1`, subscription.ID).
		Scan(&status); err != nil || status != LifecycleCancelled {
		t.Fatalf("status = %s, %v", status, err)
	}
}
