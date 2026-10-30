package packagesubscription

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresSubscriptionOpenProjectsAuthoritativeOwner(t *testing.T) {
	pool := isolatedSubscriptionPool(t)
	actor := insertPlatformActor(t, pool, "owner-projection-admin")
	tenant := insertSubscriptionTenant(t, pool, "Owner", "owner-projection-user")
	productID := insertPackageProductVersion(t, pool, actor, 1, 10, 1_000)
	now := time.Date(2026, time.October, 3, 0, 0, 0, 0, time.UTC)
	service := NewService(NewStoreWithClock(pool, func() time.Time { return now }))
	request := ownerProjectionOpenRequest(tenant, productID)
	opened, err := service.Open(t.Context(), actor, request)
	if err != nil {
		t.Fatal(err)
	}
	var revision int64
	var scopeID, ownerID uuid.UUID
	var source string
	var fulfillmentID *uuid.UUID
	var backfilled bool
	var createdAt time.Time
	if err := pool.QueryRow(t.Context(), `SELECT owner.state_revision,owner.tenant_scope_id,
		owner.owner_user_id,owner.source_kind,owner.source_fulfillment_id,
		owner.migration_backfilled,owner.created_at
		FROM package_monitor_subscription_owners owner
		JOIN package_subscription_state_versions state
		  ON state.subscription_id=owner.subscription_id AND state.revision=owner.state_revision
		 AND state.tenant_scope_id=owner.tenant_scope_id AND state.owner_user_id=owner.owner_user_id
		WHERE owner.subscription_id=$1`, opened.Subscription.ID).Scan(
		&revision, &scopeID, &ownerID, &source, &fulfillmentID, &backfilled, &createdAt); err != nil {
		t.Fatalf("read authoritative owner after Open: %v", err)
	}
	if revision != opened.Subscription.Revision || scopeID != tenant.scopeID || ownerID != tenant.userID ||
		source != "subscription_state" || fulfillmentID != nil || backfilled || !createdAt.Equal(now) {
		t.Fatalf("unexpected owner projection: revision=%d scope=%s owner=%s source=%s fulfillment=%v backfilled=%t created=%s",
			revision, scopeID, ownerID, source, fulfillmentID, backfilled, createdAt)
	}
	for range 3 {
		replayed, err := service.Open(t.Context(), actor, request)
		if err != nil || !replayed.Replayed || replayed.Subscription.ID != opened.Subscription.ID {
			t.Fatalf("replayed Open = %#v, %v", replayed, err)
		}
	}
	var owners, subscriptions, versions, writes, audits int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM package_monitor_subscription_owners),
		(SELECT count(*) FROM package_subscriptions),
		(SELECT count(*) FROM package_subscription_state_versions),
		(SELECT count(*) FROM package_subscription_write_requests WHERE completed_at IS NOT NULL),
		(SELECT count(*) FROM audit_events WHERE action='package.subscription.open')`).Scan(
		&owners, &subscriptions, &versions, &writes, &audits); err != nil {
		t.Fatal(err)
	}
	if [5]int{owners, subscriptions, versions, writes, audits} != [5]int{1, 1, 1, 1, 1} {
		t.Fatalf("replay duplicated facts: owners=%d subscriptions=%d states=%d writes=%d audits=%d",
			owners, subscriptions, versions, writes, audits)
	}
	assertMutationRejected(t, pool, "commerce owner proof is not exact", `
		INSERT INTO package_monitor_subscription_owners(
			subscription_id,state_revision,tenant_scope_id,owner_user_id,source_kind,created_at
		) VALUES ($1,1,$2,$3,'commerce_fulfillment',$4)`, opened.Subscription.ID, tenant.scopeID, tenant.userID, now)
	assertMutationRejected(t, pool, "migration provenance is reserved", `
		INSERT INTO package_monitor_subscription_owners(
			subscription_id,state_revision,tenant_scope_id,owner_user_id,source_kind,migration_backfilled,created_at
		) VALUES ($1,1,$2,$3,'subscription_state',true,$4)`, opened.Subscription.ID, tenant.scopeID, tenant.userID, now)
}

func TestPostgresSubscriptionOwnerProjectionRejectsForeignAndPlatformOwners(t *testing.T) {
	pool := isolatedSubscriptionPool(t)
	actor := insertPlatformActor(t, pool, "owner-isolation-admin")
	tenant := insertSubscriptionTenant(t, pool, "Owner", "owner-isolation-user")
	foreign := insertSubscriptionTenant(t, pool, "Foreign", "foreign-owner-user")
	productID := insertPackageProductVersion(t, pool, actor, 1, 10, 1_000)
	service := NewService(NewStore(pool))
	request := ownerProjectionOpenRequest(tenant, productID)
	request.OwnerUserID = foreign.userID
	if _, err := service.Open(t.Context(), actor, request); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("foreign owner Open = %v, want invalid input", err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES ($1,$2)`,
		tenant.scopeID, actor.UserID); err != nil {
		t.Fatal(err)
	}
	request.OwnerUserID = actor.UserID
	if _, err := service.Open(t.Context(), actor, request); err == nil {
		t.Fatal("platform member was accepted as subscription owner")
	}
	assertOwnerProjectionFactsEmpty(t, pool)
}

func TestPostgresSubscriptionOwnerProjectionRollsBackOnAuditFailure(t *testing.T) {
	pool := isolatedSubscriptionPool(t)
	actor := insertPlatformActor(t, pool, "owner-rollback-admin")
	tenant := insertSubscriptionTenant(t, pool, "Owner", "owner-rollback-user")
	productID := insertPackageProductVersion(t, pool, actor, 1, 10, 1_000)
	store := NewStore(pool)
	auditor := &ownerProjectionFailingAudit{}
	store.auditor = auditor
	if _, err := NewService(store).Open(t.Context(), actor, ownerProjectionOpenRequest(tenant, productID));
		!errors.Is(err, errOwnerProjectionAudit) {
		t.Fatalf("Open audit failure = %v", err)
	}
	if auditor.ownersBeforeFailure != 1 {
		t.Fatalf("audit observed %d owner rows before failure, want 1", auditor.ownersBeforeFailure)
	}
	assertOwnerProjectionFactsEmpty(t, pool)
}

func ownerProjectionOpenRequest(tenant tenantFixture, productID uuid.UUID) OpenRequest {
	duration := packageperiod.DurationMonth
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	return OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: productID, ProductRevision: 1,
		SiteLimit: 1, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &duration}, TimeZone: "UTC",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "owner-projection-open", RequestID: "owner-projection-open",
	}
}

var errOwnerProjectionAudit = errors.New("owner projection audit failure")

type ownerProjectionFailingAudit struct {
	ownersBeforeFailure int
}

func (a *ownerProjectionFailingAudit) Append(ctx context.Context, tx pgx.Tx, event audit.Event) error {
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM package_monitor_subscription_owners
		WHERE subscription_id=$1`, event.ResourceID).Scan(&a.ownersBeforeFailure); err != nil {
		return err
	}
	return errOwnerProjectionAudit
}

func assertOwnerProjectionFactsEmpty(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, table := range []string{
		"package_subscriptions", "package_subscription_versions", "package_subscription_state_versions",
		"package_subscription_entitlement_versions", "package_monitor_subscription_owners",
		"package_subscription_write_requests",
	} {
		var count int
		if err := pool.QueryRow(t.Context(), "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s retained %d rows after rejected Open", table, count)
		}
	}
}
