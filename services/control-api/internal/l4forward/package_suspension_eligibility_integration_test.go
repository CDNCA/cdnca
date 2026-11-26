//go:build integration

package l4forward

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// (G5): a forward on a suspended
// package subscription is left out of publication (edgepublish
// packageInEffectSQL) but read 正常 in the list and detail. It reads
// ineligible with package_suspended, as the site does, and eligible again
// once the subscription is resumed; a write on the suspended package says so
// in its response too. A cancelled one reads package_cancelled.
func TestForwardOnSuspendedPackageReadsIneligiblePostgres(t *testing.T) {
	pool := l4Package092Pool(t, 89)
	fixture := seedL4Package092Fixture(t, pool)
	mustMigrateL4Package092(t, pool, "up", l4Package092ReleaseHead(t))
	installL4Package092AutomaticPolicy(t, pool, fixture)
	service := NewService(NewStore(pool))
	actor := Actor{UserID: fixture.userID, ScopeID: fixture.scopeID, ScopeKind: "tenant"}
	request := CreateRequest{
		Fields: Fields{
			PackageSubscriptionID: &fixture.subscriptionID, Name: "suspended package", Protocol: ProtocolTCP,
			ListenAddress: "*", ListenPort: 19393, UpstreamAddress: "192.0.2.39", UpstreamPort: 443,
			ConnectTimeoutMS: 1000, ResponseTimeoutMS: 30000, MaxConnectionsPerClient: 100,
			ProxyProtocolV1: true, Enabled: true,
		},
		IdempotencyKey: "l4-suspended-create", RequestID: "l4-suspended-create",
	}
	created, err := service.Create(t.Context(), actor, request)
	if err != nil {
		t.Fatal(err)
	}
	expect := func(step string, item Forward, state EligibilityState, reason string) {
		t.Helper()
		if item.EligibilityState != state || item.IneligibleReason != reason {
			t.Fatalf("%s: eligibility=%q reason=%q, want %q %q", step, item.EligibilityState, item.IneligibleReason, state, reason)
		}
	}
	expect("created", created.Forward, EligibilityEligible, "")

	setL4SuspendedAt(t, pool, fixture.subscriptionID, true)
	detail, err := service.Get(t.Context(), actor, created.Forward.ID)
	if err != nil {
		t.Fatal(err)
	}
	expect("suspended detail", detail, EligibilityIneligible, IneligiblePackageSuspended)
	list, err := service.List(t.Context(), actor, ListFilter{Page: 1, Limit: 20})
	if err != nil || len(list.Items) != 1 {
		t.Fatalf("list: %d items, err=%v", len(list.Items), err)
	}
	expect("suspended list", list.Items[0], EligibilityIneligible, IneligiblePackageSuspended)
	// Quota admission does not refuse a suspended package; the response
	// still reads what publication does.
	update := UpdateRequest{ID: created.Forward.ID, ExpectedRevision: created.Forward.Revision, Fields: request.Fields,
		IdempotencyKey: "l4-suspended-update", RequestID: "l4-suspended-update"}
	update.Fields.Name = "edited while suspended"
	updated, err := service.Update(t.Context(), actor, update)
	if err != nil {
		t.Fatal(err)
	}
	expect("update while suspended", updated.Forward, EligibilityIneligible, IneligiblePackageSuspended)

	setL4SuspendedAt(t, pool, fixture.subscriptionID, false)
	detail, err = service.Get(t.Context(), actor, created.Forward.ID)
	if err != nil {
		t.Fatal(err)
	}
	expect("resumed detail", detail, EligibilityEligible, "")

	// G8: a cancelled subscription reads package_cancelled, as the
	// site's 订阅已终止, also when it was suspended before.
	setL4SuspendedAt(t, pool, fixture.subscriptionID, true)
	setL4Cancelled(t, pool, fixture.subscriptionID)
	detail, err = service.Get(t.Context(), actor, created.Forward.ID)
	if err != nil {
		t.Fatal(err)
	}
	expect("cancelled detail", detail, EligibilityIneligible, IneligiblePackageCancelled)
	list, err = service.List(t.Context(), actor, ListFilter{Page: 1, Limit: 20})
	if err != nil || len(list.Items) != 1 {
		t.Fatalf("list: %d items, err=%v", len(list.Items), err)
	}
	expect("cancelled list", list.Items[0], EligibilityIneligible, IneligiblePackageCancelled)
}

// setL4Cancelled cancels the subscription directly (the fixture bypasses the
// lifecycle triggers).
func setL4Cancelled(t *testing.T, pool *pgxpool.Pool, subscriptionID uuid.UUID) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE package_subscriptions SET lifecycle_status='cancelled',
			cancelled_at=COALESCE(cancelled_at,updated_at) WHERE id=$1`, subscriptionID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// setL4SuspendedAt sets or clears the subscription's suspension directly (the
// fixture bypasses the suspension triggers, as the edgepublish fixtures do).
func setL4SuspendedAt(t *testing.T, pool *pgxpool.Pool, subscriptionID uuid.UUID, suspended bool) {
	t.Helper()
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `UPDATE package_subscriptions SET
			suspended_at=CASE WHEN $2 THEN clock_timestamp() END,
			suspend_reason=CASE WHEN $2 THEN 'fixture' END WHERE id=$1`, subscriptionID, suspended)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
