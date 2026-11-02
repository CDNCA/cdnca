//go:build integration

package migrations_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestPurchasedSubscriptionOwner614: a subscription opened by a
// purchase before the fix has no package_monitor_subscription_owners row, so
// no site can be created under it. 614 backfills it from the purchase
// fulfillment; a subscription whose owner membership is suspended is skipped; down
// keeps the rows and up again is a no-op.
func TestPurchasedSubscriptionOwner614(t *testing.T) {
	// Keep equal to the 614 contract's version (renum-one.sh rewrites it).
	const version = 614
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	now := time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC)

	type purchase struct{ scopeID, userID, subscriptionID, fulfillmentID uuid.UUID }
	seed := func(name, membershipStatus string) purchase {
		t.Helper()
		p := purchase{scopeID: uuid.New(), userID: uuid.New(), subscriptionID: uuid.New(), fulfillmentID: uuid.New()}
		tenantID, orderID, suffix := uuid.New(), uuid.New(), strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
		mustExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, "614 "+name)
		mustExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, p.scopeID, tenantID)
		mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'unused')`,
			p.userID, "u614"+suffix)
		mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,$3)`,
			p.scopeID, p.userID, membershipStatus)
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		// Only the commerce facts a purchase leaves behind; their own append-only
		// and snapshot triggers are not what 614 is about.
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`SET LOCAL session_replication_role='replica'`, nil},
			{`INSERT INTO package_subscription_state_versions(
				subscription_id,revision,tenant_scope_id,owner_user_id,lifecycle_status,
				starts_at,ends_at,cancelled_at,created_at,updated_at,commit_sequence
			) VALUES($1,1,$2,$3,'active',$4,$5,NULL,$4,$4,0)`,
				[]any{p.subscriptionID, p.scopeID, p.userID, now, now.Add(30 * 24 * time.Hour)}},
			{`INSERT INTO package_orders(
				id,tenant_scope_id,user_id,operation,product_kind,product_id,product_revision,
				package_period,product_snapshot,entitlement_snapshot,pricing_snapshot,currency,
				original_amount_minor,discount_amount_minor,payable_amount_minor,
				settlement_direction,funding_source,effective_mode,effective_at,
				request_id,trace_id,created_by_scope_id,created_by_user_id,created_at,display_id,seller_scope_id
			) VALUES($1,$2,$3,'purchase','package_subscription',$4,1,'month',
				'{}'::jsonb,'{}'::jsonb,'{}'::jsonb,'CNY',0,0,0,
				'debit','provider','immediate',$5,$6,$6,$2,$3,$5,1,$2)`,
				[]any{orderID, p.scopeID, p.userID, uuid.New(), now, "o614" + suffix}},
			{`INSERT INTO package_order_fulfillments(
				id,order_id,tenant_scope_id,subscription_id,subscription_revision,entitlement_revision,fulfilled_at
			) VALUES($1,$2,$3,$4,1,1,$5)`, []any{p.fulfillmentID, orderID, p.scopeID, p.subscriptionID, now}},
			{`SET LOCAL session_replication_role='origin'`, nil},
		} {
			if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
				t.Fatalf("seed %s: %v", name, err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return p
	}
	active := seed("active", "active")
	left := seed("suspended", "suspended")

	owner := func(p purchase) (uuid.UUID, string, *uuid.UUID, bool) {
		t.Helper()
		var user uuid.UUID
		var kind string
		var fulfillment *uuid.UUID
		err := pool.QueryRow(ctx, `SELECT owner_user_id,source_kind,source_fulfillment_id
			FROM package_monitor_subscription_owners WHERE subscription_id=$1 AND state_revision=1`,
			p.subscriptionID).Scan(&user, &kind, &fulfillment)
		return user, kind, fulfillment, err == nil
	}
	if _, _, _, found := owner(active); found {
		t.Fatal("fixture already has an owner row before 614")
	}
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	user, kind, fulfillment, found := owner(active)
	if !found || user != active.userID || kind != "commerce_fulfillment" ||
		fulfillment == nil || *fulfillment != active.fulfillmentID {
		t.Fatalf("backfilled owner found=%t user=%s kind=%s fulfillment=%v", found, user, kind, fulfillment)
	}
	if _, _, _, found := owner(left); found {
		t.Fatal("subscription of a suspended member must not be backfilled")
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM package_monitor_subscription_owners
		WHERE subscription_id=$1`, active.subscriptionID).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("owner rows after up/down/up = %d, err=%v", rows, err)
	}
}
