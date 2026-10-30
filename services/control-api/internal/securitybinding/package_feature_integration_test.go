package securitybinding

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func insertFeatureSubscription(t *testing.T, pool *pgxpool.Pool, scopeID, ownerID uuid.UUID, now time.Time, customCC, waf bool) uuid.UUID {
	t.Helper()
	id, productID, platformScope := uuid.New(), uuid.New(), uuid.Nil
	if err := pool.QueryRow(t.Context(), `SELECT id FROM access_scopes WHERE kind='platform' LIMIT 1`).Scan(&platformScope); err != nil {
		t.Fatal(err)
	}
	spec := fmt.Sprintf(`{"limits":{"domains":10,"root_domains":10,"http_ports":10,"stream_ports":10,"custom_cc":%t},"protection":{"waf":%t}}`, customCC, waf)
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT iam_global_lock_shared_v1()`); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `SELECT iam_scope_locks_v1(ARRAY[$1::uuid])`, platformScope); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_products(id,name,spec,created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,$4,$5,$5)`, productID, productID.String(), spec, ownerID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_product_versions(product_id,revision,name,enabled,sort_order,spec,created_by_user_id,created_at) VALUES($1,1,$2,true,100,$3,$4,$5)`, productID, productID.String(), spec, ownerID, now); err != nil {
			return err
		}
		if err := audit.New(pool).Append(t.Context(), tx, audit.Event{ScopeID: platformScope, ActorUserID: &ownerID, Action: "package.product.create", ResourceType: "package_product", ResourceID: productID.String(), RequestID: productID.String(), Result: "success", Payload: map[string]any{"revision": 1, "enabled": true}}); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_subscriptions(id,tenant_scope_id,product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,timezone,cycle_kind,tcp_factor_numerator,tcp_factor_denominator,created_by_user_id,updated_by_user_id,created_at,updated_at)
   SELECT $1,$2,product_id,revision,jsonb_build_object('id',product_id::text,'revision',revision,'name',name,'spec',spec),10,10,10,1000000,$4,$5,'UTC','monthly',1,1,$3,$3,$4,$4 FROM package_product_versions WHERE product_id=$6`, id, scopeID, ownerID, now, now.Add(24*time.Hour), productID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO package_subscription_entitlement_versions(subscription_id,revision,tenant_scope_id,effective_at,product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,tcp_factor_numerator,tcp_factor_denominator,currency,entitlement_status,operation,created_by_user_id,created_at)
   SELECT id,1,tenant_scope_id,starts_at,product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,tcp_factor_numerator,tcp_factor_denominator,'CNY','active','migration_backfill',created_by_user_id,created_at FROM package_subscriptions WHERE id=$1`, id)
		if err != nil {
			return err
		}
		_, err = tx.Exec(t.Context(), `INSERT INTO package_monitor_subscription_owners(subscription_id,state_revision,tenant_scope_id,owner_user_id,source_kind,created_at) VALUES($1,1,$2,$3,'subscription_state',$4)`, id, scopeID, ownerID, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func linkFeatureSubscription(t *testing.T, pool *pgxpool.Pool, siteID, subscriptionID uuid.UUID) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), `UPDATE sites SET package_subscription_id=$2,package_id=(SELECT product_id FROM package_subscriptions WHERE id=$2) WHERE id=$1`, siteID, subscriptionID); err != nil {
		t.Fatal(err)
	}
}

func assignFeature(t *testing.T, pool *pgxpool.Pool, scopeID, ownerID, subscriptionID uuid.UUID, kind string, now time.Time) uuid.UUID {
	t.Helper()
	id, addonID := uuid.New(), uuid.New()
	err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `SELECT id FROM package_subscriptions WHERE id=$1 FOR UPDATE`, subscriptionID); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_addon_products(id,name,kind,quantity,monthly_price_minor,created_at,updated_at) VALUES($1,$2,$3,1,0,$4,$4)`, addonID, addonID.String(), kind, now); err != nil {
			return err
		}
		if err := audit.New(pool).Append(t.Context(), tx, audit.Event{ScopeID: scopeID, ActorUserID: &ownerID, Action: "package.addon.product.create", ResourceType: "package_addon", ResourceID: addonID.String(), RequestID: addonID.String(), Result: "success", Payload: map[string]any{"revision": 1}}); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO package_addon_assignments(id,addon_id,tenant_scope_id,owner_user_id,subscription_id,kind,amount,snapshot,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,1,'{"quantity":1,"monthly_price_minor":0}',$7,$7)`, id, addonID, scopeID, ownerID, subscriptionID, kind, now); err != nil {
			return err
		}
		return audit.New(pool).Append(t.Context(), tx, audit.Event{ScopeID: scopeID, ActorUserID: &ownerID, Action: "package.addon.assignment.create", ResourceType: "package_addon", ResourceID: id.String(), RequestID: id.String(), Result: "success", Payload: map[string]any{"revision": 1}})
	})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func revokeFeatureTx(ctx context.Context, tx pgx.Tx, pool *pgxpool.Pool, scopeID, ownerID, assignmentID uuid.UUID, now time.Time) error {
	if _, err := tx.Exec(ctx, `SELECT s.id FROM package_subscriptions s JOIN package_addon_assignments a ON a.subscription_id=s.id WHERE a.id=$1 FOR UPDATE OF s`, assignmentID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE package_addon_assignments SET revoked_at=$2,updated_at=$2,revision=revision+1 WHERE id=$1`, assignmentID, now); err != nil {
		return err
	}
	return audit.New(pool).Append(ctx, tx, audit.Event{ScopeID: scopeID, ActorUserID: &ownerID, Action: "package.addon.assignment.revoke", ResourceType: "package_addon", ResourceID: assignmentID.String(), RequestID: uuid.NewString(), Result: "success", Payload: map[string]any{"revision": 2}})
}

func TestPackageFeatures(t *testing.T) {
	pool := isolatedBindingPool(t)
	platformScope, platformUser := uuid.New(), uuid.New()
	insertScopeUser(t, pool, platformScope, platformUser, uuid.Nil, "platform", "feature-platform")
	cases := []struct {
		name string
		run  func(*testing.T, bindingFixture)
	}{
		{"PublicationAndCustomCCCreation", testPackageFeaturePublicationAndCustomCCCreation},
		{"CustomCCOwnerAndDisable", testPackageFeatureCustomCCOwnerAndDisable},
		{"PublishWaitsForConcurrentRevocation", testPackageFeaturePublishWaitsForConcurrentRevocation},
		{"DisabledPublicationCanRemoveProtection", testPackageFeatureDisabledPublicationCanRemoveProtection},
		{"SystemWAFStillNeedsSubscription", testPackageFeatureSystemWAFStillNeedsSubscription},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			fixture := bindingFixture{pool: pool, platform: securitypolicy.Actor{UserID: platformUser, ScopeID: platformScope, ScopeKind: "platform"},
				tenantA: insertTenantResources(t, pool, uuid.NewString(), securitypolicy.KindCC), tenantB: insertTenantResources(t, pool, uuid.NewString(), securitypolicy.KindWAF)}
			item.run(t, fixture)
		})
	}
}

func testPackageFeaturePublicationAndCustomCCCreation(t *testing.T, fixture bindingFixture) {
	clock := &testClock{now: bindingTestNow}
	store := newBindingStore(t, fixture.pool, newRecordingSigner(), clock, 5*time.Minute)
	sub := insertFeatureSubscription(t, fixture.pool, fixture.tenantA.scopeID, fixture.tenantA.userID, bindingTestNow, false, false)
	linkFeatureSubscription(t, fixture.pool, fixture.tenantA.siteID, sub)
	request := publishRequest(fixture.tenantA, "package-feature", 1, 0, 0)
	if _, err := store.Publish(t.Context(), fixture.platform, request); !errors.Is(err, packageaddon.ErrFeatureDenied) {
		t.Fatalf("platform bypass: %v", err)
	}
	id := assignFeature(t, fixture.pool, fixture.tenantA.scopeID, fixture.tenantA.userID, sub, "custom_cc", bindingTestNow)
	first, err := store.Publish(t.Context(), tenantActor(fixture.tenantA), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		return revokeFeatureTx(t.Context(), tx, fixture.pool, fixture.tenantA.scopeID, fixture.tenantA.userID, id, bindingTestNow)
	}); err != nil {
		t.Fatal(err)
	}
	if replay, err := store.Publish(t.Context(), tenantActor(fixture.tenantA), request); err != nil || !replay.Replayed || replay.BundleID != first.BundleID {
		t.Fatalf("replay=%+v %v", replay, err)
	}
	addPolicyVersion(t, fixture.pool, fixture.tenantA, 2)
	if _, err := store.Publish(t.Context(), tenantActor(fixture.tenantA), publishRequest(fixture.tenantA, "after-revoke", 2, 1, 0)); !errors.Is(err, packageaddon.ErrFeatureDenied) {
		t.Fatalf("new publication after revoke: %v", err)
	}
	var count int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT count(*) FROM security_policy_publications WHERE tenant_scope_id=$1`, fixture.tenantA.scopeID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("publication facts=%d %v", count, err)
	}
}

func testPackageFeatureCustomCCOwnerAndDisable(t *testing.T, fixture bindingFixture) {
	owner := uuid.New()
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'cc owner','hash')`, owner, owner.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, fixture.tenantA.scopeID, owner); err != nil {
		t.Fatal(err)
	}
	actor := securitypolicy.Actor{UserID: owner, ScopeID: fixture.tenantA.scopeID, ScopeKind: "tenant"}
	service := securitypolicy.NewService(securitypolicy.NewStoreWithClock(fixture.pool, func() time.Time { return bindingTestNow }))
	policy := policyDocument(uuid.New(), actor.ScopeID, "cc", "new custom cc", 1)
	for i := range policy.Rules {
		policy.Rules[i].ID = uuid.Nil
	}
	fields := securitypolicy.PolicyFields{Kind: policy.Kind, Name: policy.Name, Enabled: true, DefaultAction: policy.DefaultAction, Rules: policy.Rules}
	request := securitypolicy.CreateRequest{TargetScopeID: actor.ScopeID, OwnerUserID: owner, Fields: fields, IdempotencyKey: "owner-cc", RequestID: "owner-cc"}
	if _, err := service.Create(t.Context(), fixture.platform, request); !errors.Is(err, packageaddon.ErrFeatureDenied) {
		t.Fatalf("another owner's rights / platform bypass: %v", err)
	}
	sub := insertFeatureSubscription(t, fixture.pool, actor.ScopeID, owner, bindingTestNow, false, false)
	assignment := assignFeature(t, fixture.pool, actor.ScopeID, owner, sub, "custom_cc", bindingTestNow)
	created, err := service.Create(t.Context(), actor, request)
	if err != nil {
		t.Fatal(err)
	}
	fields.Rules = created.Policy.Rules
	update := securitypolicy.UpdateRequest{ID: created.Policy.ID, ExpectedRevision: 1, Fields: fields, IdempotencyKey: "owner-cc-edit", RequestID: "owner-cc-edit"}
	updated, err := service.Update(t.Context(), actor, update)
	if err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		return revokeFeatureTx(t.Context(), tx, fixture.pool, actor.ScopeID, owner, assignment, bindingTestNow)
	}); err != nil {
		t.Fatal(err)
	}
	if replay, err := service.Update(t.Context(), actor, update); err != nil || !replay.Replayed {
		t.Fatalf("update replay=%+v %v", replay, err)
	}
	update.ExpectedRevision = updated.Policy.Revision
	update.IdempotencyKey = "owner-denied"
	if _, err := service.Update(t.Context(), actor, update); !errors.Is(err, packageaddon.ErrFeatureDenied) {
		t.Fatalf("update after revoke: %v", err)
	}
	update.Fields.Enabled = false
	update.IdempotencyKey = "owner-disable"
	disabled, err := service.Update(t.Context(), actor, update)
	if err != nil || disabled.Policy.Enabled {
		t.Fatalf("disable: %+v %v", disabled, err)
	}
	if _, err := service.Delete(t.Context(), actor, securitypolicy.DeleteRequest{ID: created.Policy.ID, ExpectedRevision: disabled.Policy.Revision, IdempotencyKey: "owner-delete", RequestID: "owner-delete"}); err != nil {
		t.Fatal(err)
	}
}

func testPackageFeaturePublishWaitsForConcurrentRevocation(t *testing.T, fixture bindingFixture) {
	clock := &testClock{now: bindingTestNow}
	store := newBindingStore(t, fixture.pool, newRecordingSigner(), clock, 5*time.Minute)
	sub := insertFeatureSubscription(t, fixture.pool, fixture.tenantB.scopeID, fixture.tenantB.userID, bindingTestNow, false, false)
	linkFeatureSubscription(t, fixture.pool, fixture.tenantB.siteID, sub)
	assignment := assignFeature(t, fixture.pool, fixture.tenantB.scopeID, fixture.tenantB.userID, sub, "waf", bindingTestNow)
	tx, err := fixture.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if err := revokeFeatureTx(t.Context(), tx, fixture.pool, fixture.tenantB.scopeID, fixture.tenantB.userID, assignment, bindingTestNow); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := store.Publish(t.Context(), fixture.platform, publishRequest(fixture.tenantB, "concurrent-revoke", 1, 0, 0))
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("publication passed subscription lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, packageaddon.ErrFeatureDenied) {
			t.Fatalf("revoked feature: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("publication deadlock")
	}
}

func testPackageFeatureDisabledPublicationCanRemoveProtection(t *testing.T, fixture bindingFixture) {
	clock := &testClock{now: bindingTestNow}
	store := newBindingStore(t, fixture.pool, newRecordingSigner(), clock, 5*time.Minute)
	sub := insertFeatureSubscription(t, fixture.pool, fixture.tenantB.scopeID, fixture.tenantB.userID, bindingTestNow, false, false)
	linkFeatureSubscription(t, fixture.pool, fixture.tenantB.siteID, sub)
	policy := policyDocument(fixture.tenantB.policyID, fixture.tenantB.scopeID, "waf", "disabled", 2)
	policy.Enabled = false
	document, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE security_policies SET enabled=false,revision=2 WHERE id=$1`, policy.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `INSERT INTO security_policy_versions(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,2,$2,$3,$4)`, policy.ID, document, fixture.tenantB.userID, bindingTestNow); err != nil {
		t.Fatal(err)
	}
	publication, err := store.Publish(t.Context(), fixture.platform, publishRequest(fixture.tenantB, "disable-no-rights", 2, 0, 0))
	if err != nil || publication.PolicyVersion != 2 {
		t.Fatalf("disabled publish=%+v %v", publication, err)
	}
}

func testPackageFeatureSystemWAFStillNeedsSubscription(t *testing.T, fixture bindingFixture) {
	sub := insertFeatureSubscription(t, fixture.pool, fixture.tenantB.scopeID, fixture.tenantB.userID, bindingTestNow, false, false)
	linkFeatureSubscription(t, fixture.pool, fixture.tenantB.siteID, sub)
	policy := policyDocument(fixture.tenantB.policyID, fixture.tenantB.scopeID, "waf", "system policy", 1)
	policy.Origin = "system"
	policy.Protected = true
	err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if err := LockSiteSubscription(t.Context(), tx, fixture.tenantB.scopeID, fixture.tenantB.siteID); err != nil {
			return err
		}
		return CheckSitePolicyFeature(t.Context(), tx, fixture.tenantB.scopeID, fixture.tenantB.siteID, policy, bindingTestNow)
	})
	if !errors.Is(err, packageaddon.ErrFeatureDenied) {
		t.Fatalf("system WAF bypass: %v", err)
	}
}
