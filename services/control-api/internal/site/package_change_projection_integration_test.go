package site

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
)

// a site created under product A
// shows its subscription's current product once the subscription changed to
// B (the entitlement in effect; the row keeps A, 261): GET, the package
// filter, and a save from a page read before the change, which keeps showing
// B (the row's package_id stays the purchased product, FK 113).
func TestSiteShowsSubscriptionCurrentPackageAfterChange(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	manager := addonSiteInsertPlatformActor(t, pool, "change-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "change-platform", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Change tenant", "change-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")
	owner := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	group, err := nodescheduler.NewService(pool, func() time.Time { return now }).PutGroup(ctx,
		nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}, nodescheduler.PutGroupRequest{
			Name: "change", Policy: nodescheduler.DefaultHealthPolicy(),
			Endpoints:      []nodescheduler.Endpoint{{ID: uuid.New(), Address: "192.0.2.42", Port: 80, Weight: 1, Enabled: true}},
			IdempotencyKey: "change-line-group", RequestID: "change-line-group",
		})
	if err != nil {
		t.Fatal(err)
	}
	providerID := uuid.New()
	exec(`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'change','cloudflare','fixture-key',$3,$4,$4)`, providerID, tenant.scopeID, make([]byte, 32), tenant.userID)
	exec(`INSERT INTO dns_zones(id,scope_id,provider_id,name,is_default,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'cdn.example.com',true,$4,$4)`, uuid.New(), tenant.scopeID, providerID, tenant.userID)
	productA := addonSiteInsertPackageProductVersion(t, pool, manager, 1, 100, 1000)
	productB := addonSiteInsertNamedPackageProductVersion(t, pool, manager, "Limited B", 1, 1, 10_737_418, "per_site", "cdn.example.com", "")
	subscriptions := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, func() time.Time { return now }))
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	opened, err := subscriptions.Open(ctx, manager, packagesubscription.OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: productA, ProductRevision: 1,
		SiteLimit: 100, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "change-subscription", RequestID: "change-subscription",
	})
	if err != nil {
		t.Fatal(err)
	}
	subscriptionID := opened.Subscription.ID
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, 24*time.Hour)
	service := NewService(store)
	fields := SiteFields{Domains: []string{"change.example.co.uk"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
		Enabled: false, Status: StatusDisabled, NodeGroupID: &group.Group.GroupID, NodeGroupName: group.Group.Name,
		PackageID: &productA, PackageName: "Business", PackageSubscriptionID: &subscriptionID}
	created, err := service.Create(ctx, owner, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
		IdempotencyKey: "change-site", RequestID: "change-site", Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	siteID := created.Site.ID
	if read, err := service.Get(ctx, owner, siteID); err != nil || read.Package == nil || read.Package.ID != productA {
		t.Fatalf("site under A = (%+v, %v)", read.Package, err)
	}

	// The change: entitlement revision 2 in effect now, product B named "Limited B".
	exec(`INSERT INTO package_subscription_entitlement_versions(
		subscription_id,revision,supersedes_subscription_id,supersedes_revision,tenant_scope_id,effective_at,effective_until,
		product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,
		custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,package_period,period_price_minor,currency,
		entitlement_status,source_order_id,operation,created_by_user_id,created_at)
		SELECT current.subscription_id,current.revision+1,current.subscription_id,current.revision,current.tenant_scope_id,
		  clock_timestamp(),NULL,$2,1,
		  jsonb_build_object('id',$2::text,'revision',1,'name','Limited B','spec',version.spec),
		  1,1,current.node_limit,10737418,current.timezone,current.cycle_kind,current.custom_cycle_days,
		  current.tcp_factor_numerator,current.tcp_factor_denominator,current.package_period,current.period_price_minor,
		  current.currency,'active',NULL,'admin_edit',current.created_by_user_id,clock_timestamp()
		FROM package_subscription_entitlement_versions current
		JOIN package_product_versions version ON version.product_id=$2 AND version.revision=1
		WHERE current.subscription_id=$1 ORDER BY current.revision DESC LIMIT 1`, subscriptionID, productB)

	read, err := service.Get(ctx, owner, siteID)
	if err != nil || read.Package == nil || read.Package.ID != productB || read.Package.Name != "Limited B" ||
		read.PackageSubscriptionID == nil || *read.PackageSubscriptionID != subscriptionID {
		t.Fatalf("site after the change = (%+v, %v), want product B \"Limited B\" on the same subscription", read.Package, err)
	}
	for product, want := range map[uuid.UUID]int64{productB: 1, productA: 0} {
		filter := product
		listed, err := service.List(ctx, owner, ListFilter{Page: 1, Limit: 20, PackageID: &filter})
		if err != nil || listed.Total != want {
			t.Fatalf("package filter %s total=%d err=%v, want %d", product, listed.Total, err, want)
		}
	}

	// A page read before the change saves A back: the site keeps B.
	stale := fields
	if _, err := service.Update(ctx, owner, UpdateRequest{ID: siteID, ExpectedRevision: read.Revision, Fields: stale,
		IdempotencyKey: "change-site-save", RequestID: "change-site-save"}); err != nil {
		t.Fatalf("save from a page read before the change: %v", err)
	}
	var storedID uuid.UUID
	var storedName string
	if err := pool.QueryRow(ctx, `SELECT package_id,package_name FROM sites WHERE id=$1`, siteID).
		Scan(&storedID, &storedName); err != nil {
		t.Fatal(err)
	}
	// The row's package_id stays the subscription row's product (FK 113 to
	// package_subscriptions.product_id, which keeps A, 261); the name is B's.
	if storedID != productA || storedName != "Limited B" {
		t.Fatalf("saved site package = (%s,%q), want (A, \"Limited B\")", storedID, storedName)
	}
	if saved, err := service.Get(ctx, owner, siteID); err != nil || saved.Package == nil || saved.Package.ID != productB {
		t.Fatalf("site after the save = (%+v, %v), want product B", saved.Package, err)
	}
	// A product this subscription never had is still refused.
	foreign := uuid.New()
	other := fields
	other.PackageID = &foreign
	again, err := service.Get(ctx, owner, siteID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Update(ctx, owner, UpdateRequest{ID: siteID, ExpectedRevision: again.Revision, Fields: other,
		IdempotencyKey: "change-site-foreign", RequestID: "change-site-foreign"}); err == nil {
		t.Fatal("save naming a product the subscription never had was accepted")
	}
}
