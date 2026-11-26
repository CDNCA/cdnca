//go:build integration

package site

import (
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
)

// a site keeps http3_enabled (the user's
// choice) while the current entitlement of its subscription sets
// limits.http3 false, reads HTTP3PackageDenied (http3_effective false) then,
// and refuses only a write that switches HTTP/3 on (single update and batch
// set_protocols). The read follows package changes A→B→A.
func TestSiteHTTP3FollowsCurrentPackageEntitlement(t *testing.T) {
	pool := databasetest.MigratedPool(t, nil)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Second)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	manager := addonSiteInsertPlatformActor(t, pool, "h3-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "h3-platform", "platform.admin", "sites.manage")
	platform := Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform"}
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "H3 tenant", "h3-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")
	owner := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	group, err := nodescheduler.NewService(pool, func() time.Time { return now }).PutGroup(ctx,
		nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}, nodescheduler.PutGroupRequest{
			Name: "h3", Policy: nodescheduler.DefaultHealthPolicy(),
			Endpoints:      []nodescheduler.Endpoint{{ID: uuid.New(), Address: "192.0.2.43", Port: 80, Weight: 1, Enabled: true}},
			IdempotencyKey: "h3-line-group", RequestID: "h3-line-group",
		})
	if err != nil {
		t.Fatal(err)
	}
	providerID := uuid.New()
	exec(`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'h3','cloudflare','fixture-key',$3,$4,$4)`, providerID, tenant.scopeID, make([]byte, 32), tenant.userID)
	exec(`INSERT INTO dns_zones(id,scope_id,provider_id,name,is_default,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'cdn.example.com',true,$4,$4)`, uuid.New(), tenant.scopeID, providerID, tenant.userID)
	// A sets no limits.http3 (allowed); B is the same product sold with
	// limits.http3 false.
	productA := addonSiteInsertPackageProductVersion(t, pool, manager, 1, 100, 1000)
	productB := addonSiteInsertNamedPackageProductVersion(t, pool, manager, "Business B", 1, 100, 1000, "per_site", "cdn.example.com", "")
	subscriptions := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, func() time.Time { return now }))
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	opened, err := subscriptions.Open(ctx, manager, packagesubscription.OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: productA, ProductRevision: 1,
		SiteLimit: 100, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "h3-subscription", RequestID: "h3-subscription",
	})
	if err != nil {
		t.Fatal(err)
	}
	subscriptionID := opened.Subscription.ID
	// changeTo puts the subscription on product (its spec; http3 set
	// limits.http3), the entitlement in effect from now on.
	changeTo := func(product uuid.UUID, http3 *bool) {
		t.Helper()
		exec(`INSERT INTO package_subscription_entitlement_versions(
			subscription_id,revision,supersedes_subscription_id,supersedes_revision,tenant_scope_id,effective_at,effective_until,
			product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,traffic_limit_bytes,timezone,cycle_kind,
			custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,package_period,period_price_minor,currency,
			entitlement_status,source_order_id,operation,created_by_user_id,created_at)
			SELECT current.subscription_id,current.revision+1,current.subscription_id,current.revision,current.tenant_scope_id,
			  clock_timestamp(),NULL,$2,1,
			  jsonb_build_object('id',$2::text,'revision',1,'name',version.name,'spec',
			    CASE WHEN $3::boolean IS NULL THEN version.spec ELSE jsonb_set(version.spec,'{limits,http3}',to_jsonb($3::boolean)) END),
			  current.site_limit,current.domain_limit,current.node_limit,current.traffic_limit_bytes,current.timezone,current.cycle_kind,
			  current.custom_cycle_days,current.tcp_factor_numerator,current.tcp_factor_denominator,current.package_period,
			  current.period_price_minor,current.currency,'active',NULL,'admin_edit',current.created_by_user_id,clock_timestamp()
			FROM package_subscription_entitlement_versions current
			JOIN package_product_versions version ON version.product_id=$2 AND version.revision=1
			WHERE current.subscription_id=$1 ORDER BY current.revision DESC LIMIT 1`, subscriptionID, product, http3)
	}
	denied := false
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, 24*time.Hour)
	service := NewService(store)
	fieldsFor := func(domain string) SiteFields {
		return SiteFields{Domains: []string{domain}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
			Enabled: false, Status: StatusDisabled, NodeGroupID: &group.Group.GroupID, NodeGroupName: group.Group.Name,
			PackageID: &productA, PackageName: "Business", PackageSubscriptionID: &subscriptionID}
	}
	expect := func(step string, siteID uuid.UUID, enabled, packageDenied bool) Site {
		t.Helper()
		read, err := service.Get(ctx, owner, siteID)
		if err != nil || read.HTTP3Enabled != enabled || read.HTTP3PackageDenied != packageDenied {
			t.Fatalf("%s: http3 (enabled=%v denied=%v, err=%v), want (%v, %v)", step,
				read.HTTP3Enabled, read.HTTP3PackageDenied, err, enabled, packageDenied)
		}
		return read
	}
	step := 0
	update := func(siteID uuid.UUID, domain string, change func(*SiteFields)) error {
		t.Helper()
		step++
		current, err := service.Get(ctx, owner, siteID)
		if err != nil {
			t.Fatal(err)
		}
		fields := fieldsFor(domain)
		change(&fields)
		key := "h3-update-" + strconv.Itoa(step)
		_, err = service.Update(ctx, owner, UpdateRequest{ID: siteID, ExpectedRevision: current.Revision, Fields: fields,
			IdempotencyKey: key, RequestID: key})
		return err
	}
	batch := func(siteID uuid.UUID, http3 bool) BatchActionItemResult {
		t.Helper()
		step++
		current, err := service.Get(ctx, owner, siteID)
		if err != nil {
			t.Fatal(err)
		}
		key := "h3-batch-" + strconv.Itoa(step)
		result, err := service.BatchAction(ctx, platform, BatchActionRequest{Action: BatchActionSetProtocols,
			Items:     []BatchActionItem{{ID: siteID, ExpectedRevision: current.Revision}},
			Protocols: &BatchProtocols{HTTP3Enabled: &http3}, IdempotencyKey: key, RequestID: key})
		if err != nil || len(result.Items) != 1 {
			t.Fatalf("batch set_protocols http3=%v: (%+v, %v)", http3, result, err)
		}
		return result.Items[0]
	}

	// Under A: on, and it goes out.
	created, err := service.Create(ctx, owner, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
		IdempotencyKey: "h3-site", RequestID: "h3-site", Fields: fieldsFor("h3.example.co.uk")})
	if err != nil {
		t.Fatal(err)
	}
	siteID := created.Site.ID
	expect("under A", siteID, true, false)

	// A→B (limits.http3 false): the choice stays, the read says it does not go out.
	changeTo(productB, &denied)
	expect("after A→B", siteID, true, true)

	// A new site under B keeps the requested (default on) value; the read says not effective.
	second, err := service.Create(ctx, owner, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
		IdempotencyKey: "h3-site-2", RequestID: "h3-site-2", Fields: fieldsFor("h3-two.example.co.uk")})
	if err != nil {
		t.Fatalf("create under B: %v", err)
	}
	if !second.Site.HTTP3Enabled || !second.Site.HTTP3PackageDenied {
		t.Fatalf("create under B = (enabled=%v denied=%v), want the choice kept and denied", second.Site.HTTP3Enabled, second.Site.HTTP3PackageDenied)
	}
	expect("second site under B", second.Site.ID, true, true)

	// Saving other fields of a site already on is accepted (HTTP/3 left out and sent unchanged).
	off := false
	if err := update(siteID, "h3.example.co.uk", func(fields *SiteFields) { fields.CacheStatusHeader = &off }); err != nil {
		t.Fatalf("save other fields under B: %v", err)
	}
	on := true
	if err := update(siteID, "h3.example.co.uk", func(fields *SiteFields) { fields.HTTP3Enabled = &on }); err != nil {
		t.Fatalf("save keeping http3 on under B: %v", err)
	}
	expect("kept under B", siteID, true, true)

	// Turning it off is accepted; turning it back on is refused on the field.
	if err := update(siteID, "h3.example.co.uk", func(fields *SiteFields) { fields.HTTP3Enabled = &off }); err != nil {
		t.Fatalf("turn http3 off under B: %v", err)
	}
	expect("off under B", siteID, false, true)
	err = update(siteID, "h3.example.co.uk", func(fields *SiteFields) { fields.HTTP3Enabled = &on })
	var refusal *FieldError
	if !errors.As(err, &refusal) || refusal.Field != "http3_enabled" || refusal.Reason != "package_feature_denied" || !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("turn http3 on under B = %v, want field error http3_enabled package_feature_denied", err)
	}
	expect("refused on under B", siteID, false, true)
	// Saving other fields of a site that is off (HTTP/3 left out) is accepted.
	if err := update(siteID, "h3.example.co.uk", func(fields *SiteFields) { fields.CacheStatusHeader = &on }); err != nil {
		t.Fatalf("save other fields of an off site under B: %v", err)
	}

	// Batch set_protocols: on fails per item, off is never refused.
	if item := batch(siteID, true); item.Status != "failed" || item.Error == nil || item.Error.Code != "package_feature_denied" {
		t.Fatalf("batch on under B = %+v, want failed package_feature_denied", item)
	}
	expect("batch refused under B", siteID, false, true)
	if item := batch(second.Site.ID, false); item.Status != "updated" {
		t.Fatalf("batch off under B = %+v, want updated", item)
	}
	expect("batch off under B", second.Site.ID, false, true)

	// B→A: allowed again; switching on is accepted single-site and in a batch.
	changeTo(productA, nil)
	expect("after B→A", siteID, false, false)
	if err := update(siteID, "h3.example.co.uk", func(fields *SiteFields) { fields.HTTP3Enabled = &on }); err != nil {
		t.Fatalf("turn http3 on under A: %v", err)
	}
	expect("on under A", siteID, true, false)
	if item := batch(second.Site.ID, true); item.Status != "updated" || item.Site == nil || !item.Site.HTTP3Enabled {
		t.Fatalf("batch on under A = %+v, want updated", item)
	}
	expect("batch on under A", second.Site.ID, true, false)
}
