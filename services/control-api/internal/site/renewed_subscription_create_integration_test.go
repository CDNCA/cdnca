package site

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 验收 acc-cd：续费过的订阅（revision 2）下建站 400 validation_error。
// package_monitor_subscription_owners 只在开通时写一行（state_revision=1），
// 续费推高 package_subscriptions.revision，建站的归属校验要求两者相等，
// 于是续费、启停、编辑过的订阅都无法再建站。
func TestCreateSiteUnderRenewedSubscription(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "renewed_sub_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	manager := addonSiteInsertPlatformActor(t, pool, "renewed-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "renewed-platform", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Renewed tenant", "renewed-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")
	owner := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	group, err := nodescheduler.NewService(pool, func() time.Time { return now }).PutGroup(ctx,
		nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}, nodescheduler.PutGroupRequest{
			Name: "renewed", Policy: nodescheduler.DefaultHealthPolicy(),
			Endpoints:      []nodescheduler.Endpoint{{ID: uuid.New(), Address: "192.0.2.41", Port: 80, Weight: 1, Enabled: true}},
			IdempotencyKey: "renewed-line-group", RequestID: "renewed-line-group",
		})
	if err != nil {
		t.Fatal(err)
	}
	providerID := uuid.New()
	exec(`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'renewed','cloudflare','fixture-key',$3,$4,$4)`, providerID, tenant.scopeID, make([]byte, 32), tenant.userID)
	exec(`INSERT INTO dns_zones(id,scope_id,provider_id,name,is_default,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'cdn.example.com',true,$4,$4)`, uuid.New(), tenant.scopeID, providerID, tenant.userID)
	productID := addonSiteInsertPackageProductVersion(t, pool, manager, 1, 100, 1000)
	subscriptions := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, func() time.Time { return now }))
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	opened, err := subscriptions.Open(ctx, manager, packagesubscription.OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: productID, ProductRevision: 1,
		SiteLimit: 100, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "renewed-subscription", RequestID: "renewed-subscription",
	})
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := subscriptions.Renew(ctx, manager, packagesubscription.RenewRequest{
		TenantScopeID: tenant.scopeID, SubscriptionID: opened.Subscription.ID, ExpectedRevision: opened.Subscription.Revision,
		Terms: packageperiod.Terms{Duration: &month}, IdempotencyKey: "renewed-renew", RequestID: "renewed-renew",
	})
	if err != nil || renewed.Subscription.Revision != 2 {
		t.Fatalf("renew revision=%d err=%v", renewed.Subscription.Revision, err)
	}
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, 24*time.Hour)
	for _, subscriptionID := range []*uuid.UUID{&opened.Subscription.ID, nil} {
		key := "renewed-site-" + uuid.NewString()[:8]
		created, err := NewService(store).Create(ctx, owner, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
			IdempotencyKey: key, RequestID: key, Fields: SiteFields{Domains: []string{key + ".example.co.uk"},
				HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"}, Enabled: false, Status: StatusDisabled,
				NodeGroupID: &group.Group.GroupID, NodeGroupName: group.Group.Name,
				PackageID: &productID, PackageName: "Business", PackageSubscriptionID: subscriptionID}})
		if err != nil {
			t.Fatalf("create under renewed subscription (explicit=%t): %v", subscriptionID != nil, err)
		}
		if created.Site.PackageSubscriptionID == nil || *created.Site.PackageSubscriptionID != opened.Subscription.ID {
			t.Fatalf("site subscription = %v", created.Site.PackageSubscriptionID)
		}
	}
}
