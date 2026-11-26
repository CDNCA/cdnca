package site

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 订阅当前权益的网站数上限（site_limit，-1 不限）在新建网站与把网站绑到该订阅时执行，
// 与域名/端口同一事务、同一订阅行锁；已在上限的编辑照常保存，删除后释放名额，订阅换新权益后按新上限。
func TestSiteLimitAdmissionPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	dsn = databasetest.FreshDatabaseURL(t, dsn, "site_limit")
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "site_limit_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	manager := addonSiteInsertPlatformActor(t, pool, "site-limit-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "site-limit-manager", "billing.adjustments.manage", "packages.manage", "sites.manage")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Site limit tenant", "site-limit-user")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-limit-owner", "sites.manage", "dns.manage")
	product := addonSiteInsertPackageProductVersion(t, pool, manager, 1, 50, 1000)
	subscriptions := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, func() time.Time { return now }))
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	open := func(key string, siteLimit int64) uuid.UUID {
		t.Helper()
		opened, err := subscriptions.Open(t.Context(), manager, packagesubscription.OpenRequest{TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
			ProductID: product, ProductRevision: 1, SiteLimit: siteLimit, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
			CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor, IdempotencyKey: key, RequestID: key})
		if err != nil {
			t.Fatal(err)
		}
		return opened.Subscription.ID
	}
	subA, subB, subUnlimited := open("sub-a", 2), open("sub-b", 1), open("sub-unlimited", -1)
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, time.Hour)
	service := NewService(store)
	actor := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	// One root (example.co.uk) and the standard port only: only the website count limits these writes.
	fields := func(domain string, subscription uuid.UUID) SiteFields {
		return SiteFields{Domains: []string{domain}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"}, Enabled: false, Status: StatusDisabled, PackageSubscriptionID: &subscription}
	}
	create := func(key, domain string, subscription uuid.UUID) (WriteResult, error) {
		return service.Create(t.Context(), actor, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID, Fields: fields(domain, subscription), IdempotencyKey: key, RequestID: key})
	}
	refusedSites := func(err error, limit, used int64) {
		t.Helper()
		var refusal *packageaddon.QuotaExceededError
		if !errors.As(err, &refusal) || *refusal != (packageaddon.QuotaExceededError{Resource: packageaddon.QuotaResourceSites, Limit: limit, Used: used, Requested: 1}) {
			t.Fatalf("site limit refusal=%+v err=%v", refusal, err)
		}
	}
	revision := func(id uuid.UUID) int64 {
		t.Helper()
		var r int64
		if err := pool.QueryRow(t.Context(), `SELECT revision FROM sites WHERE id=$1`, id).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	update := func(key string, id uuid.UUID, f SiteFields) error {
		_, err := service.Update(t.Context(), actor, UpdateRequest{ID: id, ExpectedRevision: revision(id), Fields: f, IdempotencyKey: key, RequestID: key})
		return err
	}

	// Over the limit: refused, nothing written.
	first, err := create("a-1", "a1.example.co.uk", subA)
	if err != nil {
		t.Fatal(err)
	}
	second, err := create("a-2", "a2.example.co.uk", subA)
	if err != nil {
		t.Fatal(err)
	}
	_, err = create("a-3", "a3.example.co.uk", subA)
	refusedSites(err, 2, 2)
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM sites WHERE package_subscription_id=$1 AND deleted_at IS NULL`, subA).Scan(&count); err != nil || count != 2 {
		t.Fatalf("sites of A=%d err=%v", count, err)
	}
	// An edit of a site at the limit adds no site.
	if err := update("a-1-edit", first.Site.ID, fields("a1b.example.co.uk", subA)); err != nil {
		t.Fatalf("edit at the limit=%v", err)
	}

	// Deleting a site frees its slot.
	if _, err := service.Delete(t.Context(), actor, DeleteRequest{ID: second.Site.ID, ExpectedRevision: revision(second.Site.ID), IdempotencyKey: "a-2-delete", RequestID: "a-2-delete"}); err != nil {
		t.Fatal(err)
	}
	if _, err := create("a-3-again", "a3.example.co.uk", subA); err != nil {
		t.Fatalf("create after delete=%v", err)
	}

	// Binding a site to a full subscription is refused and keeps the old binding.
	if _, err := create("b-1", "b1.example.co.uk", subB); err != nil {
		t.Fatal(err)
	}
	refusedSites(update("a-1-to-b", first.Site.ID, fields("a1b.example.co.uk", subB)), 1, 1)
	var bound uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT package_subscription_id FROM sites WHERE id=$1`, first.Site.ID).Scan(&bound); err != nil || bound != subA {
		t.Fatalf("refused rebinding moved the site: %s err=%v", bound, err)
	}

	// The subscription's new entitlement (a package change) sets the limit used from then on.
	if _, err := pool.Exec(t.Context(), `INSERT INTO package_subscription_entitlement_versions(subscription_id,revision,supersedes_subscription_id,supersedes_revision,
	   tenant_scope_id,effective_at,effective_until,product_id,product_revision,product_snapshot,site_limit,domain_limit,node_limit,traffic_limit_bytes,
	   timezone,cycle_kind,custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,package_period,period_price_minor,currency,entitlement_status,source_order_id,operation,created_by_user_id,created_at)
	   SELECT subscription_id,revision+1,subscription_id,revision,tenant_scope_id,$2,NULL,product_id,product_revision,product_snapshot,3,domain_limit,node_limit,traffic_limit_bytes,
	    timezone,cycle_kind,custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,package_period,period_price_minor,currency,entitlement_status,NULL,'admin_edit',$3,$2
	   FROM package_subscription_entitlement_versions WHERE subscription_id=$1 ORDER BY revision DESC LIMIT 1`, subB, now, manager.UserID); err != nil {
		t.Fatal(err)
	}
	if err := update("a-1-to-b-raised", first.Site.ID, fields("a1b.example.co.uk", subB)); err != nil {
		t.Fatalf("rebinding under the raised limit=%v", err)
	}
	if _, err := create("b-3", "b3.example.co.uk", subB); err != nil {
		t.Fatalf("third site under the raised limit=%v", err)
	}
	_, err = create("b-4", "b4.example.co.uk", subB)
	refusedSites(err, 3, 3)

	// -1 is unlimited.
	for i := 0; i < 5; i++ {
		if _, err := create(fmt.Sprintf("u-%d", i), fmt.Sprintf("u%d.example.co.uk", i), subUnlimited); err != nil {
			t.Fatalf("unlimited site %d=%v", i, err)
		}
	}

	// The last slot goes to exactly one of two concurrent creates (the subscription row lock).
	race := open("sub-race", 1)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := create(fmt.Sprintf("race-%d", i), fmt.Sprintf("race%d.example.co.uk", i), race)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	success, denied := 0, 0
	for err := range results {
		switch {
		case err == nil:
			success++
		case errors.Is(err, packageaddon.ErrQuotaExceeded):
			denied++
		default:
			t.Fatal(err)
		}
	}
	if success != 1 || denied != 1 {
		t.Fatalf("concurrent last slot: success=%d denied=%d", success, denied)
	}
}
