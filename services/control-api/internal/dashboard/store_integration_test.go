package dashboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analytics"
	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type analyticsStub struct {
	summary      analytics.Summary
	trend        []analytics.TrendPoint
	ranks        map[analytics.RankDimension]analytics.RankPage
	err          error
	finalization analyticsFinalizationSnapshot
	actors       []analytics.Actor
	requests     []analytics.QueryRequest
}

func (stub *analyticsStub) Read(
	_ context.Context,
	_ pgx.Tx,
	_ Audience,
	_ uuid.UUID,
) (analyticsFinalizationSnapshot, error) {
	return stub.finalization, nil
}

func (stub *analyticsStub) Summary(_ context.Context, actor analytics.Actor, request analytics.QueryRequest) (analytics.Summary, error) {
	stub.actors = append(stub.actors, actor)
	stub.requests = append(stub.requests, request)
	return stub.summary, stub.err
}

func (stub *analyticsStub) Trend(_ context.Context, actor analytics.Actor, request analytics.QueryRequest) ([]analytics.TrendPoint, error) {
	stub.actors = append(stub.actors, actor)
	stub.requests = append(stub.requests, request)
	return stub.trend, stub.err
}

func (stub *analyticsStub) Rank(
	_ context.Context,
	actor analytics.Actor,
	request analytics.QueryRequest,
	dimension analytics.RankDimension,
	_ uint16,
	_ string,
) (analytics.RankPage, error) {
	stub.actors = append(stub.actors, actor)
	stub.requests = append(stub.requests, request)
	return stub.ranks[dimension], stub.err
}

type dashboardFixture struct {
	pool          *pgxpool.Pool
	store         *Store
	analytics     *analyticsStub
	now           time.Time
	platformActor Actor
	tenantActor   Actor
	otherActor    Actor
	tenantRoleID  uuid.UUID
	tenantID      uuid.UUID
	tenantScopeID uuid.UUID
}

func TestPostgresDashboardReadModelsIsolationRevocationAndUnavailableAnalytics(t *testing.T) {
	fixture, cleanup := newDashboardFixture(t)
	defer cleanup()

	tenantQuery, err := NewQuery(AudienceTenant, "today", "UTC", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := fixture.store.Tenant(t.Context(), fixture.tenantActor, tenantQuery)
	if err != nil {
		t.Fatal(err)
	}
	if tenant.DashboardVersion != Version || tenant.Meta.Range != "today" {
		t.Fatalf("tenant response metadata = %#v", tenant)
	}
	if !tenant.Resources.Available || tenant.Resources.Value == nil || tenant.Resources.Value.SitesTotal != 1 ||
		tenant.Resources.Value.ForwardsTotal != 1 {
		t.Fatalf("tenant resources = %#v", tenant.Resources)
	}
	if !tenant.Certificates.Available || tenant.Certificates.Value == nil || tenant.Certificates.Value.Total != 1 {
		t.Fatalf("tenant certificates = %#v", tenant.Certificates)
	}
	if !tenant.Billing.Available || tenant.Billing.Value == nil || tenant.Billing.Value.BalanceMinor != 0 {
		t.Fatalf("tenant billing = %#v", tenant.Billing)
	}
	if !tenant.Operations.Available || tenant.Operations.Value == nil ||
		tenant.Operations.Value.CacheTotal != 1 || tenant.Operations.Value.JobsTotal != 1 {
		t.Fatalf("tenant operations = %#v", tenant.Operations)
	}
	if tenant.Subscriptions.Value == nil || tenant.Subscriptions.Value.Items == nil ||
		tenant.Notices.Value == nil || tenant.Notices.Value.Items == nil {
		t.Fatalf("empty arrays were not concrete: subscriptions=%#v notices=%#v", tenant.Subscriptions, tenant.Notices)
	}
	if !tenant.Analytics.Available || tenant.Analytics.Value == nil || tenant.Analytics.Value.Summary.SecurityEvents != 3 {
		t.Fatalf("tenant analytics = %#v", tenant.Analytics)
	}
	assertTenantAnalyticsRequest(t, fixture, 0, tenantQuery)
	otherTenant, err := fixture.store.Tenant(t.Context(), fixture.otherActor, tenantQuery)
	if err != nil {
		t.Fatal(err)
	}
	if otherTenant.Resources.Value == nil || otherTenant.Resources.Value.SitesTotal != 0 ||
		otherTenant.Resources.Value.ForwardsTotal != 0 ||
		otherTenant.Operations.Value == nil || otherTenant.Operations.Value.CacheTotal != 0 ||
		otherTenant.Certificates.Value == nil || otherTenant.Certificates.Value.Total != 1 ||
		otherTenant.Operations.Value.JobsTotal != 1 {
		t.Fatalf("other tenant leaked tenant A site/cache facts: resources=%#v operations=%#v",
			otherTenant.Resources, otherTenant.Operations)
	}
	// 每次概览读 7 个分析请求（Summary/Trend/5 个排行），第二次租户读的第一个请求下标为 7。
	if fixture.analytics.actors[7].TenantID != fixture.otherActor.TenantID.String() {
		t.Fatalf("other tenant analytics actor = %#v", fixture.analytics.actors[7])
	}

	adminQuery, err := NewQuery(AudienceAdmin, "seven_days", "UTC", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := fixture.store.Admin(t.Context(), fixture.platformActor, adminQuery)
	if err != nil {
		t.Fatal(err)
	}
	if !admin.Accounts.Available || admin.Accounts.Value == nil ||
		admin.Accounts.Value.TenantsTotal != 2 || admin.Accounts.Value.TenantUsersTotal != 2 {
		t.Fatalf("admin accounts = %#v", admin.Accounts)
	}
	if !admin.Resources.Available || admin.Resources.Value == nil ||
		admin.Resources.Value.SitesTotal != 1 || admin.Resources.Value.NodesTotal != 1 ||
		admin.Resources.Value.CertificatesTotal != 2 {
		t.Fatalf("admin resources = %#v", admin.Resources)
	}
	if admin.NodeHealth.Value == nil || admin.NodeHealth.Value.PresenceMissing != 1 ||
		admin.NodeHealth.Value.FreshnessCutoffSeconds != 45 {
		t.Fatalf("admin node health = %#v", admin.NodeHealth)
	}
	// 每次概览读：Summary + Trend + 5 个排行维度（域名/URL/IP/地区/运营商）= 7 个请求；
	// 两次租户读之后的第 15 个请求是管理员读的第一个。
	const analyticsRequestsPerRead = 7
	if len(fixture.analytics.requests) != 3*analyticsRequestsPerRead ||
		fixture.analytics.requests[2*analyticsRequestsPerRead].Audience != analytics.AudiencePlatform ||
		fixture.analytics.requests[2*analyticsRequestsPerRead].TenantID != "" {
		t.Fatalf("admin analytics request = %#v", fixture.analytics.requests)
	}

	fixture.analytics.err = errors.New("clickhouse unavailable")
	degraded, err := fixture.store.Tenant(t.Context(), fixture.tenantActor, tenantQuery)
	if err != nil {
		t.Fatal(err)
	}
	if degraded.Analytics.Available || degraded.Analytics.Reason != ReasonDependencyUnavailable || degraded.Analytics.Value != nil {
		t.Fatalf("degraded analytics = %#v", degraded.Analytics)
	}
	if !degraded.Resources.Available || degraded.Resources.Value == nil || degraded.Resources.Value.SitesTotal != 1 {
		t.Fatalf("PostgreSQL facts were lost on analytics outage: %#v", degraded.Resources)
	}

	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 AND role_id=$3`, fixture.tenantScopeID,
		fixture.tenantActor.UserID, fixture.tenantRoleID); err != nil {
		t.Fatal(err)
	}
	beforeCalls := len(fixture.analytics.requests)
	_, err = fixture.store.Tenant(t.Context(), fixture.tenantActor, tenantQuery)
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("post-revocation error = %v, want permission denied", err)
	}
	if len(fixture.analytics.requests) != beforeCalls {
		t.Fatal("analytics was called after live RBAC revocation")
	}
}

func TestPostgresDashboardCountsActiveSiteDomainFacts(t *testing.T) {
	fixture, cleanup := newDashboardFixture(t)
	defer cleanup()

	var siteID uuid.UUID
	if err := fixture.pool.QueryRow(t.Context(), `SELECT id FROM sites WHERE scope_id=$1`, fixture.tenantScopeID).Scan(&siteID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(t.Context(), `
		INSERT INTO site_domain_facts(
			scope_id,site_id,site_revision,action,canonical_domain,
			actor_scope_id,actor_user_id,request_id,occurred_at
		) VALUES
			($1,$2,2,'activate','www.a.example.test',$1,$3,'dashboard-domain-add',$4),
			($1,$2,2,'activate','old.a.example.test',$1,$3,'dashboard-domain-retire',$4),
			($1,$2,3,'deactivate','old.a.example.test',$1,$3,'dashboard-domain-retire',$5)`,
		fixture.tenantScopeID, siteID, fixture.tenantActor.UserID,
		fixture.now.Add(time.Minute), fixture.now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}

	query, err := NewQuery(AudienceTenant, "today", "UTC", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := fixture.store.Tenant(t.Context(), fixture.tenantActor, query)
	if err != nil {
		t.Fatal(err)
	}
	if tenant.Resources.Value == nil || tenant.Resources.Value.DomainsTotal != 2 {
		t.Fatalf("tenant active access domains = %#v, want 2", tenant.Resources)
	}

	adminQuery, err := NewQuery(AudienceAdmin, "seven_days", "UTC", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := fixture.store.Admin(t.Context(), fixture.platformActor, adminQuery)
	if err != nil {
		t.Fatal(err)
	}
	if admin.Resources.Value == nil || admin.Resources.Value.DomainsTotal != 2 {
		t.Fatalf("admin active access domains = %#v, want 2", admin.Resources)
	}
}

func TestPostgresTenantDashboardReturnsScopedLoginProfile(t *testing.T) {
	fixture, cleanup := newDashboardFixture(t)
	defer cleanup()

	tenantLoginAt := fixture.now.Add(-2 * time.Minute)
	platformLoginAt := fixture.now.Add(-time.Minute)
	if _, err := fixture.pool.Exec(t.Context(), `UPDATE auth_sessions SET source_ip='203.0.113.8'
		WHERE id=$1`, fixture.tenantActor.SessionID); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		return audit.NewWithClock(fixture.pool, func() time.Time { return tenantLoginAt }).Append(t.Context(), tx, audit.Event{
			ScopeID: fixture.tenantActor.ScopeID, ActorUserID: &fixture.tenantActor.UserID,
			Action: "auth.login", ResourceType: "session_family", ResourceID: fixture.tenantActor.SessionID.String(),
			RequestID: "dashboard-tenant-login", Result: "success",
			Payload: map[string]any{"session_id": fixture.tenantActor.SessionID.String(), "geo_code": "CN-BJ"},
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		return audit.NewWithClock(fixture.pool, func() time.Time { return platformLoginAt }).Append(t.Context(), tx, audit.Event{
			ScopeID: fixture.platformActor.ScopeID, ActorUserID: &fixture.tenantActor.UserID,
			Action: "auth.login", ResourceType: "session_family", ResourceID: fixture.platformActor.SessionID.String(),
			RequestID: "dashboard-other-scope-login", Result: "success",
			Payload: map[string]any{"source_ip": "198.51.100.19", "geo_code": "other-scope"},
		})
	}); err != nil {
		t.Fatal(err)
	}

	query, err := NewQuery(AudienceTenant, "today", "UTC", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	response, err := fixture.store.Tenant(t.Context(), fixture.tenantActor, query)
	if err != nil {
		t.Fatal(err)
	}
	if !response.Profile.Available || response.Profile.Value == nil ||
		response.Profile.Value.LastLoginAt == nil || !response.Profile.Value.LastLoginAt.Equal(tenantLoginAt) ||
		response.Profile.Value.LastLoginIP != "203.0.113.8" || response.Profile.Value.LastLoginGeo != "CN-BJ" {
		t.Fatalf("tenant scoped login profile = %#v", response.Profile)
	}

	other, err := fixture.store.Tenant(t.Context(), fixture.otherActor, query)
	if err != nil {
		t.Fatal(err)
	}
	if !other.Profile.Available || other.Profile.Value == nil || other.Profile.Value.LastLoginAt != nil ||
		other.Profile.Value.LastLoginIP != "" || other.Profile.Value.LastLoginGeo != "" {
		t.Fatalf("tenant without a successful login profile = %#v", other.Profile)
	}
}

func TestPostgresTenantDashboardShowsTenantResourcesWithoutNodeRead(t *testing.T) {
	fixture, cleanup := newDashboardFixture(t)
	defer cleanup()

	query, err := NewQuery(AudienceTenant, "today", "UTC", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	// 租户角色没有（也不能有）nodes.read：资源计数照常可用，节点网络区块不可用，其余区块不受影响。
	partial, err := fixture.store.Tenant(t.Context(), fixture.tenantActor, query)
	if err != nil {
		t.Fatal(err)
	}
	if !partial.Resources.Available || partial.Resources.Value == nil {
		t.Fatalf("tenant resources without nodes.read = %#v", partial.Resources)
	}
	if partial.Network.Available || partial.Network.Value != nil ||
		partial.Network.Reason != ReasonAuthoritativeFactMissing {
		t.Fatalf("tenant network without nodes.read = %#v", partial.Network)
	}
	sectionsAvailable := []bool{
		partial.IdentityVerification.Available,
		partial.Certificates.Available,
		partial.Billing.Available,
		partial.Subscriptions.Available,
		partial.TrafficPackages.Available,
		partial.Operations.Available,
		partial.Notices.Available,
		partial.AccountSecurity.Available,
		partial.Analytics.Available,
	}
	for index, available := range sectionsAvailable {
		if !available {
			t.Fatalf("authorized tenant section %d became unavailable: %#v", index, partial)
		}
	}

	// 系统角色权限不可改（迁移 042/094）：收回租户用户的角色指派来模拟失去基础读权限。
	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM role_assignments
		WHERE role_id=$1 AND user_id=$2`, fixture.tenantRoleID, fixture.tenantActor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.Tenant(t.Context(), fixture.tenantActor, query); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant dashboard without base permission error = %v, want permission denied", err)
	}
}

func TestPostgresTenantDashboardShowsZeroBalanceWithoutBillingAccount(t *testing.T) {
	fixture, cleanup := newDashboardFixture(t)
	defer cleanup()

	query, err := NewQuery(AudienceTenant, "today", "UTC", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	zeroBalance, err := fixture.store.Tenant(t.Context(), fixture.tenantActor, query)
	if err != nil {
		t.Fatal(err)
	}
	if !zeroBalance.Billing.Available || zeroBalance.Billing.Value == nil ||
		zeroBalance.Billing.Value.BalanceMinor != 0 || zeroBalance.Billing.Value.Revision != 1 {
		t.Fatalf("persisted zero billing account = %#v", zeroBalance.Billing)
	}

	if _, err := fixture.pool.Exec(t.Context(), `DELETE FROM billing_accounts WHERE scope_id=$1`, fixture.otherActor.ScopeID); err != nil {
		t.Fatal(err)
	}
	missing, err := fixture.store.Tenant(t.Context(), fixture.otherActor, query)
	if err != nil {
		t.Fatal(err)
	}
	// fix-overview：从未充值（无账户行）显示 ¥0.00，而不是「—」。
	if !missing.Billing.Available || missing.Billing.Value == nil || missing.Billing.Value.BalanceMinor != 0 ||
		missing.Billing.Value.Currency != "CNY" || missing.Billing.Value.Revision != 0 || missing.Billing.Value.UpdatedAt != nil {
		t.Fatalf("missing billing account = %#v, want available zero CNY", missing.Billing)
	}
}

func TestPostgresDashboardSettlementCountsOnlyLinkedReversals(t *testing.T) {
	fixture, cleanup := newDashboardFixture(t)
	defer cleanup()

	seedDashboardSettlementFacts(t, fixture)
	query, err := NewQuery(AudienceAdmin, "seven_days", "UTC", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	response, err := fixture.store.Admin(t.Context(), fixture.platformActor, query)
	if err != nil {
		t.Fatal(err)
	}
	if !response.Billing.Available || response.Billing.Value == nil ||
		response.Billing.Value.GrossSettledDebitMinor != "400" ||
		response.Billing.Value.ReversedCreditMinor != "400" ||
		response.Billing.Value.NetSettledMinor != "0" {
		t.Fatalf("settled billing = %#v", response.Billing)
	}
	var unlinkedUpgradeDowngrade, linkedReversal int
	if err := fixture.pool.QueryRow(t.Context(), `SELECT
		count(*) FILTER (WHERE operation IN ('package_upgrade','package_downgrade')
			AND direction='credit' AND reverses_transaction_id IS NULL),
		count(*) FILTER (WHERE direction='credit' AND reverses_transaction_id IS NOT NULL)
		FROM billing_transactions`).Scan(&unlinkedUpgradeDowngrade, &linkedReversal); err != nil {
		t.Fatal(err)
	}
	if unlinkedUpgradeDowngrade != 2 || linkedReversal != 1 {
		t.Fatalf("ledger fixture unlinked=%d linked=%d", unlinkedUpgradeDowngrade, linkedReversal)
	}
}

func seedDashboardSettlementFacts(t *testing.T, fixture *dashboardFixture) {
	t.Helper()
	productID, subscriptionID := uuid.New(), uuid.New()
	upgradeOrderID, downgradeOrderID, purchaseOrderID := uuid.New(), uuid.New(), uuid.New()
	upgradeTransactionID, downgradeTransactionID := uuid.New(), uuid.New()
	purchaseTransactionID, reversalTransactionID := uuid.New(), uuid.New()
	clearingAccountID := uuid.New()
	now := fixture.now.Add(-time.Minute)
	err := pgx.BeginFunc(t.Context(), fixture.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `
			INSERT INTO package_products(
				id,name,enabled,sort_order,spec,revision,created_by_user_id,updated_by_user_id,created_at,updated_at
			) VALUES($1,'Dashboard settlement product',true,100,'{}',1,$6,$6,$3,$3);
			INSERT INTO package_product_versions(
				product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at
			) VALUES($1,1,'Dashboard settlement product',true,100,'{}',false,$6,$3);
			INSERT INTO package_subscriptions(
				id,tenant_scope_id,product_id,product_revision,product_snapshot,
				site_limit,domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,
				timezone,cycle_kind,custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,
				lifecycle_status,created_by_user_id,updated_by_user_id,created_at,updated_at
			) SELECT $4,$5,version.product_id,version.revision,
				jsonb_build_object('id',version.product_id::text,'revision',version.revision,
					'name',version.name,'spec',version.spec),
				-1,-1,-1,-1,$3::timestamptz - interval '1 day',$3::timestamptz + interval '1 day',
				'UTC','monthly',0,1,1,'active',$2,$2,$3,$3
			FROM package_product_versions version WHERE version.product_id=$1 AND version.revision=1`,
			pgx.QueryExecModeSimpleProtocol, productID, fixture.tenantActor.UserID, now,
			subscriptionID, fixture.tenantActor.ScopeID, fixture.platformActor.UserID); err != nil {
			return err
		}
		if err := insertDashboardCatalogAudit(t.Context(), tx, fixture.platformActor.ScopeID,
			fixture.platformActor.UserID, productID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `
			INSERT INTO package_orders(
				id,tenant_scope_id,user_id,operation,subscription_id,product_kind,product_id,
				product_revision,package_period,product_snapshot,entitlement_snapshot,pricing_snapshot,
				currency,original_amount_minor,discount_amount_minor,payable_amount_minor,
				settlement_direction,funding_source,effective_mode,effective_at,request_id,trace_id,
				created_by_scope_id,created_by_user_id,created_at
			) VALUES
				($1,$4,$5,'upgrade',$6,'package_subscription',$7,1,'month','{}','{}','{}',
				 'CNY',200,0,200,'credit','balance','immediate',$8,'dashboard-upgrade','dashboard-upgrade',$4,$5,$8),
				($2,$4,$5,'downgrade',$6,'package_subscription',$7,1,'month','{}','{}','{}',
				 'CNY',300,0,300,'credit','balance','next_cycle',$8,'dashboard-downgrade','dashboard-downgrade',$4,$5,$8),
				($3,$4,$5,'purchase',NULL,'package_subscription',$7,1,'month','{}','{}','{}',
				 'CNY',400,0,400,'debit','balance','immediate',$8,'dashboard-purchase','dashboard-purchase',$4,$5,$8)`,
			pgx.QueryExecModeSimpleProtocol, upgradeOrderID, downgradeOrderID, purchaseOrderID,
			fixture.tenantActor.ScopeID, fixture.tenantActor.UserID, subscriptionID, productID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `
			UPDATE billing_accounts SET balance_minor=500,revision=5,updated_at=$1 WHERE id=$2;
			INSERT INTO billing_accounts(
				id,scope_id,kind,currency,balance_minor,revision,created_at,updated_at
			) VALUES($3,$4,'platform_clearing','CNY',-500,5,$1,$1);
			INSERT INTO billing_transactions(
				id,target_scope_id,operation,direction,amount_minor,currency,reason,
				created_by_user_id,created_at,commercial_order_id,reverses_transaction_id
			) VALUES
				($5,$2,'package_upgrade','credit',200,'CNY','ordinary upgrade credit',$6,$1,$9,NULL),
				($7,$2,'package_downgrade','credit',300,'CNY','ordinary downgrade credit',$6,$1,$10,NULL),
				($8,$2,'package_purchase','debit',400,'CNY','original purchase debit',$6,$1,$11,NULL),
				($12,$2,'package_refund','credit',400,'CNY','linked purchase reversal',$6,$1,$11,$8)`,
			pgx.QueryExecModeSimpleProtocol, now, fixture.tenantActor.ScopeID, clearingAccountID,
			fixture.platformActor.ScopeID, upgradeTransactionID, fixture.tenantActor.UserID,
			downgradeTransactionID, purchaseTransactionID, upgradeOrderID, downgradeOrderID,
			purchaseOrderID, reversalTransactionID); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `
			INSERT INTO billing_postings(
				id,transaction_id,account_id,side,amount_minor,balance_after_minor,created_at
			) VALUES
				($1,$9,$13,'credit',200,200,$15),($2,$9,$14,'debit',200,-200,$15),
				($3,$10,$13,'credit',300,500,$15),($4,$10,$14,'debit',300,-500,$15),
				($5,$11,$13,'debit',400,100,$15),($6,$11,$14,'credit',400,-100,$15),
				($7,$12,$13,'credit',400,500,$15),($8,$12,$14,'debit',400,-500,$15)`,
			pgx.QueryExecModeSimpleProtocol,
			uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(),
			upgradeTransactionID, downgradeTransactionID, purchaseTransactionID, reversalTransactionID,
			fixture.tenantActor.ScopeID, clearingAccountID, now)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertTenantAnalyticsRequest(t *testing.T, fixture *dashboardFixture, index int, query Query) {
	t.Helper()
	if len(fixture.analytics.requests) <= index || len(fixture.analytics.actors) <= index {
		t.Fatalf("analytics calls = %d", len(fixture.analytics.requests))
	}
	request, actor := fixture.analytics.requests[index], fixture.analytics.actors[index]
	if request.Audience != analytics.AudienceTenant || request.TenantID != "" ||
		!request.From.Equal(query.From) || !request.To.Equal(query.To) {
		t.Fatalf("tenant analytics request = %#v", request)
	}
	if actor.ScopeKind != "tenant" || actor.TenantID != fixture.tenantID.String() ||
		len(actor.Permissions) != 1 || actor.Permissions[0] != analytics.ReadPermission {
		t.Fatalf("tenant analytics actor = %#v", actor)
	}
}

func newDashboardFixture(t *testing.T) (*dashboardFixture, func()) {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "dashboard_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.MaxConns = 12
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	cleanup := func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	}
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		cleanup()
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	finalizedThrough := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
	platformScopeID, platformUserID, platformRoleID, platformSessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	tenantA, scopeA, userA, roleA, sessionA := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	tenantB, scopeB, userB, roleB, sessionB := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	createdAt := now.Add(-time.Hour)
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO tenants(id,display_name,status,created_at,updated_at) VALUES
			($1,'Dashboard tenant A','active',$15,$15),($2,'Dashboard tenant B','active',$15,$15);
		INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES
			($3,'platform',NULL,$15),($4,'tenant',$1,$15),($5,'tenant',$2,$15);
		INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at) VALUES
			($6,'obs-platform','OBS platform','unused','active',$15,$15),
			($7,'obs-tenant-a','OBS tenant A','unused','active',$15,$15),
			($8,'obs-tenant-b','OBS tenant B','unused','active',$15,$15);
		INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES
			($3,$6,'active',$15),($4,$7,'active',$15),($5,$8,'active',$15);
		INSERT INTO roles(id,scope_id,name,description,system_role,created_at) VALUES
			($9,$3,'platform_owner','OBS platform owner',true,$15),
			($10,$4,'tenant_owner','OBS tenant owner A',true,$15),
			($11,$5,'tenant_owner','OBS tenant owner B',true,$15);
		INSERT INTO role_permissions(role_id,permission_name) VALUES($9,'platform.admin') ON CONFLICT DO NOTHING;
		INSERT INTO role_permissions(role_id,permission_name)
		SELECT $10, permission FROM unnest($16::text[]) permission ON CONFLICT DO NOTHING;
		INSERT INTO role_permissions(role_id,permission_name)
		SELECT $11, permission FROM unnest($16::text[]) permission ON CONFLICT DO NOTHING;
		INSERT INTO role_assignments(scope_id,user_id,role_id,assigned_at) VALUES
			($3,$6,$9,$15),($4,$7,$10,$15),($5,$8,$11,$15);
		INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at) VALUES
			($12,$17,$6,$3,$18,$15,$19),($13,$14,$7,$4,$20,$15,$19);
		INSERT INTO billing_accounts(id,scope_id,kind,currency,balance_minor,revision,created_at,updated_at) VALUES
			($4,$4,'tenant_liability','CNY',0,1,$15,$15),
			($5,$5,'tenant_liability','CNY',0,1,$15,$15)`, pgx.QueryExecModeSimpleProtocol,
		tenantA, tenantB, platformScopeID, scopeA, scopeB, platformUserID, userA, userB,
		platformRoleID, roleA, roleB, platformSessionID, sessionA, uuid.New(), createdAt,
		TenantPermissions(), uuid.New(), digest("platform-refresh"), now.Add(time.Hour),
		digest("tenant-refresh")); err != nil {
		cleanup()
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionB, uuid.New(), userB, scopeB,
		digest("other-tenant-refresh"), createdAt, now.Add(time.Hour)); err != nil {
		cleanup()
		t.Fatal(err)
	}

	if err := seedDashboardFacts(t, pool, now, tenantA, scopeA, userA, tenantB, scopeB, userB, platformScopeID, platformUserID); err != nil {
		cleanup()
		t.Fatal(err)
	}
	tokens, err := identity.NewTokenManager(strings.Repeat("d", 64), time.Hour)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	platformRaw, _, err := tokens.Mint(platformUserID, platformScopeID, platformSessionID)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	tenantRaw, _, err := tokens.Mint(userA, scopeA, sessionA)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	otherRaw, _, err := tokens.Mint(userB, scopeB, sessionB)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, time.Now)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x31}, 32), time.Now)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	analyticsReader := &analyticsStub{summary: analytics.Summary{
		MetricVersion: analytics.MetricVersion, RequestCount: 7, ResponseBytes: 11,
		TotalBytes: 11, AverageBandwidthBPS: 1.5, SecurityEvents: 3,
	}, trend: []analytics.TrendPoint{{
		Hour: now.Add(-time.Hour), MetricVersion: analytics.MetricVersion,
		RequestCount: 7, ResponseBytes: 11, TotalBytes: 11, AverageBandwidthBPS: 1.5, SecurityEvents: 3,
	}}, ranks: map[analytics.RankDimension]analytics.RankPage{
		analytics.RankByDomain:  {Items: []analytics.RankItem{{Key: "a.example.test", RequestCount: 7, ResponseBytes: 11}}, SnapshotAt: now},
		analytics.RankByRegion:  {Items: []analytics.RankItem{{Key: "unassigned", RequestCount: 7, ResponseBytes: 11}}, SnapshotAt: now},
		analytics.RankByCarrier: {Items: []analytics.RankItem{}, SnapshotAt: now},
		// 概览排行已扩展到 URL 与 IP 维度；每个维度都必须返回同一快照时间。
		analytics.RankByURL: {Items: []analytics.RankItem{}, SnapshotAt: now},
		analytics.RankByIP:  {Items: []analytics.RankItem{}, SnapshotAt: now},
	}, finalization: analyticsFinalizationSnapshot{
		// 查询窗口是自然日/自然周到当天结束，要可用就必须已结算到窗口终点（与单元测试的 &to 一致）。
		ExpectedTenants: 2, AccessTenants: 2, SecurityTenants: 2,
		Rows: 4, ReadyRows: 4, FinalizedThrough: &finalizedThrough,
	}}
	store, err := NewStore(pool, authorizer, analyticsReader)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	return &dashboardFixture{
		pool: pool, store: store, analytics: analyticsReader, now: now,
		platformActor: Actor{RawSession: platformRaw, SessionID: platformSessionID, UserID: platformUserID, ScopeID: platformScopeID, ScopeKind: "platform"},
		tenantActor:   Actor{RawSession: tenantRaw, SessionID: sessionA, UserID: userA, ScopeID: scopeA, ScopeKind: "tenant", TenantID: tenantA},
		otherActor:    Actor{RawSession: otherRaw, SessionID: sessionB, UserID: userB, ScopeID: scopeB, ScopeKind: "tenant", TenantID: tenantB},
		tenantRoleID:  roleA, tenantID: tenantA, tenantScopeID: scopeA,
	}, cleanup
}

func seedDashboardFacts(
	t *testing.T,
	pool *pgxpool.Pool,
	now time.Time,
	tenantA, scopeA, userA, tenantB, scopeB, userB, platformScopeID, platformUserID uuid.UUID,
) error {
	t.Helper()
	ctx := t.Context()
	siteA, cacheOperationA, nodeA := uuid.New(), uuid.New(), uuid.New()
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,
				updated_by_user_id,created_at,updated_at,display_id) VALUES
				($14,$1,$2,'a.example.test',ARRAY['192.0.2.10:80'],ARRAY['192.0.2.10'],$2,$2,$9,$9,1);
			INSERT INTO site_domain_facts(
				scope_id,site_id,site_revision,action,canonical_domain,
				actor_scope_id,actor_user_id,request_id,occurred_at
			) VALUES($1,$14,1,'activate','a.example.test',$1,$2,'dashboard-domain-seed',$9);
			INSERT INTO site_origin_pools(site_id,updated_at) VALUES($14,$9);
			INSERT INTO site_origins(site_id,position,host,port,weight,enabled)
			VALUES($14,1,'192.0.2.10',80,1,true);
			INSERT INTO certificate_assets(tenant_scope_id,id,name,source,created_by_user_id,updated_by_user_id,
				created_by_scope_id,updated_by_scope_id,created_at,updated_at) VALUES
				($1,$5,'Tenant A certificate','uploaded',$2,$2,$1,$1,$9,$9),
				($3,$6,'Tenant B certificate','uploaded',$4,$4,$3,$3,$9,$9);
			INSERT INTO background_jobs(id,tenant_id,kind,subject,idempotency_key,request_digest,request_id,
				state,max_attempts,claimable_at,total_count,created_at,updated_at) VALUES
				($11,$7,'obs.dashboard','tenant A job','obs-job-a',$10,'obs-job-a','queued',3,$9,1,$9,$9),
				($12,$8,'obs.dashboard','tenant B job','obs-job-b',$10,'obs-job-b','queued',3,$9,1,$9,$9);
			INSERT INTO background_job_items(tenant_id,job_id,ordinal,item_id,state) VALUES
				($7,$11,1,'obs-job-a-item','pending'),
				($8,$12,1,'obs-job-b-item','pending');
			INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,created_at,updated_at,display_id)
			VALUES($13,$1,'OBS tenant A node','active',$2,$9,$9,1);
			INSERT INTO cache_operations(id,scope_id,tenant_id,site_id,action,target_type,idempotency_key,
				request_digest,request_id,actor_user_id,actor_scope_id,state,max_attempts,target_count,node_count,
				total_count,created_at,updated_at) VALUES
				($15,$1,$7,$14,'purge','whole_site','obs-cache-a',$10,'obs-cache-a',$2,$1,
				 'queued',3,1,1,1,$9,$9);
			INSERT INTO cache_operation_targets(operation_id,scope_id,ordinal,canonical_url,canonical_path)
			VALUES($15,$1,1,'/','/');
			INSERT INTO cache_operation_nodes(operation_id,scope_id,node_id,state,total_count,next_attempt_at,created_at,updated_at)
			VALUES($15,$1,$13,'queued',1,$9,$9,$9);
			INSERT INTO cache_operation_node_targets(operation_id,scope_id,node_id,target_ordinal,state)
			VALUES($15,$1,$13,1,'queued')`, pgx.QueryExecModeSimpleProtocol,
			scopeA, userA, scopeB, userB, uuid.New(), uuid.New(), tenantA, tenantB,
			now.Add(-time.Minute), bytes.Repeat([]byte{0x42}, 32), uuid.New(), uuid.New(), nodeA,
			siteA, cacheOperationA); err != nil {
			return err
		}
		// 迁移 092 起四层转发必须绑定本租户的套餐订阅（l4_forwards_scope_package_092）。
		productID, subscriptionID := uuid.New(), uuid.New()
		if _, err := tx.Exec(ctx, `
			INSERT INTO package_products(
				id,name,enabled,sort_order,spec,revision,created_by_user_id,updated_by_user_id,created_at,updated_at
			) VALUES($1,'Dashboard forward product',true,100,'{}',1,$6,$6,$3,$3);
			INSERT INTO package_product_versions(
				product_id,revision,name,enabled,sort_order,spec,deleted,created_by_user_id,created_at
			) VALUES($1,1,'Dashboard forward product',true,100,'{}',false,$6,$3);
			INSERT INTO package_subscriptions(
				id,tenant_scope_id,product_id,product_revision,product_snapshot,
				site_limit,domain_limit,node_limit,traffic_limit_bytes,starts_at,ends_at,
				timezone,cycle_kind,custom_cycle_days,tcp_factor_numerator,tcp_factor_denominator,
				lifecycle_status,created_by_user_id,updated_by_user_id,created_at,updated_at
			) SELECT $4,$5,version.product_id,version.revision,
				jsonb_build_object('id',version.product_id::text,'revision',version.revision,
					'name',version.name,'spec',version.spec),
				-1,-1,-1,-1,$3::timestamptz - interval '1 day',$3::timestamptz + interval '1 day',
				'UTC','monthly',0,1,1,'active',$2,$2,$3,$3
			FROM package_product_versions version WHERE version.product_id=$1 AND version.revision=1`,
			pgx.QueryExecModeSimpleProtocol, productID, userA, now.Add(-time.Minute), subscriptionID, scopeA, platformUserID); err != nil {
			return err
		}
		if err := insertDashboardCatalogAudit(ctx, tx, platformScopeID, platformUserID, productID, now.Add(-time.Minute)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO l4_forwards(
				id,scope_id,owner_user_id,name,protocol,listen_port,upstream_address,upstream_port,
				connect_timeout_ms,response_timeout_ms,package_subscription_id,max_connections_per_client,
				created_by_user_id,updated_by_user_id,created_at,updated_at
			) VALUES($1,$2,$3,'OBS tenant A forward','tcp',18443,'192.0.2.20',443,3000,30000,$5,100,$3,$3,$4,$4)`,
			uuid.New(), scopeA, userA, now.Add(-time.Minute), subscriptionID); err != nil {
			return err
		}
		return audit.New(pool).Append(ctx, tx, audit.Event{
			ScopeID: scopeA, ActorUserID: &userA, Action: "cache.operation.create",
			ResourceType: "cache_operation", ResourceID: cacheOperationA.String(),
			RequestID: "obs-cache-a", Result: "success",
			Payload: map[string]any{
				"actor_scope_id": scopeA, "action": "purge", "target_type": "whole_site",
				"targets": 1, "nodes": 1, "max_attempts": 3,
			},
		})
	})
}

func TenantPermissions() []string {
	return []string{
		// 租户系统角色不能持有 nodes.read（迁移 042/079/094 的守卫会拒绝）。
		"sites.read", "certificates.read", "billing.account.read", "package_subscriptions.read",
		"traffic_packages.read", "announcements.read", "jobs.read",
	}
}

func digest(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

// insertDashboardCatalogAudit records the platform package catalog audit fact
// that migration 090 requires (package_catalog_watermark_completed_090) before a
// directly inserted package product may commit.
func insertDashboardCatalogAudit(
	ctx context.Context,
	tx pgx.Tx,
	platformScopeID, platformUserID, productID uuid.UUID,
	occurredAt time.Time,
) error {
	_, err := tx.Exec(ctx, `WITH previous AS (
		SELECT stream_position,event_hash FROM audit_events WHERE scope_id=$2
		ORDER BY stream_position DESC LIMIT 1
	)
	INSERT INTO audit_events(
		id,scope_id,stream_position,actor_user_id,action,resource_type,resource_id,
		request_id,result,payload,previous_hash,event_hash,occurred_at)
	SELECT $1,$2,COALESCE(previous.stream_position,0)+1,$3,'package.product.create','package_product',$4,
		$5,'success','{"revision":1,"enabled":true}'::jsonb,previous.event_hash,$6,$7
	FROM (SELECT true) seed LEFT JOIN previous ON true`, uuid.New(), platformScopeID, platformUserID,
		productID.String(), "dashboard-catalog-"+uuid.NewString(), make([]byte, sha256.Size), occurredAt)
	return err
}
