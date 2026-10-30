package site

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The 73 sequence: platform DNS (DNSPod) and the
// platform CNAME domain are configured first; a tenant created afterwards
// opens a package and creates a site. Its CNAME allocation must succeed
// (before the fix it failed with dns_provider_not_configured because the
// platform copy was only synced on platform configuration changes).
func TestCNAMEAllocationForTenantCreatedAfterPlatformDNS(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "cname_tenant_sync_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	now := time.Now().UTC().Truncate(time.Second)
	manager := addonSiteInsertPlatformActor(t, pool, "cname-tenant-sync-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "platform-site-admin", "platform.admin")

	// 1. 节点管理 > DNS配置: DNSPod and the platform CNAME domain, before any tenant.
	cipher, err := dnsacme.NewAESGCMCredentialCipher("cname-tenant-sync-v1", bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	dns := dnsacme.NewServiceWithClockAndVerifier(dnsacme.NewStore(pool), cipher, acceptCredentials{}, time.Now)
	platform := dnsacme.Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform"}
	if _, err := dns.SavePlatformConfig(t.Context(), platform, dnsacme.SavePlatformConfigRequest{ProviderType: "dnspod_cn",
		Credentials: map[string]string{"dp_id": "1", "dp_key": "fixture"}, TTL: 600, ExpectedRevision: 1,
		IdempotencyKey: "cname-tenant-sync-config", RequestID: "cname-tenant-sync-config"}); err != nil {
		t.Fatalf("save platform DNS config: %v", err)
	}
	if _, err := dns.CreatePlatformZone(t.Context(), platform, dnsacme.PlatformZoneRequest{Name: "cdn.cdnca.com",
		IdempotencyKey: "cname-tenant-sync-zone", RequestID: "cname-tenant-sync-zone"}); err != nil {
		t.Fatalf("create platform zone: %v", err)
	}

	// 2. A tenant created afterwards: no platform copy in its scope yet.
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "CNAME tenant sync", "cname-tenant-sync-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")
	var copies int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM dns_providers WHERE scope_id=$1`, tenant.scopeID).Scan(&copies); err != nil || copies != 0 {
		t.Fatalf("new tenant provider rows=%d err=%v (fixture assumes no copy before allocation)", copies, err)
	}
	group, err := nodescheduler.NewService(pool, func() time.Time { return now }).PutGroup(t.Context(),
		nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}, nodescheduler.PutGroupRequest{
			Name: "CNAME tenant sync", Policy: nodescheduler.DefaultHealthPolicy(),
			Endpoints:      []nodescheduler.Endpoint{{ID: uuid.New(), Address: "192.0.2.31", Port: 80, Weight: 1, Enabled: true}},
			IdempotencyKey: "cname-tenant-sync-group", RequestID: "cname-tenant-sync-group",
		})
	if err != nil {
		t.Fatal(err)
	}

	// 3. 开通套餐 + 建站.
	productID := addonSiteInsertPackageProductVersionCNAME(t, pool, manager, 1, 100, 1000, "cdn.cdnca.com", "")
	subscriptions := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, func() time.Time { return now }))
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	opened, err := subscriptions.Open(t.Context(), manager, packagesubscription.OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: productID, ProductRevision: 1,
		SiteLimit: 100, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "cname-tenant-sync-subscription", RequestID: "cname-tenant-sync-subscription",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds,
		actor_scope_id,actor_user_id,reason,created_at)
		SELECT $1,1,'automatic',$2,30000,15000,2,3,600,$1,$3,'integration_policy',clock_timestamp()
		WHERE NOT EXISTS(SELECT 1 FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1)`,
		tenant.scopeID, []uuid.UUID{uuid.New()}, tenant.userID); err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, time.Hour)
	service := NewService(store)
	owner := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	created, err := service.Create(t.Context(), owner, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
		Fields: SiteFields{Domains: []string{"tenant-sync.example.co.uk"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
			Enabled: false, Status: StatusDisabled,
			NodeGroupID: &group.Group.GroupID, NodeGroupName: group.Group.Name,
			PackageID: &productID, PackageName: "Business", PackageSubscriptionID: &opened.Subscription.ID},
		IdempotencyKey: "cname-tenant-sync-site", RequestID: "cname-tenant-sync-site"})
	if err != nil || created.Site.CNAMETaskID == nil {
		t.Fatalf("create site: %+v err=%v", created.Site.CNAMETaskID, err)
	}
	jobID := *created.Site.CNAMETaskID

	// 4. The CNAME intent runs on the production-wired allocation store.
	intents, err := cnameallocation.NewStore(pool, platformCNAMEKeyring{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	intents.UsePlatformDNS(dns)
	var tenantID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, tenant.scopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	var claim jobstate.Claim
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var err error
		claim, err = jobstate.StartTx(t.Context(), tx, jobstate.StartInput{TenantID: tenantID, JobID: jobID,
			Kind: "dns.cname.intent", WorkerID: "cname-tenant-sync-worker", LeaseDuration: time.Minute}, now)
		return err
	}); err != nil {
		t.Fatalf("claim intent: %v", err)
	}
	if err := intents.PrepareIntent(t.Context(), claim); err != nil {
		t.Fatalf("prepare intent: %v", err)
	}
	var state, code string
	if err := pool.QueryRow(t.Context(), `SELECT job.state,COALESCE(item.error_code,'')
		FROM background_jobs job JOIN background_job_items item ON item.tenant_id=job.tenant_id AND item.job_id=job.id
		WHERE job.tenant_id=$1 AND job.id=$2`, tenantID, jobID).Scan(&state, &code); err != nil {
		t.Fatal(err)
	}
	allocation, err := intents.Get(t.Context(), tenant.scopeID, created.Site.ID)
	if state != "succeeded" || err != nil || !strings.HasSuffix(allocation.Hostname, ".cdn.cdnca.com") {
		t.Fatalf("intent state=%s code=%s allocation=%+v err=%v", state, code, allocation, err)
	}
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM dns_providers WHERE scope_id=$1 AND id=$2`,
		tenant.scopeID, dnsacme.PlatformProviderCopyID(tenant.scopeID)).Scan(&copies); err != nil || copies != 1 {
		t.Fatalf("platform provider copy rows=%d err=%v", copies, err)
	}

	// 5. A second call on a scope holding the copy writes nothing.
	if synced, err := dns.EnsurePlatformTenantCopy(t.Context(), tenant.scopeID); synced || err != nil {
		t.Fatalf("repeat copy synced=%v err=%v", synced, err)
	}
}
