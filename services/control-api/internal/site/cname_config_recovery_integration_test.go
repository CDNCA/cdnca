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

// A site created before its CNAME zone is configured fails with a specific
// reason, and gets its CNAME once the zone is added.
func TestCNAMEConfigFailureRecoversAfterZoneAdded(t *testing.T) {
	testCNAMEConfigRecovery(t, false)
}

// The 73 sequence: site first, then the platform DNS configuration and the
// platform CNAME domain synced into the tenant.
func TestCNAMEConfigFailureRecoversAfterPlatformDNSConfig(t *testing.T) {
	testCNAMEConfigRecovery(t, true)
}

type acceptCredentials struct{}

func (acceptCredentials) Verify(context.Context, string, string) error { return nil }
func (acceptCredentials) VerifyCredentials(context.Context, string, map[string]string) error {
	return nil
}

func testCNAMEConfigRecovery(t *testing.T, platformPath bool) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "cname_recovery_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "cname-recovery-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "platform-site-admin", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "CNAME recovery", "cname-recovery-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")
	group, err := nodescheduler.NewService(pool, func() time.Time { return now }).PutGroup(t.Context(),
		nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}, nodescheduler.PutGroupRequest{
			Name: "CNAME recovery", Policy: nodescheduler.DefaultHealthPolicy(),
			Endpoints:      []nodescheduler.Endpoint{{ID: uuid.New(), Address: "192.0.2.30", Port: 80, Weight: 1, Enabled: true}},
			IdempotencyKey: "cname-recovery-group", RequestID: "cname-recovery-group",
		})
	if err != nil {
		t.Fatal(err)
	}
	// The package names cdn.cdnca.com while no DNS provider/zone exists yet.
	productID := addonSiteInsertPackageProductVersionCNAME(t, pool, manager, 1, 100, 1000, "cdn.cdnca.com", "")
	subscriptions := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, func() time.Time { return now }))
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	opened, err := subscriptions.Open(t.Context(), manager, packagesubscription.OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: productID, ProductRevision: 1,
		SiteLimit: 100, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "cname-recovery-subscription", RequestID: "cname-recovery-subscription",
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
	// One clock for claims and settlements; advanced past the retry back-off.
	clock := now
	intents, err := cnameallocation.NewStore(pool, platformCNAMEKeyring{}, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	owner := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	var tenantID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, tenant.scopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	runIntent := func(t *testing.T, jobID uuid.UUID) {
		t.Helper()
		var claim jobstate.Claim
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			var err error
			claim, err = jobstate.StartTx(t.Context(), tx, jobstate.StartInput{TenantID: tenantID, JobID: jobID,
				Kind: "dns.cname.intent", WorkerID: "cname-recovery-worker", LeaseDuration: time.Minute}, clock)
			return err
		}); err != nil {
			t.Fatalf("claim intent %s: %v", jobID, err)
		}
		if err := intents.PrepareIntent(t.Context(), claim); err != nil {
			t.Fatalf("prepare intent: %v", err)
		}
	}
	jobFacts := func(t *testing.T, jobID uuid.UUID) (string, string, int) {
		t.Helper()
		var state, code string
		var attempt int
		if err := pool.QueryRow(t.Context(), `SELECT job.state,COALESCE(item.error_code,''),job.attempt
			FROM background_jobs job JOIN background_job_items item ON item.tenant_id=job.tenant_id AND item.job_id=job.id
			WHERE job.tenant_id=$1 AND job.id=$2`, tenantID, jobID).Scan(&state, &code, &attempt); err != nil {
			t.Fatal(err)
		}
		return state, code, attempt
	}
	created, err := service.Create(t.Context(), owner, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
		Fields: SiteFields{Domains: []string{"recovery.example.co.uk"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
			Enabled: false, Status: StatusDisabled,
			NodeGroupID: &group.Group.GroupID, NodeGroupName: group.Group.Name,
			PackageID: &productID, PackageName: "Business", PackageSubscriptionID: &opened.Subscription.ID},
		IdempotencyKey: "cname-recovery-site", RequestID: "cname-recovery-site"})
	if err != nil || created.Site.CNAMETaskID == nil {
		t.Fatalf("create site: %+v err=%v", created.Site.CNAMETaskID, err)
	}
	jobID := *created.Site.CNAMETaskID
	siteID := created.Site.ID

	t.Run("no provider", func(t *testing.T) {
		runIntent(t, jobID)
		if state, code, _ := jobFacts(t, jobID); state != "failed" || code != cnameallocation.FailureDNSProviderNotConfigured {
			t.Fatalf("intent state=%s code=%s", state, code)
		}
		read, err := service.Get(t.Context(), owner, siteID)
		if err != nil || read.CNAMEState == nil || *read.CNAMEState != "failed" ||
			read.CNAMEFailureCode == nil || *read.CNAMEFailureCode != cnameallocation.FailureDNSProviderNotConfigured {
			t.Fatalf("site CNAME state=%v code=%v err=%v", read.CNAMEState, read.CNAMEFailureCode, err)
		}
	})

	if platformPath {
		// 节点管理 > DNS配置: the admin saves DNSPod, then adds the CNAME
		// domain; the tenant copy sync re-queues the failed site.
		cipher, err := dnsacme.NewAESGCMCredentialCipher("cname-recovery-v1", bytes.Repeat([]byte{7}, 32))
		if err != nil {
			t.Fatal(err)
		}
		dns := dnsacme.NewServiceWithClockAndVerifier(dnsacme.NewStore(pool), cipher, acceptCredentials{}, time.Now)
		platform := dnsacme.Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform"}
		if _, err := dns.SavePlatformConfig(t.Context(), platform, dnsacme.SavePlatformConfigRequest{ProviderType: "dnspod_cn",
			Credentials: map[string]string{"dp_id": "1", "dp_key": "fixture"}, TTL: 600, ExpectedRevision: 1,
			IdempotencyKey: "cname-recovery-config", RequestID: "cname-recovery-config"}); err != nil {
			t.Fatalf("save platform DNS config: %v", err)
		}
		if state, _, _ := jobFacts(t, jobID); state != "failed" {
			t.Fatalf("provider without the CNAME zone re-queued the intent: %s", state)
		}
		if _, err := dns.CreatePlatformZone(t.Context(), platform, dnsacme.PlatformZoneRequest{Name: "cdn.cdnca.com",
			IdempotencyKey: "cname-recovery-platform-zone", RequestID: "cname-recovery-platform-zone"}); err != nil {
			t.Fatalf("create platform zone: %v", err)
		}
		if state, code, attempt := jobFacts(t, jobID); state != "queued" || code != "" || attempt != 1 {
			t.Fatalf("intent after platform zone state=%s code=%s attempt=%d", state, code, attempt)
		}
		var audits int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='dns.cname.requeue'
			AND resource_id=$1 AND payload->>'reason'='platform_dns_sync'`, siteID.String()).Scan(&audits); err != nil || audits != 1 {
			t.Fatalf("requeue audits=%d err=%v", audits, err)
		}
		clock = time.Now().UTC().Add(time.Minute)
		runIntent(t, jobID)
		allocation, err := intents.Get(t.Context(), tenant.scopeID, siteID)
		if state, code, _ := jobFacts(t, jobID); state != "succeeded" || err != nil ||
			!strings.HasSuffix(allocation.Hostname, ".cdn.cdnca.com") {
			t.Fatalf("recovered intent state=%s code=%s allocation=%+v err=%v", state, code, allocation, err)
		}
		return
	}

	providerID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'DNSPod','dnspod_cn','fixture-key',$3,$4,$4)`, providerID, tenant.scopeID, make([]byte, 32), tenant.userID); err != nil {
		t.Fatal(err)
	}
	dns := dnsacme.NewService(dnsacme.NewStore(pool), nil)
	dnsActor := dnsacme.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}

	t.Run("other zone only", func(t *testing.T) {
		// A zone that is not the package's CNAME domain does not recover the
		// site; with the provider configured the reason becomes the zone.
		if _, err := pool.Exec(t.Context(), `INSERT INTO dns_zones(id,scope_id,provider_id,name,is_default,created_by_user_id,updated_by_user_id)
			VALUES($1,$2,$3,'ikvm.asia',true,$4,$4)`, uuid.New(), tenant.scopeID, providerID, tenant.userID); err != nil {
			t.Fatal(err)
		}
		if requeued := requeue(t, pool, tenant.scopeID, now); requeued != 0 {
			t.Fatalf("requeued %d sites without the CNAME zone", requeued)
		}
		if state, _, _ := jobFacts(t, jobID); state != "failed" {
			t.Fatalf("intent state=%s", state)
		}
	})

	t.Run("zone added recovers", func(t *testing.T) {
		if _, err := dns.CreateZone(t.Context(), dnsActor, dnsacme.CreateZoneRequest{ProviderID: providerID,
			Name: "cdn.cdnca.com", IdempotencyKey: "cname-recovery-zone", RequestID: "cname-recovery-zone"}); err != nil {
			t.Fatalf("create zone: %v", err)
		}
		state, code, attempt := jobFacts(t, jobID)
		if state != "queued" || code != "" || attempt != 1 {
			t.Fatalf("intent after zone added state=%s code=%s attempt=%d", state, code, attempt)
		}
		read, err := service.Get(t.Context(), owner, siteID)
		if err != nil || read.CNAMEState == nil || *read.CNAMEState != "pending" || read.CNAMEFailureCode != nil {
			t.Fatalf("site CNAME after requeue state=%v code=%v err=%v", read.CNAMEState, read.CNAMEFailureCode, err)
		}
		var audits int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE action='dns.cname.requeue'
			AND resource_id=$1 AND payload->>'previous_failure_code'=$2 AND payload->>'reason'='dns_zone_create'`,
			siteID.String(), cnameallocation.FailureDNSProviderNotConfigured).Scan(&audits); err != nil || audits != 1 {
			t.Fatalf("requeue audits=%d err=%v", audits, err)
		}
		// Idempotent: the intent is queued, so a second pass does nothing.
		if requeued := requeue(t, pool, tenant.scopeID, now); requeued != 0 {
			t.Fatalf("second pass requeued %d", requeued)
		}
		clock = time.Now().UTC().Add(time.Minute)
		runIntent(t, jobID)
		if state, code, _ := jobFacts(t, jobID); state != "succeeded" {
			t.Fatalf("recovered intent state=%s code=%s", state, code)
		}
		allocation, err := intents.Get(t.Context(), tenant.scopeID, siteID)
		if err != nil || allocation.State != cnameallocation.StatePending || !strings.HasSuffix(allocation.Hostname, ".cdn.cdnca.com") {
			t.Fatalf("allocation=%+v err=%v", allocation, err)
		}
	})
}

func requeue(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, now time.Time) int {
	t.Helper()
	var count int
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		var err error
		count, err = dnsacme.RequeueCNAMEConfigFailures(t.Context(), tx, scopeID, "test", now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return count
}
