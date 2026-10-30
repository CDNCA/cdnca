package site

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fix-nopkg (migration 533): a site without a package gets a per-site CNAME
// in the default zone whose A records are the platform default line group's
// nodes; with no platform default it fails with cname_no_default_line_group;
// binding a package later re-allocates from the package's line group.
func TestCNAMEWithoutPackageUsesPlatformDefaultLineGroup(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "cname_nopkg_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "cname-nopkg-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "platform-site-admin", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "CNAME nopkg", "cname-nopkg-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")
	scheduler := nodescheduler.NewService(pool, func() time.Time { return now })
	// Platform line group writes go through the IAM authorizer (session).
	tokens, err := identity.NewTokenManager(strings.Repeat("n", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x31}, 32), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := iamlock.NewAuthorizer(sessions, apiKeys)
	if err != nil {
		t.Fatal(err)
	}
	platformScheduler, err := nodescheduler.NewIAMService(pool, func() time.Time { return now }, authorizer, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := tokens.Mint(manager.UserID, manager.ScopeID, manager.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	platformActor := nodescheduler.Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform",
		Credential: nodescheduler.Credential{Kind: nodescheduler.CredentialSession, Raw: raw}}
	platformGroup, err := platformScheduler.PutGroup(t.Context(), platformActor, nodescheduler.PutGroupRequest{
		Name: "平台默认", Policy: nodescheduler.DefaultHealthPolicy(),
		Endpoints:      []nodescheduler.Endpoint{{ID: uuid.New(), Address: "198.51.100.7", Port: 80, Weight: 1, Enabled: true}},
		IdempotencyKey: "cname-nopkg-platform-group", RequestID: "cname-nopkg-platform-group",
	})
	if err != nil {
		t.Fatal(err)
	}
	packageGroup, err := scheduler.PutGroup(t.Context(),
		nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}, nodescheduler.PutGroupRequest{
			Name: "套餐线路", Policy: nodescheduler.DefaultHealthPolicy(),
			Endpoints:      []nodescheduler.Endpoint{{ID: uuid.New(), Address: "192.0.2.40", Port: 80, Weight: 1, Enabled: true}},
			IdempotencyKey: "cname-nopkg-package-group", RequestID: "cname-nopkg-package-group",
		})
	if err != nil {
		t.Fatal(err)
	}
	providerID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'DNSPod','dnspod_cn','fixture-key',$3,$4,$4)`, providerID, tenant.scopeID, make([]byte, 32), tenant.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_zones(id,scope_id,provider_id,name,is_default,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'cdn.cdnca.com',true,$4,$4)`, uuid.New(), tenant.scopeID, providerID, tenant.userID); err != nil {
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
	runIntent := func(t *testing.T, jobID uuid.UUID) (string, string) {
		t.Helper()
		var claim jobstate.Claim
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			var err error
			claim, err = jobstate.StartTx(t.Context(), tx, jobstate.StartInput{TenantID: tenantID, JobID: jobID,
				Kind: "dns.cname.intent", WorkerID: "cname-nopkg-worker", LeaseDuration: time.Minute}, clock)
			return err
		}); err != nil {
			t.Fatalf("claim intent %s: %v", jobID, err)
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
		return state, code
	}
	frozen := func(t *testing.T, siteID uuid.UUID) (uuid.UUID, []string, *uuid.UUID) {
		t.Helper()
		var groupID uuid.UUID
		var addresses []string
		var subscription *uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT node_group_id,target_a,package_subscription_id FROM cname_allocation_targets
			WHERE tenant_scope_id=$1 AND site_id=$2 ORDER BY created_at DESC,allocation_revision DESC LIMIT 1`,
			tenant.scopeID, siteID).Scan(&groupID, &addresses, &subscription); err != nil {
			t.Fatal(err)
		}
		return groupID, addresses, subscription
	}
	createSite := func(t *testing.T, domain string) Site {
		t.Helper()
		created, err := service.Create(t.Context(), owner, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
			Fields: SiteFields{Domains: []string{domain}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
				Enabled: false, Status: StatusDisabled},
			IdempotencyKey: "cname-nopkg-" + domain, RequestID: "cname-nopkg-" + domain})
		if err != nil || created.Site.CNAMETaskID == nil || created.Site.PackageSubscriptionID != nil {
			t.Fatalf("create site without package: task=%v subscription=%v err=%v", created.Site.CNAMETaskID, created.Site.PackageSubscriptionID, err)
		}
		return created.Site
	}

	t.Run("no platform default line group", func(t *testing.T) {
		site := createSite(t, "nodefault.example.com")
		if state, code := runIntent(t, *site.CNAMETaskID); state != "failed" || code != cnameallocation.FailureNoDefaultLineGroup {
			t.Fatalf("intent state=%s code=%s", state, code)
		}
		read, err := service.Get(t.Context(), owner, site.ID)
		if err != nil || read.CNAMEState == nil || *read.CNAMEState != "failed" ||
			read.CNAMEFailureCode == nil || *read.CNAMEFailureCode != cnameallocation.FailureNoDefaultLineGroup {
			t.Fatalf("site CNAME state=%v code=%v err=%v", read.CNAMEState, read.CNAMEFailureCode, err)
		}
	})

	// 节点管理 → 线路组 → 设为平台默认 (tenants may not).
	if _, err := scheduler.SetPlatformDefault(t.Context(), nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID,
		ScopeKind: "tenant"}, packageGroup.Group.GroupID, true, "cname-nopkg-tenant-default"); !errors.Is(err, nodescheduler.ErrPlatformWriteDenied) {
		t.Fatalf("tenant set platform default err=%v", err)
	}
	marked, err := platformScheduler.SetPlatformDefault(t.Context(), platformActor, platformGroup.Group.GroupID, true, "cname-nopkg-default")
	if err != nil || !marked.IsPlatformDefault || marked.Revision != platformGroup.Group.Revision {
		t.Fatalf("set platform default=%+v err=%v", marked.IsPlatformDefault, err)
	}

	var siteID uuid.UUID
	t.Run("site without package gets CNAME on the default line group", func(t *testing.T) {
		site := createSite(t, "nopkg.example.com")
		siteID = site.ID
		if state, code := runIntent(t, *site.CNAMETaskID); state != "succeeded" {
			t.Fatalf("intent state=%s code=%s", state, code)
		}
		allocation, err := intents.Get(t.Context(), tenant.scopeID, site.ID)
		if err != nil || allocation.Mode != cnameallocation.ModeSite || !strings.HasSuffix(allocation.Hostname, ".cdn.cdnca.com") {
			t.Fatalf("allocation=%+v err=%v", allocation, err)
		}
		groupID, addresses, subscription := frozen(t, site.ID)
		if groupID != platformGroup.Group.GroupID || len(addresses) != 1 || addresses[0] != "198.51.100.7" || subscription != nil {
			t.Fatalf("frozen target group=%s a=%v subscription=%v", groupID, addresses, subscription)
		}
		// The DNS write settles; the site shows its CNAME but has no package
		// (not served until one is bound).
		var claim jobstate.Claim
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			var err error
			claim, err = jobstate.StartTx(t.Context(), tx, jobstate.StartInput{TenantID: tenantID, JobID: allocation.JobID,
				Kind: "dns.cname.allocation", WorkerID: "cname-nopkg-allocation", LeaseDuration: time.Minute}, clock)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := intents.Complete(t.Context(), cnameallocation.ResultRequest{TargetScopeID: tenant.scopeID, SiteID: site.ID,
			AllocationID: allocation.ID, JobID: allocation.JobID, ExpectedRevision: allocation.Revision, WorkerID: claim.WorkerID,
			Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, Sequence: 1}); err != nil {
			t.Fatalf("complete allocation: %v", err)
		}
		read, err := service.Get(t.Context(), owner, site.ID)
		if err != nil || read.PackageSubscriptionID != nil || read.CNAME != allocation.Hostname {
			t.Fatalf("site subscription=%v cname=%q want %q err=%v", read.PackageSubscriptionID, read.CNAME, allocation.Hostname, err)
		}
	})

	t.Run("binding a package re-allocates from the package line group", func(t *testing.T) {
		productID := addonSiteInsertPackageProductVersionCNAME(t, pool, manager, 1, 100, 1000, "cdn.cdnca.com", "")
		// The package's line group (product snapshot spec.node_group_id).
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			for _, table := range []string{"package_products", "package_product_versions"} {
				key := "id"
				if table == "package_product_versions" {
					key = "product_id"
				}
				if _, err := tx.Exec(t.Context(), `ALTER TABLE `+table+` DISABLE TRIGGER USER`); err != nil {
					return err
				}
				if _, err := tx.Exec(t.Context(), `UPDATE `+table+` SET spec=jsonb_set(spec,'{node_group_id}',to_jsonb($2::text)) WHERE `+key+`=$1`,
					productID, packageGroup.Group.GroupID.String()); err != nil {
					return err
				}
				if _, err := tx.Exec(t.Context(), `ALTER TABLE `+table+` ENABLE TRIGGER USER`); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		subscriptions := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, func() time.Time { return now }))
		factor, _ := packageperiod.NewTrafficFactor(1, 1)
		month := packageperiod.DurationMonth
		opened, err := subscriptions.Open(t.Context(), manager, packagesubscription.OpenRequest{
			TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: productID, ProductRevision: 1,
			SiteLimit: 100, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
			CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
			IdempotencyKey: "cname-nopkg-subscription", RequestID: "cname-nopkg-subscription",
		})
		if err != nil {
			t.Fatal(err)
		}
		current, err := service.Get(t.Context(), owner, siteID)
		if err != nil {
			t.Fatal(err)
		}
		updated, err := service.Update(t.Context(), owner, UpdateRequest{ID: siteID, ExpectedRevision: current.Revision,
			Fields: SiteFields{Domains: current.Domains, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
				Enabled: false, Status: StatusDisabled,
				PackageID: &productID, PackageName: "Business", PackageSubscriptionID: &opened.Subscription.ID},
			IdempotencyKey: "cname-nopkg-bind", RequestID: "cname-nopkg-bind"})
		if err != nil || updated.Site.CNAMETaskID == nil || *updated.Site.CNAMETaskID == *current.CNAMETaskID {
			t.Fatalf("bind package: task=%v err=%v", updated.Site.CNAMETaskID, err)
		}
		clock = clock.Add(time.Minute)
		if state, code := runIntent(t, *updated.Site.CNAMETaskID); state != "succeeded" {
			t.Fatalf("rebind intent state=%s code=%s", state, code)
		}
		groupID, addresses, subscription := frozen(t, siteID)
		if groupID != packageGroup.Group.GroupID || len(addresses) != 1 || addresses[0] != "192.0.2.40" ||
			subscription == nil || *subscription != opened.Subscription.ID {
			t.Fatalf("rebound target group=%s a=%v subscription=%v", groupID, addresses, subscription)
		}
	})

	t.Run("533 down refuses while sites without a package hold CNAME facts", func(t *testing.T) {
		// Later migrations stack on 533; roll them back first so 533's own down guard runs.
		err := migrateDownTo(t.Context(), pool, 533)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P5333" {
			t.Fatalf("533 down err=%v", err)
		}
	})
}
