package site

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/cnamelines"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestCNAMEAreaLinesPublishByRegionArea: an endpoint whose
// platform region is a macro area (region_catalog.area_code, migration 678;
// matched by name or id) is written to the provider's line for that area
// (migration 679 keeps the record): plan -> publish (a recording publisher,
// no DNS provider is called) -> cname_carrier_line_records. Global stays on
// the default line, an area endpoint does not join the carrier line, a line
// that loses its endpoints is retired, and a provider without Asian
// sub-areas (Huawei) merges them on 亚洲.
func TestCNAMEAreaLinesPublishByRegionArea(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	dsn = databasetest.FreshDatabaseURL(t, dsn, "cname_area_lines")
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "cname_area_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "area-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "area-platform", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Area tenant", "area-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")

	// Platform regions with a macro area; "日本" has no catalog row (region text only).
	var platformScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScope); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO region_catalog(id,platform_scope_id,name,area_code) VALUES
		(gen_random_uuid(),$1,'东南亚一区','southeast_asia'),(gen_random_uuid(),$1,'东亚精品','east_asia'),
		(gen_random_uuid(),$1,'全球节点','global'),(gen_random_uuid(),$1,'欧洲节点','europe')`, platformScope)
	var europeID string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM region_catalog WHERE name='欧洲节点'`).Scan(&europeID); err != nil {
		t.Fatal(err)
	}

	scheduler := nodescheduler.NewService(pool, func() time.Time { return now })
	schedulerActor := nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	endpoints := []nodescheduler.Endpoint{
		{ID: uuid.New(), Address: "192.0.2.71", Port: 80, Weight: 1, Enabled: true, Region: "东南亚一区"},
		{ID: uuid.New(), Address: "192.0.2.72", Port: 80, Weight: 1, Enabled: true, Region: "东亚精品", Carrier: "电信"},
		{ID: uuid.New(), Address: "192.0.2.73", Port: 80, Weight: 1, Enabled: true, Region: europeID}, // by id
		{ID: uuid.New(), Address: "192.0.2.74", Port: 80, Weight: 1, Enabled: true, Region: "全球节点"},
		{ID: uuid.New(), Address: "198.51.100.75", Port: 80, Weight: 1, Enabled: true, Region: "日本"},
	}
	group, err := scheduler.PutGroup(ctx, schedulerActor, nodescheduler.PutGroupRequest{Name: "area",
		Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: endpoints, IdempotencyKey: "area-group", RequestID: "area-group"})
	if err != nil {
		t.Fatal(err)
	}
	providerID := uuid.New()
	exec(`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'area','aliyun','fixture-key',$3,$4,$4)`, providerID, tenant.scopeID, make([]byte, 32), tenant.userID)
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
		IdempotencyKey: "area-subscription", RequestID: "area-subscription",
	})
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO edge_automatic_publication_policy_facts(target_scope_id,revision,mode,node_ids,activation_timeout_ms,
		observation_window_ms,required_consecutive_successes,max_attempts,deadline_window_seconds,actor_scope_id,actor_user_id,reason,created_at)
		SELECT $1,COALESCE(max(revision),0)+1,'automatic',$2,30000,15000,2,3,600,$1,$3,'integration_policy',clock_timestamp()
		FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1`,
		tenant.scopeID, []uuid.UUID{uuid.New()}, tenant.userID)
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, time.Hour)
	cname, err := cnameallocation.NewStore(pool, platformCNAMEKeyring{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	var tenantID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1`, tenant.scopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	start := func(jobID uuid.UUID, kind string) jobstate.Claim {
		t.Helper()
		var claim jobstate.Claim
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var err error
			claim, err = jobstate.StartTx(ctx, tx, jobstate.StartInput{TenantID: tenantID, JobID: jobID, Kind: kind,
				WorkerID: "area-worker", LeaseDuration: time.Minute}, now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return claim
	}
	created, err := NewService(store).Create(ctx, Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"},
		CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID, IdempotencyKey: "area-site", RequestID: "area-site",
			Fields: SiteFields{Domains: []string{"area.example.co.uk"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
				Enabled: false, Status: StatusDisabled,
				NodeGroupID: &group.Group.GroupID, NodeGroupName: group.Group.Name,
				PackageID: &productID, PackageName: "Business", PackageSubscriptionID: &opened.Subscription.ID}})
	if err != nil {
		t.Fatal(err)
	}
	if err := cname.PrepareIntent(ctx, start(*created.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
		t.Fatal(err)
	}
	allocation, err := cname.Get(ctx, tenant.scopeID, created.Site.ID)
	if err != nil {
		t.Fatal(err)
	}
	claim := start(allocation.JobID, "dns.cname.allocation")
	if _, err := cname.Complete(ctx, cnameallocation.ResultRequest{TargetScopeID: tenant.scopeID, SiteID: created.Site.ID,
		AllocationID: allocation.ID, JobID: allocation.JobID, ExpectedRevision: allocation.Revision, WorkerID: claim.WorkerID,
		Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, Sequence: 1}); err != nil {
		t.Fatal(err)
	}
	lines := &recordedLines{}
	worker, err := cnamelines.NewWorker(pool, lines, func() time.Time { return now }, nil)
	if err != nil {
		t.Fatal(err)
	}
	tracked := func() []string {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT line_scope FROM cname_carrier_line_records WHERE site_id=$1 AND publish_error=''
			ORDER BY line_scope`, created.Site.ID)
		if err != nil {
			t.Fatal(err)
		}
		scopes, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return scopes
	}

	// Aliyun has every area line (os_*): one record set per area line.
	if err := worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	got := lines.take()
	if len(got) != 4 || !slices.Equal(got["东南亚地区"].A, []string{"192.0.2.71"}) ||
		!slices.Equal(got["东亚地区"].A, []string{"192.0.2.72"}) || !slices.Equal(got["欧洲"].A, []string{"192.0.2.73"}) ||
		!slices.Equal(got["境外"].A, []string{"198.51.100.75"}) || got["欧洲"].Owner != allocation.Hostname {
		t.Fatalf("aliyun publication = %+v", got)
	}
	if _, telecom := got["电信"]; telecom {
		t.Fatal("an area endpoint joined the carrier line")
	}
	if scopes := tracked(); !slices.Equal(scopes, []string{"east_asia", "europe", "overseas", "southeast_asia"}) {
		t.Fatalf("aliyun tracked = %v", scopes)
	}
	if err := worker.Tick(ctx); err != nil || len(lines.take()) != 0 {
		t.Fatalf("converged area lines were rewritten (%v)", err)
	}

	// The European endpoint leaves: 欧洲 is retired, then forgotten.
	endpoints = slices.Delete(endpoints, 2, 3)
	if _, err := scheduler.PutGroup(ctx, schedulerActor, nodescheduler.PutGroupRequest{GroupID: group.Group.GroupID,
		ExpectedRevision: group.Group.Revision, Name: "area", Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: endpoints,
		IdempotencyKey: "area-group-2", RequestID: "area-group-2"}); err != nil {
		t.Fatal(err)
	}
	if err := worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got = lines.take(); len(got) != 1 || len(got["欧洲"].A)+len(got["欧洲"].AAAA) != 0 {
		t.Fatalf("europe retirement = %+v", got)
	}
	if err := worker.Tick(ctx); err != nil || len(lines.take()) != 0 {
		t.Fatalf("retired line rewritten (%v)", err)
	}
	if scopes := tracked(); slices.Contains(scopes, "europe") {
		t.Fatalf("retired line still tracked: %v", scopes)
	}

	// Huawei has no Asian sub-areas: from a clean slate (records live in the
	// new account), East and Southeast Asia share 亚洲 (AP), stored as asia.
	exec(`DELETE FROM cname_carrier_line_records WHERE site_id=$1`, created.Site.ID)
	exec(`UPDATE dns_providers SET provider_type='huawei' WHERE id=$1`, providerID)
	if err := worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got = lines.take(); len(got) != 2 || !slices.Equal(got["亚洲"].A, []string{"192.0.2.71", "192.0.2.72"}) ||
		!slices.Equal(got["境外"].A, []string{"198.51.100.75"}) {
		t.Fatalf("huawei publication = %+v", got)
	}
	if scopes := tracked(); !slices.Equal(scopes, []string{"asia", "overseas"}) {
		t.Fatalf("huawei tracked = %v", scopes)
	}
}
