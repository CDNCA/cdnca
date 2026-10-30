package site

import (
	"context"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// retargetFixture is one tenant with a line group, a DNSPod platform provider
// copy and one settled CNAME allocation, used to drive the retarget planner.
type retargetFixture struct {
	t          *testing.T
	ctx        context.Context
	pool       *pgxpool.Pool
	now        time.Time
	tenant     addonSiteTenantFixture
	manager    packagesubscription.Actor
	scheduler  *nodescheduler.Service
	group      nodescheduler.LineGroupRevision
	endpoints  []nodescheduler.Endpoint
	cname      *cnameallocation.Store
	allocation cnameallocation.Allocation
	siteID     uuid.UUID
	tenantID   uuid.UUID
	holds      map[uuid.UUID]int64
	puts       int
}

func (fixture *retargetFixture) exec(query string, args ...any) {
	fixture.t.Helper()
	if _, err := fixture.pool.Exec(fixture.ctx, query, args...); err != nil {
		fixture.t.Fatal(err)
	}
}

// newRetargetFixture creates the tenant, one node per endpoint and the line
// group; the site is created by createSite so a test can change the group first.
func newRetargetFixture(t *testing.T, failoverMode string, endpoints []nodescheduler.Endpoint) *retargetFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "cname_retarget_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE") })
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	fixture := &retargetFixture{t: t, ctx: t.Context(), pool: pool, now: time.Now().UTC().Truncate(time.Second),
		holds: map[uuid.UUID]int64{}}
	fixture.tenant = addonSiteInsertSubscriptionTenant(t, pool, "Retarget tenant", "retarget-owner")
	addonSiteAssignSubscriptionRole(t, pool, fixture.tenant.scopeID, fixture.tenant.userID, "site-owner",
		"sites.manage", "dns.manage", "node_scheduling.manage")
	fixture.manager = addonSiteInsertPlatformActor(t, pool, "retarget-admin")
	addonSiteAssignSubscriptionRole(t, pool, fixture.manager.ScopeID, fixture.manager.UserID, "retarget-platform",
		"platform.admin")
	for index := range endpoints {
		nodeID := uuid.New()
		// The endpoint address is the node's IP (a node-bound endpoint must use one).
		fixture.exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4,ipv6)
			VALUES($1,$2,$3,'active',$4,$5,CASE WHEN family($6::inet)=4 THEN $6::inet END,CASE WHEN family($6::inet)=6 THEN $6::inet END)`,
			nodeID, fixture.tenant.scopeID, nodeID.String(), fixture.tenant.userID, index+1, endpoints[index].Address)
		endpoints[index].ID, endpoints[index].NodeID = uuid.New(), nodeID
		endpoints[index].Port, endpoints[index].Enabled = 80, true
		if endpoints[index].Weight == 0 {
			endpoints[index].Weight = 1
		}
	}
	fixture.scheduler = nodescheduler.NewService(pool, func() time.Time { return fixture.now })
	fixture.endpoints = endpoints
	fixture.putGroup(failoverMode, "retarget")
	return fixture
}

// putGroup writes a new sealed line group revision with fixture.endpoints.
func (fixture *retargetFixture) putGroup(failoverMode, name string) {
	fixture.t.Helper()
	fixture.puts++
	key := "retarget-line-group-" + string(rune('a'+fixture.puts))
	result, err := fixture.scheduler.PutGroup(fixture.ctx, nodescheduler.Actor{UserID: fixture.tenant.userID,
		ScopeID: fixture.tenant.scopeID, ScopeKind: "tenant"}, nodescheduler.PutGroupRequest{
		GroupID: fixture.group.GroupID, ExpectedRevision: fixture.group.Revision, Name: name,
		FailoverMode: failoverMode, Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: slices.Clone(fixture.endpoints),
		IdempotencyKey: key, RequestID: key,
	})
	if err != nil {
		fixture.t.Fatal(err)
	}
	fixture.group = result.Group
}

func (fixture *retargetFixture) setIPWeight(enabled bool) {
	fixture.t.Helper()
	settings := `{"dns_config":{"ip_weight":false}}`
	if enabled {
		settings = `{"dns_config":{"ip_weight":true}}`
	}
	command, err := fixture.pool.Exec(fixture.ctx, `INSERT INTO platform_system_other_settings(platform_scope_id,revision,settings,updated_at)
		SELECT id,1,$1::jsonb,now() FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL
		ON CONFLICT (platform_scope_id) DO UPDATE SET settings=EXCLUDED.settings,revision=platform_system_other_settings.revision+1`,
		settings)
	if err != nil || command.RowsAffected() != 1 {
		fixture.t.Fatalf("set ip_weight: %v %v", command, err)
	}
}

func (fixture *retargetFixture) setHold(nodeID uuid.UUID, held bool) {
	fixture.t.Helper()
	fixture.holds[nodeID]++
	var since any
	if held {
		since = fixture.now
	}
	if fixture.holds[nodeID] == 1 {
		fixture.exec(`INSERT INTO node_serving_holds(node_id,source,held,reason_code,revision,held_since,changed_at,updated_at)
			VALUES($1,'availability_monitor',$2,'probe_unhealthy',1,$3,clock_timestamp(),clock_timestamp())`, nodeID, held, since)
		return
	}
	fixture.exec(`UPDATE node_serving_holds SET held=$2,revision=$3,held_since=$4,changed_at=clock_timestamp(),updated_at=clock_timestamp()
		WHERE node_id=$1 AND source='availability_monitor'`, nodeID, held, fixture.holds[nodeID], since)
}

// createSite creates the site and settles its CNAME allocation as done;
// returns the frozen A values.
func (fixture *retargetFixture) createSite() []string {
	fixture.t.Helper()
	frozen := fixture.prepareSite()
	claim := fixture.start(fixture.allocation.JobID, "dns.cname.allocation")
	if _, err := fixture.cname.Complete(fixture.ctx, cnameallocation.ResultRequest{TargetScopeID: fixture.tenant.scopeID,
		SiteID: fixture.siteID, AllocationID: fixture.allocation.ID, JobID: fixture.allocation.JobID,
		ExpectedRevision: fixture.allocation.Revision, WorkerID: claim.WorkerID, Attempt: claim.Job.Attempt,
		LeaseID: claim.LeaseID, Sequence: 1}); err != nil {
		fixture.t.Fatal(err)
	}
	return frozen
}

func (fixture *retargetFixture) start(jobID uuid.UUID, kind string) jobstate.Claim {
	fixture.t.Helper()
	var claim jobstate.Claim
	if err := pgx.BeginFunc(fixture.ctx, fixture.pool, func(tx pgx.Tx) error {
		var err error
		claim, err = jobstate.StartTx(fixture.ctx, tx, jobstate.StartInput{TenantID: fixture.tenantID, JobID: jobID, Kind: kind,
			WorkerID: "retarget-worker", LeaseDuration: time.Minute}, fixture.now)
		return err
	}); err != nil {
		fixture.t.Fatal(err)
	}
	return claim
}

// prepareSite creates the platform DNSPod provider copy, the site and its
// CNAME allocation with a frozen target (job queued, not yet claimed).
func (fixture *retargetFixture) prepareSite() []string {
	t, ctx, pool := fixture.t, fixture.ctx, fixture.pool
	t.Helper()
	manager := fixture.manager
	providerID := dnsacme.PlatformProviderCopyID(fixture.tenant.scopeID)
	fixture.exec(`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'retarget','dnspod_cn','fixture-key',$3,$4,$4)`, providerID, fixture.tenant.scopeID, make([]byte, 32), fixture.tenant.userID)
	fixture.exec(`INSERT INTO dns_zones(id,scope_id,provider_id,name,is_default,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'cdn.example.com',true,$4,$4)`, uuid.New(), fixture.tenant.scopeID, providerID, fixture.tenant.userID)
	productID := addonSiteInsertPackageProductVersion(t, pool, manager, 1, 100, 1000)
	subscriptions := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, func() time.Time { return fixture.now }))
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	opened, err := subscriptions.Open(ctx, manager, packagesubscription.OpenRequest{
		TenantScopeID: fixture.tenant.scopeID, OwnerUserID: fixture.tenant.userID, ProductID: productID, ProductRevision: 1,
		SiteLimit: 100, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "retarget-subscription", RequestID: "retarget-subscription",
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.exec(`INSERT INTO edge_automatic_publication_policy_facts(target_scope_id,revision,mode,node_ids,activation_timeout_ms,
		observation_window_ms,required_consecutive_successes,max_attempts,deadline_window_seconds,actor_scope_id,actor_user_id,reason,created_at)
		SELECT $1,COALESCE(max(revision),0)+1,'automatic',$2,30000,15000,2,3,600,$1,$3,'integration_policy',clock_timestamp()
		FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1`,
		fixture.tenant.scopeID, []uuid.UUID{uuid.New()}, fixture.tenant.userID)
	store := NewStoreWithClock(pool, func() time.Time { return fixture.now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, fixture.now, time.Hour)
	if fixture.cname, err = cnameallocation.NewStore(pool, platformCNAMEKeyring{}, func() time.Time { return fixture.now }); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1`, fixture.tenant.scopeID).Scan(&fixture.tenantID); err != nil {
		t.Fatal(err)
	}
	created, err := NewService(store).Create(ctx, Actor{UserID: fixture.tenant.userID, ScopeID: fixture.tenant.scopeID, ScopeKind: "tenant"},
		CreateRequest{TargetScopeID: fixture.tenant.scopeID, OwnerUserID: fixture.tenant.userID, IdempotencyKey: "retarget-site",
			RequestID: "retarget-site", Fields: SiteFields{Domains: []string{"retarget.example.co.uk"}, HTTPPorts: []string{"80"},
				Origins: []string{"192.0.2.1"}, Enabled: false, Status: StatusDisabled,
				NodeGroupID: &fixture.group.GroupID, NodeGroupName: fixture.group.Name,
				PackageID: &productID, PackageName: "Business", PackageSubscriptionID: &opened.Subscription.ID}})
	if err != nil {
		t.Fatal(err)
	}
	fixture.siteID = created.Site.ID
	if err := fixture.cname.PrepareIntent(ctx, fixture.start(*created.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
		t.Fatal(err)
	}
	if fixture.allocation, err = fixture.cname.Get(ctx, fixture.tenant.scopeID, created.Site.ID); err != nil {
		t.Fatal(err)
	}
	var frozen []string
	if err := pool.QueryRow(ctx, `SELECT target_a FROM cname_allocation_targets WHERE job_id=$1`,
		fixture.allocation.JobID).Scan(&frozen); err != nil {
		t.Fatal(err)
	}
	return frozen
}

// plan runs the planner and returns the single open retarget (or none).
func (fixture *retargetFixture) plan(want int) (cnameallocation.Retarget, bool) {
	fixture.t.Helper()
	count, err := fixture.cname.PlanRetargets(fixture.ctx)
	if err != nil || count != want {
		fixture.t.Fatalf("PlanRetargets = %d %v, want %d", count, err, want)
	}
	open, err := fixture.cname.OpenRetargets(fixture.ctx)
	if err != nil || len(open) > 1 {
		fixture.t.Fatalf("OpenRetargets = %+v %v", open, err)
	}
	if len(open) == 0 {
		return cnameallocation.Retarget{}, false
	}
	return open[0], true
}

func (fixture *retargetFixture) commit(retarget cnameallocation.Retarget) {
	fixture.t.Helper()
	if err := fixture.cname.AttachRetarget(fixture.ctx, retarget, dnsreconcile.Task{ID: uuid.New(), Revision: 1}); err != nil {
		fixture.t.Fatal(err)
	}
	if err := fixture.cname.SettleRetarget(fixture.ctx, retarget, "committed", ""); err != nil {
		fixture.t.Fatal(err)
	}
}

// FX32: with 开启IP权重 on the DNSPod platform copy, a weight-only line group
// change must be republished, also when it lands while an older revision's
// retarget is still in flight.
func TestCNAMERetargetRepublishesWeightOnlyChanges(t *testing.T) {
	fixture := newRetargetFixture(t, "", []nodescheduler.Endpoint{
		{Address: "192.0.2.31", Weight: 10}, {Address: "192.0.2.32", Weight: 10},
	})
	fixture.createSite()
	fixture.setIPWeight(true)
	if _, open := fixture.plan(0); open {
		t.Fatal("published values already match")
	}

	// Weight-only change: same addresses, new revision.
	fixture.endpoints[0].Weight = 70
	fixture.putGroup("", "retarget")
	weighted, open := fixture.plan(1)
	if !open || weighted.NodeGroupRevision != fixture.group.Revision ||
		!maps.Equal(weighted.Publish.Weights, map[cnameallocation.WeightKey]uint32{{Address: "192.0.2.31"}: 70, {Address: "192.0.2.32"}: 10}) {
		t.Fatalf("weight-only retarget = %+v (open %v)", weighted, open)
	}
	fixture.commit(weighted)
	if _, open := fixture.plan(0); open {
		t.Fatal("committed weights must not be planned again")
	}

	// 加 IP 后快速改权重: the add-IP retarget freezes revision N; the weight
	// change (N+1) lands while it is in flight and must follow once it commits.
	// The extra IP is a secondary IP of the existing node (节点管理 > 副IP).
	fixture.exec(`UPDATE nodes SET management_settings=jsonb_set(management_settings,'{secondary_ips}','["192.0.2.33"]') WHERE id=$1`,
		fixture.endpoints[1].NodeID)
	fixture.endpoints = append(fixture.endpoints, nodescheduler.Endpoint{ID: uuid.New(), NodeID: fixture.endpoints[1].NodeID,
		Address: "192.0.2.33", Port: 80, Weight: 10, Enabled: true})
	fixture.putGroup("", "retarget")
	added, open := fixture.plan(1)
	if !open || !slices.Equal(added.Values.A, []string{"192.0.2.31", "192.0.2.32", "192.0.2.33"}) {
		t.Fatalf("add-IP retarget = %+v", added)
	}
	fixture.endpoints[2].Weight = 90
	fixture.putGroup("", "retarget")
	if _, open := fixture.plan(0); !open {
		t.Fatal("the in-flight retarget must stay open, not be planned twice")
	}
	fixture.commit(added)
	followUp, open := fixture.plan(1)
	if !open || followUp.NodeGroupRevision != fixture.group.Revision || followUp.Publish.Weights[cnameallocation.WeightKey{Address: "192.0.2.33"}] != 90 {
		t.Fatalf("follow-up retarget after the stale revision committed = %+v (open %v)", followUp, open)
	}
	fixture.commit(followUp)

	// A revision that changes neither addresses nor weights is not republished.
	fixture.putGroup("", "retarget-renamed")
	if _, open := fixture.plan(0); open {
		t.Fatal("a rename must not retarget")
	}
	// Without 开启IP权重 weights are not written, so a weight change is a no-op.
	fixture.setIPWeight(false)
	fixture.endpoints[0].Weight = 5
	fixture.putGroup("", "retarget-renamed")
	if _, open := fixture.plan(0); open {
		t.Fatal("weights are ignored while 开启IP权重 is off")
	}
}

// Sold packages use the platform's line groups: their endpoints live in the
// platform scope, so 开启IP权重 must read them there, not in the tenant scope.
func TestCNAMEPublishSettingsReadPlatformLineGroupWeights(t *testing.T) {
	fixture := newRetargetFixture(t, "", []nodescheduler.Endpoint{{Address: "192.0.2.41"}})
	fixture.createSite()
	fixture.setIPWeight(true)
	platform := fixture.manager.ScopeID
	group, node, endpoint, telecom := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	err := pgx.BeginFunc(fixture.ctx, fixture.pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id)
			  VALUES($1,$2,$3,'active',$4,(SELECT COALESCE(max(display_id),0)+1 FROM nodes))`,
				[]any{node, platform, "platform-node", fixture.manager.UserID}},
			{`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,updated_at)
			  VALUES($1,$2,'platform-group',1,$3,$3,now(),now())`, []any{group, platform, fixture.manager.UserID}},
			{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,probe_interval_ms,probe_timeout_ms,
			  failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,created_by_user_id,created_at)
			  VALUES($1,$2,1,'platform-group','lg-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,2,$3,$4,now())`,
				[]any{group, platform, make([]byte, 32), fixture.manager.UserID}},
			{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
			  VALUES($1,$2,$3,$4,1,'192.0.2.42',4,80,'','',0,40,true)`, []any{endpoint, node, platform, group}},
			// NET-02（fp-net2，待出包前全量跑）：同一 IP 挂电信线路、另设权重，两条各自保留。
			{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,port,region,carrier,priority,weight,enabled)
			  VALUES($1,$2,$3,$4,1,'192.0.2.42',4,80,'','电信',0,90,true)`, []any{telecom, node, platform, group}},
			{`INSERT INTO node_line_endpoint_health(tenant_scope_id,line_group_id,config_revision,endpoint_id,status,consecutive_successes,
			  consecutive_failures,last_sequence,last_changed_at,row_revision,created_at,updated_at)
			  SELECT $1,$2,1,id,'unknown',0,0,0,now(),1,now(),now() FROM node_line_endpoints
			  WHERE tenant_scope_id=$1 AND line_group_id=$2`, []any{platform, group}},
			{`UPDATE node_line_group_revisions SET sealed_at=now() WHERE tenant_scope_id=$1 AND line_group_id=$2`, []any{platform, group}},
		} {
			if _, err := tx.Exec(fixture.ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var zoneID uuid.UUID
	if err := fixture.pool.QueryRow(fixture.ctx, `SELECT zone_id FROM cname_allocation_targets WHERE job_id=$1`,
		fixture.allocation.JobID).Scan(&zoneID); err != nil {
		t.Fatal(err)
	}
	settings, err := cnameallocation.LoadPublishSettings(fixture.ctx, fixture.pool, fixture.tenant.scopeID, zoneID, group, 1)
	if err != nil || !maps.Equal(settings.Weights, map[cnameallocation.WeightKey]uint32{
		{Address: "192.0.2.42"}: 40, {Carrier: "电信", Address: "192.0.2.42"}: 90}) {
		t.Fatalf("platform group weights = %+v %v", settings, err)
	}
	if weight, ok := settings.DefaultLineWeight("192.0.2.42"); !ok || weight != 40 {
		t.Fatalf("default line weight = %d %v", weight, ok)
	}
}

// scriptedReconcile returns its tasks in order (the last one repeats).
type scriptedReconcile struct {
	tasks []dnsreconcile.Task
	gets  int
}

func (fake *scriptedReconcile) Apply(context.Context, dnsreconcile.ApplyRequest) (dnsreconcile.Task, error) {
	return fake.tasks[0], nil
}
func (fake *scriptedReconcile) Get(context.Context, uuid.UUID, uuid.UUID) (dnsreconcile.Task, error) {
	fake.gets++
	return fake.tasks[min(fake.gets, len(fake.tasks)-1)], nil
}
func (fake *scriptedReconcile) Commit(context.Context, dnsreconcile.CommitRequest) (dnsreconcile.Task, error) {
	return fake.tasks[len(fake.tasks)-1], nil
}

// FX40: with the production 16 minute lease, an allocation whose child DNS
// task settles quickly is done seconds later, not after the lease expires.
func TestCNAMEAllocationYieldsLeaseUntilChildSettles(t *testing.T) {
	fixture := newRetargetFixture(t, "", []nodescheduler.Endpoint{{Address: "192.0.2.51"}})
	fixture.prepareSite()
	clock := fixture.now
	jobs, err := jobstate.NewStore(fixture.pool, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	cname, err := cnameallocation.NewStore(fixture.pool, platformCNAMEKeyring{}, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	child := dnsreconcile.Task{ID: uuid.New(), TenantID: fixture.tenantID, SiteID: fixture.siteID, Revision: 1}
	applying, committed := child, child
	applying.Result.Status, committed.Result.Status = dnscheck.TaskApplying, dnscheck.TaskCommitted
	reconcile := &scriptedReconcile{tasks: []dnsreconcile.Task{applying, applying, committed}}
	worker, err := cnameallocation.NewWorker(cnameallocation.WorkerConfig{WorkerID: "fx40-worker",
		LeaseDuration: 16 * time.Minute, Now: func() time.Time { return clock }},
		cnameallocation.WorkerDependencies{Claims: jobs, Targets: cname, Reconcile: reconcile})
	if err != nil {
		t.Fatal(err)
	}
	jobState := func() (string, time.Time) {
		t.Helper()
		var state string
		var claimable *time.Time
		if err := fixture.pool.QueryRow(fixture.ctx, `SELECT state,claimable_at FROM background_jobs WHERE id=$1`,
			fixture.allocation.JobID).Scan(&state, &claimable); err != nil {
			t.Fatal(err)
		}
		if claimable == nil {
			return state, time.Time{}
		}
		return state, *claimable
	}
	run := func() {
		t.Helper()
		if _, err := worker.RunOnce(fixture.ctx, fixture.tenantID); err != nil {
			t.Fatal(err)
		}
	}
	// n14n16: the first childPollFastAttempts polls are 2 s apart (the CNAME
	// is listed about 10 s after the write), then the delay doubles.
	run() // claims, applies the child, attaches it and yields
	if state, claimable := jobState(); state != "queued" || !claimable.Equal(clock.Add(2*time.Second)) {
		t.Fatalf("after attach: state=%s claimable=%v, want queued at +2s", state, claimable)
	}
	clock = clock.Add(2 * time.Second)
	run() // child still applying: yields again (attempt 2, still 2s)
	if state, claimable := jobState(); state != "queued" || !claimable.Equal(clock.Add(2*time.Second)) {
		t.Fatalf("in flight: state=%s claimable=%v, want queued at +2s", state, claimable)
	}
	clock = clock.Add(2 * time.Second)
	run() // child committed: the allocation settles
	allocation, err := cname.Get(fixture.ctx, fixture.tenant.scopeID, fixture.siteID)
	if err != nil || allocation.State != cnameallocation.StateDone {
		t.Fatalf("allocation = %+v %v, want done 4s after the first claim", allocation, err)
	}
	if state, _ := jobState(); state != "succeeded" {
		t.Fatalf("job state = %s", state)
	}
}

// expectA plans and commits one retarget publishing want (nil: nothing to plan).
func (fixture *retargetFixture) expectA(want ...string) {
	fixture.t.Helper()
	if len(want) == 0 {
		if retarget, open := fixture.plan(0); open {
			fixture.t.Fatalf("unexpected retarget %+v", retarget.Values)
		}
		return
	}
	retarget, open := fixture.plan(1)
	if !open || !slices.Equal(retarget.Values.A, want) {
		fixture.t.Fatalf("retarget A = %v (open %v), want %v", retarget.Values.A, open, want)
	}
	fixture.commit(retarget)
}

// NF19 备用IP上线顺序: endpoints of the lowest priority are published; the
// others are standby and come online by sort order as primaries go offline.
func TestCNAMEPublishesStandbyEndpointsByPriority(t *testing.T) {
	fixture := newRetargetFixture(t, nodescheduler.FailoverPrimaryOffline, []nodescheduler.Endpoint{
		{Address: "192.0.2.61", Priority: 1}, {Address: "192.0.2.62", Priority: 1},
		{Address: "192.0.2.64", Priority: 2, SortOrder: 20}, {Address: "192.0.2.63", Priority: 2, SortOrder: 10},
	})
	primaryA, primaryB, standbyEarly := fixture.endpoints[0].NodeID, fixture.endpoints[1].NodeID, fixture.endpoints[3].NodeID
	if frozen := fixture.createSite(); !slices.Equal(frozen, []string{"192.0.2.61", "192.0.2.62"}) {
		t.Fatalf("frozen target = %v; standby IPs must not be published while primaries serve", frozen)
	}
	fixture.expectA()
	fixture.setHold(primaryA, true) // one primary offline: the first standby by sort order comes online
	fixture.expectA("192.0.2.62", "192.0.2.63")
	fixture.setHold(standbyEarly, true) // that standby fails too: the next one replaces it
	fixture.expectA("192.0.2.62", "192.0.2.64")
	fixture.setHold(standbyEarly, false)
	fixture.expectA("192.0.2.62", "192.0.2.63")
	fixture.setHold(primaryB, true) // both primaries offline: both standbys serve
	fixture.expectA("192.0.2.63", "192.0.2.64")
	fixture.setHold(primaryA, false)
	fixture.setHold(primaryB, false) // primaries back: standbys leave DNS
	fixture.expectA("192.0.2.61", "192.0.2.62")
}

// 在线IP数少于备用IP数时: standbys come online (all of them) only once fewer
// primaries are online than there are standbys.
func TestCNAMEPublishesStandbyEndpointsWhenOnlineBelowStandbyCount(t *testing.T) {
	fixture := newRetargetFixture(t, nodescheduler.FailoverOnlineLessThanBackupCount, []nodescheduler.Endpoint{
		{Address: "192.0.2.71", Priority: 1}, {Address: "192.0.2.72", Priority: 1}, {Address: "192.0.2.73", Priority: 1},
		{Address: "192.0.2.74", Priority: 5, SortOrder: 1}, {Address: "192.0.2.75", Priority: 5, SortOrder: 2},
	})
	if frozen := fixture.createSite(); !slices.Equal(frozen, []string{"192.0.2.71", "192.0.2.72", "192.0.2.73"}) {
		t.Fatalf("frozen target = %v", frozen)
	}
	fixture.setHold(fixture.endpoints[0].NodeID, true) // 2 online, 2 standbys: not fewer, no switch
	fixture.expectA("192.0.2.72", "192.0.2.73")
	fixture.setHold(fixture.endpoints[1].NodeID, true) // 1 online < 2 standbys: all standbys online
	fixture.expectA("192.0.2.73", "192.0.2.74", "192.0.2.75")
	// Every endpoint held: the family fails open to all admin-enabled IPs.
	for _, endpoint := range fixture.endpoints[2:] {
		fixture.setHold(endpoint.NodeID, true)
	}
	fixture.expectA("192.0.2.71", "192.0.2.72", "192.0.2.73", "192.0.2.74", "192.0.2.75")
}

// One priority tier (the default, every endpoint priority 0) keeps publishing
// every serving endpoint as before.
func TestCNAMESinglePriorityTierPublishesAllServing(t *testing.T) {
	fixture := newRetargetFixture(t, "", []nodescheduler.Endpoint{{Address: "192.0.2.81"}, {Address: "192.0.2.82"}})
	if frozen := fixture.createSite(); !slices.Equal(frozen, []string{"192.0.2.81", "192.0.2.82"}) {
		t.Fatalf("frozen target = %v", frozen)
	}
	fixture.setHold(fixture.endpoints[0].NodeID, true)
	fixture.expectA("192.0.2.82")
}
