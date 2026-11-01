package site

import (
	"context"
	"encoding/json"
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
	"github.com/cdnca/cdnca/services/control-api/internal/smartsched"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestSmartScheduleLinesEndToEnd: dnspup
// latency of a line group's endpoints lands in the minute samples, the
// selector keeps the fastest healthy endpoints, and the CNAME carrier line
// is rewritten with that set (desired_digest of the equal-weight set).
// Disabling restores the static line.
func TestSmartScheduleLinesEndToEnd(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	dsn = databasetest.FreshDatabaseURL(t, dsn, "smart_lines")
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "smart_lines_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "smart-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "smart-platform", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Smart tenant", "smart-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")
	scheduler := nodescheduler.NewService(pool, func() time.Time { return now })
	schedulerActor := nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	nodes := map[string]uuid.UUID{}
	endpoints := []nodescheduler.Endpoint{}
	for index, item := range []struct{ address, carrier, region string }{
		{"192.0.2.71", "电信", "广东"}, {"192.0.2.72", "电信", "浙江"}, {"192.0.2.73", "电信", "江苏"}, {"192.0.2.74", "联通", ""},
	} {
		nodeID := uuid.New()
		nodes[item.address] = nodeID
		exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4) VALUES($1,$2,$3,'active',$4,$5,$6)`,
			nodeID, tenant.scopeID, "smart-"+item.address, tenant.userID, index+1, item.address)
		endpoints = append(endpoints, nodescheduler.Endpoint{ID: uuid.New(), NodeID: nodeID, Address: item.address, Port: 80,
			Weight: 1, Enabled: true, Carrier: item.carrier, Region: item.region})
	}
	group, err := scheduler.PutGroup(ctx, schedulerActor, nodescheduler.PutGroupRequest{Name: "lines",
		Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: endpoints, IdempotencyKey: "smart-group", RequestID: "smart-group"})
	if err != nil {
		t.Fatal(err)
	}
	providerID := uuid.New()
	exec(`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'lines','aliyun','fixture-key',$3,$4,$4)`, providerID, tenant.scopeID, make([]byte, 32), tenant.userID)
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
		IdempotencyKey: "smart-subscription", RequestID: "smart-subscription",
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
				WorkerID: "smart-worker", LeaseDuration: time.Minute}, now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return claim
	}
	created, err := NewService(store).Create(ctx, Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"},
		CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID, IdempotencyKey: "smart-site", RequestID: "smart-site",
			Fields: SiteFields{Domains: []string{"smart.example.co.uk"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
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
	lines := &recordedLines{}
	worker, err := cnamelines.NewWorker(pool, lines, func() time.Time { return now }, nil)
	if err != nil {
		t.Fatal(err)
	}
	claim := start(allocation.JobID, "dns.cname.allocation")
	if _, err := cname.Complete(ctx, cnameallocation.ResultRequest{TargetScopeID: tenant.scopeID, SiteID: created.Site.ID,
		AllocationID: allocation.ID, JobID: allocation.JobID, ExpectedRevision: allocation.Revision, WorkerID: claim.WorkerID,
		Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, Sequence: 1}); err != nil {
		t.Fatal(err)
	}
	if err := worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	static := lines.take()["电信"]
	if !slices.Equal(static.A, []string{"192.0.2.71", "192.0.2.72", "192.0.2.73"}) {
		t.Fatalf("static telecom line = %+v", static)
	}
	staticDigest := cnamelines.Set{A: static.A, AAAA: []string{}}.Digest(static.TTL, static.Weights)
	digest := func(scope string) string {
		t.Helper()
		var value string
		if err := pool.QueryRow(ctx, `SELECT desired_digest FROM cname_carrier_line_records WHERE site_id=$1 AND line_scope=$2`,
			created.Site.ID, scope).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	if digest("telecom") != staticDigest {
		t.Fatal("static digest mismatch")
	}

	// dnspup rows of the endpoints' nodes (telecom checkpoints in 广东).
	probe := func(address string, latency int, ok bool) {
		t.Helper()
		checkpoints, _ := json.Marshal([]map[string]any{
			{"id": "cp1", "group": "telecom", "carrier": "telecom", "region": "cn", "province": "广东", "ok": ok, "latency_ms": latency},
			{"id": "cp2", "group": "telecom", "carrier": "telecom", "region": "cn", "province": "广东", "ok": ok, "latency_ms": latency + 2},
		})
		exec(`INSERT INTO node_dnspup_probe_results(node_id,address,port,observed_at,total_checks,failed_checks,failed,checkpoints)
			VALUES($1,$2,80,$3,2,0,false,$4)`, nodes[address], address, now.Add(-time.Minute), checkpoints)
	}
	probe("192.0.2.71", 40, true)
	probe("192.0.2.72", 10, true)
	probe("192.0.2.73", 20, true)
	exec(`INSERT INTO node_line_group_smart_schedules(tenant_scope_id,line_group_id,enabled,top_n,granularity,
			latency_window_minutes,max_load_percent,fallback,revision,updated_by_user_id,updated_at)
		VALUES($1,$2,true,2,'carrier',15,85,'carrier_then_default',1,$3,$4)`, tenant.scopeID, group.Group.GroupID, tenant.userID, now)
	selector, err := smartsched.NewWorker(pool, func() time.Time { return now }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := selector.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	var samples int
	if err := pool.QueryRow(ctx, `SELECT coalesce(sum(cardinality(latencies_ms)),0) FROM node_line_latency_samples
		WHERE line_group_id=$1 AND province='广东' AND carrier='telecom' AND source='dnspup'`, group.Group.GroupID).Scan(&samples); err != nil || samples != 6 {
		t.Fatalf("samples = %d (%v)", samples, err)
	}
	if err := worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	telecom := lines.take()["电信"]
	if !slices.Equal(telecom.A, []string{"192.0.2.72", "192.0.2.73"}) || len(telecom.Weights) != 0 {
		t.Fatalf("smart telecom line = %+v", telecom)
	}
	want := cnamelines.Set{A: []string{"192.0.2.72", "192.0.2.73"}, AAAA: []string{}}.Digest(telecom.TTL, map[string]uint32{})
	if digest("telecom") != want {
		t.Fatalf("desired_digest = %s, want %s", digest("telecom"), want)
	}
	// Re-ingesting the same window (cursor) adds nothing; reselection keeps the set.
	if err := selector.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if err := worker.Tick(ctx); err != nil || len(lines.take()) != 0 {
		t.Fatalf("unchanged selection rewritten (%v)", err)
	}
	// Hysteresis: 192.0.2.71 becomes 12 ms at p50 (slowest kept is 20): 40% faster -> replaces .73.
	for range 4 {
		probe2 := now.Add(-30 * time.Second)
		checkpoints, _ := json.Marshal([]map[string]any{{"id": "cp3", "group": "telecom", "carrier": "telecom",
			"province": "广东", "ok": true, "latency_ms": 5}})
		exec(`INSERT INTO node_dnspup_probe_results(node_id,address,port,observed_at,total_checks,failed_checks,failed,checkpoints)
			VALUES($1,'192.0.2.71',80,$2,1,0,false,$3) ON CONFLICT DO NOTHING`, nodes["192.0.2.71"], probe2, checkpoints)
		now = now.Add(time.Second)
	}
	if err := selector.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	var selected []byte
	if err := pool.QueryRow(ctx, `SELECT selected FROM node_line_smart_selections WHERE line_group_id=$1 AND line_scope='telecom'`,
		group.Group.GroupID).Scan(&selected); err != nil {
		t.Fatal(err)
	}
	var picks []smartsched.Pick
	if err := json.Unmarshal(selected, &picks); err != nil || !slices.Equal(smartsched.Selection{Selected: picks}.Addresses(),
		[]string{"192.0.2.71", "192.0.2.72"}) {
		t.Fatalf("hysteresis selection = %s (%v)", selected, err)
	}
	// Disabling clears the selection: the line returns to the static digest.
	exec(`UPDATE node_line_group_smart_schedules SET enabled=false,revision=2 WHERE line_group_id=$1`, group.Group.GroupID)
	if err := selector.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if err := worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got := lines.take()["电信"]; !slices.Equal(got.A, static.A) || digest("telecom") != staticDigest {
		t.Fatalf("disabled line = %+v digest %s", got, digest("telecom"))
	}
}
