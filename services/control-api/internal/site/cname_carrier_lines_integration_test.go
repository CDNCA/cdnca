package site

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/cnamelines"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsproviderremotesource"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type recordedLines struct {
	mu   sync.Mutex
	got  []dnsproviderremotesource.AddressPublication
	fail bool
}

func (lines *recordedLines) PublishAddresses(_ context.Context, publication dnsproviderremotesource.AddressPublication) error {
	lines.mu.Lock()
	defer lines.mu.Unlock()
	lines.got = append(lines.got, publication)
	if lines.fail {
		return dnsproviderremotesource.ErrLineUnconfirmed
	}
	return nil
}

func (lines *recordedLines) take() map[string]dnsproviderremotesource.AddressPublication {
	lines.mu.Lock()
	defer lines.mu.Unlock()
	byLine := map[string]dnsproviderremotesource.AddressPublication{}
	for _, publication := range lines.got {
		byLine[publication.Line] = publication
	}
	lines.got = nil
	return byLine
}

// TestCNAMECarrierLinesPublishEndpointsPerLine: a settled site CNAME gets one record set per carrier line from
// the endpoints' carrier/region; unchanged sets are not rewritten, a line
// that loses its endpoints is retired, failures are retried, a line the
// aggregated edge schedules is left to it.
func TestCNAMECarrierLinesPublishEndpointsPerLine(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "cname_lines_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "lines-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "lines-platform", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Lines tenant", "lines-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")
	scheduler := nodescheduler.NewService(pool, func() time.Time { return now })
	schedulerActor := nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	endpoints := []nodescheduler.Endpoint{
		{ID: uuid.New(), Address: "192.0.2.51", Port: 80, Weight: 1, Enabled: true, Carrier: "中国电信"},
		{ID: uuid.New(), Address: "192.0.2.52", Port: 80, Weight: 1, Enabled: true, Carrier: "联通"},
		{ID: uuid.New(), Address: "2001:db8::53", Port: 80, Weight: 1, Enabled: true, Carrier: "电信"},
		{ID: uuid.New(), Address: "198.51.100.54", Port: 80, Weight: 1, Enabled: true, Region: "香港"},
		{ID: uuid.New(), Address: "203.0.113.55", Port: 80, Weight: 1, Enabled: true, Carrier: "BGP"},
	}
	group, err := scheduler.PutGroup(ctx, schedulerActor, nodescheduler.PutGroupRequest{Name: "lines",
		Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: endpoints, IdempotencyKey: "lines-group", RequestID: "lines-group"})
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
		IdempotencyKey: "lines-subscription", RequestID: "lines-subscription",
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
				WorkerID: "lines-worker", LeaseDuration: time.Minute}, now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return claim
	}
	created, err := NewService(store).Create(ctx, Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"},
		CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID, IdempotencyKey: "lines-site", RequestID: "lines-site",
			Fields: SiteFields{Domains: []string{"lines.example.co.uk"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
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
	// Not settled yet: nothing is written.
	if err := worker.Tick(ctx); err != nil || len(lines.take()) != 0 {
		t.Fatalf("unsettled allocation published lines (%v)", err)
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
	got := lines.take()
	telecom, unicom, overseas := got["电信"], got["联通"], got["境外"]
	if len(got) != 3 || !slices.Equal(telecom.A, []string{"192.0.2.51"}) || !slices.Equal(telecom.AAAA, []string{"2001:db8::53"}) ||
		!slices.Equal(unicom.A, []string{"192.0.2.52"}) || !slices.Equal(overseas.A, []string{"198.51.100.54"}) ||
		telecom.Owner != allocation.Hostname || telecom.TTL != 300 || telecom.SiteID != created.Site.ID {
		t.Fatalf("first publication = %+v", got)
	}
	// Converged: a second pass writes nothing.
	if err := worker.Tick(ctx); err != nil || len(lines.take()) != 0 {
		t.Fatalf("converged lines were rewritten (%v)", err)
	}
	var auditCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='dns.cname_line.publish'
		AND resource_id=$1 AND result='success'`, created.Site.ID.String()).Scan(&auditCount); err != nil || auditCount != 3 {
		t.Fatalf("publish audits = %d (%v)", auditCount, err)
	}

	// The unicom endpoint moves to the telecom carrier: unicom is retired
	// (empty set), telecom gains it.
	endpoints[1].Carrier = "电信"
	if _, err := scheduler.PutGroup(ctx, schedulerActor, nodescheduler.PutGroupRequest{GroupID: group.Group.GroupID,
		ExpectedRevision: group.Group.Revision, Name: "lines", Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: endpoints,
		IdempotencyKey: "lines-group-2", RequestID: "lines-group-2"}); err != nil {
		t.Fatal(err)
	}
	if err := worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	got = lines.take()
	if len(got) != 2 || !slices.Equal(got["电信"].A, []string{"192.0.2.51", "192.0.2.52"}) ||
		len(got["联通"].A)+len(got["联通"].AAAA) != 0 {
		t.Fatalf("carrier change = %+v", got)
	}
	var unicomRows int
	if err := worker.Tick(ctx); err != nil || len(lines.take()) != 0 {
		t.Fatalf("retired line rewritten (%v)", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM cname_carrier_line_records WHERE site_id=$1 AND line_scope='unicom'`,
		created.Site.ID).Scan(&unicomRows); err != nil || unicomRows != 0 {
		t.Fatalf("retired line still tracked: %d (%v)", unicomRows, err)
	}

	// The aggregated edge takes the overseas line: our tracking is dropped
	// and the line is never written again.
	var platformScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScope); err != nil {
		t.Fatal(err)
	}
	supplyID := uuid.New()
	exec(`INSERT INTO site_supplies(id,platform_scope_id,kind,name,target,status,created_at,updated_at)
		VALUES($1,$2,'third_party_cdn','cf','edge.cdn.example.net','active',now(),now())`, supplyID, platformScope)
	exec(`INSERT INTO aggregated_edge_line_targets(site_id,line_scope,kind,supply_id,target,since,next_publish_at,updated_at)
		VALUES($1,'overseas','third_party_cdn',$2,'edge.cdn.example.net',now(),now(),now())`, created.Site.ID, supplyID)
	endpoints[3].Address = "198.51.100.64"
	if _, err := scheduler.PutGroup(ctx, schedulerActor, nodescheduler.PutGroupRequest{GroupID: group.Group.GroupID,
		ExpectedRevision: group.Group.Revision + 1, Name: "lines", Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: endpoints,
		IdempotencyKey: "lines-group-3", RequestID: "lines-group-3"}); err != nil {
		t.Fatal(err)
	}
	// A provider failure is recorded and retried after the back-off.
	lines.fail = true
	if err := worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got = lines.take(); len(got) != 0 {
		t.Fatalf("aggregated edge line written: %+v", got)
	}
	var overseasRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM cname_carrier_line_records WHERE site_id=$1 AND line_scope='overseas'`,
		created.Site.ID).Scan(&overseasRows); err != nil || overseasRows != 0 {
		t.Fatalf("aggregated edge line still tracked: %d (%v)", overseasRows, err)
	}
	endpoints[0].Address = "192.0.2.61"
	if _, err := scheduler.PutGroup(ctx, schedulerActor, nodescheduler.PutGroupRequest{GroupID: group.Group.GroupID,
		ExpectedRevision: group.Group.Revision + 2, Name: "lines", Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: endpoints,
		IdempotencyKey: "lines-group-4", RequestID: "lines-group-4"}); err != nil {
		t.Fatal(err)
	}
	if err := worker.Tick(ctx); err != nil || len(lines.take()) != 1 {
		t.Fatalf("telecom change not attempted (%v)", err)
	}
	var code string
	if err := pool.QueryRow(ctx, `SELECT publish_error FROM cname_carrier_line_records WHERE site_id=$1 AND line_scope='telecom'`,
		created.Site.ID).Scan(&code); err != nil || code != cnamelines.ErrUnconfirmed {
		t.Fatalf("failure code = %q (%v)", code, err)
	}
	lines.fail = false
	if err := worker.Tick(ctx); err != nil || len(lines.take()) != 0 {
		t.Fatalf("retried before the back-off (%v)", err)
	}
	// Due by the worker's clock (fixed at now), not the database's: the test
	// has run for seconds past now, so now()-1s could still be after it.
	exec(`UPDATE cname_carrier_line_records SET next_attempt_at=$2 WHERE site_id=$1`, created.Site.ID, now.Add(-time.Second))
	if err := worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got = lines.take(); len(got) != 1 || !slices.Equal(got["电信"].A, []string{"192.0.2.52", "192.0.2.61"}) {
		t.Fatalf("retry = %+v", got)
	}

	// NET-02（fp-net2，迁移 500；待出包前全量跑）：同一 IP+端口分别挂到电信/联通/移动线路，
	// 保存通过（去重键含运营商），每条运营商线路各写一份，不被合并；同一运营商下重复仍拒绝。
	shared := func(carrier string) nodescheduler.Endpoint {
		return nodescheduler.Endpoint{ID: uuid.New(), Address: "192.0.2.61", Port: 80, Weight: 1, Enabled: true, Carrier: carrier}
	}
	// endpoints[0]（192.0.2.61）的运营商原值是"中国电信"；去重键按运营商原值（迁移 500），同一写法才是重复
	duplicate := append(slices.Clone(endpoints), shared(endpoints[0].Carrier))
	if _, err := scheduler.PutGroup(ctx, schedulerActor, nodescheduler.PutGroupRequest{GroupID: group.Group.GroupID,
		ExpectedRevision: group.Group.Revision + 3, Name: "lines", Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: duplicate,
		IdempotencyKey: "lines-group-dup", RequestID: "lines-group-dup"}); !errors.Is(err, nodescheduler.ErrInvalidInput) {
		t.Fatalf("same-carrier duplicate error = %v", err)
	}
	endpoints = append(endpoints, shared("联通"), shared("移动"))
	if _, err := scheduler.PutGroup(ctx, schedulerActor, nodescheduler.PutGroupRequest{GroupID: group.Group.GroupID,
		ExpectedRevision: group.Group.Revision + 3, Name: "lines", Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: endpoints,
		IdempotencyKey: "lines-group-5", RequestID: "lines-group-5"}); err != nil {
		t.Fatalf("one IP on several carrier lines: %v", err)
	}
	if err := worker.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	got = lines.take()
	// 电信线路集合不变（192.0.2.52/61 已发布）不重写；联通、移动各写入同一 IP。
	if _, rewritten := got["电信"]; rewritten || len(got) != 2 || !slices.Equal(got["联通"].A, []string{"192.0.2.61"}) ||
		!slices.Equal(got["移动"].A, []string{"192.0.2.61"}) {
		t.Fatalf("shared address per carrier line = %+v", got)
	}
}
