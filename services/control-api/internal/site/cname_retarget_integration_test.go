package site

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/domaintrust"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Serving holds (migration 280) decide which line endpoints a CNAME resolves
// to, both when the target is first frozen and when it is later republished.
func TestCNAMETargetsFollowServingHolds(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "cname_retarget_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "retarget-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "retarget-platform", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Retarget tenant", "retarget-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")
	nodeA, nodeB := uuid.New(), uuid.New()
	for index, id := range []uuid.UUID{nodeA, nodeB} {
		// A node-bound endpoint must use the node's own IP: .21, .22.
		exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4) VALUES($1,$2,$3,'active',$4,$5,$6)`,
			id, tenant.scopeID, id.String(), tenant.userID, index+1, "192.0.2.2"+string(rune('1'+index)))
	}
	group, err := nodescheduler.NewService(pool, func() time.Time { return now }).PutGroup(ctx,
		nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}, nodescheduler.PutGroupRequest{
			Name: "retarget", Policy: nodescheduler.DefaultHealthPolicy(),
			Endpoints: []nodescheduler.Endpoint{
				{ID: uuid.New(), NodeID: nodeA, Address: "192.0.2.21", Port: 80, Weight: 1, Enabled: true},
				{ID: uuid.New(), NodeID: nodeB, Address: "192.0.2.22", Port: 80, Weight: 1, Enabled: true},
			},
			IdempotencyKey: "retarget-line-group", RequestID: "retarget-line-group",
		})
	if err != nil {
		t.Fatal(err)
	}
	providerID := uuid.New()
	exec(`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'retarget','cloudflare','fixture-key',$3,$4,$4)`, providerID, tenant.scopeID, make([]byte, 32), tenant.userID)
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
		IdempotencyKey: "retarget-subscription", RequestID: "retarget-subscription",
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
	holdRevision := map[uuid.UUID]int64{}
	setHold := func(nodeID uuid.UUID, held bool) {
		t.Helper()
		holdRevision[nodeID]++
		var since any
		if held {
			since = now
		}
		if holdRevision[nodeID] == 1 {
			exec(`INSERT INTO node_serving_holds(node_id,source,held,reason_code,revision,held_since,changed_at,updated_at)
				VALUES($1,'availability_monitor',$2,'probe_unhealthy',1,$3,clock_timestamp(),clock_timestamp())`, nodeID, held, since)
			return
		}
		exec(`UPDATE node_serving_holds SET held=$2,revision=$3,held_since=$4,changed_at=clock_timestamp(),updated_at=clock_timestamp()
			WHERE node_id=$1 AND source='availability_monitor'`, nodeID, held, holdRevision[nodeID], since)
	}
	start := func(jobID uuid.UUID, kind string) jobstate.Claim {
		t.Helper()
		var claim jobstate.Claim
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var err error
			claim, err = jobstate.StartTx(ctx, tx, jobstate.StartInput{TenantID: tenantID, JobID: jobID, Kind: kind,
				WorkerID: "retarget-worker", LeaseDuration: time.Minute}, now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return claim
	}

	// G6 #11: a CNAME under a blocklisted zone is refused with the site write.
	blockID := uuid.New()
	exec(`INSERT INTO platform_domain_blocklist(id,pattern,match_type,reason,created_by_user_id,updated_by_user_id,created_at,updated_at)
		VALUES($1,'example.com','root','',$2,$2,now(),now())`, blockID, manager.UserID)
	if _, err := NewService(store).Create(ctx, Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"},
		CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID, IdempotencyKey: "retarget-blocked", RequestID: "retarget-blocked",
			Fields: SiteFields{Domains: []string{"retarget.example.co.uk"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
				Enabled: false, Status: StatusDisabled,
				NodeGroupID: &group.Group.GroupID, NodeGroupName: group.Group.Name,
				PackageID: &productID, PackageName: "Business", PackageSubscriptionID: &opened.Subscription.ID}}); !errors.Is(err, domaintrust.ErrDomainBlocked) {
		t.Fatalf("site with blocked CNAME zone = %v", err)
	}
	exec(`DELETE FROM platform_domain_blocklist WHERE id=$1`, blockID)

	// A is monitor-paused before the site exists: its frozen target omits A.
	setHold(nodeA, true)
	created, err := NewService(store).Create(ctx, Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"},
		CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID, IdempotencyKey: "retarget-site", RequestID: "retarget-site",
			Fields: SiteFields{Domains: []string{"retarget.example.co.uk"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
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
	var frozen []string
	if err := pool.QueryRow(ctx, `SELECT target_a FROM cname_allocation_targets WHERE job_id=$1`, allocation.JobID).Scan(&frozen); err != nil ||
		!slices.Equal(frozen, []string{"192.0.2.22"}) {
		t.Fatalf("frozen target = %v %v; paused node A must not be published", frozen, err)
	}
	claim := start(allocation.JobID, "dns.cname.allocation")
	if _, err := cname.Complete(ctx, cnameallocation.ResultRequest{TargetScopeID: tenant.scopeID, SiteID: created.Site.ID,
		AllocationID: allocation.ID, JobID: allocation.JobID, ExpectedRevision: allocation.Revision, WorkerID: claim.WorkerID,
		Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, Sequence: 1}); err != nil {
		t.Fatal(err)
	}

	plan := func(want int, values []string) cnameallocation.Retarget {
		t.Helper()
		count, err := cname.PlanRetargets(ctx)
		if err != nil || count != want {
			t.Fatalf("PlanRetargets = %d %v, want %d", count, err, want)
		}
		open, err := cname.OpenRetargets(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if values == nil {
			if len(open) != 0 {
				t.Fatalf("unexpected open retargets %+v", open)
			}
			return cnameallocation.Retarget{}
		}
		if len(open) != 1 || !slices.Equal(open[0].Values.A, values) || open[0].OwnerName != allocation.Hostname ||
			open[0].SiteID != created.Site.ID || open[0].ActorUserID != tenant.userID {
			t.Fatalf("open retargets = %+v, want A=%v", open, values)
		}
		return open[0]
	}
	commit := func(retarget cnameallocation.Retarget) {
		t.Helper()
		if err := cname.AttachRetarget(ctx, retarget, dnsreconcile.Task{ID: uuid.New(), Revision: 1}); err != nil {
			t.Fatal(err)
		}
		if err := cname.SettleRetarget(ctx, retarget, "committed", ""); err != nil {
			t.Fatal(err)
		}
	}
	plan(0, nil) // published values already match the serving set

	setHold(nodeA, false) // A recovered: DNS must add it back
	restored := plan(1, []string{"192.0.2.21", "192.0.2.22"})
	plan(0, restored.Values.A) // in flight: not planned twice
	commit(restored)
	plan(0, nil)

	setHold(nodeB, true) // B paused: DNS drops B only
	paused := plan(1, []string{"192.0.2.21"})
	commit(paused)

	// Both paused: the last IPv4 endpoints keep serving (fail-open).
	setHold(nodeA, true)
	protected := plan(1, []string{"192.0.2.21", "192.0.2.22"})
	if err := cname.SettleRetarget(ctx, protected, "failed", "dns_reconcile_failed"); err != nil {
		t.Fatal(err)
	}
	plan(0, nil) // a failed retarget is retried only after the back-off
	var states []string
	rows, err := pool.Query(ctx, `SELECT state FROM dns_cname_retargets WHERE allocation_id=$1 ORDER BY sequence`, allocation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if states, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || !slices.Equal(states, []string{"committed", "committed", "failed"}) {
		t.Fatalf("retarget states = %v %v", states, err)
	}

	// Bound to a node market supply, the hostname becomes a CNAME to the
	// supply name; unbound, it returns to the line group's addresses.
	// Skip the failed retarget's back-off: the durable-fact trigger forbids
	// editing it, so backdate it with user triggers off in this test only.
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE dns_cname_retargets SET created_at=created_at-interval '1 hour', updated_at=updated_at-interval '1 hour'
			WHERE allocation_id=$1 AND state='failed'`, allocation.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	setHold(nodeA, false)
	setHold(nodeB, false)
	var platformScope uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform'`).Scan(&platformScope); err != nil {
		t.Fatal(err)
	}
	supplyID := uuid.New()
	exec(`INSERT INTO site_supplies(id,platform_scope_id,kind,name,market_subscription_id,target,status,created_at,updated_at)
		VALUES($1,$2,'market_subscription','market',$3,'G7K2abcdefgh.supply.example.','active',now(),now())`, supplyID, platformScope, uuid.New())
	exec(`INSERT INTO site_supply_bindings(site_id,supply_id,role,priority,created_at) VALUES($1,$2,'primary',1,now())`, created.Site.ID, supplyID)
	if count, err := cname.PlanRetargets(ctx); err != nil || count != 1 {
		t.Fatalf("market PlanRetargets = %d %v", count, err)
	}
	open, err := cname.OpenRetargets(ctx)
	if err != nil || len(open) != 1 || open[0].Values.CNAME != "g7k2abcdefgh.supply.example" || len(open[0].Values.A) != 0 {
		t.Fatalf("market retarget = %+v %v", open, err)
	}
	check := cnameallocation.PublishCheckRequest(open[0].TenantID, open[0].SiteID, open[0].ZoneID, open[0].ZoneRevision,
		open[0].OwnerName, open[0].Values, open[0].Publish)
	if len(check.Expected) != 1 || check.Expected[0].Type.String() != "CNAME" {
		t.Fatalf("market check must expect exactly one CNAME: %+v", check.Expected)
	}
	commit(open[0])
	plan(0, nil) // CNAME already published
	exec(`DELETE FROM site_supply_bindings WHERE site_id=$1`, created.Site.ID)
	back := plan(1, []string{"192.0.2.21", "192.0.2.22"})
	if back.Values.CNAME != "" {
		t.Fatalf("unbound site must leave CNAME mode: %+v", back.Values)
	}
	commit(back)

	// ACME HTTP-01 serving gate (migration 342): while the site has an open
	// epoch whose only required member is B, DNS publishes B only; once the
	// epoch closes A returns.
	epochID := uuid.New()
	gate := func(statement string, args ...any) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, statement, args...)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	gate(`INSERT INTO acme_http01_site_overlay_states(tenant_scope_id,site_id,current_version,epoch_count,created_at,updated_at)
		VALUES($1,$2,0,1,now(),now())`, tenant.scopeID, created.Site.ID)
	gate(`INSERT INTO acme_http01_site_overlay_epochs(id,tenant_scope_id,site_id,sequence,member_count,member_set_sha256,opened_at)
		VALUES($1,$2,$3,1,1,acme_http01_node_set_digest(ARRAY[$4::uuid]),now())`, epochID, tenant.scopeID, created.Site.ID, nodeB)
	gate(`INSERT INTO acme_http01_site_overlay_epoch_members(epoch_id,node_id) VALUES($1,$2)`, epochID, nodeB)
	gate(`UPDATE acme_http01_site_overlay_states SET open_epoch_id=$3 WHERE tenant_scope_id=$1 AND site_id=$2`,
		tenant.scopeID, created.Site.ID, epochID)
	gated := plan(1, []string{"192.0.2.22"})
	commit(gated)
	gate(`UPDATE acme_http01_site_overlay_states SET open_epoch_id=NULL WHERE tenant_scope_id=$1 AND site_id=$2`,
		tenant.scopeID, created.Site.ID)
	gate(`UPDATE acme_http01_site_overlay_epochs SET closed_at=now() WHERE id=$1`, epochID)
	commit(plan(1, []string{"192.0.2.21", "192.0.2.22"}))

	// Attack escalation (migration 460): the site's line override points the
	// CNAME at a platform high defense group (the retarget references the
	// platform's line group revision), level D at the blackhole with TTL 60,
	// and removing the override returns it to its own group.
	highNode, highScope, highGroup := uuid.New(), manager.ScopeID, uuid.New()
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, statement := range []struct {
			query string
			args  []any
		}{
			{`SET LOCAL session_replication_role = replica`, nil},
			{`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4) VALUES($1,$2,'high','active',$3,3,'192.0.2.31')`,
				[]any{highNode, highScope, manager.UserID}},
			{`INSERT INTO node_line_groups(id,tenant_scope_id,name,current_revision,created_by_user_id,updated_by_user_id,created_at,
				updated_at,display_id,resolved_value,ipv4_resolved_value) VALUES($1,$2,'high-defense',1,$3,$3,now(),now(),
				(SELECT COALESCE(max(display_id),0)+1 FROM node_line_groups),'lg-'||replace($1::uuid::text,'-',''),'v4-'||replace($1::uuid::text,'-',''))`,
				[]any{highGroup, highScope, manager.UserID}},
			{`INSERT INTO node_line_group_revisions(line_group_id,tenant_scope_id,revision,name,resolved_value,ipv4_resolved_value,probe_interval_ms,
				probe_timeout_ms,failure_threshold,recovery_threshold,failure_debounce_ms,recovery_debounce_ms,endpoint_count,configuration_digest,
				created_by_user_id,created_at,sealed_at) VALUES($1,$2,1,'high-defense','lg-'||replace($1::uuid::text,'-',''),
				'v4-'||replace($1::uuid::text,'-',''),10000,3000,3,3,0,0,1,$3,$4,now(),now())`,
				[]any{highGroup, highScope, make([]byte, 32), manager.UserID}},
			{`INSERT INTO node_line_endpoints(id,node_id,tenant_scope_id,line_group_id,config_revision,address,address_family,
				port,region,carrier,priority,weight,enabled) VALUES($1,$2,$3,$4,1,'192.0.2.31',4,80,'hk','bgp',0,1,true)`,
				[]any{uuid.New(), highNode, highScope, highGroup}},
		} {
			if _, err := tx.Exec(ctx, statement.query, statement.args...); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO escalate_site_routes(tenant_scope_id,site_id,line_owner_scope_id,line_group_id,dns_target,dns_changed_at,updated_at)
		VALUES($1,$2,$3,$4,'line_group',now(),now())`, tenant.scopeID, created.Site.ID, highScope, highGroup)
	escalated := plan(1, []string{"192.0.2.31"})
	if escalated.NodeGroupID != highGroup || escalated.Publish.TTL != 300 {
		t.Fatalf("escalated retarget = %+v", escalated)
	}
	commit(escalated)
	plan(0, nil)
	exec(`UPDATE escalate_site_routes SET dns_target='blackhole',blackhole_since=now() WHERE site_id=$1`, created.Site.ID)
	blackhole := plan(1, []string{cnameallocation.BlackholeAddress})
	check = cnameallocation.PublishCheckRequest(blackhole.TenantID, blackhole.SiteID, blackhole.ZoneID, blackhole.ZoneRevision,
		blackhole.OwnerName, blackhole.Values, blackhole.Publish)
	if blackhole.Publish.TTL != cnameallocation.BlackholeTTL || check.TTL != cnameallocation.BlackholeTTL {
		t.Fatalf("blackhole TTL = %d / %d", blackhole.Publish.TTL, check.TTL)
	}
	commit(blackhole)
	plan(0, nil)
	exec(`DELETE FROM escalate_site_routes WHERE site_id=$1`, created.Site.ID)
	if back := plan(1, []string{"192.0.2.21", "192.0.2.22"}); back.NodeGroupID != group.Group.GroupID || back.Publish.TTL != 300 {
		t.Fatalf("returned retarget = %+v", back)
	}
}
