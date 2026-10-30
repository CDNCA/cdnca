package site

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/l4lineswitch"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FX27: switching an L4 site's line must keep the old node listening until
// its CNAME stopped resolving there and resolver caches had 2×TTL to expire.
func TestL4LineSwitchDNSGateFollowsCNAMERetarget(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "l4_dns_gate_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "gate-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "gate-platform", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Gate tenant", "gate-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")
	oldNode, keptNode := uuid.New(), uuid.New()
	for index, id := range []uuid.UUID{oldNode, keptNode} {
		// A node-bound endpoint must use the node's own IP: .31, .32.
		exec(`INSERT INTO nodes(id,scope_id,name,admin_state,created_by_user_id,display_id,ipv4) VALUES($1,$2,$3,'active',$4,$5,$6)`,
			id, tenant.scopeID, id.String(), tenant.userID, index+1, "192.0.2.3"+string(rune('1'+index)))
	}
	scheduler := nodescheduler.NewService(pool, func() time.Time { return now })
	schedulerActor := nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	keptEndpoint := nodescheduler.Endpoint{ID: uuid.New(), NodeID: keptNode, Address: "192.0.2.32", Port: 80, Weight: 1, Enabled: true}
	group, err := scheduler.PutGroup(ctx, schedulerActor, nodescheduler.PutGroupRequest{
		Name: "gate", Policy: nodescheduler.DefaultHealthPolicy(),
		Endpoints: []nodescheduler.Endpoint{
			{ID: uuid.New(), NodeID: oldNode, Address: "192.0.2.31", Port: 80, Weight: 1, Enabled: true}, keptEndpoint,
		},
		IdempotencyKey: "gate-line-group", RequestID: "gate-line-group",
	})
	if err != nil {
		t.Fatal(err)
	}
	providerID := uuid.New()
	exec(`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'gate','cloudflare','fixture-key',$3,$4,$4)`, providerID, tenant.scopeID, make([]byte, 32), tenant.userID)
	exec(`INSERT INTO dns_zones(id,scope_id,provider_id,name,is_default,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'cdn.example.com',true,$4,$4)`, uuid.New(), tenant.scopeID, providerID, tenant.userID)
	// A stream belongs to no website (migration 506): its CNAME is its
	// package's shared allocation (按套餐生成).
	productID := addonSiteInsertPackageProductVersionCNAMEMode(t, pool, manager, 1, 100, 1000, "shared", "cdn.example.com", "")
	subscriptions := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, func() time.Time { return now }))
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	opened, err := subscriptions.Open(ctx, manager, packagesubscription.OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: productID, ProductRevision: 1,
		SiteLimit: 100, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "gate-subscription", RequestID: "gate-subscription",
	})
	if err != nil {
		t.Fatal(err)
	}
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
				WorkerID: "gate-worker", LeaseDuration: time.Minute}, now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return claim
	}
	created, err := NewService(store).Create(ctx, Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"},
		CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID, IdempotencyKey: "gate-site", RequestID: "gate-site",
			Fields: SiteFields{Domains: []string{"gate.example.co.uk"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
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
	gate := func(wantState string, wantOwners, wantPending int) l4lineswitch.DNSGateStatus {
		t.Helper()
		var status l4lineswitch.DNSGateStatus
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var err error
			status, err = l4lineswitch.ReadDNSGate(ctx, tx, tenant.scopeID, []uuid.UUID{oldNode})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if status.State != wantState || status.Owners != wantOwners || status.PendingOwners != wantPending {
			t.Fatalf("DNS gate = %+v, want %s owners=%d pending=%d", status, wantState, wantOwners, wantPending)
		}
		return status
	}

	// Only CNAMEs carrying L4 forwards are owners: a package without a stream does not hold the switch.
	gate(l4lineswitch.DNSGateReady, 0, 0)
	exec(`INSERT INTO l4_forwards(id,scope_id,owner_user_id,name,protocol,listen_port,upstream_address,upstream_port,
			connect_timeout_ms,response_timeout_ms,created_by_user_id,updated_by_user_id,package_subscription_id,
			max_connections_per_client)
		VALUES($1,$2,$3,'gate-stream','tcp',9443,'192.0.2.1',443,1000,30000,$3,$3,$4,100)`,
		uuid.New(), tenant.scopeID, tenant.userID, opened.Subscription.ID)
	// The frozen CNAME still resolves to the node the switch retires.
	gate(l4lineswitch.DNSGateRetargetPending, 1, 1)

	// The line drops the old node: the retarget is planned but not committed yet.
	if _, err := scheduler.PutGroup(ctx, schedulerActor, nodescheduler.PutGroupRequest{
		GroupID: group.Group.GroupID, ExpectedRevision: group.Group.Revision, Name: "gate",
		Policy: nodescheduler.DefaultHealthPolicy(), Endpoints: []nodescheduler.Endpoint{keptEndpoint},
		IdempotencyKey: "gate-line-group-2", RequestID: "gate-line-group-2",
	}); err != nil {
		t.Fatal(err)
	}
	if count, err := cname.PlanRetargets(ctx); err != nil || count != 1 {
		t.Fatalf("PlanRetargets = %d %v", count, err)
	}
	open, err := cname.OpenRetargets(ctx)
	if err != nil || len(open) != 1 {
		t.Fatalf("open retargets = %+v %v", open, err)
	}
	gate(l4lineswitch.DNSGateRetargetPending, 1, 1)

	// Committed: DNS no longer names the old node, but caches may for 2×TTL.
	if err := cname.AttachRetarget(ctx, open[0], dnsreconcile.Task{ID: uuid.New(), Revision: 1}); err != nil {
		t.Fatal(err)
	}
	if err := cname.SettleRetarget(ctx, open[0], "committed", ""); err != nil {
		t.Fatal(err)
	}
	waiting := gate(l4lineswitch.DNSGatePropagationWait, 1, 0)
	if waiting.ReadyAt == nil || waiting.ReadyAt.Before(time.Now().Add(4*time.Minute)) {
		t.Fatalf("propagation window must be at least five minutes: %+v", waiting.ReadyAt)
	}

	// Once the window has passed the old listeners may be drained. The
	// durable-fact trigger forbids editing the retarget, so backdate it with
	// user triggers off in this test only.
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE dns_cname_retargets SET created_at=created_at-interval '1 hour',
			updated_at=updated_at-interval '1 hour' WHERE allocation_id=$1`, allocation.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	gate(l4lineswitch.DNSGateReady, 1, 0)
}
