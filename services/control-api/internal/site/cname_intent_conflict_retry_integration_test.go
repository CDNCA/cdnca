package site

import (
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/dnscheck"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsreconcile"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fix-cnamewait (73, 10-26): the second site of a package sharing one CNAME
// ran its dns.cname.intent while the first site's allocation was still
// pending. Allocate returned ErrConflict, the worker only ended the round and
// the intent kept its 16-minute lease, so the site showed "生成中" until the
// lease expired. With the production lease the intent must be claimable again
// within 30 s and succeed once the first allocation settled.
func TestCNAMEIntentConflictRetriesWithinSeconds(t *testing.T) {
	pool := trustMigratedPool(t)
	ctx := t.Context()
	clock := time.Now().UTC().Truncate(time.Second)
	now := func() time.Time { return clock }
	manager := addonSiteInsertPlatformActor(t, pool, "cnamewait-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "cnamewait-platform", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "CNAME wait tenant", "cnamewait-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")
	group, err := nodescheduler.NewService(pool, now).PutGroup(ctx,
		nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}, nodescheduler.PutGroupRequest{
			Name: "cnamewait", Policy: nodescheduler.DefaultHealthPolicy(),
			Endpoints:      []nodescheduler.Endpoint{{ID: uuid.New(), Address: "192.0.2.61", Port: 80, Weight: 1, Enabled: true}},
			IdempotencyKey: "cnamewait-group", RequestID: "cnamewait-group",
		})
	if err != nil {
		t.Fatal(err)
	}
	providerID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'cnamewait','cloudflare','fixture-key',$3,$4,$4)`, providerID, tenant.scopeID, make([]byte, 32), tenant.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO dns_zones(id,scope_id,provider_id,name,is_default,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'cdn.example.com',true,$4,$4)`, uuid.New(), tenant.scopeID, providerID, tenant.userID); err != nil {
		t.Fatal(err)
	}
	// 按套餐生成: every site of the subscription shares one allocation.
	productID := addonSiteInsertPackageProductVersionCNAMEMode(t, pool, manager, 1, 100, 1000, "shared", "cdn.example.com", "")
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	opened, err := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, now)).Open(ctx, manager,
		packagesubscription.OpenRequest{
			TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: productID, ProductRevision: 1,
			SiteLimit: 100, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
			CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
			IdempotencyKey: "cnamewait-subscription", RequestID: "cnamewait-subscription",
		})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds,
		actor_scope_id,actor_user_id,reason,created_at)
		SELECT $1,COALESCE(max(revision),0)+1,'automatic',$2,30000,15000,2,3,600,$1,$3,'integration_policy',clock_timestamp()
		FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1`,
		tenant.scopeID, []uuid.UUID{uuid.New()}, tenant.userID); err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithClock(pool, now, nil)
	store.guard = installAddonSiteEntitlement(t, pool, clock, time.Hour)
	service := NewService(store)
	owner := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	create := func(key string) WriteResult {
		t.Helper()
		result, err := service.Create(ctx, owner, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
			Fields: SiteFields{Domains: []string{key + ".example.co.uk"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
				Enabled: false, Status: StatusDisabled, NodeGroupID: &group.Group.GroupID, NodeGroupName: group.Group.Name,
				PackageID: &productID, PackageName: "Business", PackageSubscriptionID: &opened.Subscription.ID},
			IdempotencyKey: key, RequestID: key})
		if err != nil || result.Site.CNAMETaskID == nil {
			t.Fatalf("create %s: task=%v err=%v", key, result.Site.CNAMETaskID, err)
		}
		return result
	}
	var tenantID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1`, tenant.scopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	cname, err := cnameallocation.NewStore(pool, platformCNAMEKeyring{}, now)
	if err != nil {
		t.Fatal(err)
	}
	start := func(jobID uuid.UUID, kind string) jobstate.Claim {
		t.Helper()
		var claim jobstate.Claim
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var err error
			claim, err = jobstate.StartTx(ctx, tx, jobstate.StartInput{TenantID: tenantID, JobID: jobID, Kind: kind,
				WorkerID: "cnamewait-fixture", LeaseDuration: time.Minute}, clock)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return claim
	}

	// The first site's allocation is pending (its child DNS task in flight).
	first := create("cnamewait-first")
	if err := cname.PrepareIntent(ctx, start(*first.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
		t.Fatal(err)
	}
	allocation, err := cname.Get(ctx, tenant.scopeID, first.Site.ID)
	if err != nil || allocation.State != cnameallocation.StatePending {
		t.Fatalf("first allocation state=%s err=%v, want pending", allocation.State, err)
	}

	// Two more sites of the same user follow while it is pending; their
	// intents run on the production-wired worker (16 min lease).
	waiting := []WriteResult{create("cnamewait-second"), create("cnamewait-third")}
	jobs, err := jobstate.NewStore(pool, now)
	if err != nil {
		t.Fatal(err)
	}
	committed := dnsreconcile.Task{ID: uuid.New(), TenantID: tenantID, Revision: 1}
	committed.Result.Status = dnscheck.TaskCommitted
	worker, err := cnameallocation.NewWorker(cnameallocation.WorkerConfig{WorkerID: "control-api-cname-allocation",
		LeaseDuration: 16 * time.Minute, Now: now}, cnameallocation.WorkerDependencies{
		Intents: cname, Claims: jobs, Targets: cname, Reconcile: &scriptedReconcile{tasks: []dnsreconcile.Task{committed}}})
	if err != nil {
		t.Fatal(err)
	}
	for range waiting {
		if didWork, err := worker.RunOnce(ctx, tenantID); !didWork || !errors.Is(err, cnameallocation.ErrConflict) {
			t.Fatalf("waiting intent first run = (%v,%v), want work with ErrConflict", didWork, err)
		}
	}
	for _, site := range waiting {
		var state string
		var claimable *time.Time
		if err := pool.QueryRow(ctx, `SELECT state,claimable_at FROM background_jobs WHERE id=$1`, *site.Site.CNAMETaskID).
			Scan(&state, &claimable); err != nil {
			t.Fatal(err)
		}
		if claimable == nil || claimable.Sub(clock) > 30*time.Second {
			t.Fatalf("conflicted intent state=%s claimable_at=%v, want claimable within 30s of %s (lease kept 16 min)",
				state, claimable, clock)
		}
	}

	// The first allocation settles; 30 s later both intents are reclaimed and bind.
	claim := start(allocation.JobID, "dns.cname.allocation")
	if _, err := cname.Complete(ctx, cnameallocation.ResultRequest{TargetScopeID: tenant.scopeID, SiteID: first.Site.ID,
		AllocationID: allocation.ID, JobID: allocation.JobID, ExpectedRevision: allocation.Revision, WorkerID: claim.WorkerID,
		Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, Sequence: 1}); err != nil {
		t.Fatalf("complete first allocation: %v", err)
	}
	clock = clock.Add(30 * time.Second)
	for range waiting {
		if didWork, err := worker.RunOnce(ctx, tenantID); !didWork || err != nil {
			t.Fatalf("waiting intent retry = (%v,%v), want reclaimed within 30s", didWork, err)
		}
	}
	for _, site := range waiting {
		var state, cnameState, hostname string
		var attempt int
		if err := pool.QueryRow(ctx, `SELECT job.state,job.attempt,site.cname_state,site.cname
			FROM background_jobs job, sites site WHERE job.id=$1 AND site.id=$2`, *site.Site.CNAMETaskID, site.Site.ID).
			Scan(&state, &attempt, &cnameState, &hostname); err != nil {
			t.Fatal(err)
		}
		if state != "succeeded" || attempt != 2 || cnameState != "done" || hostname != allocation.Hostname {
			t.Fatalf("site %s intent state=%s attempt=%d cname_state=%s cname=%q, want succeeded/2/done/%q",
				site.Site.ID, state, attempt, cnameState, hostname, allocation.Hostname)
		}
	}
}
