package site

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 73 cdnca-t1 stayed cname_state=pending after its
// dns.cname.allocation job was ended retries_exhausted (20/20) by jobstate.
// The terminal hook fails the allocation and the site in that transaction,
// the site can be regenerated, and the sweep repairs sites that ended before
// the hook (once; a second sweep changes nothing).
func TestCNAMEJobEndedFailsSite(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "cname_ended_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "ended-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "ended-platform", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Ended tenant", "ended-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")
	owner := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	group, err := nodescheduler.NewService(pool, func() time.Time { return now }).PutGroup(ctx,
		nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}, nodescheduler.PutGroupRequest{
			Name: "ended", Policy: nodescheduler.DefaultHealthPolicy(),
			Endpoints:      []nodescheduler.Endpoint{{ID: uuid.New(), Address: "192.0.2.40", Port: 80, Weight: 1, Enabled: true}},
			IdempotencyKey: "ended-line-group", RequestID: "ended-line-group",
		})
	if err != nil {
		t.Fatal(err)
	}
	providerID := uuid.New()
	exec(`INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'ended','cloudflare','fixture-key',$3,$4,$4)`, providerID, tenant.scopeID, make([]byte, 32), tenant.userID)
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
		IdempotencyKey: "ended-subscription", RequestID: "ended-subscription",
	})
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO edge_automatic_publication_policy_facts(target_scope_id,revision,mode,node_ids,activation_timeout_ms,
		observation_window_ms,required_consecutive_successes,max_attempts,deadline_window_seconds,actor_scope_id,actor_user_id,reason,created_at)
		SELECT $1,COALESCE(max(revision),0)+1,'automatic',$2,30000,15000,2,3,600,$1,$3,'integration_policy',clock_timestamp()
		FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1`,
		tenant.scopeID, []uuid.UUID{uuid.New()}, tenant.userID)
	// One clock for the site writes, CNAME settlements and claims (exhaust
	// advances it past every lease); 113 refuses an allocation update older
	// than the terminal settlement.
	jobClock := now
	store := NewStoreWithClock(pool, func() time.Time { return jobClock }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, 24*time.Hour)
	service := NewService(store)
	cname, err := cnameallocation.NewStore(pool, platformCNAMEKeyring{}, func() time.Time { return jobClock })
	if err != nil {
		t.Fatal(err)
	}
	var tenantID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1`, tenant.scopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	jobs, err := jobstate.NewStore(pool, func() time.Time { return jobClock })
	if err != nil {
		t.Fatal(err)
	}
	start := func(jobID uuid.UUID, kind string) jobstate.Claim {
		t.Helper()
		var claim jobstate.Claim
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var err error
			claim, err = jobstate.StartTx(ctx, tx, jobstate.StartInput{TenantID: tenantID, JobID: jobID, Kind: kind,
				WorkerID: "ended-worker", LeaseDuration: time.Minute}, jobClock)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return claim
	}
	fields := func(domain string) SiteFields {
		return SiteFields{Domains: []string{domain}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
			Enabled: false, Status: StatusDisabled,
			NodeGroupID: &group.Group.GroupID, NodeGroupName: group.Group.Name,
			PackageID: &productID, PackageName: "Business", PackageSubscriptionID: &opened.Subscription.ID}
	}
	// allocated creates a site and runs its intent: the site now points at a
	// pending dns.cname.allocation job.
	allocated := func(name string) (WriteResult, cnameallocation.Allocation) {
		t.Helper()
		created, err := service.Create(ctx, owner, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
			IdempotencyKey: name, RequestID: name, Fields: fields(name + ".example.co.uk")})
		if err != nil {
			t.Fatal(err)
		}
		if err := cname.PrepareIntent(ctx, start(*created.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatal(err)
		}
		allocation, err := cname.Get(ctx, tenant.scopeID, created.Site.ID)
		if err != nil || allocation.State != cnameallocation.StatePending {
			t.Fatalf("allocation %+v err=%v", allocation, err)
		}
		return created, allocation
	}
	jobState := func(jobID uuid.UUID) (string, string) {
		t.Helper()
		var state, code string
		if err := pool.QueryRow(ctx, `SELECT state,COALESCE(last_error_code,'') FROM background_jobs
			WHERE tenant_id=$1 AND id=$2`, tenantID, jobID).Scan(&state, &code); err != nil {
			t.Fatal(err)
		}
		return state, code
	}
	// exhaust burns every attempt of the job (each claim's lease lapses on
	// the claim clock), as on 73 (20/20): the claim after the last attempt
	// finalizes it retries_exhausted.
	exhaust := func(t *testing.T, jobID uuid.UUID) {
		t.Helper()
		var maximum int
		if err := pool.QueryRow(ctx, `SELECT max_attempts FROM background_jobs WHERE tenant_id=$1 AND id=$2`,
			tenantID, jobID).Scan(&maximum); err != nil {
			t.Fatal(err)
		}
		for round := 0; round <= 4*maximum+4; round++ {
			if state, _ := jobState(jobID); state != "queued" && state != "running" {
				return
			}
			jobClock = jobClock.Add(6 * time.Minute)
			if _, err := jobs.Claim(ctx, jobstate.ClaimInput{TenantID: tenantID, Kind: "dns.cname.allocation",
				WorkerID: "ended-worker", Limit: 1, LeaseDuration: time.Minute}); err != nil {
				t.Fatalf("claim round %d: %v", round, err)
			}
		}
	}
	siteFacts := func(siteID uuid.UUID) (string, string) {
		t.Helper()
		read, err := service.Get(ctx, owner, siteID)
		if err != nil || read.CNAMEState == nil {
			t.Fatalf("read site %v err=%v", read.CNAMEState, err)
		}
		code := ""
		if read.CNAMEFailureCode != nil {
			code = *read.CNAMEFailureCode
		}
		return *read.CNAMEState, code
	}
	audits := func(siteID uuid.UUID, source string) int {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='dns.cname.job_ended'
			AND resource_id=$1 AND payload->>'source'=$2`, siteID.String(), source).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}

	// First, while the claim clock still matches the audit clock.
	t.Run("cancelled intent fails the site", func(t *testing.T) {
		created, err := service.Create(ctx, owner, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
			IdempotencyKey: "ended-cancel", RequestID: "ended-cancel", Fields: fields("ended-cancel.example.co.uk")})
		if err != nil {
			t.Fatal(err)
		}
		// The task center / site delete path: CancelTx with its 094 receipt.
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			return cancelBackgroundJob(ctx, tx, owner, "ended-cancel-job", tenantID, *created.Site.CNAMETaskID, jobClock)
		}); err != nil {
			t.Fatal(err)
		}
		if state, code := siteFacts(created.Site.ID); state != "failed" || code != cnameallocation.FailureAllocationCancelled {
			t.Fatalf("site cname_state=%s code=%s, want failed/%s", state, code, cnameallocation.FailureAllocationCancelled)
		}
	})

	t.Run("allocation retries exhausted fails the site and regenerates", func(t *testing.T) {
		created, allocation := allocated("ended-exhaust")
		exhaust(t, allocation.JobID)
		if state, code := jobState(allocation.JobID); state != "failed" || code != jobstate.CodeRetriesExhausted {
			t.Fatalf("job state=%s code=%s", state, code)
		}
		if state, code := siteFacts(created.Site.ID); state != "failed" || code != cnameallocation.FailureAllocationExhausted {
			t.Fatalf("site cname_state=%s code=%s, want failed/%s", state, code, cnameallocation.FailureAllocationExhausted)
		}
		failed, err := cname.Get(ctx, tenant.scopeID, created.Site.ID)
		if err != nil || failed.State != cnameallocation.StateFailed {
			t.Fatalf("allocation after exhaustion %+v err=%v", failed, err)
		}
		var allocationCode string
		if err := pool.QueryRow(ctx, `SELECT failure_code FROM cname_allocations WHERE id=$1`, allocation.ID).Scan(&allocationCode); err != nil ||
			allocationCode != cnameallocation.FailureAllocationExhausted {
			t.Fatalf("allocation failure_code=%s err=%v", allocationCode, err)
		}
		if got := audits(created.Site.ID, "terminal"); got != 1 {
			t.Fatalf("job_ended audits=%d", got)
		}
		// 「重新生成」 issues a new intent that allocates again.
		read, err := service.Get(ctx, owner, created.Site.ID)
		if err != nil {
			t.Fatal(err)
		}
		regenerate := fields("ended-exhaust.example.co.uk")
		regenerate.CNAMERegenerate = true
		updated, err := service.Update(ctx, owner, UpdateRequest{ID: created.Site.ID, ExpectedRevision: read.Revision,
			Fields: regenerate, IdempotencyKey: "ended-exhaust-regenerate", RequestID: "ended-exhaust-regenerate"})
		if err != nil || updated.Site.CNAMETaskID == nil || *updated.Site.CNAMETaskID == allocation.JobID {
			t.Fatalf("regenerate err=%v task=%v", err, updated.Site.CNAMETaskID)
		}
		if err := cname.PrepareIntent(ctx, start(*updated.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatal(err)
		}
		again, err := cname.Get(ctx, tenant.scopeID, created.Site.ID)
		if err != nil || again.State != cnameallocation.StatePending || again.JobID == allocation.JobID {
			t.Fatalf("regenerated allocation %+v err=%v", again, err)
		}
		if state, _ := siteFacts(created.Site.ID); state != "pending" {
			t.Fatalf("regenerated site cname_state=%s", state)
		}
		claim := start(again.JobID, "dns.cname.allocation")
		if _, err := cname.Complete(ctx, cnameallocation.ResultRequest{TargetScopeID: tenant.scopeID, SiteID: created.Site.ID,
			AllocationID: again.ID, JobID: again.JobID, ExpectedRevision: again.Revision, WorkerID: claim.WorkerID,
			Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, Sequence: 1}); err != nil {
			t.Fatal(err)
		}
		if state, code := siteFacts(created.Site.ID); state != "done" || code != "" {
			t.Fatalf("regenerated site cname_state=%s code=%s, want done", state, code)
		}
	})

	t.Run("sweep repairs sites ended before the hook, once", func(t *testing.T) {
		created, allocation := allocated("ended-sweep")
		// 73 before this fix: the job ended retries_exhausted, nothing else.
		jobstate.RegisterTerminalHook("dns.cname.allocation", func(context.Context, pgx.Tx, uuid.UUID, uuid.UUID, string, time.Time) error {
			return nil
		})
		exhaust(t, allocation.JobID)
		jobstate.RegisterTerminalHook("dns.cname.allocation", cnameallocation.TerminalHook())
		if state, code := jobState(allocation.JobID); state != "failed" || code != jobstate.CodeRetriesExhausted {
			t.Fatalf("job state=%s code=%s", state, code)
		}
		if state, _ := siteFacts(created.Site.ID); state != "pending" {
			t.Fatalf("stuck fixture cname_state=%s, want pending", state)
		}
		failed, err := cname.SweepEndedJobs(ctx)
		if err != nil || failed != 1 {
			t.Fatalf("first sweep failed=%d err=%v", failed, err)
		}
		if state, code := siteFacts(created.Site.ID); state != "failed" || code != cnameallocation.FailureAllocationExhausted {
			t.Fatalf("swept site cname_state=%s code=%s", state, code)
		}
		if got := audits(created.Site.ID, "sweep"); got != 1 {
			t.Fatalf("sweep audits=%d", got)
		}
		failed, err = cname.SweepEndedJobs(ctx)
		if err != nil || failed != 0 {
			t.Fatalf("second sweep failed=%d err=%v", failed, err)
		}
		if got := audits(created.Site.ID, "sweep"); got != 1 {
			t.Fatalf("second sweep added audits: %d", got)
		}
	})
}
