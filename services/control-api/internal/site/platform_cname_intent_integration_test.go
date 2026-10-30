package site

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsmaintenance"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packageperiod"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type platformCNAMEKeyring struct{}

func (platformCNAMEKeyring) Active(context.Context) (cnameallocation.Key, error) {
	return cnameallocation.Key{ID: "test-cname-key", Secret: bytes.Repeat([]byte{0x31}, 32)}, nil
}

func (ring platformCNAMEKeyring) Lookup(ctx context.Context, id string) (cnameallocation.Key, error) {
	if id != "test-cname-key" {
		return cnameallocation.Key{}, cnameallocation.ErrNotFound
	}
	return ring.Active(ctx)
}

func TestPlatformCNAMEIntentAuthorization(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "platform_site_cname_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "platform-site-cname-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "platform-site-admin", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Platform CNAME target", "platform-site-cname-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")
	group, err := nodescheduler.NewService(pool, func() time.Time { return now }).PutGroup(t.Context(),
		nodescheduler.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}, nodescheduler.PutGroupRequest{
			Name: "CNAME target", Policy: nodescheduler.DefaultHealthPolicy(),
			Endpoints: []nodescheduler.Endpoint{
				{ID: uuid.New(), Address: "192.0.2.20", Port: 80, Weight: 1, Enabled: true},
				{ID: uuid.New(), Address: "2001:db8::20", Port: 80, Weight: 1, Enabled: true},
			},
			IdempotencyKey: "cname-line-group", RequestID: "cname-line-group",
		})
	if err != nil {
		t.Fatal(err)
	}
	providerID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'CNAME fixture','cloudflare','fixture-key',$3,$4,$4)`, providerID, tenant.scopeID, make([]byte, 32), tenant.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_zones(id,scope_id,provider_id,name,is_default,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'cdn.example.com',true,$4,$4)`, uuid.New(), tenant.scopeID, providerID, tenant.userID); err != nil {
		t.Fatal(err)
	}
	productID := addonSiteInsertPackageProductVersion(t, pool, manager, 1, 100, 1000)
	subscriptions := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, func() time.Time { return now }))
	factor, _ := packageperiod.NewTrafficFactor(1, 1)
	month := packageperiod.DurationMonth
	opened, err := subscriptions.Open(t.Context(), manager, packagesubscription.OpenRequest{
		TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: productID, ProductRevision: 1,
		SiteLimit: 100, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
		CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
		IdempotencyKey: "platform-cname-subscription", RequestID: "platform-cname-subscription",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds,
		actor_scope_id,actor_user_id,reason,created_at)
		SELECT $1,COALESCE(max(revision),0)+1,'automatic',$2,30000,15000,2,3,600,$1,$3,'integration_policy',clock_timestamp()
		FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1`,
		tenant.scopeID, []uuid.UUID{uuid.New()}, tenant.userID); err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, time.Hour)
	service := NewService(store)
	intents, err := cnameallocation.NewStore(pool, platformCNAMEKeyring{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform", SessionID: manager.SessionID}
	owner := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	fields := func(domain string) SiteFields {
		return SiteFields{Domains: []string{domain}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
			Enabled: false, Status: StatusDisabled,
			NodeGroupID: &group.Group.GroupID, NodeGroupName: group.Group.Name,
			PackageID: &productID, PackageName: "Business", PackageSubscriptionID: &opened.Subscription.ID}
	}
	create := func(t *testing.T, caller Actor, key string) WriteResult {
		t.Helper()
		result, err := service.Create(t.Context(), caller, CreateRequest{TargetScopeID: tenant.scopeID,
			OwnerUserID: tenant.userID, Fields: fields(key + ".example.co.uk"), IdempotencyKey: key, RequestID: key})
		if err != nil {
			t.Fatalf("create with actor scope %s: %v", caller.ScopeKind, err)
		}
		return result
	}
	startIntent := func(t *testing.T, jobID uuid.UUID) jobstate.Claim {
		t.Helper()
		var tenantID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, tenant.scopeID).Scan(&tenantID); err != nil {
			t.Fatal(err)
		}
		var claim jobstate.Claim
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			var err error
			claim, err = jobstate.StartTx(t.Context(), tx, jobstate.StartInput{TenantID: tenantID, JobID: jobID,
				Kind: "dns.cname.intent", WorkerID: "platform-cname-worker", LeaseDuration: time.Minute}, now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return claim
	}
	assertIntent := func(t *testing.T, siteID, jobID uuid.UUID) {
		t.Helper()
		var actorScope, actorUser, targetScope, subscriptionID, sessionID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT intent.actor_scope_id,intent.actor_user_id,intent.tenant_scope_id,
			intent.package_subscription_id,authority.actor_session_id
			FROM cname_allocation_intents intent JOIN cname_platform_intent_sessions authority
			  ON authority.tenant_id=intent.tenant_id AND authority.job_id=intent.job_id WHERE intent.site_id=$1 AND intent.job_id=$2`, siteID, jobID).
			Scan(&actorScope, &actorUser, &targetScope, &subscriptionID, &sessionID); err != nil {
			t.Fatal(err)
		}
		if actorScope != manager.ScopeID || actorUser != manager.UserID || targetScope != tenant.scopeID || subscriptionID != opened.Subscription.ID || sessionID != manager.SessionID {
			t.Fatalf("intent authority/binding changed: actor=%s/%s target=%s subscription=%s", actorScope, actorUser, targetScope, subscriptionID)
		}
		claim := startIntent(t, jobID)
		if err := intents.PrepareIntent(t.Context(), claim); err != nil {
			t.Fatalf("worker prepare intent: %v", err)
		}
		var state string
		if err := pool.QueryRow(t.Context(), `SELECT state FROM background_jobs WHERE tenant_id=$1 AND id=$2`, claim.Job.TenantID, jobID).Scan(&state); err != nil || state != "succeeded" {
			t.Fatalf("intent execution state=%s err=%v", state, err)
		}
		allocation, err := intents.Get(t.Context(), tenant.scopeID, siteID)
		if err != nil || allocation.State != cnameallocation.StatePending || allocation.Hostname == "" {
			t.Fatalf("worker allocation=%+v err=%v", allocation, err)
		}
		var ipv4, ipv6 []string
		if err := pool.QueryRow(t.Context(), `SELECT target_a,target_aaaa FROM cname_allocation_targets WHERE allocation_id=$1 AND job_id=$2`, allocation.ID, allocation.JobID).Scan(&ipv4, &ipv6); err != nil ||
			len(ipv4) != 1 || ipv4[0] != "192.0.2.20" || len(ipv6) != 1 || ipv6[0] != "2001:db8::20" {
			t.Fatalf("frozen DNS targets changed: A=%v AAAA=%v err=%v", ipv4, ipv6, err)
		}
	}
	assertWriteFacts := func(t *testing.T, siteID uuid.UUID, operation, requestID string) {
		t.Helper()
		var jobs, audits int
		if err := pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM cname_allocation_intents WHERE site_id=$1 AND request_id=$2),
			(SELECT count(*) FROM audit_events WHERE resource_id=$1::text AND request_id=$2 AND action=$3 AND result='success')`,
			siteID, requestID, operation).Scan(&jobs, &audits); err != nil || jobs != 1 || audits != 1 {
			t.Fatalf("durable facts jobs=%d audits=%d err=%v", jobs, audits, err)
		}
	}
	markFailed := func(t *testing.T, siteID uuid.UUID) {
		t.Helper()
		err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			var tenantID, jobID uuid.UUID
			if err := tx.QueryRow(t.Context(), `SELECT scope.tenant_id,site.cname_task_id FROM sites site
				JOIN access_scopes scope ON scope.id=site.scope_id WHERE site.id=$1`, siteID).Scan(&tenantID, &jobID); err != nil {
				return err
			}
			claim, err := jobstate.StartTx(t.Context(), tx, jobstate.StartInput{TenantID: tenantID, JobID: jobID,
				Kind: "dns.cname.intent", WorkerID: "cname-fixture", LeaseDuration: time.Minute}, now)
			if err != nil {
				return err
			}
			if _, err := jobstate.ReportTx(t.Context(), tx, jobstate.ReportInput{TenantID: tenantID, JobID: jobID,
				WorkerID: claim.WorkerID, LeaseID: claim.LeaseID,
				Report: jobstate.Report{ItemID: "allocate", State: jobstate.ItemFailed, Code: "allocation_rejected", Attempt: claim.Job.Attempt, Sequence: 1}}, now); err != nil {
				return err
			}
			_, err = tx.Exec(t.Context(), `UPDATE sites SET cname_state='failed' WHERE id=$1`, siteID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Run("create", func(t *testing.T) {
		result := create(t, actor, "platform-create")
		if result.Site.CNAMETaskID == nil {
			t.Fatal("create did not enqueue durable CNAME intent")
		}
		replayed := create(t, actor, "platform-create")
		if !replayed.Replayed || replayed.Site.ID != result.Site.ID || *replayed.Site.CNAMETaskID != *result.Site.CNAMETaskID {
			t.Fatal("create replay changed the durable intent")
		}
		assertWriteFacts(t, result.Site.ID, "site.create", "platform-create")
		assertIntent(t, result.Site.ID, *result.Site.CNAMETaskID)
	})
	t.Run("blocked after intent", func(t *testing.T) {
		// G6 #11 background backstop: a zone blocklisted after the site write
		// fails the allocation with domain_blocked instead of allocating.
		result := create(t, actor, "platform-blocked")
		blockID := uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO platform_domain_blocklist(id,pattern,match_type,reason,
			created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,'example.com','root','',$2,$2,now(),now())`,
			blockID, manager.UserID); err != nil {
			t.Fatal(err)
		}
		defer func() {
			_, _ = pool.Exec(context.Background(), `DELETE FROM platform_domain_blocklist WHERE id=$1`, blockID)
		}()
		claim := startIntent(t, *result.Site.CNAMETaskID)
		if err := intents.PrepareIntent(t.Context(), claim); err != nil {
			t.Fatalf("worker prepare intent: %v", err)
		}
		var state, code, cnameState string
		if err := pool.QueryRow(t.Context(), `SELECT job.state,
			(SELECT error_code FROM background_job_results WHERE tenant_id=job.tenant_id AND job_id=job.id ORDER BY reported_at DESC LIMIT 1),
			(SELECT cname_state FROM sites WHERE id=$3)
			FROM background_jobs job WHERE job.tenant_id=$1 AND job.id=$2`, claim.Job.TenantID, *result.Site.CNAMETaskID,
			result.Site.ID).Scan(&state, &code, &cnameState); err != nil || state != "failed" || code != "domain_blocked" || cnameState != "failed" {
			t.Fatalf("blocked intent state=%s code=%s cname=%s err=%v", state, code, cnameState, err)
		}
	})
	t.Run("update", func(t *testing.T) {
		initial := create(t, owner, "platform-update")
		markFailed(t, initial.Site.ID)
		updatedFields := fields("platform-update.example.co.uk")
		updatedFields.CNAMERegenerate = true
		request := UpdateRequest{ID: initial.Site.ID,
			ExpectedRevision: initial.Site.Revision, Fields: updatedFields, IdempotencyKey: "platform-update-retry", RequestID: "platform-update-retry"}
		result, err := service.Update(t.Context(), actor, request)
		if err != nil {
			t.Fatal(err)
		}
		if result.Site.CNAMETaskID == nil || *result.Site.CNAMETaskID == *initial.Site.CNAMETaskID {
			t.Fatal("update did not enqueue a new durable CNAME intent")
		}
		replayed, err := service.Update(t.Context(), actor, request)
		if err != nil || !replayed.Replayed || replayed.Site.CNAMETaskID == nil || *replayed.Site.CNAMETaskID != *result.Site.CNAMETaskID {
			t.Fatalf("update replay changed durable intent: %v", err)
		}
		assertWriteFacts(t, initial.Site.ID, "site.update", request.RequestID)
		assertIntent(t, result.Site.ID, *result.Site.CNAMETaskID)
	})
	// site-edit-parity2: 73 PATCH /v1/sites/01a163c0… (ikvm.asia, http 80,
	// origin 203.0.113.14, 测试套餐, cname_state=failed) returned 400 twice. The
	// editor's 「更改 CNAME」 dialog sent the operator's new domain (the zone
	// ikvm.asia) with cname_regenerate, while the subscription snapshot still
	// says cdn.example.com: the store refuses it. The refusal must name
	// cname_domain; an echo of the site's own facts (is_default, status,
	// cname_state=failed, …) plus the retry must save.
	t.Run("73-shaped edit with a different CNAME domain names the field", func(t *testing.T) {
		initial := create(t, actor, "ikvm-shaped")
		markFailed(t, initial.Site.ID)
		edited := fields("ikvm-shaped.example.co.uk")
		edited.Origins = []string{"203.0.113.14"}
		edited.CNAMEMode, edited.CNAMEDomain, edited.CNAMERegenerate = "site", "ikvm.asia", true
		_, err := service.Update(t.Context(), actor, UpdateRequest{ID: initial.Site.ID, ExpectedRevision: initial.Site.Revision,
			Fields: edited, IdempotencyKey: "ikvm-shaped-domain", RequestID: "ikvm-shaped-domain"})
		var fieldErr *FieldError
		if !errors.As(err, &fieldErr) || fieldErr.Field != "cname_domain" || !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("different CNAME domain error = %v, want FieldError cname_domain", err)
		}
		// The editor echoes the stored facts (is_default=false, status, the
		// failed state) and the stored domain: the retry saves.
		echo := fields("ikvm-shaped.example.co.uk")
		echo.CNAMEMode, echo.CNAMEDomain, echo.CNAMERegenerate = "site", "cdn.example.com", true
		echo.IsDefault = false
		result, err := service.Update(t.Context(), actor, UpdateRequest{ID: initial.Site.ID, ExpectedRevision: initial.Site.Revision,
			Fields: echo, IdempotencyKey: "ikvm-shaped-echo", RequestID: "ikvm-shaped-echo"})
		if err != nil || result.Site.CNAMETaskID == nil || *result.Site.CNAMETaskID == *initial.Site.CNAMETaskID {
			t.Fatalf("echoed retry = %+v, %v; want a new CNAME intent", result.Site.CNAMETaskID, err)
		}
	})
	// testdebt11: editing a site while its CNAME intent is queued keeps the
	// intent current (migration 405); a CNAME input change supersedes it.
	startJob := func(t *testing.T, jobID uuid.UUID, kind string) jobstate.Claim {
		t.Helper()
		var claim jobstate.Claim
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			var tenantID uuid.UUID
			if err := tx.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, tenant.scopeID).Scan(&tenantID); err != nil {
				return err
			}
			var err error
			claim, err = jobstate.StartTx(t.Context(), tx, jobstate.StartInput{TenantID: tenantID, JobID: jobID,
				Kind: kind, WorkerID: "edit-cname-worker", LeaseDuration: time.Minute}, now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return claim
	}
	completeAllocation := func(t *testing.T, siteID uuid.UUID) {
		t.Helper()
		allocation, err := intents.Get(t.Context(), tenant.scopeID, siteID)
		if err != nil {
			t.Fatal(err)
		}
		claim := startJob(t, allocation.JobID, "dns.cname.allocation")
		if _, err := intents.Complete(t.Context(), cnameallocation.ResultRequest{TargetScopeID: tenant.scopeID, SiteID: siteID,
			AllocationID: allocation.ID, JobID: allocation.JobID, ExpectedRevision: allocation.Revision, WorkerID: claim.WorkerID,
			Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, Sequence: 1}); err != nil {
			t.Fatalf("complete allocation: %v", err)
		}
		var state, cname string
		if err := pool.QueryRow(t.Context(), `SELECT cname_state,cname FROM sites WHERE id=$1`, siteID).Scan(&state, &cname); err != nil ||
			state != "done" || cname == "" {
			t.Fatalf("site CNAME after completion state=%s cname=%q err=%v", state, cname, err)
		}
	}
	jobState := func(t *testing.T, jobID uuid.UUID) (string, string) {
		t.Helper()
		var state string
		var code *string
		if err := pool.QueryRow(t.Context(), `SELECT job.state,(SELECT error_code FROM background_job_results
			WHERE tenant_id=job.tenant_id AND job_id=job.id ORDER BY reported_at DESC LIMIT 1)
			FROM background_jobs job WHERE job.id=$1`, jobID).Scan(&state, &code); err != nil {
			t.Fatal(err)
		}
		if code == nil {
			return state, ""
		}
		return state, *code
	}
	// assertRetirementCleaned leases the retirement of owner through the
	// worker store with the record values the system wrote, and settles it.
	assertRetirementCleaned := func(t *testing.T, owner string) {
		t.Helper()
		due, err := intents.DueRetirements(t.Context(), 1000)
		if err != nil {
			t.Fatal(err)
		}
		for _, retired := range due {
			if !strings.EqualFold(retired.Owner, owner) {
				continue
			}
			if len(retired.A) != 1 || retired.A[0] != "192.0.2.20" || len(retired.AAAA) != 1 || retired.AAAA[0] != "2001:db8::20" {
				t.Fatalf("retired owner written values A=%v AAAA=%v", retired.A, retired.AAAA)
			}
			if err := intents.FinishRetirement(t.Context(), retired, 2, 0, ""); err != nil {
				t.Fatal(err)
			}
			var state string
			if err := pool.QueryRow(t.Context(), `SELECT state FROM cname_record_retirements WHERE id=$1`, retired.ID).Scan(&state); err != nil || state != "cleaned" {
				t.Fatalf("retirement state=%s err=%v", state, err)
			}
			if err := intents.FinishRetirement(t.Context(), retired, 2, 0, ""); !errors.Is(err, cnameallocation.ErrClaimLost) {
				t.Fatalf("second settle = %v, want ErrClaimLost", err)
			}
			return
		}
		t.Fatalf("retired owner %s not due (%d due)", owner, len(due))
	}
	t.Run("edit while intent queued keeps intent", func(t *testing.T) {
		initial := create(t, owner, "edit-queued")
		edited := fields("edit-queued.example.co.uk")
		edited.Origins = []string{"192.0.2.2"}
		result, err := service.Update(t.Context(), owner, UpdateRequest{ID: initial.Site.ID, ExpectedRevision: initial.Site.Revision,
			Fields: edited, IdempotencyKey: "edit-queued-update", RequestID: "edit-queued-update"})
		if err != nil {
			t.Fatalf("edit while CNAME intent queued: %v", err)
		}
		if result.Site.Revision != initial.Site.Revision+1 || result.Site.CNAMETaskID == nil || *result.Site.CNAMETaskID != *initial.Site.CNAMETaskID {
			t.Fatalf("edit changed the CNAME intent: revision=%d task=%v", result.Site.Revision, result.Site.CNAMETaskID)
		}
		if err := intents.PrepareIntent(t.Context(), startJob(t, *initial.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatalf("intent after edit: %v", err)
		}
		if state, code := jobState(t, *initial.Site.CNAMETaskID); state != "succeeded" {
			t.Fatalf("intent after edit state=%s code=%s", state, code)
		}
		completeAllocation(t, initial.Site.ID)
	})
	// retest-n1 step 4: deleting a site cancels its queued CNAME intent and
	// its running allocation job; neither is claimable afterwards.
	t.Run("site delete cancels in-flight CNAME jobs", func(t *testing.T) {
		queued := create(t, owner, "delete-queued")
		if _, err := service.Delete(t.Context(), owner, DeleteRequest{ID: queued.Site.ID, ExpectedRevision: queued.Site.Revision,
			IdempotencyKey: "delete-queued", RequestID: "delete-queued"}); err != nil {
			t.Fatalf("delete with queued CNAME intent: %v", err)
		}
		if state, code := jobState(t, *queued.Site.CNAMETaskID); state != "cancelled" {
			t.Fatalf("queued intent after site delete state=%s code=%s", state, code)
		}
		running := create(t, owner, "delete-running")
		if err := intents.PrepareIntent(t.Context(), startJob(t, *running.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatal(err)
		}
		allocation, err := intents.Get(t.Context(), tenant.scopeID, running.Site.ID)
		if err != nil {
			t.Fatal(err)
		}
		startJob(t, allocation.JobID, "dns.cname.allocation")
		var revision int64
		if err := pool.QueryRow(t.Context(), `SELECT revision FROM sites WHERE id=$1`, running.Site.ID).Scan(&revision); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Delete(t.Context(), owner, DeleteRequest{ID: running.Site.ID, ExpectedRevision: revision,
			IdempotencyKey: "delete-running", RequestID: "delete-running"}); err != nil {
			t.Fatalf("delete with running CNAME allocation: %v", err)
		}
		if state, code := jobState(t, allocation.JobID); state != "cancelled" {
			t.Fatalf("running allocation after site delete state=%s code=%s", state, code)
		}
		var claimable int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM background_jobs WHERE id = ANY($1)
			AND (claimable_at IS NOT NULL OR lease_id IS NOT NULL)`,
			[]uuid.UUID{*queued.Site.CNAMETaskID, allocation.JobID}).Scan(&claimable); err != nil || claimable != 0 {
			t.Fatalf("cancelled CNAME jobs still claimable: %d, %v", claimable, err)
		}
		// n12b: the deleted site's own owner is retired with the delete.
		var reason string
		if err := pool.QueryRow(t.Context(), `SELECT reason FROM cname_record_retirements
			WHERE site_id=$1 AND lower(owner_name)=lower($2)`, running.Site.ID, allocation.Hostname).Scan(&reason); err != nil || reason != "site_deleted" {
			t.Fatalf("deleted site retirement reason=%q err=%v", reason, err)
		}
		assertRetirementCleaned(t, allocation.Hostname)
	})
	// 记录修复 repaired the CNAME owner of a site
	// deleted hours earlier and failed it with dns_no_serving_endpoint. Only
	// owners a live site still binds are repair targets.
	t.Run("record repair skips the owner of a deleted site", func(t *testing.T) {
		repair, err := dnsmaintenance.NewStore(pool)
		if err != nil {
			t.Fatal(err)
		}
		listed := func(t *testing.T, owner string) bool {
			t.Helper()
			targets, err := repair.RepairTargets(t.Context(), tenant.scopeID, providerID)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range targets {
				if strings.EqualFold(strings.TrimSuffix(target.Owner, "."), owner) {
					return true
				}
			}
			return false
		}
		created := create(t, owner, "repair-deleted")
		if err := intents.PrepareIntent(t.Context(), startJob(t, *created.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatal(err)
		}
		completeAllocation(t, created.Site.ID)
		allocation, err := intents.Get(t.Context(), tenant.scopeID, created.Site.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !listed(t, allocation.Hostname) {
			t.Fatalf("live site owner %s is not a repair target", allocation.Hostname)
		}
		var revision int64
		if err := pool.QueryRow(t.Context(), `SELECT revision FROM sites WHERE id=$1`, created.Site.ID).Scan(&revision); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Delete(t.Context(), owner, DeleteRequest{ID: created.Site.ID, ExpectedRevision: revision,
			IdempotencyKey: "repair-deleted-delete", RequestID: "repair-deleted-delete"}); err != nil {
			t.Fatal(err)
		}
		if listed(t, allocation.Hostname) {
			t.Fatalf("deleted site owner %s is still a repair target", allocation.Hostname)
		}
		if _, err := repair.RepairTarget(t.Context(), tenant.scopeID, providerID, allocation.Hostname); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("repair target of deleted site owner err=%v, want ErrNoRows", err)
		}
	})
	// n12b: a tenant's 「重新生成」 after a failed allocation advances the
	// generation with the one runtime HMAC key; 113 refused that (P1131 →
	// ErrConflict, the intent never settled).
	// N19 (live retest 3): the allocation job yielded while its child DNS
	// task was in flight (queued, current attempt deferred); deleting the site
	// cancelled it without ending that attempt (115: "cancelled background
	// job attempt is invalid", HTTP 500) and the site could not be deleted.
	t.Run("site delete cancels a yielded CNAME allocation", func(t *testing.T) {
		site := create(t, owner, "delete-n19-yielded")
		if err := intents.PrepareIntent(t.Context(), startJob(t, *site.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatal(err)
		}
		allocation, err := intents.Get(t.Context(), tenant.scopeID, site.Site.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := intents.Yield(t.Context(), startJob(t, allocation.JobID, "dns.cname.allocation"), time.Second); err != nil {
			t.Fatal(err)
		}
		var revision int64
		if err := pool.QueryRow(t.Context(), `SELECT revision FROM sites WHERE id=$1`, site.Site.ID).Scan(&revision); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Delete(t.Context(), owner, DeleteRequest{ID: site.Site.ID, ExpectedRevision: revision,
			IdempotencyKey: "delete-n19-yielded", RequestID: "delete-n19-yielded"}); err != nil {
			t.Fatalf("delete with yielded CNAME allocation: %v", err)
		}
		if state, code := jobState(t, allocation.JobID); state != "cancelled" {
			t.Fatalf("allocation after site delete state=%s code=%s", state, code)
		}
		var running, claimable int
		if err := pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM background_job_attempts WHERE job_id=$1 AND state='running'),
			(SELECT count(*) FROM background_jobs WHERE id=$1 AND (claimable_at IS NOT NULL OR lease_id IS NOT NULL))`,
			allocation.JobID).Scan(&running, &claimable); err != nil || running != 0 || claimable != 0 {
			t.Fatalf("after delete: running attempts %d, claimable %d, %v", running, claimable, err)
		}
		// n12b: the owner it may have written is retired with the delete
		var reason string
		if err := pool.QueryRow(t.Context(), `SELECT reason FROM cname_record_retirements
			WHERE site_id=$1 AND lower(owner_name)=lower($2)`, site.Site.ID, allocation.Hostname).Scan(&reason); err != nil || reason != "site_deleted" {
			t.Fatalf("deleted site retirement reason=%q err=%v", reason, err)
		}
	})
	t.Run("tenant regenerate after failed allocation", func(t *testing.T) {
		initial := create(t, owner, "regen-failed")
		if err := intents.PrepareIntent(t.Context(), startJob(t, *initial.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatal(err)
		}
		first, err := intents.Get(t.Context(), tenant.scopeID, initial.Site.ID)
		if err != nil {
			t.Fatal(err)
		}
		claim := startJob(t, first.JobID, "dns.cname.allocation")
		if _, err := intents.Fail(t.Context(), cnameallocation.ResultRequest{TargetScopeID: tenant.scopeID, SiteID: initial.Site.ID,
			AllocationID: first.ID, JobID: first.JobID, ExpectedRevision: first.Revision, WorkerID: claim.WorkerID,
			Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, Sequence: 1, FailureCode: "dns_reconcile_failed"}); err != nil {
			t.Fatalf("fail allocation: %v", err)
		}
		// cname-regen-default: the claim sits in the default zone, so the
		// projection stores cname_domain=''; the retry compares the domain the
		// claim uses with the package snapshot (cdn.example.com) and is allowed.
		var revision int64
		var projectedDomain string
		if err := pool.QueryRow(t.Context(), `SELECT revision,cname_domain FROM sites WHERE id=$1`,
			initial.Site.ID).Scan(&revision, &projectedDomain); err != nil || projectedDomain != "" {
			t.Fatalf("default-zone projection cname_domain=%q err=%v, want ''", projectedDomain, err)
		}
		retry := fields("regen-failed.example.co.uk")
		retry.CNAMERegenerate = true
		updated, err := service.Update(t.Context(), owner, UpdateRequest{ID: initial.Site.ID, ExpectedRevision: revision,
			Fields: retry, IdempotencyKey: "regen-failed-retry", RequestID: "regen-failed-retry"})
		if err != nil {
			t.Fatalf("regenerate failed CNAME: %v", err)
		}
		if err := intents.PrepareIntent(t.Context(), startJob(t, *updated.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatalf("regenerate intent: %v", err)
		}
		second, err := intents.Get(t.Context(), tenant.scopeID, initial.Site.ID)
		if err != nil || second.State != cnameallocation.StatePending || second.Hostname == first.Hostname || second.KeyID != first.KeyID {
			t.Fatalf("regenerated allocation=%+v (first %s) err=%v", second, first.Hostname, err)
		}
		// The first generation's owner name was written to the provider:
		// it is retired in the same transaction for the cleanup worker.
		var retired int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM cname_record_retirements
			WHERE allocation_id=$1 AND lower(owner_name)=lower($2) AND reason='generation_rotated'`,
			first.ID, first.Hostname).Scan(&retired); err != nil || retired != 1 {
			t.Fatalf("rotated owner retirements=%d err=%v", retired, err)
		}
		// The failed generation was never served: released at once, no longer
		// "in use" for 清除CDN无关解析, and leased by the retirement worker.
		var inUse int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM cname_hostname_claims
			WHERE lower(hostname)=lower($1) AND NOT cname_claim_released_476(id)`, first.Hostname).Scan(&inUse); err != nil || inUse != 0 {
			t.Fatalf("rotated owner still claimed in use=%d err=%v", inUse, err)
		}
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM cname_hostname_claims
			WHERE lower(hostname)=lower($1) AND NOT cname_claim_released_476(id)`, second.Hostname).Scan(&inUse); err != nil || inUse != 1 {
			t.Fatalf("current owner in use=%d err=%v", inUse, err)
		}
		assertRetirementCleaned(t, first.Hostname)
	})
	// (73): the site list's 重新生成 on a site whose
	// allocation failed in the default zone (projection cname_domain='') went
	// through the batch action and failed the commit with P1134: the batch
	// UPDATE wrote the projected '' while the intent row holds the package
	// snapshot domain, so 479's intent branch never matched. The platform
	// scope also keeps a default zone of the same name (the platform DNS
	// configuration the tenant copy was synced from, another provider).
	t.Run("batch regenerate after failed default-zone allocation", func(t *testing.T) {
		platformProvider := uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
			VALUES($1,$2,'platform DNS','cloudflare','fixture-key',$3,$4,$4)`, platformProvider, manager.ScopeID, make([]byte, 32), manager.UserID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO dns_zones(id,scope_id,provider_id,name,is_default,created_by_user_id,updated_by_user_id)
			VALUES($1,$2,$3,'cdn.example.com',true,$4,$4)`, uuid.New(), manager.ScopeID, platformProvider, manager.UserID); err != nil {
			t.Fatal(err)
		}
		var defaults int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM dns_zones WHERE name='cdn.example.com' AND is_default AND status='draft'`).
			Scan(&defaults); err != nil || defaults != 2 {
			t.Fatalf("default draft zones named cdn.example.com=%d err=%v, want 2", defaults, err)
		}
		initial := create(t, owner, "batch-regen-default")
		if err := intents.PrepareIntent(t.Context(), startJob(t, *initial.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatal(err)
		}
		first, err := intents.Get(t.Context(), tenant.scopeID, initial.Site.ID)
		if err != nil {
			t.Fatal(err)
		}
		claim := startJob(t, first.JobID, "dns.cname.allocation")
		if _, err := intents.Fail(t.Context(), cnameallocation.ResultRequest{TargetScopeID: tenant.scopeID, SiteID: initial.Site.ID,
			AllocationID: first.ID, JobID: first.JobID, ExpectedRevision: first.Revision, WorkerID: claim.WorkerID,
			Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, Sequence: 1, FailureCode: "dns_reconcile_unavailable"}); err != nil {
			t.Fatalf("fail allocation: %v", err)
		}
		var revision int64
		var projectedDomain, state string
		if err := pool.QueryRow(t.Context(), `SELECT revision,cname_domain,cname_state FROM sites WHERE id=$1`,
			initial.Site.ID).Scan(&revision, &projectedDomain, &state); err != nil || projectedDomain != "" || state != "failed" {
			t.Fatalf("73-shaped site cname_domain=%q state=%s err=%v, want '' failed", projectedDomain, state, err)
		}
		for _, caller := range []struct {
			name  string
			actor Actor
		}{{"tenant", owner}, {"platform", actor}} {
			request := BatchActionRequest{Action: BatchActionRegenerateCNAME,
				Items:          []BatchActionItem{{ID: initial.Site.ID, ExpectedRevision: revision}},
				IdempotencyKey: "batch-regen-default-" + caller.name, RequestID: "batch-regen-default-" + caller.name}
			result, err := service.BatchAction(t.Context(), caller.actor, request)
			if err != nil {
				t.Fatalf("%s batch regenerate: %v", caller.name, err)
			}
			if len(result.Items) != 1 || result.Items[0].Status != "queued" || result.Items[0].Site == nil ||
				result.Items[0].Site.CNAMETaskID == nil || result.Items[0].Site.CNAMEState == nil || *result.Items[0].Site.CNAMEState != "pending" {
				t.Fatalf("%s batch regenerate = %+v", caller.name, result.Items)
			}
			if err := intents.PrepareIntent(t.Context(), startJob(t, *result.Items[0].Site.CNAMETaskID, "dns.cname.intent")); err != nil {
				t.Fatalf("%s regenerate intent: %v", caller.name, err)
			}
			second, err := intents.Get(t.Context(), tenant.scopeID, initial.Site.ID)
			// a tenant retry rotates the owner name; a platform intent refreshes
			// the same claim (cnameallocation refresh), so only the tenant's changes
			if err != nil || second.State != cnameallocation.StatePending || second.JobID == first.JobID ||
				(caller.name == "tenant" && second.Hostname == first.Hostname) {
				t.Fatalf("%s regenerated allocation=%+v (first %s) err=%v", caller.name, second, first.Hostname, err)
			}
			// fail the new generation too, so the platform caller retries a
			// failed default-zone site again
			claim := startJob(t, second.JobID, "dns.cname.allocation")
			if _, err := intents.Fail(t.Context(), cnameallocation.ResultRequest{TargetScopeID: tenant.scopeID, SiteID: initial.Site.ID,
				AllocationID: second.ID, JobID: second.JobID, ExpectedRevision: second.Revision, WorkerID: claim.WorkerID,
				Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, Sequence: 1, FailureCode: "dns_reconcile_unavailable"}); err != nil {
				t.Fatalf("fail regenerated allocation: %v", err)
			}
			first = second
			if err := pool.QueryRow(t.Context(), `SELECT revision FROM sites WHERE id=$1`, initial.Site.ID).Scan(&revision); err != nil {
				t.Fatal(err)
			}
		}
	})
	// cname-regen-default: cancelling a subscription retires its package
	// allocation's owner (476 covered only site delete and rotation); the
	// owner stays in use while a live site still serves it.
	t.Run("subscription cancel retires package owner", func(t *testing.T) {
		sharedProduct := addonSiteInsertPackageProductVersionCNAMEMode(t, pool, manager, 1, 100, 1000, "shared", "cdn.example.com", "")
		cancelling := packagesubscription.NewService(packagesubscription.NewStoreWithClock(pool, func() time.Time { return now }).
			WithCancelTx(cnameallocation.RetireSubscriptionOwnersTx))
		shared, err := cancelling.Open(t.Context(), manager, packagesubscription.OpenRequest{
			TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: sharedProduct, ProductRevision: 1,
			SiteLimit: 100, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
			CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
			IdempotencyKey: "cancel-retire-subscription", RequestID: "cancel-retire-subscription",
		})
		if err != nil {
			t.Fatal(err)
		}
		siteFields := fields("cancel-retire.example.co.uk")
		siteFields.PackageID, siteFields.PackageSubscriptionID = &sharedProduct, &shared.Subscription.ID
		created, err := service.Create(t.Context(), owner, CreateRequest{TargetScopeID: tenant.scopeID,
			OwnerUserID: tenant.userID, Fields: siteFields, IdempotencyKey: "cancel-retire", RequestID: "cancel-retire"})
		if err != nil {
			t.Fatal(err)
		}
		if err := intents.PrepareIntent(t.Context(), startJob(t, *created.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatal(err)
		}
		completeAllocation(t, created.Site.ID)
		allocation, err := intents.Get(t.Context(), tenant.scopeID, created.Site.ID)
		if err != nil {
			t.Fatal(err)
		}
		var subscriptionRevision int64
		if err := pool.QueryRow(t.Context(), `SELECT revision FROM package_subscriptions WHERE id=$1`,
			shared.Subscription.ID).Scan(&subscriptionRevision); err != nil {
			t.Fatal(err)
		}
		if _, err := cancelling.Cancel(t.Context(), manager, packagesubscription.CancelRequest{TenantScopeID: tenant.scopeID,
			SubscriptionID: shared.Subscription.ID, ExpectedRevision: subscriptionRevision,
			IdempotencyKey: "cancel-retire-cancel", RequestID: "cancel-retire-cancel"}); err != nil {
			t.Fatalf("cancel subscription: %v", err)
		}
		var mode, reason string
		var retiredSite uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT allocation.mode,retirement.reason,retirement.site_id
			FROM cname_record_retirements retirement JOIN cname_allocations allocation ON allocation.id=retirement.allocation_id
			WHERE lower(retirement.owner_name)=lower($1)`, allocation.Hostname).Scan(&mode, &reason, &retiredSite); err != nil ||
			mode != "package" || reason != "generation_rotated" || retiredSite != created.Site.ID {
			t.Fatalf("cancelled subscription owner retirement mode=%q reason=%q site=%s err=%v", mode, reason, retiredSite, err)
		}
		var inUse int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM cname_hostname_claims
			WHERE lower(hostname)=lower($1) AND NOT cname_claim_released_476(id)`, allocation.Hostname).Scan(&inUse); err != nil || inUse != 1 {
			t.Fatalf("owner of a live site released early: in use=%d err=%v", inUse, err)
		}
		var revision int64
		if err := pool.QueryRow(t.Context(), `SELECT revision FROM sites WHERE id=$1`, created.Site.ID).Scan(&revision); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Delete(t.Context(), owner, DeleteRequest{ID: created.Site.ID, ExpectedRevision: revision,
			IdempotencyKey: "cancel-retire-delete", RequestID: "cancel-retire-delete"}); err != nil {
			t.Fatalf("delete site of cancelled subscription: %v", err)
		}
		assertRetirementCleaned(t, allocation.Hostname)
	})
	t.Run("subscription change supersedes queued intent", func(t *testing.T) {
		initial := create(t, owner, "edit-superseded")
		second, err := subscriptions.Open(t.Context(), manager, packagesubscription.OpenRequest{
			TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: productID, ProductRevision: 1,
			SiteLimit: 100, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
			CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
			IdempotencyKey: "edit-superseded-subscription", RequestID: "edit-superseded-subscription",
		})
		if err != nil {
			t.Fatal(err)
		}
		changed := fields("edit-superseded.example.co.uk")
		changed.PackageSubscriptionID = &second.Subscription.ID
		result, err := service.Update(t.Context(), owner, UpdateRequest{ID: initial.Site.ID, ExpectedRevision: initial.Site.Revision,
			Fields: changed, IdempotencyKey: "edit-superseded-update", RequestID: "edit-superseded-update"})
		if err != nil {
			t.Fatalf("subscription change while CNAME intent queued: %v", err)
		}
		if result.Site.CNAMETaskID == nil || *result.Site.CNAMETaskID == *initial.Site.CNAMETaskID {
			t.Fatal("subscription change did not issue a new CNAME intent")
		}
		if err := intents.PrepareIntent(t.Context(), startJob(t, *initial.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatalf("superseded intent: %v", err)
		}
		if state, code := jobState(t, *initial.Site.CNAMETaskID); state != "failed" || code != "intent_superseded" {
			t.Fatalf("superseded intent state=%s code=%s", state, code)
		}
		if _, err := intents.Get(t.Context(), tenant.scopeID, initial.Site.ID); !errors.Is(err, cnameallocation.ErrNotFound) {
			t.Fatalf("superseded intent allocated: %v", err)
		}
		var siteState string
		var task uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT cname_state,cname_task_id FROM sites WHERE id=$1`, initial.Site.ID).Scan(&siteState, &task); err != nil ||
			siteState != "pending" || task != *result.Site.CNAMETaskID {
			t.Fatalf("site after superseded intent state=%s task=%s err=%v", siteState, task, err)
		}
		if err := intents.PrepareIntent(t.Context(), startJob(t, task, "dns.cname.intent")); err != nil {
			t.Fatalf("current intent: %v", err)
		}
		if state, code := jobState(t, task); state != "succeeded" {
			t.Fatalf("current intent state=%s code=%s", state, code)
		}
		completeAllocation(t, initial.Site.ID)
		var subscriptionID uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT package_subscription_id FROM cname_allocation_targets WHERE site_id=$1`, initial.Site.ID).Scan(&subscriptionID); err != nil ||
			subscriptionID != second.Subscription.ID {
			t.Fatalf("allocation followed subscription %s err=%v, want %s", subscriptionID, err, second.Subscription.ID)
		}
	})
	t.Run("site domain change keeps queued intent", func(t *testing.T) {
		// The site's own served domain is not a CNAME allocation input (the
		// label derives from tenant/provider/owner/mode/zone/generation).
		initial := create(t, owner, "edit-domain")
		renamed := fields("edit-domain-renamed.example.co.uk")
		result, err := service.Update(t.Context(), owner, UpdateRequest{ID: initial.Site.ID, ExpectedRevision: initial.Site.Revision,
			Fields: renamed, IdempotencyKey: "edit-domain-update", RequestID: "edit-domain-update"})
		if err != nil {
			t.Fatalf("site domain change while CNAME intent queued: %v", err)
		}
		if result.Site.CNAMETaskID == nil || *result.Site.CNAMETaskID != *initial.Site.CNAMETaskID {
			t.Fatalf("site domain change replaced the CNAME intent: %v", result.Site.CNAMETaskID)
		}
		if err := intents.PrepareIntent(t.Context(), startJob(t, *initial.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatalf("intent after domain change: %v", err)
		}
		if state, code := jobState(t, *initial.Site.CNAMETaskID); state != "succeeded" {
			t.Fatalf("intent after domain change state=%s code=%s", state, code)
		}
		completeAllocation(t, initial.Site.ID)
	})
	t.Run("CNAME domain and hostname change supersedes queued intent", func(t *testing.T) {
		// A site's CNAME domain/hostname come from its subscription's product
		// snapshot; moving to a product with another domain and an explicit
		// hostname is the CNAME input change.
		if _, err := pool.Exec(t.Context(), `INSERT INTO dns_zones(id,scope_id,provider_id,name,is_default,created_by_user_id,updated_by_user_id)
			VALUES($1,$2,$3,'cdn2.example.com',false,$4,$4)`, uuid.New(), tenant.scopeID, providerID, tenant.userID); err != nil {
			t.Fatal(err)
		}
		otherProduct := addonSiteInsertPackageProductVersionCNAME(t, pool, manager, 1, 100, 1000, "cdn2.example.com", "edge.cdn2.example.com")
		other, err := subscriptions.Open(t.Context(), manager, packagesubscription.OpenRequest{
			TenantScopeID: tenant.scopeID, OwnerUserID: tenant.userID, ProductID: otherProduct, ProductRevision: 1,
			SiteLimit: 100, NodeLimit: 1, Terms: packageperiod.Terms{Duration: &month}, TimeZone: "Asia/Shanghai",
			CyclePolicy: packageperiod.CyclePolicy{Kind: packageperiod.CycleMonthly}, TrafficFactor: factor,
			IdempotencyKey: "edit-cname-subscription", RequestID: "edit-cname-subscription",
		})
		if err != nil {
			t.Fatal(err)
		}
		initial := create(t, owner, "edit-cname")
		changed := fields("edit-cname.example.co.uk")
		changed.PackageID, changed.PackageSubscriptionID = &otherProduct, &other.Subscription.ID
		result, err := service.Update(t.Context(), owner, UpdateRequest{ID: initial.Site.ID, ExpectedRevision: initial.Site.Revision,
			Fields: changed, IdempotencyKey: "edit-cname-update", RequestID: "edit-cname-update"})
		if err != nil {
			t.Fatalf("CNAME domain change while CNAME intent queued: %v", err)
		}
		if result.Site.CNAMETaskID == nil || *result.Site.CNAMETaskID == *initial.Site.CNAMETaskID {
			t.Fatal("CNAME domain change did not issue a new CNAME intent")
		}
		if err := intents.PrepareIntent(t.Context(), startJob(t, *initial.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatalf("superseded intent: %v", err)
		}
		if state, code := jobState(t, *initial.Site.CNAMETaskID); state != "failed" || code != "intent_superseded" {
			t.Fatalf("superseded intent state=%s code=%s", state, code)
		}
		if _, err := intents.Get(t.Context(), tenant.scopeID, initial.Site.ID); !errors.Is(err, cnameallocation.ErrNotFound) {
			t.Fatalf("superseded intent allocated: %v", err)
		}
		if err := intents.PrepareIntent(t.Context(), startJob(t, *result.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatalf("current intent: %v", err)
		}
		completeAllocation(t, initial.Site.ID)
		var cname, cnameDomain, cnameHostname string
		if err := pool.QueryRow(t.Context(), `SELECT cname,cname_domain,cname_hostname2 FROM sites WHERE id=$1`, initial.Site.ID).
			Scan(&cname, &cnameDomain, &cnameHostname); err != nil || cname != "edge.cdn2.example.com" ||
			cnameDomain != "cdn2.example.com" || cnameHostname != "edge.cdn2.example.com" {
			t.Fatalf("site CNAME after new intent cname=%s domain=%s hostname=%s err=%v", cname, cnameDomain, cnameHostname, err)
		}
	})
	t.Run("batch", func(t *testing.T) {
		initial := create(t, owner, "platform-batch")
		markFailed(t, initial.Site.ID)
		request := BatchActionRequest{Action: BatchActionRegenerateCNAME,
			Items:          []BatchActionItem{{ID: initial.Site.ID, ExpectedRevision: initial.Site.Revision}},
			IdempotencyKey: "platform-batch-retry", RequestID: "platform-batch-retry"}
		result, err := service.BatchAction(t.Context(), actor, request)
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Items) != 1 || result.Items[0].Status != "queued" || result.Items[0].Site == nil || result.Items[0].Site.CNAMETaskID == nil {
			t.Fatalf("batch regeneration = %+v", result)
		}
		replayed, err := service.BatchAction(t.Context(), actor, request)
		if err != nil || !replayed.Replayed || replayed.Items[0].Site == nil || *replayed.Items[0].Site.CNAMETaskID != *result.Items[0].Site.CNAMETaskID {
			t.Fatalf("batch replay changed durable intent: %v", err)
		}
		assertWriteFacts(t, initial.Site.ID, "site.batch.regenerate_cname", request.RequestID)
		var publications int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_automatic_publication_requests WHERE target_scope_id=$1 AND source_request_id=$2`, tenant.scopeID, request.RequestID).Scan(&publications); err != nil || publications != 0 {
			t.Fatalf("DNS-only retry enqueued edge publication: %d err=%v", publications, err)
		}
		assertIntent(t, initial.Site.ID, *result.Items[0].Site.CNAMETaskID)
	})
	// 10-26 线上 ikvm.asia：分配失败后站点投影 cname_domain=''（默认区域），批量重新生成
	// 把 '' 原样写回而意图记真实域名，412 触发器拒为 P1134，整批 500。
	t.Run("batch regenerates a failed allocation in the default zone", func(t *testing.T) {
		initial := create(t, owner, "platform-batch-failed-alloc")
		if err := intents.PrepareIntent(t.Context(), startJob(t, *initial.Site.CNAMETaskID, "dns.cname.intent")); err != nil {
			t.Fatal(err)
		}
		allocation, err := intents.Get(t.Context(), tenant.scopeID, initial.Site.ID)
		if err != nil {
			t.Fatal(err)
		}
		claim := startJob(t, allocation.JobID, "dns.cname.allocation")
		if _, err := intents.Fail(t.Context(), cnameallocation.ResultRequest{TargetScopeID: tenant.scopeID, SiteID: initial.Site.ID,
			AllocationID: allocation.ID, JobID: allocation.JobID, ExpectedRevision: allocation.Revision, WorkerID: claim.WorkerID,
			Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, Sequence: 1, FailureCode: "dns_reconcile_unavailable"}); err != nil {
			t.Fatalf("fail allocation: %v", err)
		}
		var state, domain string
		var revision int64
		if err := pool.QueryRow(t.Context(), `SELECT cname_state,cname_domain,revision FROM sites WHERE id=$1`, initial.Site.ID).
			Scan(&state, &domain, &revision); err != nil || state != "failed" || domain != "" {
			t.Fatalf("failed allocation projection state=%s domain=%q err=%v", state, domain, err)
		}
		request := BatchActionRequest{Action: BatchActionRegenerateCNAME,
			Items:          []BatchActionItem{{ID: initial.Site.ID, ExpectedRevision: revision}},
			IdempotencyKey: "platform-batch-failed-alloc", RequestID: "platform-batch-failed-alloc"}
		result, err := service.BatchAction(t.Context(), actor, request)
		if err != nil {
			t.Fatalf("batch regeneration of failed allocation: %v", err)
		}
		if len(result.Items) != 1 || result.Items[0].Status != "queued" || result.Items[0].Site == nil || result.Items[0].Site.CNAMETaskID == nil {
			t.Fatalf("batch regeneration = %+v", result)
		}
		assertIntent(t, initial.Site.ID, *result.Items[0].Site.CNAMETaskID)
	})
	t.Run("other batch mutations retain automatic publication", func(t *testing.T) {
		initial := create(t, owner, "batch-edge-publication")
		revision := initial.Site.Revision
		for _, action := range []string{BatchActionEnable, BatchActionDisable, BatchActionDelete} {
			request := BatchActionRequest{Action: action, Items: []BatchActionItem{{ID: initial.Site.ID, ExpectedRevision: revision}},
				IdempotencyKey: "edge-batch-" + action, RequestID: "edge-batch-" + action}
			result, err := service.BatchAction(t.Context(), actor, request)
			if err != nil || len(result.Items) != 1 || result.Items[0].Error != nil {
				t.Fatalf("batch %s failed: %+v %v", action, result, err)
			}
			replayed, err := service.BatchAction(t.Context(), actor, request)
			if err != nil || !replayed.Replayed {
				t.Fatalf("batch %s replay failed: %v", action, err)
			}
			var publications int
			if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM edge_automatic_publication_requests WHERE target_scope_id=$1 AND operation=$2`, tenant.scopeID, "site.batch."+action).Scan(&publications); err != nil || publications != 1 {
				t.Fatalf("batch %s publication count=%d err=%v", action, publications, err)
			}
			revision++
		}
	})
	t.Run("worker rejects authority revoked after enqueue", func(t *testing.T) {
		for _, state := range []string{"revoked", "expired"} {
			t.Run(state, func(t *testing.T) {
				candidate := actor
				candidate.SessionID = addonSiteInsertSubscriptionSession(t, pool, manager.ScopeID, manager.UserID)
				initial := create(t, candidate, "worker-session-"+state)
				query := `UPDATE auth_sessions SET revoked_at=clock_timestamp(),revocation_reason='logout' WHERE id=$1`
				if state == "expired" {
					query = `UPDATE auth_sessions SET expires_at=clock_timestamp()-interval '1 minute' WHERE id=$1`
				}
				if _, err := pool.Exec(t.Context(), query, candidate.SessionID); err != nil {
					t.Fatal(err)
				}
				claim := startIntent(t, *initial.Site.CNAMETaskID)
				if err := intents.PrepareIntent(t.Context(), claim); err != nil {
					t.Fatal(err)
				}
				var jobState, siteState string
				if err := pool.QueryRow(t.Context(), `SELECT job.state,site.cname_state FROM background_jobs job
					JOIN sites site ON site.cname_task_id=job.id WHERE job.id=$1`, claim.Job.ID).Scan(&jobState, &siteState); err != nil || jobState != "failed" || siteState != "failed" {
					t.Fatalf("inactive authority executed job=%s site=%s err=%v", jobState, siteState, err)
				}
				if _, err := intents.Get(t.Context(), tenant.scopeID, initial.Site.ID); !errors.Is(err, cnameallocation.ErrNotFound) {
					t.Fatalf("inactive authority created allocation: %v", err)
				}
			})
		}
	})
	t.Run("platform intent concurrent execution", func(t *testing.T) {
		initial := create(t, actor, "concurrent-platform-worker")
		claim := startIntent(t, *initial.Site.CNAMETaskID)
		const workers = 8
		results := make(chan error, workers)
		start := make(chan struct{})
		for range workers {
			go func() {
				<-start
				results <- intents.PrepareIntent(t.Context(), claim)
			}()
		}
		close(start)
		successes := 0
		for range workers {
			err := <-results
			if err == nil {
				successes++
			} else if !errors.Is(err, cnameallocation.ErrConflict) && !errors.Is(err, cnameallocation.ErrClaimLost) &&
				!errors.Is(err, cnameallocation.ErrRetryable) {
				t.Errorf("platform concurrent execution: %v", err)
			}
		}
		var state string
		var jobs int
		if err := pool.QueryRow(t.Context(), `SELECT state,
			(SELECT count(*) FROM background_jobs WHERE kind='dns.cname.allocation' AND request_id='concurrent-platform-worker')
			FROM background_jobs WHERE id=$1`, claim.Job.ID).Scan(&state, &jobs); err != nil || state != "succeeded" || jobs != 1 || successes < 1 {
			t.Fatalf("platform concurrency state=%s jobs=%d successes=%d err=%v", state, jobs, successes, err)
		}
	})
	t.Run("allocation concurrent replay preserves one durable job", func(t *testing.T) {
		initial := create(t, owner, "concurrent-allocation")
		request := cnameallocation.AllocateRequest{TargetScopeID: tenant.scopeID, SiteID: initial.Site.ID,
			ActorScopeID: owner.ScopeID, ActorUserID: owner.UserID, Mode: cnameallocation.ModeSite, Domain: "cdn.example.com",
			IdempotencyKey: "concurrent-allocation", RequestID: "concurrent-allocation", TraceID: "concurrent-allocation", ExpectedSiteRevision: initial.Site.Revision}
		const workers = 8
		results := make([]cnameallocation.Allocation, workers)
		errorsByWorker := make([]error, workers)
		var wait sync.WaitGroup
		start := make(chan struct{})
		for index := range workers {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				<-start
				results[index], errorsByWorker[index] = intents.Allocate(t.Context(), request)
			}(index)
		}
		close(start)
		wait.Wait()
		for index, err := range errorsByWorker {
			if errors.Is(err, cnameallocation.ErrConflict) || errors.Is(err, cnameallocation.ErrRetryable) {
				results[index], err = intents.Allocate(t.Context(), request)
			}
			if err != nil {
				t.Fatalf("allocation worker %d: %v (site=%s revision=%d scope=%s actor=%s)", index, err, request.SiteID, request.ExpectedSiteRevision, request.TargetScopeID, request.ActorScopeID)
			}
			if index > 0 && (results[index].ID != results[0].ID || results[index].JobID != results[0].JobID) {
				t.Fatal("concurrent allocation created a second identity")
			}
		}
		var jobs, requests int
		if err := pool.QueryRow(t.Context(), `SELECT
			(SELECT count(*) FROM background_jobs WHERE kind='dns.cname.allocation' AND request_id=$1),
			(SELECT count(*) FROM cname_allocation_requests WHERE site_id=$2 AND operation='allocate')`, request.RequestID, initial.Site.ID).Scan(&jobs, &requests); err != nil || jobs != 1 || requests != 1 {
			t.Fatalf("replay duplicated allocation jobs=%d requests=%d err=%v", jobs, requests, err)
		}
		request.Domain = "other.example.com"
		if _, err := intents.Allocate(t.Context(), request); !errors.Is(err, cnameallocation.ErrConflict) {
			t.Fatalf("changed replay digest accepted: %v", err)
		}
	})
	t.Run("missing platform permissions fail closed", func(t *testing.T) {
		permissions := []string{"sites.manage", "dns.manage", "package_subscriptions.manage"}
		for _, missing := range permissions {
			t.Run(missing, func(t *testing.T) {
				userID := uuid.New()
				name := "missing-" + strings.NewReplacer(".", "-", "_", "-").Replace(missing)
				addonSiteInsertSubscriptionUser(t, pool, manager.ScopeID, userID, name)
				grants := []string{}
				for _, permission := range permissions {
					if permission != missing {
						grants = append(grants, permission)
					}
				}
				addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, userID, name, grants...)
				candidate := Actor{UserID: userID, ScopeID: manager.ScopeID, ScopeKind: "platform",
					SessionID: addonSiteInsertSubscriptionSession(t, pool, manager.ScopeID, userID)}
				_, err := service.Create(t.Context(), candidate, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
					Fields: fields(name + ".example.co.uk"), IdempotencyKey: name, RequestID: name})
				if !errors.Is(err, ErrPermissionDenied) {
					t.Fatalf("missing %s accepted: %v", missing, err)
				}
			})
		}
	})
	t.Run("invalid session and target bindings fail closed", func(t *testing.T) {
		for _, kind := range []string{"missing", "revoked", "expired", "other-user", "other-scope"} {
			t.Run(kind, func(t *testing.T) {
				candidate := actor
				candidate.SessionID = uuid.Nil
				if kind != "missing" {
					sessionUser, sessionScope := manager.UserID, manager.ScopeID
					if kind == "other-user" {
						sessionUser = uuid.New()
						addonSiteInsertSubscriptionUser(t, pool, manager.ScopeID, sessionUser, "other-cname-admin")
					}
					if kind == "other-scope" {
						sessionUser, sessionScope = tenant.userID, tenant.scopeID
					}
					candidate.SessionID = addonSiteInsertSubscriptionSession(t, pool, sessionScope, sessionUser)
					if kind == "revoked" {
						if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=clock_timestamp(),revocation_reason='logout' WHERE id=$1`, candidate.SessionID); err != nil {
							t.Fatal(err)
						}
					}
					if kind == "expired" {
						if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET expires_at=clock_timestamp()-interval '1 minute' WHERE id=$1`, candidate.SessionID); err != nil {
							t.Fatal(err)
						}
					}
				}
				key := "invalid-session-" + kind
				_, err := service.Create(t.Context(), candidate, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
					Fields: fields(key + ".example.co.uk"), IdempotencyKey: key, RequestID: key})
				if !errors.Is(err, ErrPermissionDenied) {
					t.Fatalf("invalid session accepted: %v", err)
				}
				initial := create(t, owner, key+"-existing")
				markFailed(t, initial.Site.ID)
				updatedFields := fields(key + "-existing.example.co.uk")
				updatedFields.CNAMERegenerate = true
				_, err = service.Update(t.Context(), candidate, UpdateRequest{ID: initial.Site.ID, ExpectedRevision: initial.Site.Revision,
					Fields: updatedFields, IdempotencyKey: key + "-update", RequestID: key + "-update"})
				if !errors.Is(err, ErrPermissionDenied) {
					t.Fatalf("update accepted invalid session: %v", err)
				}
				batch, err := service.BatchAction(t.Context(), candidate, BatchActionRequest{Action: BatchActionRegenerateCNAME,
					Items:          []BatchActionItem{{ID: initial.Site.ID, ExpectedRevision: initial.Site.Revision}},
					IdempotencyKey: key + "-batch", RequestID: key + "-batch"})
				if err != nil || len(batch.Items) != 1 || batch.Items[0].Error == nil || batch.Items[0].Error.Code != "permission_denied" {
					t.Fatalf("batch accepted invalid session: %+v %v", batch, err)
				}
			})
		}
		other := addonSiteInsertSubscriptionTenant(t, pool, "Other target", "other-target-owner")
		for _, kind := range []string{"owner", "scope", "subscription", "product"} {
			t.Run(kind, func(t *testing.T) {
				key := "invalid-binding-" + kind
				request := CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
					Fields: fields(key + ".example.co.uk"), IdempotencyKey: key, RequestID: key}
				switch kind {
				case "owner":
					request.OwnerUserID = other.userID
				case "scope":
					request.TargetScopeID = other.scopeID
				case "subscription":
					id := uuid.New()
					request.Fields.PackageSubscriptionID = &id
				case "product":
					id := uuid.New()
					request.Fields.PackageID = &id
				}
				if _, err := service.Create(t.Context(), actor, request); !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("invalid target binding accepted: %v", err)
				}
			})
		}
	})
	// N20 (live 09:47:01): the site creation's automatic publication and the
	// CNAME intent deadlocked. The publication holds the scope row and the
	// subscription (checkPackageRuntime FOR UPDATE), then inserts
	// site_ipv6_rollout_targets (FK key-share on the site); the intent held
	// the site FOR UPDATE and waited FOR SHARE on the subscription.
	t.Run("N20 intent and automatic publication do not deadlock", func(t *testing.T) {
		initial := create(t, actor, "n20-deadlock")
		claim := startIntent(t, *initial.Site.CNAMETaskID)
		publication, err := pool.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer publication.Rollback(context.Background())
		var publisherPID int
		if err := publication.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&publisherPID); err != nil {
			t.Fatal(err)
		}
		if _, err := publication.Exec(t.Context(), `SELECT 1 FROM edge_configuration_scopes WHERE scope_id=$1 FOR UPDATE`, tenant.scopeID); err != nil {
			t.Fatal(err)
		}
		if _, err := publication.Exec(t.Context(), `SELECT 1 FROM package_subscriptions WHERE tenant_scope_id=$1 AND id=$2 FOR UPDATE`,
			tenant.scopeID, opened.Subscription.ID); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		prepared := make(chan error, 1)
		go func() { prepared <- intents.PrepareIntent(context.Background(), claim) }()
		// Wait until the intent blocks on a lock the publication holds.
		for waiting := false; !waiting; {
			if time.Since(started) > 10*time.Second {
				t.Fatal("intent never waited on the publication's locks")
			}
			select {
			case err := <-prepared:
				t.Fatalf("intent finished before the publication released its locks: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
				WHERE $1=ANY(pg_blocking_pids(pid)))`, publisherPID).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
		}
		configID := uuid.New()
		if _, err := publication.Exec(t.Context(), `INSERT INTO config_versions(id,configuration_scope_id,canonical_snapshot,
			canonical_snapshot_sha256,generator_name,generator_version,status,idempotency_key,request_digest,created_at)
			VALUES($1,$2,$3,$4,'n20','1','building',$5,$6,clock_timestamp())`, configID, tenant.scopeID,
			[]byte(configID.String()), make([]byte, 32), configID.String(), make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		if _, err := publication.Exec(t.Context(), `INSERT INTO site_ipv6_rollout_targets(config_version_id,configuration_scope_id,
			site_id,source_revision,desired_enabled,site_revision,created_at) VALUES($1,$2,$3,1,true,$4,clock_timestamp())`,
			configID, tenant.scopeID, initial.Site.ID, initial.Site.Revision); err != nil {
			t.Fatalf("publication rollout target (deadlock victim?): %v", err)
		}
		if err := publication.Commit(t.Context()); err != nil {
			t.Fatalf("publication commit: %v", err)
		}
		select {
		case err := <-prepared:
			if err != nil {
				t.Fatalf("intent after the publication: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("intent still blocked 5s after the publication committed")
		}
		var jobState string
		var allocations int
		if err := pool.QueryRow(t.Context(), `SELECT state,(SELECT count(*) FROM cname_site_bindings
			WHERE tenant_scope_id=$2 AND site_id=$3) FROM background_jobs WHERE id=$1`, claim.Job.ID, tenant.scopeID,
			initial.Site.ID).Scan(&jobState, &allocations); err != nil || jobState != "succeeded" || allocations < 1 {
			t.Fatalf("intent job=%s allocations=%d err=%v", jobState, allocations, err)
		}
		if elapsed := time.Since(started); elapsed > 10*time.Second {
			t.Fatalf("intent allocated %s after the claim, want at most 10s", elapsed)
		}
	})
}
