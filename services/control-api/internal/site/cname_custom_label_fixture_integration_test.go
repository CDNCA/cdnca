package site

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/packagesubscription"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// cnameLabelFixture: a migrated private schema with a
// tenant, a platform default line group, a package line group and the default
// CNAME zone cdn.cdnca.com. The schema is never public.
type cnameLabelFixture struct {
	pool          *pgxpool.Pool
	service       *Service
	store         *Store
	intents       *cnameallocation.Store
	owner         Actor
	manager       packagesubscription.Actor
	tenant        addonSiteTenantFixture
	tenantID      uuid.UUID
	platformGroup uuid.UUID
	packageGroup  uuid.UUID
	now           time.Time
	clock         time.Time
}

func newCNAMELabelFixture(t *testing.T) *cnameLabelFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	dsn = databasetest.FreshDatabaseURL(t, dsn, "cname_label")
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "cname_label_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	f := &cnameLabelFixture{pool: pool, now: time.Now().UTC().Truncate(time.Second)}
	f.clock = f.now
	now := f.now
	f.manager = addonSiteInsertPlatformActor(t, pool, "cname-label-admin")
	addonSiteAssignSubscriptionRole(t, pool, f.manager.ScopeID, f.manager.UserID, "platform-site-admin", "platform.admin")
	f.tenant = addonSiteInsertSubscriptionTenant(t, pool, "CNAME label", "cname-label-owner")
	addonSiteAssignSubscriptionRole(t, pool, f.tenant.scopeID, f.tenant.userID, "site-owner", "sites.manage", "dns.manage", "node_scheduling.manage")
	scheduler := nodescheduler.NewService(pool, func() time.Time { return now })
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
	raw, _, err := tokens.Mint(f.manager.UserID, f.manager.ScopeID, f.manager.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	platformActor := nodescheduler.Actor{UserID: f.manager.UserID, ScopeID: f.manager.ScopeID, ScopeKind: "platform",
		Credential: nodescheduler.Credential{Kind: nodescheduler.CredentialSession, Raw: raw}}
	platformGroup, err := platformScheduler.PutGroup(t.Context(), platformActor, nodescheduler.PutGroupRequest{
		Name: "平台默认", Policy: nodescheduler.DefaultHealthPolicy(),
		Endpoints:      []nodescheduler.Endpoint{{ID: uuid.New(), Address: "198.51.100.7", Port: 80, Weight: 1, Enabled: true}},
		IdempotencyKey: "cname-label-platform-group", RequestID: "cname-label-platform-group",
	})
	if err != nil {
		t.Fatal(err)
	}
	packageGroup, err := scheduler.PutGroup(t.Context(),
		nodescheduler.Actor{UserID: f.tenant.userID, ScopeID: f.tenant.scopeID, ScopeKind: "tenant"}, nodescheduler.PutGroupRequest{
			Name: "套餐线路", Policy: nodescheduler.DefaultHealthPolicy(),
			Endpoints:      []nodescheduler.Endpoint{{ID: uuid.New(), Address: "192.0.2.40", Port: 80, Weight: 1, Enabled: true}},
			IdempotencyKey: "cname-label-package-group", RequestID: "cname-label-package-group",
		})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platformScheduler.SetPlatformDefault(t.Context(), platformActor, platformGroup.Group.GroupID, true,
		"cname-label-default", "cname-label-default"); err != nil {
		t.Fatal(err)
	}
	f.platformGroup, f.packageGroup = platformGroup.Group.GroupID, packageGroup.Group.GroupID
	providerID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'DNSPod','dnspod_cn','fixture-key',$3,$4,$4)`, providerID, f.tenant.scopeID, make([]byte, 32), f.tenant.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_zones(id,scope_id,provider_id,name,is_default,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'cdn.cdnca.com',true,$4,$4)`, uuid.New(), f.tenant.scopeID, providerID, f.tenant.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds,
		actor_scope_id,actor_user_id,reason,created_at)
		SELECT $1,1,'automatic',$2,30000,15000,2,3,600,$1,$3,'integration_policy',clock_timestamp()
		WHERE NOT EXISTS(SELECT 1 FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1)`,
		f.tenant.scopeID, []uuid.UUID{uuid.New()}, f.tenant.userID); err != nil {
		t.Fatal(err)
	}
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, time.Hour)
	f.store = store
	f.service = NewService(store)
	f.intents, err = cnameallocation.NewStore(pool, platformCNAMEKeyring{}, func() time.Time { return f.clock })
	if err != nil {
		t.Fatal(err)
	}
	f.owner = Actor{UserID: f.tenant.userID, ScopeID: f.tenant.scopeID, ScopeKind: "tenant"}
	if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, f.tenant.scopeID).Scan(&f.tenantID); err != nil {
		t.Fatal(err)
	}
	return f
}

// runIntent claims and executes one dns.cname.intent job; it returns the job
// state and the failure code.
func (f *cnameLabelFixture) runIntent(t *testing.T, jobID uuid.UUID) (string, string) {
	t.Helper()
	var claim jobstate.Claim
	if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
		var err error
		claim, err = jobstate.StartTx(t.Context(), tx, jobstate.StartInput{TenantID: f.tenantID, JobID: jobID,
			Kind: "dns.cname.intent", WorkerID: "cname-label-worker", LeaseDuration: time.Minute}, f.clock)
		return err
	}); err != nil {
		t.Fatalf("claim intent %s: %v", jobID, err)
	}
	if err := f.intents.PrepareIntent(t.Context(), claim); err != nil {
		t.Fatalf("prepare intent: %v", err)
	}
	var state, code string
	if err := f.pool.QueryRow(t.Context(), `SELECT job.state,COALESCE(item.error_code,'')
		FROM background_jobs job JOIN background_job_items item ON item.tenant_id=job.tenant_id AND item.job_id=job.id
		WHERE job.tenant_id=$1 AND job.id=$2`, f.tenantID, jobID).Scan(&state, &code); err != nil {
		t.Fatal(err)
	}
	return state, code
}

func (f *cnameLabelFixture) createSite(t *testing.T, domain string) Site {
	t.Helper()
	created, err := f.service.Create(t.Context(), f.owner, CreateRequest{TargetScopeID: f.tenant.scopeID, OwnerUserID: f.tenant.userID,
		Fields: SiteFields{Domains: []string{domain}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
			Enabled: false, Status: StatusDisabled},
		IdempotencyKey: "cname-label-" + domain, RequestID: "cname-label-" + domain})
	if err != nil || created.Site.CNAMETaskID == nil {
		t.Fatalf("create site %s: task=%v err=%v", domain, created.Site.CNAMETaskID, err)
	}
	return created.Site
}

// claimHostname is the hostname of the site's current CNAME claim and whether
// that claim is an explicit hostname.
func (f *cnameLabelFixture) claimHostname(t *testing.T, siteID uuid.UUID) (string, bool) {
	t.Helper()
	var hostname string
	var explicit bool
	if err := f.pool.QueryRow(t.Context(), `SELECT claim.hostname,claim.explicit_hostname FROM cname_site_bindings binding
		JOIN cname_allocations allocation ON allocation.tenant_scope_id=binding.tenant_scope_id AND allocation.id=binding.current_allocation_id
		JOIN cname_hostname_claims claim ON claim.id=allocation.current_claim_id AND claim.allocation_id=allocation.id
		WHERE binding.tenant_scope_id=$1 AND binding.site_id=$2`, f.tenant.scopeID, siteID).Scan(&hostname, &explicit); err != nil {
		t.Fatalf("claim of site %s: %v", siteID, err)
	}
	return hostname, explicit
}

// setLabel writes the side-table row of a line group prefix, a product prefix
// or a sold package name.
func (f *cnameLabelFixture) setLabel(t *testing.T, kind string, subjectID uuid.UUID, label string) {
	t.Helper()
	if _, err := f.pool.Exec(t.Context(), `INSERT INTO cname_label_settings(subject_kind,subject_id,label,updated_by_user_id,updated_at)
		VALUES($1,$2,$3,$4,now()) ON CONFLICT (subject_kind,subject_id) DO UPDATE SET label=EXCLUDED.label`,
		kind, subjectID, label, f.manager.UserID); err != nil {
		t.Fatalf("set %s label: %v", kind, err)
	}
}

// completeAllocation settles the site's pending allocation as done (the DNS
// write succeeded), so another site of the same package can bind to it.
func (f *cnameLabelFixture) completeAllocation(t *testing.T, siteID uuid.UUID) {
	t.Helper()
	allocation, err := f.intents.Get(t.Context(), f.tenant.scopeID, siteID)
	if err != nil {
		t.Fatal(err)
	}
	var claim jobstate.Claim
	if err := pgx.BeginFunc(t.Context(), f.pool, func(tx pgx.Tx) error {
		var err error
		claim, err = jobstate.StartTx(t.Context(), tx, jobstate.StartInput{TenantID: f.tenantID, JobID: allocation.JobID,
			Kind: "dns.cname.allocation", WorkerID: "cname-label-allocation", LeaseDuration: time.Minute}, f.clock)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.intents.Complete(t.Context(), cnameallocation.ResultRequest{TargetScopeID: f.tenant.scopeID, SiteID: siteID,
		AllocationID: allocation.ID, JobID: allocation.JobID, ExpectedRevision: allocation.Revision, WorkerID: claim.WorkerID,
		Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, Sequence: 1}); err != nil {
		t.Fatalf("complete allocation: %v", err)
	}
}

func (f *cnameLabelFixture) admin() Actor {
	return Actor{UserID: f.manager.UserID, ScopeID: f.manager.ScopeID, ScopeKind: "platform", SessionID: f.manager.SessionID}
}
