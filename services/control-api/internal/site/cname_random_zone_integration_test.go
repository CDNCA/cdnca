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
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/jobstate"
	"github.com/cdnca/cdnca/services/control-api/internal/nodescheduler"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration 550: a new site without a package
// gets one of the CNAME domains marked 参与随机分配, on any DNS provider; with
// none marked it uses the default CNAME domain; an allocated site keeps its
// domain across flag changes and 重新生成; the platform copy carries the mark.
func TestCNAMERandomZoneAllocation(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "cname_random_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "cname-random-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "platform-site-admin", "platform.admin")

	// Platform default line group: sites without a package freeze its nodes.
	tokens, err := identity.NewTokenManager(strings.Repeat("r", 32), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := sessioncredential.NewVerifier(tokens, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	apiKeys, err := apikeycredential.NewVerifier(bytes.Repeat([]byte{0x32}, 32), func() time.Time { return now })
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
	raw, _, err := tokens.Mint(manager.UserID, manager.ScopeID, manager.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	platformActor := nodescheduler.Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform",
		Credential: nodescheduler.Credential{Kind: nodescheduler.CredentialSession, Raw: raw}}
	group, err := platformScheduler.PutGroup(t.Context(), platformActor, nodescheduler.PutGroupRequest{
		Name: "平台默认", Policy: nodescheduler.DefaultHealthPolicy(),
		Endpoints:      []nodescheduler.Endpoint{{ID: uuid.New(), Address: "198.51.100.9", Port: 80, Weight: 1, Enabled: true}},
		IdempotencyKey: "cname-random-group", RequestID: "cname-random-group",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := platformScheduler.SetPlatformDefault(t.Context(), platformActor, group.Group.GroupID, true, "cname-random-default"); err != nil {
		t.Fatal(err)
	}

	// 节点管理 > DNS配置: the platform provider with three CNAME domains; the
	// first is the default, b and c take part in random allocation.
	cipher, err := dnsacme.NewAESGCMCredentialCipher("cname-random-v1", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	dns := dnsacme.NewServiceWithClockAndVerifier(dnsacme.NewStore(pool), cipher, acceptCredentials{}, time.Now)
	platform := dnsacme.Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform"}
	if _, err := dns.SavePlatformConfig(t.Context(), platform, dnsacme.SavePlatformConfigRequest{ProviderType: "dnspod_cn",
		Credentials: map[string]string{"dp_id": "1", "dp_key": "fixture"}, TTL: 600, ExpectedRevision: 1,
		IdempotencyKey: "cname-random-config", RequestID: "cname-random-config"}); err != nil {
		t.Fatalf("save platform DNS config: %v", err)
	}
	marked := true
	platformZones := map[string]dnsacme.PlatformZone{}
	for _, item := range []struct {
		name   string
		random *bool
	}{{"a.cdn.example.com", nil}, {"b.cdn.example.com", &marked}, {"c.cdn.example.com", &marked}} {
		zone, err := dns.CreatePlatformZone(t.Context(), platform, dnsacme.PlatformZoneRequest{Name: item.name,
			RandomAllocation: item.random, IdempotencyKey: "cname-random-zone-" + item.name, RequestID: "cname-random-zone-" + item.name})
		if err != nil {
			t.Fatalf("create platform zone %s: %v", item.name, err)
		}
		platformZones[item.name] = zone
	}

	tenant := addonSiteInsertSubscriptionTenant(t, pool, "CNAME random", "cname-random-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage", "dns.manage")
	// A tenant DNS account on another provider with its own marked zone: the
	// draw may cross providers.
	ownProvider := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_providers(id,scope_id,name,provider_type,credential_key_id,credential_ciphertext,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,'阿里云','aliyun','fixture-key',$3,$4,$4)`, ownProvider, tenant.scopeID, make([]byte, 32), tenant.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO edge_automatic_publication_policy_facts(
		target_scope_id,revision,mode,node_ids,activation_timeout_ms,observation_window_ms,
		required_consecutive_successes,max_attempts,deadline_window_seconds,
		actor_scope_id,actor_user_id,reason,created_at)
		SELECT $1,1,'automatic',$2,30000,15000,2,3,600,$1,$3,'integration_policy',clock_timestamp()
		WHERE NOT EXISTS(SELECT 1 FROM edge_automatic_publication_policy_facts WHERE target_scope_id=$1)`,
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
	intents.UsePlatformDNS(dns)
	var pickIndex int
	var pickedFrom []int
	intents.UseZonePick(func(n int) int {
		pickedFrom = append(pickedFrom, n)
		return pickIndex % n
	})
	owner := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	var tenantID uuid.UUID
	if err := pool.QueryRow(t.Context(), `SELECT tenant_id FROM access_scopes WHERE id=$1`, tenant.scopeID).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	runIntent := func(t *testing.T, jobID uuid.UUID) (string, string) {
		t.Helper()
		var claim jobstate.Claim
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			var err error
			claim, err = jobstate.StartTx(t.Context(), tx, jobstate.StartInput{TenantID: tenantID, JobID: jobID,
				Kind: "dns.cname.intent", WorkerID: "cname-random-worker", LeaseDuration: time.Minute}, now)
			return err
		}); err != nil {
			t.Fatalf("claim intent %s: %v", jobID, err)
		}
		if err := intents.PrepareIntent(t.Context(), claim); err != nil {
			t.Fatalf("prepare intent: %v", err)
		}
		var state, code string
		if err := pool.QueryRow(t.Context(), `SELECT job.state,COALESCE(item.error_code,'')
			FROM background_jobs job JOIN background_job_items item ON item.tenant_id=job.tenant_id AND item.job_id=job.id
			WHERE job.tenant_id=$1 AND job.id=$2`, tenantID, jobID).Scan(&state, &code); err != nil {
			t.Fatal(err)
		}
		return state, code
	}
	allocate := func(t *testing.T, domain string) (Site, cnameallocation.Allocation) {
		t.Helper()
		created, err := service.Create(t.Context(), owner, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
			Fields: SiteFields{Domains: []string{domain}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
				Enabled: false, Status: StatusDisabled},
			IdempotencyKey: "cname-random-" + domain, RequestID: "cname-random-" + domain})
		if err != nil || created.Site.CNAMETaskID == nil {
			t.Fatalf("create site %s: task=%v err=%v", domain, created.Site.CNAMETaskID, err)
		}
		if state, code := runIntent(t, *created.Site.CNAMETaskID); state != "succeeded" {
			t.Fatalf("intent of %s state=%s code=%s", domain, state, code)
		}
		allocation, err := intents.Get(t.Context(), tenant.scopeID, created.Site.ID)
		if err != nil {
			t.Fatal(err)
		}
		return created.Site, allocation
	}
	settle := func(t *testing.T, siteID uuid.UUID, allocation cnameallocation.Allocation, failure string) {
		t.Helper()
		var claim jobstate.Claim
		if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
			var err error
			claim, err = jobstate.StartTx(t.Context(), tx, jobstate.StartInput{TenantID: tenantID, JobID: allocation.JobID,
				Kind: "dns.cname.allocation", WorkerID: "cname-random-allocation", LeaseDuration: time.Minute}, now)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		request := cnameallocation.ResultRequest{TargetScopeID: tenant.scopeID, SiteID: siteID,
			AllocationID: allocation.ID, JobID: allocation.JobID, ExpectedRevision: allocation.Revision, WorkerID: claim.WorkerID,
			Attempt: claim.Job.Attempt, LeaseID: claim.LeaseID, Sequence: 1, FailureCode: failure}
		var err error
		if failure == "" {
			_, err = intents.Complete(t.Context(), request)
		} else {
			_, err = intents.Fail(t.Context(), request)
		}
		if err != nil {
			t.Fatalf("settle allocation (failure %q): %v", failure, err)
		}
	}
	setRandom := func(t *testing.T, name string, random bool) {
		t.Helper()
		current := platformZones[name]
		updated, err := dns.UpdatePlatformZone(t.Context(), platform, dnsacme.PlatformZoneRequest{ID: current.ID, Name: current.Name,
			Remark: current.Remark, RandomAllocation: &random, ExpectedRevision: current.Revision,
			IdempotencyKey: "cname-random-mark-" + name + "-" + uuid.NewString(), RequestID: "cname-random-mark-" + name})
		if err != nil || updated.RandomAllocation != random {
			t.Fatalf("mark %s random=%v: %+v err=%v", name, random, updated, err)
		}
		platformZones[name] = updated
	}

	var firstSite Site
	var firstDomain string
	t.Run("tenant copy carries the random allocation mark", func(t *testing.T) {
		pickIndex = 0
		firstSite, _ = allocate(t, "first.example.com")
		rows, err := pool.Query(t.Context(), `SELECT name,random_allocation,is_default FROM dns_zones
			WHERE scope_id=$1 AND provider_id=$2 ORDER BY name`, tenant.scopeID, dnsacme.PlatformProviderCopyID(tenant.scopeID))
		if err != nil {
			t.Fatal(err)
		}
		type copyRow struct {
			name            string
			random, primary bool
		}
		copies, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (copyRow, error) {
			var value copyRow
			return value, row.Scan(&value.name, &value.random, &value.primary)
		})
		if err != nil || len(copies) != 3 ||
			copies[0] != (copyRow{"a.cdn.example.com", false, true}) ||
			copies[1] != (copyRow{"b.cdn.example.com", true, false}) ||
			copies[2] != (copyRow{"c.cdn.example.com", true, false}) {
			t.Fatalf("tenant copies=%+v err=%v", copies, err)
		}
	})

	// The tenant's own zone on another provider is also marked.
	if _, err := pool.Exec(t.Context(), `INSERT INTO dns_zones(id,scope_id,provider_id,name,random_allocation,created_by_user_id,updated_by_user_id)
		VALUES($1,$2,$3,'own.cdn.example.net',true,$4,$4)`, uuid.New(), tenant.scopeID, ownProvider, tenant.userID); err != nil {
		t.Fatal(err)
	}

	t.Run("new sites draw among the marked zones across providers", func(t *testing.T) {
		seen := map[string]uuid.UUID{}
		for index := range 3 {
			pickIndex = index
			pickedFrom = nil
			_, allocation := allocate(t, "draw"+string(rune('a'+index))+".example.com")
			if len(pickedFrom) != 1 || pickedFrom[0] != 3 {
				t.Fatalf("draw sizes=%v, want one draw among 3 marked zones", pickedFrom)
			}
			if !strings.HasSuffix(allocation.Hostname, "."+allocation.Domain) {
				t.Fatalf("hostname %q outside domain %q", allocation.Hostname, allocation.Domain)
			}
			seen[allocation.Domain] = allocation.ProviderID
		}
		// Candidates are ordered by name: b, c (platform), own (tenant aliyun).
		if seen["b.cdn.example.com"] != dnsacme.PlatformProviderCopyID(tenant.scopeID) ||
			seen["c.cdn.example.com"] != dnsacme.PlatformProviderCopyID(tenant.scopeID) || seen["own.cdn.example.net"] != ownProvider {
			t.Fatalf("drawn domains=%v", seen)
		}
	})

	t.Run("regenerating a failed CNAME keeps its domain", func(t *testing.T) {
		pickIndex = 2
		site, allocation := allocate(t, "regen.example.com")
		firstDomain = allocation.Domain
		settle(t, site.ID, allocation, "provider_write_failed")
		current, err := service.Get(t.Context(), owner, site.ID)
		if err != nil {
			t.Fatal(err)
		}
		// The editor echoes the drawn domain back with 重新生成.
		pickIndex = 0
		pickedFrom = nil
		updated, err := service.Update(t.Context(), owner, UpdateRequest{ID: site.ID, ExpectedRevision: current.Revision,
			Fields: SiteFields{Domains: current.Domains, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
				Enabled: false, Status: StatusDisabled, CNAMEDomain: *current.CNAMEDomain, CNAMERegenerate: true},
			IdempotencyKey: "cname-random-regen", RequestID: "cname-random-regen"})
		if err != nil || updated.Site.CNAMETaskID == nil {
			t.Fatalf("regenerate: %+v err=%v", updated.Site.CNAMETaskID, err)
		}
		if state, code := runIntent(t, *updated.Site.CNAMETaskID); state != "succeeded" {
			t.Fatalf("regenerate intent state=%s code=%s", state, code)
		}
		again, err := intents.Get(t.Context(), tenant.scopeID, site.ID)
		if err != nil || again.Domain != firstDomain || again.ZoneID != allocation.ZoneID || len(pickedFrom) != 0 {
			t.Fatalf("regenerated domain=%q zone=%s want %q/%s draws=%v err=%v", again.Domain, again.ZoneID, firstDomain,
				allocation.ZoneID, pickedFrom, err)
		}
	})

	t.Run("allocated sites keep their domain when the marks change; none marked uses the default", func(t *testing.T) {
		before, err := intents.Get(t.Context(), tenant.scopeID, firstSite.ID)
		if err != nil {
			t.Fatal(err)
		}
		setRandom(t, "b.cdn.example.com", false)
		setRandom(t, "c.cdn.example.com", false)
		if _, err := pool.Exec(t.Context(), `UPDATE dns_zones SET random_allocation=false WHERE scope_id=$1 AND provider_id=$2`,
			tenant.scopeID, ownProvider); err != nil {
			t.Fatal(err)
		}
		var marked int
		if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM dns_zones WHERE scope_id=$1 AND random_allocation`,
			tenant.scopeID).Scan(&marked); err != nil || marked != 0 {
			t.Fatalf("marked zones after unmarking=%d err=%v (platform sync must copy false)", marked, err)
		}
		after, err := intents.Get(t.Context(), tenant.scopeID, firstSite.ID)
		if err != nil || after.ZoneID != before.ZoneID || after.Hostname != before.Hostname {
			t.Fatalf("allocated site moved: before=%s/%s after=%s/%s err=%v", before.Domain, before.Hostname, after.Domain, after.Hostname, err)
		}
		pickedFrom = nil
		_, fallback := allocate(t, "fallback.example.com")
		if fallback.Domain != "a.cdn.example.com" || len(pickedFrom) != 0 {
			t.Fatalf("no marked zone: domain=%q draws=%v, want the default a.cdn.example.com", fallback.Domain, pickedFrom)
		}
	})

	t.Run("an explicit CNAME domain is used as given on its own provider", func(t *testing.T) {
		// The default zone is on the platform copy; the explicit domain is on
		// the tenant's aliyun account (was cname_zone_provider_mismatch).
		site, drawn := allocate(t, "explicit.example.com")
		settle(t, site.ID, drawn, "")
		current, err := service.Get(t.Context(), owner, site.ID)
		if err != nil {
			t.Fatal(err)
		}
		pickedFrom = nil
		explicit, err := intents.Allocate(t.Context(), cnameallocation.AllocateRequest{TargetScopeID: tenant.scopeID, SiteID: site.ID,
			ActorScopeID: tenant.scopeID, ActorUserID: tenant.userID, Mode: cnameallocation.ModeSite, Domain: "own.cdn.example.net",
			IdempotencyKey: "cname-random-explicit", RequestID: "cname-random-explicit", TraceID: "cname-random-explicit",
			ExpectedSiteRevision: current.Revision, Regenerate: true})
		if err != nil || explicit.Domain != "own.cdn.example.net" || explicit.ProviderID != ownProvider || len(pickedFrom) != 0 {
			t.Fatalf("explicit allocation=%+v draws=%v err=%v", explicit, pickedFrom, err)
		}
		// Its own provider disabled: refused with the provider reason.
		if _, err := pool.Exec(t.Context(), `UPDATE dns_providers SET status='disabled' WHERE scope_id=$1 AND id=$2`,
			tenant.scopeID, ownProvider); err != nil {
			t.Fatal(err)
		}
		other, otherDrawn := allocate(t, "explicit2.example.com")
		settle(t, other.ID, otherDrawn, "")
		current, err = service.Get(t.Context(), owner, other.ID)
		if err != nil {
			t.Fatal(err)
		}
		_, err = intents.Allocate(t.Context(), cnameallocation.AllocateRequest{TargetScopeID: tenant.scopeID, SiteID: other.ID,
			ActorScopeID: tenant.scopeID, ActorUserID: tenant.userID, Mode: cnameallocation.ModeSite, Domain: "own.cdn.example.net",
			IdempotencyKey: "cname-random-disabled", RequestID: "cname-random-disabled", TraceID: "cname-random-disabled",
			ExpectedSiteRevision: current.Revision, Regenerate: true})
		if err == nil {
			t.Fatal("allocation on a disabled provider succeeded")
		}
	})
}
