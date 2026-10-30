package site

import (
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/domainownership"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type trustActor struct {
	scopeID, userID uuid.UUID
	kind            string
}

func (a trustActor) ownership() domainownership.Actor {
	return domainownership.Actor{UserID: a.userID, ScopeID: a.scopeID, ScopeKind: a.kind}
}
func (a trustActor) siteActor() Actor {
	return Actor{UserID: a.userID, ScopeID: a.scopeID, ScopeKind: a.kind}
}

// trustVerifier answers TXT/HTTP checks from in-memory records keyed by name.
type trustVerifier struct {
	mu   sync.Mutex
	txt  map[string]string
	http map[string]string
}

func (f *trustVerifier) setTXT(name, token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.txt[name] = token
}
func (f *trustVerifier) setHTTP(apex, token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.http[apex] = token
}
func (f *trustVerifier) VerifyTXT(_ context.Context, name, token string) (bool, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.txt[name] == token {
		return true, "", nil
	}
	return false, "txt_not_found", nil
}
func (f *trustVerifier) VerifyHTTP(_ context.Context, apex, token string) (bool, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.http[apex] == token {
		return true, "", nil
	}
	return false, "http_mismatch", nil
}

type trustFixture struct {
	t        *testing.T
	pool     *pgxpool.Pool
	now      time.Time
	clock    func() time.Time
	admin    trustActor
	a, b     trustActor
	verifier *trustVerifier
	service  *domainownership.Service
	sites    *Service
	seq      int
}

func trustMigratedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "domain_trust_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
	})
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
	return pool
}

func newTrustFixture(t *testing.T) *trustFixture {
	t.Helper()
	pool := trustMigratedPool(t)
	f := &trustFixture{t: t, pool: pool, now: time.Now().UTC().Truncate(time.Second),
		verifier: &trustVerifier{txt: map[string]string{}, http: map[string]string{}}}
	f.clock = func() time.Time { return f.now }
	f.admin = f.insertActor("platform", "trust-admin", "platform_owner", "platform.admin", "sites.manage",
		"sites.read", "domains.security.manage", "system_configuration.manage")
	f.a = f.insertActor("tenant", "trust-a", "tenant_owner", "sites.manage", "sites.read")
	f.b = f.insertActor("tenant", "trust-b", "tenant_owner", "sites.manage", "sites.read")
	service, err := domainownership.NewService(pool, audit.NewWithClock(pool, f.clock), f.verifier, nil, f.clock)
	if err != nil {
		t.Fatal(err)
	}
	f.service = service
	store := NewStoreWithClock(pool, f.clock, nil)
	store.guard = installAddonSiteEntitlement(t, pool, f.now, 24*time.Hour)
	f.sites = NewService(store)
	return f
}

func (f *trustFixture) exec(query string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), query, args...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *trustFixture) insertActor(kind, username, role string, permissions ...string) trustActor {
	f.t.Helper()
	scopeID, userID, roleID := uuid.New(), uuid.New(), uuid.New()
	if kind == "tenant" {
		tenantID := uuid.New()
		f.exec(`INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, username)
		f.exec(`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	} else {
		var existing uuid.UUID
		if err := f.pool.QueryRow(context.Background(),
			`SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL LIMIT 1`).Scan(&existing); err == nil {
			scopeID = existing
		} else {
			f.exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID)
		}
	}
	f.exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'unused')`, userID, username)
	f.exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	f.exec(`INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,$3,'domain trust test',true)`,
		roleID, scopeID, role+"-"+username)
	for _, permission := range permissions {
		f.exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,$2) ON CONFLICT DO NOTHING`, roleID, permission)
	}
	f.exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scopeID, userID, roleID)
	digest := sha256.Sum256(userID[:])
	f.exec(`INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, uuid.New(), uuid.New(), userID, scopeID, digest[:],
		time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC))
	return trustActor{scopeID: scopeID, userID: userID, kind: kind}
}

func (f *trustFixture) setPolicy(policy string) {
	f.t.Helper()
	f.exec(`INSERT INTO platform_system_other_settings(platform_scope_id,revision,settings,updated_by_user_id,updated_at)
		VALUES($1,1,jsonb_build_object('domain_ownership_policy',$2::text),$3,$4)
		ON CONFLICT (platform_scope_id) DO UPDATE SET settings=platform_system_other_settings.settings ||
			jsonb_build_object('domain_ownership_policy',$2::text),revision=platform_system_other_settings.revision+1`,
		f.admin.scopeID, policy, f.admin.userID, f.now)
}

func (f *trustFixture) key(prefix string) string {
	f.seq++
	return prefix + "-" + uuid.NewString()[:8]
}

// createSite creates an enabled site through the site service as actor for
// owner (owner == actor for tenants).
func (f *trustFixture) createSite(actor, owner trustActor, domains ...string) (WriteResult, error) {
	key := f.key("site")
	return f.sites.Create(context.Background(), actor.siteActor(), CreateRequest{
		TargetScopeID: owner.scopeID, OwnerUserID: owner.userID, IdempotencyKey: key, RequestID: key,
		Fields: SiteFields{Domains: domains, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"},
			Enabled: true, Status: StatusActive},
	})
}

func (f *trustFixture) verify(actor trustActor, domain, method string) domainownership.Ownership {
	f.t.Helper()
	started, err := f.service.Start(context.Background(), actor.ownership(), domain, method, f.key("start"))
	if err != nil {
		f.t.Fatalf("start %s: %v", domain, err)
	}
	if method == domainownership.MethodDNSTXT {
		f.verifier.setTXT(started.TXTName, started.Token)
	} else {
		f.verifier.setHTTP(started.Apex, started.Token)
	}
	checked, err := f.service.Check(context.Background(), actor.ownership(), domain, f.key("check"))
	if err != nil || checked.Status != domainownership.StatusVerified {
		f.t.Fatalf("check %s = %+v, %v", domain, checked, err)
	}
	return checked
}

func (f *trustFixture) siteEnabled(id uuid.UUID) bool {
	f.t.Helper()
	var enabled bool
	if err := f.pool.QueryRow(context.Background(), `SELECT enabled FROM sites WHERE id=$1`, id).Scan(&enabled); err != nil {
		f.t.Fatal(err)
	}
	return enabled
}
