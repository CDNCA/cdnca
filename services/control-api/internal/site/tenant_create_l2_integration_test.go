package site

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// REF-ROLE-L2-CREATE (Codex 双角色审测 10-27): a tenant's create with
// origin_pool.l2_mode off/custom stores package and no config (as the update
// keeps the platform's); a platform administrator's create keeps off/custom,
// and migration 466 still refuses a custom config of another scope.
func TestTenantSiteCreateFollowsPackageL2(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "site_create_l2_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "site-l2-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "platform-site-admin", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Site L2", "site-l2-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "site-owner", "sites.manage")
	other := addonSiteInsertSubscriptionTenant(t, pool, "Site L2 other", "site-l2-other")
	l2Config := func(scopeID, userID uuid.UUID, name string) uuid.UUID {
		id := uuid.New()
		if _, err := pool.Exec(t.Context(), `INSERT INTO l2_topology_configs(id,tenant_scope_id,name,region,mode,load_method,
			created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,'default','cache','rr',$4,$4,$5,$5)`,
			id, scopeID, name, userID, now); err != nil {
			t.Fatal(err)
		}
		return id
	}
	ownConfig := l2Config(tenant.scopeID, tenant.userID, "本租户 L2")
	otherConfig := l2Config(other.scopeID, other.userID, "他人 L2")
	store := NewStoreWithClock(pool, func() time.Time { return now }, nil)
	store.guard = installAddonSiteEntitlement(t, pool, now, time.Hour)
	service := NewService(store)
	owner := Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}
	platform := Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform", SessionID: manager.SessionID}
	create := func(t *testing.T, actor Actor, key string, pool OriginPool) (WriteResult, error) {
		t.Helper()
		return service.Create(t.Context(), actor, CreateRequest{TargetScopeID: tenant.scopeID, OwnerUserID: tenant.userID,
			Fields:     SiteFields{Domains: []string{key + ".example.com"}, HTTPPorts: []string{"80"}, Origins: []string{"192.0.2.1"}, Enabled: false, Status: StatusDisabled},
			OriginPool: &pool, IdempotencyKey: key, RequestID: key})
	}
	origin := func(mode string, config *uuid.UUID) OriginPool {
		return OriginPool{Origins: []Origin{{Host: "192.0.2.1", Port: 80, Weight: 1, Enabled: true}}, FailoverTries: 1, L2Mode: mode, L2ConfigID: config}
	}
	stored := func(t *testing.T, siteID uuid.UUID) (string, *uuid.UUID) {
		t.Helper()
		var mode string
		var config *uuid.UUID
		if err := pool.QueryRow(t.Context(), `SELECT l2_mode,l2_config_id FROM site_origin_pools WHERE site_id=$1`, siteID).Scan(&mode, &config); err != nil {
			t.Fatal(err)
		}
		return mode, config
	}
	for name, test := range map[string]OriginPool{
		"tenant off":                origin(SiteL2Off, nil),
		"tenant custom same scope":  origin(SiteL2Custom, &ownConfig),
		"tenant custom other scope": origin(SiteL2Custom, &otherConfig),
		"tenant package":            origin(SiteL2Package, nil),
		"tenant omitted":            origin("", nil),
	} {
		t.Run(name, func(t *testing.T) {
			key := "l2-" + strings.ReplaceAll(name, " ", "-")
			created, err := create(t, owner, key, test)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			if mode, config := stored(t, created.Site.ID); mode != SiteL2Package || config != nil {
				t.Fatalf("stored l2 %s %v, want package", mode, config)
			}
			// the same key and body replays the first answer
			replay, err := create(t, owner, key, test)
			if err != nil || !replay.Replayed || replay.Site.ID != created.Site.ID {
				t.Fatalf("replay: %+v %v", replay, err)
			}
		})
	}
	// CU-SITE-02: a create pool that leaves the origin timeouts out (and has
	// no owner default) stores the system defaults instead of a 400.
	t.Run("omitted timeouts fall back to the system defaults", func(t *testing.T) {
		created, err := create(t, owner, "cu-site-02-timeouts", origin(SiteL2Package, nil))
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		var connect, read int
		if err := pool.QueryRow(t.Context(), `SELECT connect_timeout_ms,read_timeout_ms FROM site_origin_pools WHERE site_id=$1`,
			created.Site.ID).Scan(&connect, &read); err != nil || connect != 3000 || read != 30000 {
			t.Fatalf("stored timeouts %d/%d err=%v, want 3000/30000", connect, read, err)
		}
	})
	t.Run("platform keeps off and same-scope custom", func(t *testing.T) {
		off, err := create(t, platform, "l2-platform-off", origin(SiteL2Off, nil))
		if err != nil {
			t.Fatal(err)
		}
		if mode, _ := stored(t, off.Site.ID); mode != SiteL2Off {
			t.Fatalf("platform off stored %s", mode)
		}
		custom, err := create(t, platform, "l2-platform-custom", origin(SiteL2Custom, &ownConfig))
		if err != nil {
			t.Fatal(err)
		}
		if mode, config := stored(t, custom.Site.ID); mode != SiteL2Custom || config == nil || *config != ownConfig {
			t.Fatalf("platform custom stored %s %v", mode, config)
		}
		if _, err := create(t, platform, "l2-platform-cross", origin(SiteL2Custom, &otherConfig)); err == nil {
			t.Fatal("platform custom of another scope was stored (migration 466)")
		}
	})
}
