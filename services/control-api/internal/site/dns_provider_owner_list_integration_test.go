package site

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 网站列表/证书管理 > DNS API 的平台视图列出全部用户的
// DNS API，带「用户」列（scope 的 tenant_owner），可按用户筛选，并排除平台 DNS 副本；
// 租户视图不带用户、不能按用户筛选。
func TestPlatformDNSProviderListCarriesOwnerAndFilters(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	dsn = databasetest.FreshDatabaseURL(t, dsn, "dns_provider_owner")
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "dns_provider_owner_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "dns-owner-list-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "platform-dns-admin", "platform.admin")
	alice := dnsOwnerListInsertOwnerTenant(t, pool, "DNS owner A", "dns-owner-alice")
	// 无 tenant_owner 的 scope：「用户」列为空，不报错。
	orphan := addonSiteInsertSubscriptionTenant(t, pool, "DNS owner none", "dns-owner-viewer")

	cipher, err := dnsacme.NewAESGCMCredentialCipher("dns-owner-list-v1", bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	dns := dnsacme.NewServiceWithClockAndVerifier(dnsacme.NewStore(pool), cipher, acceptCredentials{}, time.Now)
	platform := dnsacme.Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform"}
	tenant := dnsacme.Actor{UserID: alice.userID, ScopeID: alice.scopeID, ScopeKind: "tenant"}
	// 平台 DNS 配置会给每个租户同步一份 managed_by=platform 副本。
	if _, err := dns.SavePlatformConfig(t.Context(), platform, dnsacme.SavePlatformConfigRequest{ProviderType: "dnspod_cn",
		Credentials: map[string]string{"dp_id": "1", "dp_key": "fixture"}, TTL: 600, ExpectedRevision: 1,
		IdempotencyKey: "dns-owner-list-config", RequestID: "dns-owner-list-config"}); err != nil {
		t.Fatalf("save platform DNS config: %v", err)
	}
	create := func(actor dnsacme.Actor, target uuid.UUID, name string) dnsacme.Provider {
		t.Helper()
		value, err := dns.CreateProvider(t.Context(), actor, dnsacme.CreateProviderRequest{TargetScopeID: target, Name: name,
			ProviderType: "cloudflare", Credentials: map[string]string{"api_token": "fixture-token-" + name},
			IdempotencyKey: "dns-owner-list-" + name, RequestID: "dns-owner-list-" + name})
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		if value.Owner != nil {
			t.Fatalf("create %s returned owner %+v; owner is list-only", name, value.Owner)
		}
		return value
	}
	a1 := create(tenant, uuid.Nil, "alice-one")
	a2 := create(platform, alice.scopeID, "alice-two")
	o1 := create(platform, orphan.scopeID, "orphan-one")

	page := func(actor dnsacme.Actor, request dnsacme.ProviderPageRequest) dnsacme.ProviderPage {
		t.Helper()
		value, err := dns.ListProviderPage(t.Context(), actor, request)
		if err != nil {
			t.Fatalf("list %+v: %v", request, err)
		}
		return value
	}
	ids := func(items []dnsacme.Provider) []uuid.UUID {
		result := make([]uuid.UUID, 0, len(items))
		for _, item := range items {
			result = append(result, item.ID)
		}
		return result
	}

	// 1. 平台 + managed_by=tenant：只有用户自己的 3 个账户（新到旧），不含平台副本，带所属用户。
	all := page(platform, dnsacme.ProviderPageRequest{Limit: 100, ProviderListFilter: dnsacme.ProviderListFilter{ManagedBy: "tenant"}})
	if got := ids(all.Items); len(got) != 3 || got[0] != o1.ID || got[1] != a2.ID || got[2] != a1.ID {
		t.Fatalf("platform tenant-only list = %v, want [%s %s %s]", got, o1.ID, a2.ID, a1.ID)
	}
	for _, item := range all.Items {
		switch item.ScopeID {
		case alice.scopeID:
			if item.Owner == nil || item.Owner.ID != alice.userID || item.Owner.Username != "dns-owner-alice" || item.Owner.DisplayID == "" {
				t.Fatalf("alice provider owner = %+v", item.Owner)
			}
		case orphan.scopeID:
			if item.Owner != nil {
				t.Fatalf("orphan scope provider owner = %+v, want nil", item.Owner)
			}
		default:
			t.Fatalf("unexpected scope %s", item.ScopeID)
		}
	}

	// 2. 不带筛选的平台视图照旧含平台副本（证书页其余选择器依赖）。
	unfiltered := page(platform, dnsacme.ProviderPageRequest{Limit: 100})
	copies := 0
	for _, item := range unfiltered.Items {
		if item.ManagedBy == dnsacme.ProviderManagedByPlatform {
			copies++
		}
	}
	if copies == 0 || len(unfiltered.Items) != 3+copies {
		t.Fatalf("unfiltered platform list = %d items, %d platform copies", len(unfiltered.Items), copies)
	}

	// 3. 按用户筛选 + 翻页：游标带着筛选，换筛选不能接着翻。
	filter := dnsacme.ProviderListFilter{ScopeID: alice.scopeID, ManagedBy: "tenant"}
	first := page(platform, dnsacme.ProviderPageRequest{Limit: 1, ProviderListFilter: filter})
	if got := ids(first.Items); len(got) != 1 || got[0] != a2.ID || first.NextCursor == "" {
		t.Fatalf("alice page 1 = %v cursor=%q", got, first.NextCursor)
	}
	second := page(platform, dnsacme.ProviderPageRequest{Limit: 1, Cursor: first.NextCursor, ProviderListFilter: filter})
	if got := ids(second.Items); len(got) != 1 || got[0] != a1.ID || second.NextCursor != "" {
		t.Fatalf("alice page 2 = %v cursor=%q", got, second.NextCursor)
	}
	if _, err := dns.ListProviderPage(t.Context(), platform, dnsacme.ProviderPageRequest{Limit: 1, Cursor: first.NextCursor,
		ProviderListFilter: dnsacme.ProviderListFilter{ManagedBy: "tenant"}}); !errors.Is(err, dnsacme.ErrInvalidInput) {
		t.Fatalf("cursor reused with another filter: err = %v", err)
	}

	// 4. 租户视图：只有自己的、不带用户；不能按用户筛选（哪怕是自己的 scope）。
	own := page(tenant, dnsacme.ProviderPageRequest{Limit: 100})
	if got := ids(own.Items); len(got) != 2 || got[0] != a2.ID || got[1] != a1.ID {
		t.Fatalf("tenant list = %v", got)
	}
	for _, item := range own.Items {
		if item.Owner != nil {
			t.Fatalf("tenant view carries owner %+v", item.Owner)
		}
	}
	if _, err := dns.ListProviderPage(t.Context(), tenant, dnsacme.ProviderPageRequest{Limit: 10,
		ProviderListFilter: dnsacme.ProviderListFilter{ScopeID: alice.scopeID}}); !errors.Is(err, dnsacme.ErrInvalidInput) {
		t.Fatalf("tenant scope filter: err = %v", err)
	}
}

// 租户 + tenant_owner 用户（addonSiteInsertSubscriptionTenant 给的是 tenant_viewer，与 owner 互斥）。
func dnsOwnerListInsertOwnerTenant(t *testing.T, pool *pgxpool.Pool, name, username string) addonSiteTenantFixture {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO tenants (id, display_name) VALUES ($1,$2)`, tenantID, name); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO access_scopes (id, kind, tenant_id) VALUES ($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	addonSiteInsertSubscriptionUser(t, pool, scopeID, userID, username)
	addonSiteAssignSubscriptionRole(t, pool, scopeID, userID, "tenant_owner", "dns.manage")
	return addonSiteTenantFixture{scopeID: scopeID, userID: userID}
}
