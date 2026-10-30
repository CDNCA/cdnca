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
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DNS-SEC-20261027-01（fix-dnscert）：平台只把 CNAME 子域委派给租户；租户不能拿同步来的
// 「平台DNS配置」副本新增父域解析区、申请 DNS-01、设为默认/建站自动添加记录，也不能编辑/删除/验证它。
// 租户本人提交的账户照常可用；平台管理员代租户操作照常可用。
func TestPlatformDNSCopyServesOnlyThePlatform(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL required")
	}
	admin, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "platform_dns_copy_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	manager := addonSiteInsertPlatformActor(t, pool, "platform-dns-copy-admin")
	addonSiteAssignSubscriptionRole(t, pool, manager.ScopeID, manager.UserID, "platform-dns-admin", "platform.admin")
	tenant := addonSiteInsertSubscriptionTenant(t, pool, "Platform DNS copy", "platform-dns-copy-owner")
	addonSiteAssignSubscriptionRole(t, pool, tenant.scopeID, tenant.userID, "dns-owner",
		"dns.manage", "certificates.manage", "sites.manage")

	cipher, err := dnsacme.NewAESGCMCredentialCipher("platform-dns-copy-v1", bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	dns := dnsacme.NewServiceWithClockAndVerifier(dnsacme.NewStore(pool), cipher, acceptCredentials{}, time.Now)
	platform := dnsacme.Actor{UserID: manager.UserID, ScopeID: manager.ScopeID, ScopeKind: "platform"}
	if _, err := dns.SavePlatformConfig(t.Context(), platform, dnsacme.SavePlatformConfigRequest{ProviderType: "dnspod_cn",
		Credentials: map[string]string{"dp_id": "1", "dp_key": "fixture"}, TTL: 600, ExpectedRevision: 1,
		IdempotencyKey: "platform-dns-copy-config", RequestID: "platform-dns-copy-config"}); err != nil {
		t.Fatalf("save platform DNS config: %v", err)
	}
	if _, err := dns.CreatePlatformZone(t.Context(), platform, dnsacme.PlatformZoneRequest{Name: "cdn.platform-audit.test",
		IdempotencyKey: "platform-dns-copy-zone", RequestID: "platform-dns-copy-zone"}); err != nil {
		t.Fatalf("create platform zone: %v", err)
	}
	copyID := dnsacme.PlatformProviderCopyID(tenant.scopeID)
	owner := dnsacme.Actor{UserID: tenant.userID, ScopeID: tenant.scopeID, ScopeKind: "tenant"}

	// 1. 同步出的副本持久标为 platform，并在租户列表里如实显示。
	providers, err := dns.ListProviders(t.Context(), owner)
	if err != nil {
		t.Fatal(err)
	}
	var copyRow dnsacme.Provider
	for _, provider := range providers {
		if provider.ID == copyID {
			copyRow = provider
		}
	}
	if copyRow.ManagedBy != dnsacme.ProviderManagedByPlatform || copyRow.Status != dnsacme.ProviderStatusVerified {
		t.Fatalf("platform copy row = %+v", copyRow)
	}

	// 2. 租户越界用途在调用服务商/写库前拒绝。
	refused := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, dnsacme.ErrPlatformManagedProvider) {
			t.Fatalf("%s: error = %v, want ErrPlatformManagedProvider", name, err)
		}
	}
	_, err = dns.CreateZone(t.Context(), owner, dnsacme.CreateZoneRequest{ProviderID: copyID, Name: "platform-audit.test",
		IdempotencyKey: "copy-zone-parent", RequestID: "copy-zone-parent"})
	refused("create parent zone", err)
	_, err = dns.CreateOrder(t.Context(), owner, dnsacme.CreateOrderRequest{DNSProviderID: &copyID,
		Domains: []string{"admin.platform-audit.test"}, ChallengeType: "dns-01",
		IdempotencyKey: "copy-order", RequestID: "copy-order"})
	refused("dns-01 order", err)
	_, err = dns.UpdateProvider(t.Context(), owner, dnsacme.UpdateProviderRequest{ID: copyID, ExpectedRevision: copyRow.Revision,
		Name: "renamed", Status: dnsacme.ProviderStatusDisabled, IdempotencyKey: "copy-update", RequestID: "copy-update"})
	refused("update", err)
	_, err = dns.VerifyProvider(t.Context(), owner, dnsacme.VerifyProviderRequest{ID: copyID, ExpectedRevision: copyRow.Revision,
		IdempotencyKey: "copy-verify", RequestID: "copy-verify"})
	refused("verify", err)
	refused("delete", dns.DeleteProvider(t.Context(), owner, dnsacme.DeleteRequest{ID: copyID, ExpectedRevision: copyRow.Revision,
		IdempotencyKey: "copy-delete", RequestID: "copy-delete"}))
	var zones, orders int
	if err := pool.QueryRow(t.Context(), `SELECT
		(SELECT count(*) FROM dns_zones WHERE scope_id=$1 AND name='platform-audit.test'),
		(SELECT count(*) FROM certificate_orders WHERE scope_id=$1)`, tenant.scopeID).Scan(&zones, &orders); err != nil ||
		zones != 0 || orders != 0 {
		t.Fatalf("refused uses wrote zones=%d orders=%d err=%v", zones, orders, err)
	}

	// 3. 建站「DNS API（自动添加记录）」与网站默认设置不认平台副本。
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return checkSiteDefaultReference(t.Context(), tx, tenant.scopeID, SiteDefaultDNSProvider, copyID.String())
	}); !errors.Is(err, ErrAutoDNSProvider) {
		t.Fatalf("site default with platform copy: %v", err)
	}
	siteID := insertPlatformCopySite(t, pool, tenant.scopeID, tenant.userID, "admin.platform-extra.test")
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return enqueueSiteAutoDNS(t.Context(), tx, tenant.scopeID, siteID, copyID, time.Now().UTC())
	}); !errors.Is(err, ErrAutoDNSProvider) {
		t.Fatalf("auto DNS with platform copy: %v", err)
	}

	// 4. 租户本人账户照常：建区（无托管根域解析器时不调服务商）与自动添加记录入队。
	own, err := dns.CreateProvider(t.Context(), owner, dnsacme.CreateProviderRequest{Name: "my dnspod", ProviderType: "dnspod_cn",
		Credentials: map[string]string{"dp_id": "2", "dp_key": "own"}, IdempotencyKey: "own-provider", RequestID: "own-provider"})
	if err != nil || own.ManagedBy != dnsacme.ProviderManagedByTenant {
		t.Fatalf("own provider = %+v err=%v", own, err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE dns_providers SET status='verified' WHERE id=$1`, own.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := dns.CreateZone(t.Context(), owner, dnsacme.CreateZoneRequest{ProviderID: own.ID, Name: "tenant-own.test",
		IdempotencyKey: "own-zone", RequestID: "own-zone"}); err != nil {
		t.Fatalf("own zone: %v", err)
	}
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		return enqueueSiteAutoDNS(t.Context(), tx, tenant.scopeID, siteID, own.ID, time.Now().UTC())
	}); err != nil {
		t.Fatalf("auto DNS with own account: %v", err)
	}

	// 5. 平台管理员代租户：可用平台副本新增解析区（平台已批准的代办用途）。
	if _, err := dns.CreateZone(t.Context(), platform, dnsacme.CreateZoneRequest{TargetScopeID: tenant.scopeID,
		ProviderID: copyID, Name: "platform-approved.test", IdempotencyKey: "admin-zone", RequestID: "admin-zone"}); err != nil {
		t.Fatalf("platform admin zone on copy: %v", err)
	}
}

func insertPlatformCopySite(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID, domain string) uuid.UUID {
	t.Helper()
	siteID := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO sites(
			id,scope_id,owner_user_id,domain,origins,origin_hosts,created_by_user_id,updated_by_user_id,display_id
		) VALUES($1,$2,$3,$4,ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,
			(SELECT COALESCE(max(display_id),0)+1 FROM sites WHERE scope_id=$2))`,
		siteID, scopeID, userID, domain); err != nil {
		t.Fatal(err)
	}
	return siteID
}
