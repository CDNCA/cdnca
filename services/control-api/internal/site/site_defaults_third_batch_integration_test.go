//go:build integration

package site

import (
	"context"
	"errors"
	"testing"
)

// 迁移 514：默认设置第三批 IPv6 / Gzip / DNS API 落到建站事务。
// 待出包前全量跑（PG）。
func TestSiteDefaultsThirdBatchApplyOnCreate(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	a := f.a.siteActor()
	providerA := f.insertVerifiedProvider(f.a, "a-default-dns")
	providerB := f.insertVerifiedProvider(f.b, "b-default-dns")
	save := func(name, value string) (SiteUserDefault, error) {
		key := f.key("third-batch-" + name)
		return f.sites.CreateUserDefault(ctx, a, SiteUserDefaultCreateRequest{
			Fields: SiteUserDefaultFields{SettingName: name, Value: value}, IdempotencyKey: key, RequestID: key})
	}
	// Another tenant's DNS account cannot be the default.
	if _, err := save(SiteDefaultDNSProvider, providerB.String()); !errors.Is(err, ErrAutoDNSProvider) {
		t.Fatalf("other tenant's provider as default: %v", err)
	}
	for name, value := range map[string]string{SiteDefaultIPv6: "1", SiteDefaultGzip: "1",
		SiteDefaultDNSProvider: providerA.String(), SiteDefaultCCBanSeconds: "1200"} {
		if _, err := save(name, value); err != nil {
			t.Fatalf("save %s: %v", name, err)
		}
	}
	create := func(domain string, fields SiteFields, dnsAllowed bool) WriteResult {
		t.Helper()
		key := f.key("third-batch-site")
		fields.Domains, fields.Origins, fields.CNAME = []string{domain}, []string{"192.0.2.1"}, "a1b2c3.cdn.example.net"
		fields.Enabled, fields.Status = true, StatusActive
		result, err := f.sites.Create(ctx, a, CreateRequest{IdempotencyKey: key, RequestID: key, Fields: fields,
			DefaultDNSAllowed: dnsAllowed})
		if err != nil {
			t.Fatalf("create %s: %v", domain, err)
		}
		return result
	}
	// Left out: IPv6 on, gzip with the platform types, the default DNS account.
	omitted := create("third-a.example.test", SiteFields{IPv6Omitted: true}, true)
	var ipv6, gzip bool
	var provider *string
	if err := f.pool.QueryRow(ctx, `SELECT s.ipv6_enabled, COALESCE((a.settings->'compression'->>'enabled')::boolean,false),
			t.provider_id::text FROM sites s LEFT JOIN site_access_settings a ON a.site_id=s.id
			LEFT JOIN site_auto_dns_tasks t ON t.site_id=s.id WHERE s.id=$1`, omitted.Site.ID).Scan(&ipv6, &gzip, &provider); err != nil ||
		!ipv6 || !gzip || provider == nil || *provider != providerA.String() {
		t.Fatalf("omitted: ipv6 %v gzip %v provider %v err %v", ipv6, gzip, provider, err)
	}
	// Named ipv6_enabled=false wins; without dns.manage no records are added.
	explicit := create("third-b.example.test", SiteFields{}, false)
	var tasks int
	if err := f.pool.QueryRow(ctx, `SELECT s.ipv6_enabled, (SELECT count(*) FROM site_auto_dns_tasks WHERE site_id=s.id)
		FROM sites s WHERE s.id=$1`, explicit.Site.ID).Scan(&ipv6, &tasks); err != nil || ipv6 || tasks != 0 {
		t.Fatalf("explicit: ipv6 %v tasks %d err %v", ipv6, tasks, err)
	}
	// A default account revoked later skips the records; the site is created.
	// 106 触发器不认直接写 credential_revoked（保持旧值），吊销只由停用账号（status='disabled'）触发。
	f.exec(`UPDATE dns_providers SET status='disabled' WHERE id=$1`, providerA)
	revoked := create("third-c.example.test", SiteFields{IPv6Omitted: true}, true)
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM site_auto_dns_tasks WHERE site_id=$1`, revoked.Site.ID).Scan(&tasks); err != nil || tasks != 0 {
		t.Fatalf("revoked default: tasks %d err %v", tasks, err)
	}
}
