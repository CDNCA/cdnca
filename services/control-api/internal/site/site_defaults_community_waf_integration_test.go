//go:build integration

package site

import (
	"context"
	"testing"
)

// 社区版网站没有套餐：建站时照常按默认设置（屏蔽透明代理）复制 WAF 规则库并绑定。
func TestSiteDefaultWAFCopiedForSiteWithoutPackage(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	a := f.a.siteActor()
	key := f.key("community-block-proxy")
	if _, err := f.sites.CreateUserDefault(ctx, a, SiteUserDefaultCreateRequest{
		Fields: SiteUserDefaultFields{SettingName: SiteDefaultBlockProxy, Value: "1"}, IdempotencyKey: key, RequestID: key}); err != nil {
		t.Fatal(err)
	}
	key = f.key("community-waf-site")
	fields := SiteFields{Domains: []string{"community-waf.example.test"}, Origins: []string{"192.0.2.1"},
		CNAME: "a1b2c3.cdn.example.net", Enabled: true, Status: StatusActive}
	created, err := f.sites.Create(ctx, a, CreateRequest{IdempotencyKey: key, RequestID: key, Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	var subscription *string
	var bindings int
	if err := f.pool.QueryRow(ctx, `SELECT s.package_subscription_id::text,
		(SELECT count(*) FROM security_policy_site_bindings b WHERE b.site_id=s.id AND b.policy_kind='waf')
		FROM sites s WHERE s.id=$1`, created.Site.ID).Scan(&subscription, &bindings); err != nil || subscription != nil || bindings != 1 {
		t.Fatalf("subscription %v waf bindings %d err %v", subscription, bindings, err)
	}
}
