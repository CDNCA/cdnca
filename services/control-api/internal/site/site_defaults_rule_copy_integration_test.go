//go:build integration

package site

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// 迁移 516：默认设置复杂规则按复制快照。
// 待出包前全量跑（PG）。
func TestSiteDefaultsCopyRuleLibrariesOnCreate(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	a := f.a.siteActor()
	// 本人的黑白名单 IP 规则库（ACL 不需要套餐功能）；另一租户的库不能做默认。
	acl, other := uuid.New(), uuid.New()
	insertACL := func(id uuid.UUID, owner trustActor, name string) {
		var tenant uuid.UUID
		if err := f.pool.QueryRow(ctx, `SELECT tenant_id FROM access_scopes WHERE id=$1`, owner.scopeID).Scan(&tenant); err != nil {
			t.Fatal(err)
		}
		f.exec(`INSERT INTO security_policies(id,scope_id,tenant_id,owner_user_id,kind,name,description,enabled,default_action,rules,
			created_by_user_id,updated_by_user_id,created_at,updated_at) VALUES($1,$2,$3,$4,'acl',$5,'',true,'allow',
			'[{"id":"0190b1d6-3c8e-7a51-9f00-0000000000a1","name":"block 203.0.113.0/24","priority":1,"enabled":true,
			  "conditions":[{"field":"client_ip","operator":"ip_in_cidr","values":["203.0.113.0/24"]}],
			  "action":"block","flow":"stop","action_config":{}}]'::jsonb,$4,$4,$6,$6)`,
			id, owner.scopeID, tenant, owner.userID, name, f.now)
	}
	insertACL(acl, f.a, "默认黑名单")
	insertACL(other, f.b, "别人的黑名单")
	save := func(name, value string) (SiteUserDefault, error) {
		key := f.key("rule-copy-" + name)
		return f.sites.CreateUserDefault(ctx, a, SiteUserDefaultCreateRequest{
			Fields: SiteUserDefaultFields{SettingName: name, Value: value}, IdempotencyKey: key, RequestID: key})
	}
	if _, err := save(SiteDefaultACLPolicy, other.String()); !errors.Is(err, ErrSiteDefaultPolicy) {
		t.Fatalf("other tenant's library as default: %v", err)
	}
	if _, err := save(SiteDefaultACLPolicy, acl.String()); err != nil {
		t.Fatalf("save acl default: %v", err)
	}
	if _, err := save(SiteDefaultReqHeader, "X-From: cdn"); err != nil {
		t.Fatalf("save request header default: %v", err)
	}
	first, err := f.createSite(f.a, f.a, "copy-a.example.test")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// 新站绑定的是复制出的新库（不是原库），规则相同、ID 不同，绑定未发布（由 rebind 自动下发）。
	var bound uuid.UUID
	var revision int64
	var rules int
	if err := f.pool.QueryRow(ctx, `SELECT b.policy_id,b.revision,jsonb_array_length(p.rules) FROM security_policy_site_bindings b
		JOIN security_policies p ON p.id=b.policy_id WHERE b.site_id=$1 AND b.policy_kind='acl'`, first.Site.ID).
		Scan(&bound, &revision, &rules); err != nil || bound == acl || revision != 0 || rules != 1 {
		t.Fatalf("binding: policy %s (source %s) revision %d rules %d err %v", bound, acl, revision, rules, err)
	}
	// 改原库不影响已建站点的副本。
	// rules 有 CHECK（026：1–100 条），不能改成空数组；改原库那条规则的网段。
	f.exec(`UPDATE security_policies SET rules=jsonb_set(rules,'{0,conditions,0,values}','["198.51.100.0/24"]') WHERE id=$1`, acl)
	var copied string
	if err := f.pool.QueryRow(ctx, `SELECT rules->0->'conditions'->0->'values'->>0 FROM security_policies WHERE id=$1`, bound).Scan(&copied); err != nil || copied != "203.0.113.0/24" {
		t.Fatalf("copy changed with its source: cidr %q err %v", copied, err)
	}
	// 创建者无 http_policies.manage：源站请求头默认跳过，建站照常。
	var policies int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM http_policies WHERE site_id=$1`, first.Site.ID).Scan(&policies); err != nil || policies != 0 {
		t.Fatalf("http policy without permission: %d %v", policies, err)
	}
	// 原库被删：之后的建站跳过复制，不失败。
	f.exec(`UPDATE security_policies SET deleted_at=$2 WHERE id=$1`, acl, f.now)
	second, err := f.createSite(f.a, f.a, "copy-b.example.test")
	if err != nil {
		t.Fatalf("create after source deleted: %v", err)
	}
	var bindings int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM security_policy_site_bindings WHERE site_id=$1`, second.Site.ID).Scan(&bindings); err != nil || bindings != 0 {
		t.Fatalf("bindings after source deleted: %d %v", bindings, err)
	}
}

// 迁移 519：区域屏蔽预设 block_region。保存走迁移 519 的
// CHECK；站点套餐不含 WAF 时跳过并入，建站照常。并入 WAF 副本见 securitybinding
// TestSiteDefaultRegionBlockJoinsNewSiteWAF。待出包前全量跑（PG）。
func TestSiteDefaultsBlockRegionSavedAndSkippedWithoutWAF(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	a := f.a.siteActor()
	save := func(value string) error {
		key := f.key("block-region")
		_, err := f.sites.CreateUserDefault(ctx, a, SiteUserDefaultCreateRequest{
			Fields: SiteUserDefaultFields{SettingName: SiteDefaultBlockRegion, Value: value}, IdempotencyKey: key, RequestID: key})
		return err
	}
	if err := save("CN"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("country code as preset: %v", err)
	}
	if err := save("abrord_no_inc"); err != nil {
		t.Fatalf("save preset: %v", err)
	}
	created, err := f.createSite(f.a, f.a, "region-a.example.test")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var bindings int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM security_policy_site_bindings WHERE site_id=$1`, created.Site.ID).Scan(&bindings); err != nil || bindings != 0 {
		t.Fatalf("waf binding without the package feature: %d %v", bindings, err)
	}
}
