//go:build integration

package site

import (
	"context"
	"testing"
)

// 迁移 518：网站缓存 / 条件源站默认文档在建站同事务复制给新站。
// 待出包前全量跑（PG）。
func TestSiteDefaultsCopyCacheAndConditionalOriginOnCreate(t *testing.T) {
	f := newTrustFixture(t)
	ctx := context.Background()
	a := f.a.siteActor()
	save := func(name, value string) {
		t.Helper()
		key := f.key("documents-" + name)
		if _, err := f.sites.CreateUserDefault(ctx, a, SiteUserDefaultCreateRequest{
			Fields: SiteUserDefaultFields{SettingName: name, Value: value}, IdempotencyKey: key, RequestID: key}); err != nil {
			t.Fatalf("save %s: %v", name, err)
		}
	}
	save(SiteDefaultCacheRule, `{"mode":"override","rules":[{"order":1,"extensions":[".css"],"ttl_seconds":3600}],`+
		`"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":1073741824}`)
	save(SiteDefaultCondOrigin, `{"routes":[{"id":"api","priority":10,"path_prefix":"/api/","pool_id":"@default"}]}`)
	created, err := f.createSite(f.a, f.a, "documents-a.example.test")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// 缓存：新站首个修订（override、定义即本站），审计与写请求齐全（034/080 延迟约束在提交时已通过）。
	var revision int64
	var mode, binding string
	var rules int
	if err := f.pool.QueryRow(ctx, `SELECT r.revision,r.mode,r.binding_mode,jsonb_array_length(r.rules)
		FROM cache_policy_heads h JOIN cache_policy_revisions r ON r.site_id=h.site_id AND r.revision=h.current_revision
		WHERE h.site_id=$1 AND r.definition_id=$1`, created.Site.ID).Scan(&revision, &mode, &binding, &rules); err != nil ||
		revision != 1 || mode != "override" || binding != "override" || rules != 1 {
		t.Fatalf("cache policy: rev %d mode %s binding %s rules %d err %v", revision, mode, binding, rules, err)
	}
	var audits int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='cache_policy.publish' AND resource_id=$1`,
		created.Site.ID.String()).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("cache audit: %d %v", audits, err)
	}
	// 条件源站：规则的池换成新站自己的默认池，源站是新站自己的源站。
	state, err := f.sites.GetConditionalOrigin(ctx, a, created.Site.ID)
	if err != nil {
		t.Fatalf("conditional origin: %v", err)
	}
	if len(state.Document.Routes) != 1 || state.Document.Routes[0].PoolID != state.Document.DefaultPoolID ||
		len(state.Document.Pools) != 1 || state.Document.Pools[0].Endpoints[0].Host != "192.0.2.1" {
		t.Fatalf("conditional origin document: %+v", state.Document)
	}
	// 改默认不影响已建站点。
	f.exec(`UPDATE site_user_defaults SET setting_value='{"routes":[{"id":"x","priority":0,"path_prefix":"/x/","pool_id":"@default"}]}'
		WHERE setting_name='cond_origin'`)
	if again, err := f.sites.GetConditionalOrigin(ctx, a, created.Site.ID); err != nil || again.Document.Routes[0].ID != "api" {
		t.Fatalf("existing site followed the default: %+v %v", again.Document.Routes, err)
	}
	// 无默认的租户 b：不建缓存策略、不写条件源站。
	other, err := f.createSite(f.b, f.b, "documents-b.example.test")
	if err != nil {
		t.Fatalf("create b: %v", err)
	}
	var heads, configs int
	if err := f.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM cache_policy_heads WHERE site_id=$1),
		(SELECT count(*) FROM site_origin_route_configs WHERE site_id=$1)`, other.Site.ID).Scan(&heads, &configs); err != nil ||
		heads != 0 || configs != 0 {
		t.Fatalf("site without defaults: heads %d configs %d err %v", heads, configs, err)
	}
}
