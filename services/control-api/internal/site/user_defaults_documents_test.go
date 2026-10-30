package site

import (
	"encoding/json"
	"strings"
	"testing"
)

// fp-site6：网站缓存默认是一份缓存策略文档，按站点缓存页同样的规则校验并规范化。
func TestSiteDefaultCacheRuleValues(t *testing.T) {
	got, ok := normalizeSiteDefaultValue(SiteDefaultCacheRule,
		`{"mode":"override","rules":[{"order":1,"extensions":[".JPG",".css"],"ttl_seconds":3600}],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":1073741824}`)
	if !ok || !strings.Contains(got, `".jpg"`) || strings.Contains(got, `".JPG"`) {
		t.Fatalf("normalized: %s %v", got, ok)
	}
	if again, ok := normalizeSiteDefaultValue(SiteDefaultCacheRule, got); !ok || again != got {
		t.Fatalf("not idempotent: %s / %s", got, again)
	}
	for _, value := range []string{
		`{"mode":"override","rules":[],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":1073741824}`, // override 须有规则
		`{"mode":"nope","rules":[],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":0}`,
		`{"mode":"disabled","rules":[],"query_mode":"preserve","query_names":[],"vary_headers":[],"disk_quota_bytes":0} {}`, // 尾随内容
		`not json`,
	} {
		if _, ok := normalizeSiteDefaultValue(SiteDefaultCacheRule, value); ok {
			t.Errorf("accepted %s", value)
		}
	}
}

// 条件源站默认只有条件：pool_id 必须是占位 @default，不能带源站池或备用池。
func TestSiteDefaultCondOriginValues(t *testing.T) {
	got, ok := normalizeSiteDefaultValue(SiteDefaultCondOrigin,
		`{"routes":[{"id":"api","priority":10,"path_prefix":"/api/","pool_id":"@default"},{"id":"cn","priority":0,"client_cidrs":["10.0.0.0/8"],"pool_id":"@default"}]}`)
	if !ok {
		t.Fatal("valid rules rejected")
	}
	var document siteDefaultCondOriginDocument
	if err := json.Unmarshal([]byte(got), &document); err != nil || len(document.Routes) != 2 {
		t.Fatalf("decoded: %+v %v", document, err)
	}
	for _, route := range document.Routes {
		if route.PoolID != SiteDefaultCondOriginPool {
			t.Fatalf("placeholder lost: %+v", route)
		}
	}
	if strings.Contains(got, "endpoints") || strings.Contains(got, "192.0.2.1") {
		t.Fatalf("origin addresses stored in the default: %s", got)
	}
	for _, value := range []string{
		`{"routes":[]}`,
		`{"routes":[{"id":"a","priority":0,"path_prefix":"/a/","pool_id":"backup"}]}`,                              // 只能是占位池
		`{"routes":[{"id":"a","priority":0,"path_prefix":"/a/","pool_id":"@default","fallback_pool_id":"x"}]}`,     // 无备用池
		`{"routes":[{"id":"a","priority":0,"pool_id":"@default"}]}`,                                                // 没有条件
		`{"routes":[{"id":"a","priority":0,"client_cidrs":["10.0.0.1/8"],"pool_id":"@default"}]}`,                  // CIDR 非规范
		`{"routes":[{"id":"a","priority":0,"path_prefix":"/a/","pool_id":"@default"}],"pools":[{"id":"default"}]}`, // 不收源站池
	} {
		if _, ok := normalizeSiteDefaultValue(SiteDefaultCondOrigin, value); ok {
			t.Errorf("accepted %s", value)
		}
	}
}

// 复制时占位换成新站自己的默认源站池，源站地址取新站的。
func TestCondOriginOverPoolUsesTheNewSitePool(t *testing.T) {
	pool := ConditionalOriginPool{ID: "default", Endpoints: []ConditionalOriginEndpoint{{ID: "origin-00", Host: "203.0.113.9", Port: 8080, Weight: 1}}}
	retry := ConditionalOriginRetry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 2, ConnectTimeoutMS: 1000, ReadTimeoutMS: 1000, TotalBudgetMS: 2000}
	document, err := NormalizeConditionalOriginDocument(condOriginOverPool(
		[]ConditionalOriginRoute{{ID: "api", PathPrefix: "/api/", PoolID: SiteDefaultCondOriginPool}}, pool, retry))
	if err != nil || document.DefaultPoolID != "default" || document.Routes[0].PoolID != "default" ||
		document.Pools[0].Endpoints[0].Host != "203.0.113.9" {
		t.Fatalf("document: %+v %v", document, err)
	}
}
