package site

import (
	"strings"
	"testing"
)

// fp-site5b：复杂规则（规则库 ID）、屏蔽透明代理、源站请求头、上传限制的取值校验。
func TestSiteDefaultRuleCopyValues(t *testing.T) {
	policy := "0190b1d6-3c8e-7a51-9f00-000000000001"
	for _, tc := range []struct {
		name, value, want string
		ok                bool
	}{
		{SiteDefaultCCPolicy, policy, policy, true},
		{SiteDefaultWAFPolicy, "  " + strings.ToUpper(policy) + " ", policy, true},
		{SiteDefaultACLPolicy, "00000000-0000-0000-0000-000000000000", "", false},
		{SiteDefaultACLPolicy, "acl", "", false},
		{SiteDefaultBlockProxy, "1", "1", true},
		{SiteDefaultBlockProxy, "yes", "", false},
		{SiteDefaultBlockRegion, " abrord_no_inc ", "abrord_no_inc", true}, // 取值原样
		{SiteDefaultBlockRegion, "china_not_inc", "china_not_inc", true},
		{SiteDefaultBlockRegion, "none", "none", true},
		{SiteDefaultBlockRegion, "CN", "", false}, // 自定义国家走 WAF 规则库
		{SiteDefaultPostSize, "100", "100", true},
		{SiteDefaultPostSize, "0", "", false},
		{SiteDefaultPostSize, "1025", "", false},
		{SiteDefaultReqHeader, "X-Real-Port: $server_port\r\n\r\n x-from :cdn ", "x-real-port: $server_port\nx-from: cdn", true},
		{SiteDefaultReqHeader, "no colon here", "", false},
		{SiteDefaultReqHeader, "Host: example.com", "", false},           // HTTP 策略禁止的请求头
		{SiteDefaultReqHeader, "x-a: 1\nX-A: 2", "", false},              // 重复名称
		{SiteDefaultReqHeader, "x-cdnca-internal: 1", "", false},         // 保留前缀
		{SiteDefaultReqHeader, "X-Forwarded-For: 1.1.1.1", "", false},    // 节点自管的转发头
		{SiteDefaultReqHeader, "x-a: $no_such_variable_here", "", false}, // 未知变量
	} {
		got, ok := normalizeSiteDefaultValue(tc.name, tc.value)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("%s=%q: %q %v", tc.name, tc.value, got, ok)
		}
	}
}

func TestSiteDefaultRequestHeadersBecomeSetActions(t *testing.T) {
	actions, ok := parseSiteDefaultRequestHeaders("X-Origin-Scheme: $scheme\nx-env: prod")
	if !ok || len(actions) != 2 || actions[0].Kind != "set" || actions[0].Name != "x-origin-scheme" ||
		actions[0].Values[0] != "$scheme" || actions[1].Values[0] != "prod" {
		t.Fatalf("actions: %+v %v", actions, ok)
	}
}

// fp-site7：区域屏蔽预设与屏蔽透明代理一起并入新站 WAF；都没设或「不屏蔽」时不建规则。
func TestSiteDefaultWAFExtraRules(t *testing.T) {
	if rules := (siteCreationUserDefaults{}).wafExtraRules(); len(rules) != 0 {
		t.Fatalf("no defaults: %+v", rules)
	}
	if rules := (siteCreationUserDefaults{SiteDefaultBlockRegion: "none", SiteDefaultBlockProxy: "0"}).wafExtraRules(); len(rules) != 0 {
		t.Fatalf("none / off: %+v", rules)
	}
	rules := (siteCreationUserDefaults{SiteDefaultBlockRegion: "abrord_inc"}).wafExtraRules()
	if len(rules) != 1 || rules[0].Conditions[0].Field != "country" || rules[0].Conditions[0].Operator != "not_in" {
		t.Fatalf("region only: %+v", rules)
	}
	if rules := (siteCreationUserDefaults{SiteDefaultBlockRegion: "china_inc", SiteDefaultBlockProxy: "1"}).wafExtraRules(); len(rules) != 4 {
		t.Fatalf("proxy + region: %d rules", len(rules))
	}
}
