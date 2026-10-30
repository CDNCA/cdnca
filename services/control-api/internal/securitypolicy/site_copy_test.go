package securitypolicy

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// 屏蔽透明代理（#26）：Via / X-Forwarded-For / Forwarded 任一头存在即拦截，
// 规则是可发布的 WAF 规则，并且站点页 proxyBlocked 能认出来（block + 这三个头）。
func TestProxyBlockRulesArePublishableWAFRules(t *testing.T) {
	rules := ProxyBlockRules()
	normalized, err := NormalizePublishableWAFRules(rules)
	if err != nil {
		t.Fatalf("publishable: %v", err)
	}
	seen := map[string]bool{}
	for _, rule := range normalized {
		if rule.Action != ActionBlock || len(rule.Conditions) != 1 || rule.Conditions[0].Field != "header" {
			t.Fatalf("rule: %+v", rule)
		}
		seen[rule.Conditions[0].Key] = true
	}
	for _, header := range []string{"via", "x-forwarded-for", "forwarded"} {
		if !seen[header] {
			t.Fatalf("missing %s: %+v", header, seen)
		}
	}
	block := func(headers map[string][]string) bool {
		policy := Policy{Kind: KindWAF, Enabled: true, DefaultAction: ActionAllow, Rules: normalized}
		for index := range policy.Rules {
			policy.Rules[index].ID = uuid.New()
		}
		evaluation, err := evaluateAt(policy, RequestFacts{Method: "GET", Path: "/", ClientIP: "198.51.100.7", Headers: headers}, time.Now())
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		return evaluation.Action == ActionBlock
	}
	if !block(map[string][]string{"via": {"1.1 squid"}}) || !block(map[string][]string{"x-forwarded-for": {"10.0.0.1"}}) ||
		!block(map[string][]string{"forwarded": {"for=10.0.0.1"}}) {
		t.Fatal("a proxy header did not block")
	}
	if block(map[string][]string{"user-agent": {"curl/8"}}) {
		t.Fatal("a request without proxy headers was blocked")
	}
}

func TestSiteCopyNameIsUniquePerSiteAndBounded(t *testing.T) {
	siteA, siteB := uuid.MustParse("0190b1d6-3c8e-7a51-9f00-0000000000aa"), uuid.MustParse("0190b1d6-3c8e-7a51-9f00-0000000000bb")
	if a, b := siteCopyName("默认 CC", "a.example.com", siteA), siteCopyName("默认 CC", "a.example.com", siteB); a == b {
		t.Fatalf("same name for two sites: %q", a)
	}
	long := siteCopyName(strings.Repeat("库", 200), strings.Repeat("x", 100)+".example.com", siteA)
	if utf8.RuneCountInString(long) > 128 || !strings.HasSuffix(long, "000000aa") {
		t.Fatalf("long name: %d %q", utf8.RuneCountInString(long), long)
	}
}

// 区域屏蔽预设（#4/#31）：四个取值各是一条可发布的 country 规则，港澳台按
// HK/MO/TW；none 与未知取值不建规则。
func TestRegionBlockPresetsArePublishableCountryRules(t *testing.T) {
	cases := map[string]struct{ blocked, allowed []string }{
		RegionBlockAbroad:      {[]string{"US", "HK", "TW"}, []string{"CN"}},
		RegionBlockAbroadNoHMT: {[]string{"US", "JP"}, []string{"CN", "HK", "MO", "TW"}},
		RegionBlockChina:       {[]string{"CN", "HK", "MO", "TW"}, []string{"US"}},
		RegionBlockChinaNoHMT:  {[]string{"CN"}, []string{"HK", "MO", "TW", "US"}},
	}
	for preset, want := range cases {
		if !ValidRegionBlockPreset(preset) {
			t.Fatalf("%s not valid", preset)
		}
		normalized, err := NormalizePublishableWAFRules(RegionBlockRules(preset))
		if err != nil || len(normalized) != 1 || normalized[0].Conditions[0].Field != "country" {
			t.Fatalf("%s: %+v %v", preset, normalized, err)
		}
		policy := Policy{Kind: KindWAF, Enabled: true, DefaultAction: ActionAllow, Rules: normalized}
		policy.Rules[0].ID = uuid.New()
		blocks := func(country string) bool {
			evaluation, err := evaluateAt(policy, RequestFacts{Method: "GET", Path: "/", ClientIP: "198.51.100.7", Country: country}, time.Now())
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			return evaluation.Action == ActionBlock
		}
		for _, country := range want.blocked {
			if !blocks(country) {
				t.Fatalf("%s: %s not blocked", preset, country)
			}
		}
		for _, country := range want.allowed {
			if blocks(country) {
				t.Fatalf("%s: %s blocked", preset, country)
			}
		}
	}
	if !ValidRegionBlockPreset(RegionBlockNone) || RegionBlockRules(RegionBlockNone) != nil || ValidRegionBlockPreset("abroad") {
		t.Fatal("none / unknown preset")
	}
}
