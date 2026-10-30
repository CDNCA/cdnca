package rulecatalog

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

func TestBuiltinWAFSeedIsValidLogOnlyAndCompiles(t *testing.T) {
	items := BuiltinWAFSeed()
	want := []string{"SQL注入", "XSS", "文件上传", "文件包含", "命令注入", "Java代码注入", "Java反序列化", "PHP代码注入", "PHP反序列化", "SSTI模板注入",
		"WebShell", "敏感目录", "恶意爬虫与扫描器", "下载工具与空 UA"}
	if len(items) != len(want) {
		t.Fatalf("items = %d", len(items))
	}
	names := map[string]bool{}
	for _, item := range items {
		names[item.Name] = true
		if item.Kind != KindWAFRuleSet || !strings.HasPrefix(item.SystemKey, "waf_set:") || item.Body.WAFRuleSet == nil ||
			!strings.Contains(item.Description, "签名") {
			t.Fatalf("item %s malformed", item.SystemKey)
		}
		for _, rule := range item.Body.WAFRuleSet.Rules {
			if rule.Action != "log" {
				t.Errorf("%s/%s action %q: built-in sets must ship log-only", item.SystemKey, rule.ID, rule.Action)
			}
			for _, group := range rule.MatcherGroups {
				for _, matcher := range group.Matchers {
					if _, err := regexp.Compile(matcher.Value); err != nil {
						t.Errorf("%s/%s regex: %v", item.SystemKey, rule.ID, err)
					}
				}
			}
		}
	}
	for _, name := range want {
		if !names[name] {
			t.Errorf("missing %s", name)
		}
	}
	catalog := Catalog{Schema: CatalogSchema, Items: append(CompetitorSeed(), items...)}
	sortItems(catalog.Items)
	if _, _, err := CanonicalCatalog(catalog); err != nil {
		t.Fatalf("seed catalog invalid: %v", err)
	}
	// Signatures fire on representative payloads (after urldecode+lowercase on the node).
	samples := map[string]string{
		"waf_set:sqli": "id=1 union all select 1,2", "waf_set:xss": "q=<script>alert(1)</script>",
		"waf_set:file_include": "f=php://filter/resource=index", "waf_set:cmd_injection": "ip=1.1.1.1; cat /etc/hosts",
		"waf_set:java_code_injection": "x=${jndi:ldap://a/b}", "waf_set:java_deserialization": "d=rO0ABXNyABFqYXZh",
		"waf_set:php_code_injection": "c=system('id')", "waf_set:php_deserialization": `o=O:8:"stdClass":1:{s:1:"a";}`,
		"waf_set:ssti": "name={{7*7}}", "waf_set:webshell": "x=eval(base64_decode('aWQ='))",
		"waf_set:sensitive_paths": "/.git/config", "waf_set:bot_tools": "sqlmap/1.7.2#stable (https://sqlmap.org)",
		"waf_set:download_tools": "curl/8.4.0",
	}
	for _, item := range items {
		sample, ok := samples[item.SystemKey]
		if !ok {
			continue
		}
		hit := false
		for _, rule := range item.Body.WAFRuleSet.Rules {
			for _, group := range rule.MatcherGroups {
				hit = hit || regexp.MustCompile(group.Matchers[0].Value).MatchString(sample)
			}
		}
		if !hit {
			t.Errorf("%s does not match %q", item.SystemKey, sample)
		}
	}
}

func TestCRSWAFSeedSitsNextToSelfDevelopedSets(t *testing.T) {
	selfDeveloped := map[string]bool{}
	for _, item := range BuiltinWAFSeed() {
		selfDeveloped[item.SystemKey] = true
	}
	engines, settings, bundles := 0, 0, 0
	for _, item := range CRSWAFSeed() {
		if err := ValidateItem(item); err != nil {
			t.Fatalf("%s: %v", item.SystemKey, err)
		}
		// The rule text is at revision 2 (LICENSE and NOTICE, license migration 082).
		wantRevision := uint64(1)
		if item.SystemKey == "waf_set:crs_rules" {
			wantRevision = 2
		}
		if selfDeveloped[item.SystemKey] || !strings.HasPrefix(item.SystemKey, "waf_set:crs_") || item.Revision != wantRevision {
			t.Fatalf("%s must be a new CRS item, not a revision of a self-developed set", item.SystemKey)
		}
		body := item.Body.WAFRuleSet
		switch {
		case body.Engine != nil:
			engines++
			if item.Hidden || body.Engine.Paranoia < 1 || body.Engine.Threshold < 1 {
				t.Fatalf("%s engine = %+v", item.SystemKey, body.Engine)
			}
		case body.Settings != nil:
			settings++
		case body.Bundle != nil:
			bundles++
		}
		if (body.Engine == nil) != item.Hidden {
			t.Fatalf("%s hidden=%v", item.SystemKey, item.Hidden)
		}
	}
	if engines != 11 || settings != 1 || bundles != 1 {
		t.Fatalf("engines=%d settings=%d bundles=%d", engines, settings, bundles)
	}
	encoded, _, err := CanonicalCatalog(Catalog{Schema: CatalogSchema, Items: CurrentSeed()})
	if err != nil {
		t.Fatalf("current seed invalid: %v", err)
	}
	if len(encoded) > MaxCatalogBytes*3/4 {
		t.Fatalf("current seed is %d bytes, too close to the %d catalog limit", len(encoded), MaxCatalogBytes)
	}
}

func TestCompetitorFilterParamsCoverEveryFilter(t *testing.T) {
	items := CompetitorFilterParams()
	if len(items) != 17 {
		t.Fatalf("filters = %d", len(items))
	}
	for _, item := range items {
		if item.Revision != 2 || item.Body.CCFilter.Params == nil || ValidateItem(item) != nil {
			t.Fatalf("%s: revision %d params %+v err %v", item.SystemKey, item.Revision, item.Body.CCFilter.Params, ValidateItem(item))
		}
	}
	if _, _, err := CanonicalCatalog(Catalog{Schema: CatalogSchema, Items: CurrentSeed()}); err != nil {
		t.Fatal(err)
	}
	bad := CCFilterParams{BanSeconds: 360, PassSeconds: 21600, PowBits: 16, ChallengeSeconds: 120, BindIPv4Prefix: 24,
		BindIPv6Prefix: 64, KeyRotateSeconds: 3600}
	if ValidCCFilterParams("browser_verify_auto", bad) {
		t.Fatal("key rotation shorter than the pass lifetime accepted")
	}
	bad.KeyRotateSeconds, bad.PowBits = 86400, 4
	if ValidCCFilterParams("browser_verify_auto", bad) {
		t.Fatal("4-bit proof of work accepted")
	}
	if ValidCCFilterParams("req_rate", CCFilterParams{BanSeconds: 360, PowBits: 12}) {
		t.Fatal("verification params accepted on req_rate")
	}
}

// ge-waf S2: the bot / sensitive path signatures hit their targets and leave
// ordinary browsers, apps and paths alone (bare substrings "java" /
// "php" / "python" in any User-Agent would block those).
func TestBuiltinWAFBotAndPathSignaturesAvoidFalsePositives(t *testing.T) {
	sets := map[string]Item{}
	for _, item := range BuiltinWAFSeed() {
		sets[item.SystemKey] = item
	}
	matches := func(key, ruleID, value string) bool {
		for _, rule := range sets[key].Body.WAFRuleSet.Rules {
			if rule.ID != ruleID {
				continue
			}
			for _, group := range rule.MatcherGroups {
				matcher := group.Matchers[0]
				hit := regexp.MustCompile(matcher.Value).MatchString(value)
				if matcher.Operator == "not_regex" {
					hit = !hit
				}
				if hit {
					return true
				}
			}
		}
		return false
	}
	cases := []struct {
		key, rule, value string
		want             bool
	}{
		{"waf_set:bot_tools", "bot.scanner", "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)", true},
		{"waf_set:bot_tools", "bot.scanner", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36", false},
		{"waf_set:bot_tools", "bot.crawler", "python-requests/2.31.0", true},
		{"waf_set:bot_tools", "bot.crawler", "Go-http-client/1.1", true},
		{"waf_set:bot_tools", "bot.crawler", "Mozilla/5.0 (Linux; Android 14) JavaFX Python/3 PHP-app", false},
		{"waf_set:download_tools", "download.tools", "Wget/1.21.4", true},
		{"waf_set:download_tools", "download.tools", "Mozilla/5.0 curl-like-browser", false},
		{"waf_set:download_tools", "download.empty_ua", "", true},
		{"waf_set:download_tools", "download.empty_ua", "   ", true},
		{"waf_set:download_tools", "download.empty_ua", "Mozilla/5.0", false},
		{"waf_set:sensitive_paths", "dirs.vcs", "/app/.svn/entries", true},
		{"waf_set:sensitive_paths", "dirs.vcs", "/github/user", false},
		{"waf_set:sensitive_paths", "dirs.backup", "/db.sql.gz", true},
		{"waf_set:sensitive_paths", "dirs.backup", "/static/app.js", false},
		{"waf_set:sensitive_paths", "dirs.status", "/actuator/env", true},
		{"waf_set:webshell", "webshell.oneliner", "a=assert(@$_POST['x'])", true},
		{"waf_set:webshell", "webshell.oneliner", "q=evaluate my system design", false},
		{"waf_set:webshell", "webshell.files", "/uploads/wso2.php", true},
		{"waf_set:webshell", "webshell.upload", "jspx", true},
		{"waf_set:webshell", "webshell.upload", "png", false},
	}
	for _, test := range cases {
		if got := matches(test.key, test.rule, test.value); got != test.want {
			t.Errorf("%s/%s %q = %v, want %v", test.key, test.rule, test.value, got, test.want)
		}
	}
}

// TestWAFEngineSetAdaptiveFields: grey_action / adaptive / strong_rules
// (ADR 0011 RI-02) only on a two-level set, which needs a grey action.
func TestWAFEngineSetAdaptiveFields(t *testing.T) {
	two := WAFEngineSet{Engine: WAFEngineCRS, Files: []string{"REQUEST-942"}, IncludeIDs: []int{}, ExcludeIDs: []int{}, Action: "block",
		Paranoia: 2, Threshold: 5, StrongParanoia: 1, WeakThreshold: 10, GreyAction: WAFGreyChallenge, Adaptive: true, StrongRules: []int{942200, 942260}}
	if !validWAFEngineSet(two) {
		t.Fatal("two-level adaptive set refused")
	}
	one := two
	one.Paranoia, one.StrongParanoia, one.WeakThreshold, one.GreyAction, one.Adaptive, one.StrongRules = 1, 0, 0, "", false, nil
	if !validWAFEngineSet(one) {
		t.Fatal("one-level set refused")
	}
	for name, mutate := range map[string]func(*WAFEngineSet){
		"no grey":        func(s *WAFEngineSet) { s.GreyAction = "" },
		"grey block":     func(s *WAFEngineSet) { s.GreyAction = "block" },
		"order":          func(s *WAFEngineSet) { s.StrongRules = []int{942260, 942200} },
		"twice":          func(s *WAFEngineSet) { s.StrongRules = []int{942200, 942200} },
		"range":          func(s *WAFEngineSet) { s.StrongRules = []int{42200} },
		"too many":       func(s *WAFEngineSet) { s.StrongRules = make([]int, MaxWAFStrongRules+1) },
		"one-level grey": func(s *WAFEngineSet) { *s = one; s.GreyAction = WAFGreyAllow },
		"one-level auto": func(s *WAFEngineSet) { *s = one; s.Adaptive = true },
		"one-level rule": func(s *WAFEngineSet) { *s = one; s.StrongRules = []int{942200} },
		// waf-gap6 learned weak weights: two-level only, ascending, CRS IDs, 0-4
		"weight order":     func(s *WAFEngineSet) { s.WeakWeights = []WAFWeight{{942300, 1}, {942120, 1}} },
		"weight twice":     func(s *WAFEngineSet) { s.WeakWeights = []WAFWeight{{942120, 1}, {942120, 2}} },
		"weight range":     func(s *WAFEngineSet) { s.WeakWeights = []WAFWeight{{42120, 1}} },
		"weight negative":  func(s *WAFEngineSet) { s.WeakWeights = []WAFWeight{{942120, -1}} },
		"weight 5":         func(s *WAFEngineSet) { s.WeakWeights = []WAFWeight{{942120, 5}} },
		"weights too many": func(s *WAFEngineSet) { s.WeakWeights = make([]WAFWeight, MaxWAFStrongRules+1) },
		"one-level weight": func(s *WAFEngineSet) { *s = one; s.WeakWeights = []WAFWeight{{942120, 1}} },
	} {
		set := two
		set.StrongRules = append([]int(nil), two.StrongRules...)
		mutate(&set)
		if validWAFEngineSet(set) {
			t.Errorf("%s accepted", name)
		}
	}
	weighted := two
	weighted.WeakWeights = []WAFWeight{{942120, 0}, {942300, 2}}
	if !validWAFEngineSet(weighted) {
		t.Fatal("learned weights refused")
	}
	if encoded, _ := json.Marshal(weighted); !strings.Contains(string(encoded), `"weak_weights":[{"rule":942120,"weight":0},{"rule":942300,"weight":2}]`) {
		t.Fatalf("weak_weights JSON %s", encoded)
	}
	// the JSON names (the CRS profile pack bytes)
	encoded, _ := json.Marshal(two)
	for _, name := range []string{`"grey_action":"challenge"`, `"adaptive":true`, `"strong_rules":[942200,942260]`} {
		if !strings.Contains(string(encoded), name) {
			t.Fatalf("%s missing in %s", name, encoded)
		}
	}
	if encoded, _ := json.Marshal(one); strings.Contains(string(encoded), "grey_action") || strings.Contains(string(encoded), "adaptive") ||
		strings.Contains(string(encoded), "weak_weights") {
		t.Fatalf("one-level set carries adaptive fields: %s", encoded)
	}
}
