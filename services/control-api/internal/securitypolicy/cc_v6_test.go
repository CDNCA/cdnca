package securitypolicy

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func ccConditionRule(conditions ...Condition) Rule {
	return Rule{Name: "cc", Priority: 1, Enabled: true, Action: ActionRateLimit, Flow: FlowStop, Conditions: conditions,
		ActionConfig: ActionConfig{RateLimit: &RateLimitConfig{Algorithm: "fixed_window", WindowSeconds: 10,
			MaxRequests: 30, ResponseAction: "reject_429"}}}
}

// TestIPConditionAcceptsNetmaskAndRanges (NF27): a dotted netmask becomes
// its CIDR, a range a-b becomes the fewest CIDRs covering it; plain CIDRs
// and addresses keep their canonical form.
func TestIPConditionAcceptsNetmaskAndRanges(t *testing.T) {
	cases := map[string]struct {
		in   []string
		want []string
	}{
		"netmask":       {in: []string{"10.0.0.1/255.255.255.0"}, want: []string{"10.0.0.0/24"}},
		"netmask zero":  {in: []string{"192.0.2.9/255.255.255.255"}, want: []string{"192.0.2.9/32"}},
		"range aligned": {in: []string{"10.0.0.0-10.0.0.255"}, want: []string{"10.0.0.0/24"}},
		"range split": {in: []string{"10.0.0.1 - 10.0.0.6"},
			want: []string{"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"}},
		"range single": {in: []string{"192.0.2.7-192.0.2.7"}, want: []string{"192.0.2.7/32"}},
		"range v6":     {in: []string{"2001:db8::-2001:db8::ff"}, want: []string{"2001:db8::/120"}},
		"range wide":   {in: []string{"0.0.0.0-255.255.255.255"}, want: []string{"0.0.0.0/0"}},
		"mixed": {in: []string{"198.51.100.0/24", "10.0.0.8-10.0.0.15", "192.0.2.1"},
			want: []string{"10.0.0.8/29", "192.0.2.1/32", "198.51.100.0/24"}},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			rule, err := normalizeCCRule(ccConditionRule(Condition{Field: "client_ip", Operator: "ip_in_cidr", Values: test.in}))
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if got := rule.Conditions[0].Values; !slices.Equal(got, test.want) {
				t.Fatalf("values = %q, want %q", got, test.want)
			}
		})
	}
	for name, values := range map[string][]string{
		"non contiguous mask": {"10.0.0.1/255.0.255.0"},
		"v6 netmask":          {"2001:db8::1/ffff::"},
		"reversed range":      {"10.0.0.9-10.0.0.1"},
		"mixed family range":  {"10.0.0.1-2001:db8::1"},
		"mapped range":        {"::ffff:10.0.0.1-::ffff:10.0.0.9"},
		"overlap duplicate":   {"10.0.0.0/24", "10.0.0.0-10.0.0.255"},
		"too many cidrs":      {"0.0.0.1-255.255.255.254", "::1-ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "10.0.0.1-10.0.0.254", "10.1.0.1-10.1.0.254", "10.2.0.1-10.2.0.254", "10.3.0.1-10.3.0.254"},
		"garbage":             {"10.0.0.1-"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeCCRule(ccConditionRule(Condition{Field: "client_ip", Operator: "ip_in_cidr", Values: values})); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

// TestCCRepeatsIPAndHeaderConditions (NF27/NF32): CC rules may repeat
// client_ip and header conditions (all must hold) and match user agent and
// referer; other fields stay single; WAF keeps one condition per field.
func TestCCRepeatsIPAndHeaderConditions(t *testing.T) {
	rule, err := normalizeCCRule(ccConditionRule(
		Condition{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"10.0.0.0/8"}},
		Condition{Field: "client_ip", Operator: "ip_not_in_cidr", Values: []string{"10.1.0.0/16"}},
		Condition{Field: "header", Operator: "equals", Key: "X-Api", Values: []string{"a"}},
		Condition{Field: "header", Operator: "prefix", Key: "x-client", Values: []string{"b"}},
		Condition{Field: "user_agent", Operator: "regex", Values: []string{"(?i)python"}},
		Condition{Field: "referer", Operator: "contains", Values: []string{"spam.example"}},
	))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(rule.Conditions) != 6 || rule.Conditions[2].Key != "x-api" {
		t.Fatalf("conditions = %#v", rule.Conditions)
	}
	for name, conditions := range map[string][]Condition{
		"repeated host": {{Field: "host", Operator: "equals", Values: []string{"a.example"}},
			{Field: "host", Operator: "equals", Values: []string{"b.example"}}},
		"header suffix":  {{Field: "header", Operator: "suffix", Key: "x-a", Values: []string{"a"}}},
		"ua detect":      {{Field: "user_agent", Operator: "detect", Values: []string{"sqli"}}},
		"bad regex":      {{Field: "referer", Operator: "regex", Values: []string{"("}}},
		"ip not equals":  {{Field: "client_ip", Operator: "not_equals", Values: []string{"10.0.0.1"}}},
		"equals range":   {{Field: "client_ip", Operator: "equals", Values: []string{"10.0.0.1-10.0.0.2"}}},
		"identical pair": {{Field: "referer", Operator: "contains", Values: []string{"a"}}, {Field: "referer", Operator: "contains", Values: []string{"a"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeCCRule(ccConditionRule(conditions...)); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
	waf := PolicyFields{Kind: KindWAF, Name: "waf", Enabled: true, DefaultAction: ActionAllow, Rules: []Rule{{
		Name: "waf", Priority: 1, Enabled: true, Action: ActionBlock, Flow: FlowStop, Conditions: []Condition{
			{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"10.0.0.0/8"}},
			{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"10.1.0.0/16"}}}}}}
	if err := normalizePublishableFields(&waf, true); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("WAF repeated client_ip: %v", err)
	}
	// A range that needs several CIDRs is CC-only: WAF and ACL run one CIDR.
	acl := PolicyFields{Kind: KindACL, Name: "acl", Enabled: true, DefaultAction: ActionAllow, Rules: []Rule{{
		Name: "acl", Priority: 1, Enabled: true, Action: ActionBlock, Flow: FlowStop, Conditions: []Condition{
			{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"10.0.0.1/255.255.255.0"}}}}}}
	if err := normalizePublishableFields(&acl, true); err != nil || acl.Rules[0].Conditions[0].Values[0] != "10.0.0.0/24" {
		t.Fatalf("ACL netmask: %v %#v", err, acl.Rules[0].Conditions)
	}
}

// TestEvaluatePreviewsUserAgentRefererAndRegex: the preview (试算) runs the
// v6 CC conditions like the node.
func TestEvaluatePreviewsUserAgentRefererAndRegex(t *testing.T) {
	fields := PolicyFields{Kind: KindCC, Name: "cc", Enabled: true, DefaultAction: ActionAllow, Rules: []Rule{ccConditionRule(
		Condition{Field: "user_agent", Operator: "regex", Values: []string{"(?i)python"}},
		Condition{Field: "referer", Operator: "prefix", Values: []string{"https://spam."}},
		Condition{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"10.0.0.0-10.0.0.255"}},
		Condition{Field: "client_ip", Operator: "ip_not_in_cidr", Values: []string{"10.0.0.7"}},
	)}}
	if err := normalizePublishableFields(&fields, true); err != nil {
		t.Fatal(err)
	}
	fields.Rules[0].ID = uuid.New()
	policy := Policy{ID: uuid.New(), Kind: KindCC, Enabled: true, DefaultAction: ActionAllow, Rules: fields.Rules, Revision: 1}
	facts := func(ip, ua, referer string) RequestFacts {
		return RequestFacts{ClientIP: ip, Headers: HeaderValues{"User-Agent": {ua}, "Referer": {referer}}}
	}
	for name, test := range map[string]struct {
		facts   RequestFacts
		matched bool
	}{
		"all hold":      {facts("10.0.0.9", "Python-urllib/3", "https://spam.example/"), true},
		"excluded ip":   {facts("10.0.0.7", "Python-urllib/3", "https://spam.example/"), false},
		"outside range": {facts("10.0.1.9", "Python-urllib/3", "https://spam.example/"), false},
		"other ua":      {facts("10.0.0.9", "Mozilla/5.0", "https://spam.example/"), false},
		"other referer": {facts("10.0.0.9", "python", "https://www.example/"), false},
	} {
		t.Run(name, func(t *testing.T) {
			decision, err := evaluate(policy, test.facts)
			if err != nil || decision.UsedDefault == test.matched {
				t.Fatalf("decision = %#v, %v (want matched %v)", decision, err, test.matched)
			}
		})
	}
}

func TestACLImportAcceptsNetmask(t *testing.T) {
	rules, err := ParseACLImport("block 10.0.0.1/255.255.255.0 # office\n")
	if err != nil || rules[0].Conditions[0].Values[0] != "10.0.0.0/24" {
		t.Fatalf("ParseACLImport = %#v, %v", rules, err)
	}
}

func v6CCSettings() *CCSettings {
	return &CCSettings{
		TrustedCrawlers: []CCTrustedCrawler{
			{Name: " Google ", UserAgentTokens: []string{"Googlebot", "Google-InspectionTool"},
				Networks: []string{"66.249.64.1/19"}, RDNSSuffixes: []string{".GoogleBot.com", "google.com"}},
			{Name: "baidu", UserAgentTokens: []string{"Baiduspider"}, Networks: []string{}, RDNSSuffixes: []string{"baidu.com"}},
		},
		ChallengeCookieDomain: " .Example.TEST ",
	}
}

// TestCCSettingsNormalizeTrustedCrawlersAndCookieDomain (FX47/NF28).
func TestCCSettingsNormalizeTrustedCrawlersAndCookieDomain(t *testing.T) {
	settings := v6CCSettings()
	if err := normalizeCCSettings(KindCC, settings, true); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	want := []CCTrustedCrawler{
		{Name: "baidu", UserAgentTokens: []string{"Baiduspider"}, RDNSSuffixes: []string{"baidu.com"}},
		{Name: "google", UserAgentTokens: []string{"Google-InspectionTool", "Googlebot"}, Networks: []string{"66.249.64.0/19"},
			RDNSSuffixes: []string{"google.com", "googlebot.com"}},
	}
	if len(settings.TrustedCrawlers) != 2 || settings.ChallengeCookieDomain != "example.test" {
		t.Fatalf("settings = %#v", settings)
	}
	for index := range want {
		got := settings.TrustedCrawlers[index]
		if got.Name != want[index].Name || !slices.Equal(got.UserAgentTokens, want[index].UserAgentTokens) ||
			!slices.Equal(got.Networks, want[index].Networks) || !slices.Equal(got.RDNSSuffixes, want[index].RDNSSuffixes) {
			t.Fatalf("crawler %d = %#v, want %#v", index, got, want[index])
		}
	}
	empty := &CCSettings{TrustedCrawlers: []CCTrustedCrawler{}}
	if err := normalizeCCSettings(KindCC, empty, true); err != nil || empty.TrustedCrawlers != nil {
		t.Fatalf("empty crawlers = %#v, %v", empty, err)
	}
	for name, mutate := range map[string]func(*CCSettings){
		"no token":        func(value *CCSettings) { value.TrustedCrawlers[0].UserAgentTokens = nil },
		"no verification": func(value *CCSettings) { value.TrustedCrawlers[1].RDNSSuffixes = nil },
		"duplicate name":  func(value *CCSettings) { value.TrustedCrawlers[1].Name = "google" },
		"tld suffix":      func(value *CCSettings) { value.TrustedCrawlers[1].RDNSSuffixes = []string{"com"} },
		"all network":     func(value *CCSettings) { value.TrustedCrawlers[0].Networks = []string{"0.0.0.0/0"} },
		"short token":     func(value *CCSettings) { value.TrustedCrawlers[0].UserAgentTokens = []string{"G"} },
		"domain label":    func(value *CCSettings) { value.ChallengeCookieDomain = "localhost" },
		"domain wildcard": func(value *CCSettings) { value.ChallengeCookieDomain = "*.example.test" },
		"domain port":     func(value *CCSettings) { value.ChallengeCookieDomain = "example.test:443" },
	} {
		t.Run(name, func(t *testing.T) {
			value := v6CCSettings()
			mutate(value)
			if err := normalizeCCSettings(KindCC, value, true); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
	if err := normalizeCCSettings(KindWAF, v6CCSettings(), true); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("WAF settings: %v", err)
	}
}

// TestRuntimeSnapshotCarriesTrustedCrawlersAndCookieDomain: both reach the
// node as settings of the snapshot and survive ValidateRuntimeSnapshot.
func TestRuntimeSnapshotCarriesTrustedCrawlersAndCookieDomain(t *testing.T) {
	policy := Policy{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000020"),
		ScopeID: uuid.MustParse("018f1000-0000-7000-8000-000000000001"), Kind: KindCC, Name: "cc", Enabled: true,
		DefaultAction: ActionAllow, Revision: 2, CCSettings: v6CCSettings(), Rules: []Rule{func() Rule {
			rule := ccConditionRule(Condition{Field: "path", Operator: "prefix", Values: []string{"/"}})
			rule.ID = uuid.MustParse("018f1000-0000-7000-8000-000000000021")
			return rule
		}()}}
	compiled, err := CompileRuntimeSnapshot(policy, uuid.MustParse("018f1000-0000-7000-8000-000000000002"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"trusted_crawlers":[{"name":"baidu","user_agent_tokens":["Baiduspider"],"rdns_suffixes":["baidu.com"]}`,
		`"challenge_cookie_domain":"example.test"`} {
		if !strings.Contains(string(compiled.CanonicalJSON), want) {
			t.Fatalf("snapshot %s missing %s", compiled.CanonicalJSON, want)
		}
	}
	if err := ValidateRuntimeSnapshot(compiled.Snapshot); err != nil {
		t.Fatalf("ValidateRuntimeSnapshot: %v", err)
	}
	plain := policy
	plain.CCSettings = nil
	compiled, err = CompileRuntimeSnapshot(plain, uuid.MustParse("018f1000-0000-7000-8000-000000000002"))
	if err != nil || strings.Contains(string(compiled.CanonicalJSON), "trusted_crawlers") ||
		strings.Contains(string(compiled.CanonicalJSON), "challenge_cookie_domain") {
		t.Fatalf("plain snapshot = %s, %v", compiled.CanonicalJSON, err)
	}
}
