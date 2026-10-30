package edgeconfig

import (
	"strings"
	"testing"
)

func v6CCV2Policy() CCV2Policy {
	policy := testCCV2Policy("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "11111111-1111-4111-8111-111111111111")
	policy.Rules[0].Match.ClientIP = []CCV2IPMatch{
		{CIDRs: []string{"10.0.0.0/24", "192.0.2.0/25"}},
		{Negate: true, CIDRs: []string{"10.0.0.7/32"}},
	}
	policy.Rules[0].Match.Headers = []CCV2HeaderMatch{
		{Name: "referer", Kind: CCV2HeaderContains, Values: []string{"spam.example"}},
		{Name: "user-agent", Kind: CCV2HeaderRegex, Values: []string{"(?i)python"}},
		{Name: "x-api-key", Kind: CCV2HeaderExact, Values: []string{"a", "b"}},
	}
	policy.TrustedCrawlers = []CCV2TrustedCrawler{{Name: "baidu", UserAgentTokens: []string{"Baiduspider"},
		RDNSSuffixes: []string{"baidu.com", "baidu.jp"}}, {Name: "google", UserAgentTokens: []string{"Googlebot"},
		Networks: []string{"66.249.64.0/19"}, RDNSSuffixes: []string{"google.com", "googlebot.com"}}}
	policy.ChallengeCookieDomain = "example.test"
	return policy
}

// TestCCV2V6FieldsEncodeOnlyWhenSetAndNeedCCV6: trusted crawlers, the pass
// cookie domain, IP lists and header matches are CC API v6; a policy without
// them keeps its bytes and its version.
func TestCCV2V6FieldsEncodeOnlyWhenSetAndNeedCCV6(t *testing.T) {
	plain := testCCV2Policy("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "11111111-1111-4111-8111-111111111111")
	encoded, err := CanonicalCCV2Policy(plain)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"trusted_crawlers", "challenge_cookie_domain", "client_ip\":[", "headers"} {
		if strings.Contains(string(encoded), field) {
			t.Fatalf("plain policy encodes %s: %s", field, encoded)
		}
	}
	if CCV2PolicyAPIVersion(plain) != 2 {
		t.Fatalf("plain policy CC v%d", CCV2PolicyAPIVersion(plain))
	}
	policy := v6CCV2Policy()
	encoded, err = CanonicalCCV2Policy(policy)
	if err != nil {
		t.Fatalf("v6 policy rejected: %v", err)
	}
	for _, want := range []string{
		`"client_ip":[{"cidrs":["10.0.0.0/24","192.0.2.0/25"]},{"negate":true,"cidrs":["10.0.0.7/32"]}]`,
		`"headers":[{"name":"referer","kind":"contains","values":["spam.example"]},{"name":"user-agent","kind":"regex","values":["(?i)python"]},{"name":"x-api-key","kind":"exact","values":["a","b"]}]`,
		`"trusted_crawlers":[{"name":"baidu","user_agent_tokens":["Baiduspider"],"rdns_suffixes":["baidu.com","baidu.jp"]},{"name":"google","user_agent_tokens":["Googlebot"],"networks":["66.249.64.0/19"],"rdns_suffixes":["google.com","googlebot.com"]}]`,
		`"challenge_cookie_domain":"example.test"`,
	} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("encoded:\n%s\nwant %s", encoded, want)
		}
	}
	decoded, err := DecodeCCV2Policy(encoded)
	if err != nil || len(decoded.TrustedCrawlers) != 2 || len(decoded.Rules[0].Match.Headers) != 3 {
		t.Fatalf("decode: %v %#v", err, decoded)
	}
	if CCV2PolicyAPIVersion(policy) != 6 {
		t.Fatalf("v6 policy CC v%d", CCV2PolicyAPIVersion(policy))
	}
	for name, mutate := range map[string]func(*CCV2Policy){
		"crawlers only": func(value *CCV2Policy) { *value = plain; value.TrustedCrawlers = policy.TrustedCrawlers },
		"domain only":   func(value *CCV2Policy) { *value = plain; value.ChallengeCookieDomain = "example.test" },
		"ip list only": func(value *CCV2Policy) {
			*value = plain
			value.Rules = cloneCCV2Rules(plain.Rules)
			value.Rules[0].Match.ClientIP = []CCV2IPMatch{{Negate: true, CIDRs: []string{"10.0.0.0/8"}}}
		},
		"header only": func(value *CCV2Policy) {
			*value = plain
			value.Rules = cloneCCV2Rules(plain.Rules)
			value.Rules[0].Match.Headers = []CCV2HeaderMatch{{Name: "user-agent", Kind: CCV2HeaderPrefix, Values: []string{"curl/"}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var value CCV2Policy
			mutate(&value)
			if _, err := CanonicalCCV2Policy(value); err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if CCV2PolicyAPIVersion(value) != 6 {
				t.Fatalf("CC v%d, want 6", CCV2PolicyAPIVersion(value))
			}
		})
	}
}

func TestCCV2V6RejectsNonCanonicalForms(t *testing.T) {
	cases := map[string]func(*CCV2Policy){
		"single positive cidr is source_cidr": func(value *CCV2Policy) {
			value.Rules[0].Match.ClientIP = []CCV2IPMatch{{CIDRs: []string{"10.0.0.0/24"}}}
		},
		"source_cidr with list": func(value *CCV2Policy) { value.Rules[0].Match.SourceCIDR = "10.0.0.0/8" },
		"empty ip list":         func(value *CCV2Policy) { value.Rules[0].Match.ClientIP = []CCV2IPMatch{} },
		"empty cidrs":           func(value *CCV2Policy) { value.Rules[0].Match.ClientIP[1].CIDRs = []string{} },
		"unsorted cidrs": func(value *CCV2Policy) {
			value.Rules[0].Match.ClientIP[0].CIDRs = []string{"192.0.2.0/25", "10.0.0.0/24"}
		},
		"unmasked cidr":     func(value *CCV2Policy) { value.Rules[0].Match.ClientIP[1].CIDRs = []string{"10.0.0.7/24"} },
		"mapped cidr":       func(value *CCV2Policy) { value.Rules[0].Match.ClientIP[1].CIDRs = []string{"::ffff:10.0.0.7/128"} },
		"bare address":      func(value *CCV2Policy) { value.Rules[0].Match.ClientIP[1].CIDRs = []string{"10.0.0.7"} },
		"empty headers":     func(value *CCV2Policy) { value.Rules[0].Match.Headers = []CCV2HeaderMatch{} },
		"upper header name": func(value *CCV2Policy) { value.Rules[0].Match.Headers[2].Name = "X-Api-Key" },
		"bad header name":   func(value *CCV2Policy) { value.Rules[0].Match.Headers[2].Name = "x api" },
		"unknown kind":      func(value *CCV2Policy) { value.Rules[0].Match.Headers[2].Kind = "suffix" },
		"unsorted values":   func(value *CCV2Policy) { value.Rules[0].Match.Headers[2].Values = []string{"b", "a"} },
		"empty value":       func(value *CCV2Policy) { value.Rules[0].Match.Headers[2].Values = []string{""} },
		"control value":     func(value *CCV2Policy) { value.Rules[0].Match.Headers[2].Values = []string{"a\nb"} },
		"bad regex":         func(value *CCV2Policy) { value.Rules[0].Match.Headers[1].Values = []string{"("} },
		"empty crawlers":    func(value *CCV2Policy) { value.TrustedCrawlers = []CCV2TrustedCrawler{} },
		"unsorted crawlers": func(value *CCV2Policy) {
			value.TrustedCrawlers[0], value.TrustedCrawlers[1] = value.TrustedCrawlers[1], value.TrustedCrawlers[0]
		},
		"crawler no verification": func(value *CCV2Policy) {
			value.TrustedCrawlers[0].RDNSSuffixes = nil
		},
		"crawler no token":     func(value *CCV2Policy) { value.TrustedCrawlers[0].UserAgentTokens = nil },
		"crawler empty suffix": func(value *CCV2Policy) { value.TrustedCrawlers[0].RDNSSuffixes = []string{} },
		"crawler bad suffix":   func(value *CCV2Policy) { value.TrustedCrawlers[0].RDNSSuffixes = []string{".baidu.com"} },
		"crawler tld suffix":   func(value *CCV2Policy) { value.TrustedCrawlers[0].RDNSSuffixes = []string{"com"} },
		"crawler bad network":  func(value *CCV2Policy) { value.TrustedCrawlers[1].Networks = []string{"66.249.64.1/19"} },
		"crawler all network":  func(value *CCV2Policy) { value.TrustedCrawlers[1].Networks = []string{"0.0.0.0/0"} },
		"crawler token space":  func(value *CCV2Policy) { value.TrustedCrawlers[0].UserAgentTokens = []string{"a b\n"} },
		"crawler name":         func(value *CCV2Policy) { value.TrustedCrawlers[0].Name = "" },
		"domain upper":         func(value *CCV2Policy) { value.ChallengeCookieDomain = "Example.test" },
		"domain dot":           func(value *CCV2Policy) { value.ChallengeCookieDomain = ".example.test" },
		"domain single label":  func(value *CCV2Policy) { value.ChallengeCookieDomain = "test" },
		"domain wildcard":      func(value *CCV2Policy) { value.ChallengeCookieDomain = "*.example.test" },
		"disabled with crawlers": func(value *CCV2Policy) {
			value.Enabled = false
			value.Rules = []CCV2Rule{}
			value.ChallengeCookieDomain = ""
		},
		"disabled with domain": func(value *CCV2Policy) {
			value.Enabled = false
			value.Rules = []CCV2Rule{}
			value.TrustedCrawlers = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			policy := v6CCV2Policy()
			policy.Rules = cloneCCV2Rules(policy.Rules)
			policy.TrustedCrawlers = cloneCCV2TrustedCrawlers(policy.TrustedCrawlers)
			mutate(&policy)
			if _, err := CanonicalCCV2Policy(policy); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
