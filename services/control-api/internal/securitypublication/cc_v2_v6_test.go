package securitypublication

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// v6PolicyForTest: IP lists (range, netmask, exclusion), header / UA /
// Referer matches, trusted crawlers and a pass cookie domain (CC API v6).
func v6PolicyForTest() securitypolicy.Policy {
	limit := func(action string, ban int) securitypolicy.ActionConfig {
		return securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window",
			WindowSeconds: 10, MaxRequests: 30, ResponseAction: action, BanSeconds: ban}}
	}
	return securitypolicy.Policy{
		ID: uuid.MustParse("018f1000-0000-7000-8000-000000000020"), ScopeID: testTenantScopeID,
		Kind: securitypolicy.KindCC, Name: "v6", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 4,
		Rules: []securitypolicy.Rule{
			{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000021"), Name: "ip lists", Priority: 10, Enabled: true,
				Conditions: []securitypolicy.Condition{
					{Field: "path", Operator: "prefix", Values: []string{"/"}},
					{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"10.0.0.0-10.0.0.255", "192.0.2.1/255.255.255.128"}},
					{Field: "client_ip", Operator: "ip_not_in_cidr", Values: []string{"10.0.0.7"}},
				},
				Action: securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop, ActionConfig: limit("temporary_ban", 60)},
			{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000022"), Name: "headers", Priority: 20, Enabled: true,
				Conditions: []securitypolicy.Condition{
					{Field: "user_agent", Operator: "regex", Values: []string{"(?i)python"}},
					{Field: "referer", Operator: "contains", Values: []string{"spam.example"}},
					{Field: "header", Operator: "prefix", Key: "X-Client", Values: []string{"bot-"}},
					{Field: "header", Operator: "equals", Key: "x-api", Values: []string{"b", "a"}},
				},
				Action: securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop, ActionConfig: limit("reject_429", 0)},
			{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000023"), Name: "single address", Priority: 30, Enabled: true,
				Conditions: []securitypolicy.Condition{
					{Field: "client_ip", Operator: "equals", Values: []string{"203.0.113.9"}},
				},
				Action: securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop, ActionConfig: limit("reject_429", 0)},
			{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000024"), Name: "two positives", Priority: 40, Enabled: true,
				Conditions: []securitypolicy.Condition{
					{Field: "client_ip", Operator: "equals", Values: []string{"2001:db8::9"}},
					{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"2001:db8::/64"}},
				},
				Action: securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop, ActionConfig: limit("reject_429", 0)},
		},
		CCSettings: &securitypolicy.CCSettings{
			TrustedCrawlers: []securitypolicy.CCTrustedCrawler{
				{Name: "google", UserAgentTokens: []string{"Googlebot"}, Networks: []string{"66.249.64.0/19"},
					RDNSSuffixes: []string{"google.com", "googlebot.com"}},
				{Name: "baidu", UserAgentTokens: []string{"Baiduspider"}, RDNSSuffixes: []string{"baidu.com", "baidu.jp"}},
			},
			ChallengeCookieDomain: "example.test",
		},
	}
}

func compileV6Fixture(t *testing.T, policy securitypolicy.Policy) (source, compiled []byte, result edgeconfig.CCV2Policy) {
	t.Helper()
	runtime, err := securitypolicy.CompileRuntimeSnapshot(policy, testSiteID)
	if err != nil {
		t.Fatalf("CompileRuntimeSnapshot: %v", err)
	}
	bindings, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{{
		BindingID: uuid.MustParse("018f1000-0000-7000-8000-000000000030"), BindingRevision: 1,
		PublicationID:         uuid.MustParse("018f1000-0000-7000-8000-000000000031"),
		RuntimeSnapshotSHA256: runtime.SHA256, Snapshot: runtime.Snapshot}})
	if err != nil {
		t.Fatalf("CompileSiteSecurityBindings: %v", err)
	}
	canonical, err := edgeconfig.CanonicalCCV2Policy(bindings.Site.CCV2.Policy)
	if err != nil {
		t.Fatal(err)
	}
	return runtime.CanonicalJSON, canonical, bindings.Site.CCV2.Policy
}

// TestCompileCCV2V6MatchesAgentParityFixture writes / checks the pair the
// agent's independent compiler reproduces (agents/edge-agent/internal/ccv2
// v6_test.go). Regenerate with CDNCA_WRITE_CC_FIXTURES=<testdata dir>.
func TestCompileCCV2V6MatchesAgentParityFixture(t *testing.T) {
	source, compiled, policy := compileV6Fixture(t, v6PolicyForTest())
	if output := os.Getenv("CDNCA_WRITE_CC_FIXTURES"); output != "" {
		for name, content := range map[string][]byte{"v6.source.json": source, "v6.compiled.json": compiled} {
			if err := os.WriteFile(filepath.Join(output, name), content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, required := range []string{
		`"match":{"path":{"kind":"prefix","value":"/"},"client_ip":[{"cidrs":["10.0.0.0/24","192.0.2.0/25"]},{"negate":true,"cidrs":["10.0.0.7/32"]}]}`,
		`"headers":[{"name":"x-api","kind":"exact","values":["a","b"]},{"name":"x-client","kind":"prefix","values":["bot-"]},{"name":"referer","kind":"contains","values":["spam.example"]},{"name":"user-agent","kind":"regex","values":["(?i)python"]}]`,
		`"match":{"source_cidr":"203.0.113.9/32"}`,
		`"client_ip":[{"cidrs":["2001:db8::9/128"]},{"cidrs":["2001:db8::/64"]}]`,
		`"trusted_crawlers":[{"name":"baidu","user_agent_tokens":["Baiduspider"],"rdns_suffixes":["baidu.com","baidu.jp"]},{"name":"google","user_agent_tokens":["Googlebot"],"networks":["66.249.64.0/19"],"rdns_suffixes":["google.com","googlebot.com"]}]`,
		`"challenge_cookie_domain":"example.test"`,
	} {
		if !strings.Contains(string(compiled), required) {
			t.Fatalf("compiled policy missing %s:\n%s", required, compiled)
		}
	}
	if edgeconfig.CCV2PolicyAPIVersion(policy) != 6 {
		t.Fatalf("v6 policy CC API v%d", edgeconfig.CCV2PolicyAPIVersion(policy))
	}
	for name, content := range map[string][]byte{"v6.source.json": source, "v6.compiled.json": compiled} {
		want, err := os.ReadFile(filepath.Join(countByParityFixtures, name))
		if err != nil {
			t.Fatalf("parity fixture (regenerate with CDNCA_WRITE_CC_FIXTURES): %v", err)
		}
		if !bytes.Equal(content, want) {
			t.Fatalf("%s drifted from the agent parity fixture:\n got %s\nwant %s", name, content, want)
		}
	}
}

// TestCompileCCV2DisabledPolicyDropsV6Settings: a disabled policy runs
// nothing, so it carries no crawlers or cookie domain and needs no CC v6.
func TestCompileCCV2DisabledPolicyDropsV6Settings(t *testing.T) {
	policy := v6PolicyForTest()
	policy.Enabled = false
	_, compiled, result := compileV6Fixture(t, policy)
	if strings.Contains(string(compiled), "trusted_crawlers") || strings.Contains(string(compiled), "challenge_cookie_domain") ||
		edgeconfig.CCV2PolicyAPIVersion(result) != 2 {
		t.Fatalf("disabled policy: %s", compiled)
	}
}
