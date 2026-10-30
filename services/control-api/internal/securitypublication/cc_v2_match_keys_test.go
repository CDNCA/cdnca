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

// fix-ja4rule ③ (CC API v7, CAPABILITY_NAME_CC_MATCH_KEYS): counting by
// User-Agent, a named header / cookie / query argument, and a JA4 match. The
// edge agent reads the same pair (agents/edge-agent/internal/ccv2/match_keys_test.go).
func matchKeysPolicyForTest() securitypolicy.Policy {
	limit := func(maximum int) securitypolicy.ActionConfig {
		return securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window",
			WindowSeconds: 60, MaxRequests: maximum, ResponseAction: "temporary_ban", BanSeconds: 300}}
	}
	all := []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}}
	return securitypolicy.Policy{
		ID: uuid.MustParse("018f1000-0000-7000-8000-000000000040"), ScopeID: testTenantScopeID,
		Kind: securitypolicy.KindCC, Name: "match-keys", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 2,
		Rules: []securitypolicy.Rule{
			{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000041"), Name: "ua", Priority: 10, Enabled: true,
				Conditions: all, Action: securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop, ActionConfig: limit(50),
				CountBy: []securitypolicy.CountKey{{Key: securitypolicy.CountKeyUserAgent}}},
			{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000042"), Name: "api key", Priority: 20, Enabled: true,
				Conditions: all, Action: securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop, ActionConfig: limit(100),
				CountBy:      []securitypolicy.CountKey{{Key: securitypolicy.CountKeyHeader, Name: "X-Api-Key"}, {Key: securitypolicy.CountKeyURIPath}},
				ActionTarget: securitypolicy.ActionTargetCountKey},
			{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000043"), Name: "cookie+query", Priority: 30, Enabled: true,
				Conditions: all, Action: securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop, ActionConfig: limit(100),
				CountBy: []securitypolicy.CountKey{{Key: securitypolicy.CountKeyQuery, Name: "token"}, {Key: securitypolicy.CountKeyCookie, Name: "sid"}}},
			{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000044"), Name: "ja4 match", Priority: 40, Enabled: true,
				Conditions: []securitypolicy.Condition{{Field: "ja4", Operator: "in", Values: []string{
					"t13d3112h2_e8f1e7e78f70_6bebaf5329ac", "t13d1516h2_8daaf6152771_e5627efa2ab1"}}},
				Action: securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop, ActionConfig: limit(10)},
		},
	}
}

func TestCompileCCV2MatchKeysMatchesAgentParityFixture(t *testing.T) {
	policy := matchKeysPolicyForTest()
	if err := securitypolicy.ValidatePublishablePolicy(policy); err != nil {
		t.Fatalf("v7 policy refused: %v", err)
	}
	runtime, err := securitypolicy.CompileRuntimeSnapshot(policy, testSiteID)
	if err != nil {
		t.Fatalf("CompileRuntimeSnapshot: %v", err)
	}
	result, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{{
		BindingID: uuid.MustParse("018f1000-0000-7000-8000-000000000030"), BindingRevision: 1,
		PublicationID:         uuid.MustParse("018f1000-0000-7000-8000-000000000031"),
		RuntimeSnapshotSHA256: runtime.SHA256, Snapshot: runtime.Snapshot}})
	if err != nil {
		t.Fatalf("CompileSiteSecurityBindings: %v", err)
	}
	compiled, err := edgeconfig.CanonicalCCV2Policy(result.Site.CCV2.Policy)
	if err != nil {
		t.Fatal(err)
	}
	source := runtime.CanonicalJSON
	if output := os.Getenv("CDNCA_WRITE_CC_FIXTURES"); output != "" {
		for name, content := range map[string][]byte{"match-keys.source.json": source, "match-keys.compiled.json": compiled} {
			if err := os.WriteFile(filepath.Join(output, name), content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, required := range []string{
		`"count_by":[{"key":"user_agent"}]`,
		// header names are lower case; keys in canonical order.
		`"count_by":[{"key":"uri_path"},{"key":"header","name":"x-api-key"}]`,
		`"count_by":[{"key":"cookie","name":"sid"},{"key":"query","name":"token"}]`,
		`"ja4":["t13d1516h2_8daaf6152771_e5627efa2ab1","t13d3112h2_e8f1e7e78f70_6bebaf5329ac"]`,
	} {
		if !strings.Contains(string(compiled), required) {
			t.Fatalf("compiled policy missing %s:\n%s", required, compiled)
		}
	}
	if edgeconfig.CCV2PolicyAPIVersion(result.Site.CCV2.Policy) != 7 || !edgeconfig.CCV2PolicyUsesJA4(result.Site.CCV2.Policy) {
		t.Fatalf("v7 policy CC API v%d", edgeconfig.CCV2PolicyAPIVersion(result.Site.CCV2.Policy))
	}
	for name, content := range map[string][]byte{"match-keys.source.json": source, "match-keys.compiled.json": compiled} {
		want, err := os.ReadFile(filepath.Join(countByParityFixtures, name))
		if err != nil {
			t.Fatalf("parity fixture (regenerate with CDNCA_WRITE_CC_FIXTURES): %v", err)
		}
		if !bytes.Equal(content, want) {
			t.Fatalf("%s drifted from the agent parity fixture:\n got %s\nwant %s", name, content, want)
		}
	}
}
