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

// countByParityFixtures is where the edge agent's ccv2 compiler reads the
// same pair (agents/edge-agent/internal/ccv2/count_by_test.go): both sides
// must produce these bytes or the node's release precheck rejects them.
const countByParityFixtures = "../../../../agents/edge-agent/internal/ccv2/testdata"

func countByPolicyForTest() securitypolicy.Policy {
	challenge := &securitypolicy.ChallengeConfig{Type: "js", FailureWindowSeconds: 60, MaxFailures: 5,
		PassSeconds: 3600, BanSeconds: 600, PowBits: 16, ChallengeSeconds: 120, BindIPv4Prefix: 24,
		BindIPv6Prefix: 64, KeyRotateSeconds: 86400, TriggerWindowSeconds: 10, TriggerMaxRequests: 30}
	return securitypolicy.Policy{
		ID: uuid.MustParse("018f1000-0000-7000-8000-000000000020"), ScopeID: testTenantScopeID,
		Kind: securitypolicy.KindCC, Name: "count-by", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 3,
		Rules: []securitypolicy.Rule{
			{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000021"), Name: "cidr+uri", Priority: 10, Enabled: true,
				Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
				Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
				ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window",
					WindowSeconds: 10, MaxRequests: 30, ResponseAction: "temporary_ban", BanSeconds: 60}},
				CountBy: []securitypolicy.CountKey{{Key: securitypolicy.CountKeyURI}, {Key: securitypolicy.CountKeyClientCIDR}}},
			{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000022"), Name: "ja4 ban", Priority: 20, Enabled: true,
				Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/api"}}},
				Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
				ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window",
					WindowSeconds: 60, MaxRequests: 100, ResponseAction: "temporary_ban", BanSeconds: 300}},
				CountBy: []securitypolicy.CountKey{{Key: securitypolicy.CountKeyJA4}}, ActionTarget: securitypolicy.ActionTargetCountKey},
			{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000023"), Name: "host leaky", Priority: 30, Enabled: true,
				Conditions: []securitypolicy.Condition{{Field: "method", Operator: "equals", Values: []string{"POST"}}},
				Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
				ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "leaky_bucket",
					RatePerSecond: 5, Burst: 10, ResponseAction: "reject_429"}},
				CountBy: []securitypolicy.CountKey{{Key: securitypolicy.CountKeyHost}, {Key: securitypolicy.CountKeyURIPath}}},
			{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000024"), Name: "cidr challenge", Priority: 40, Enabled: true,
				Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
				Action:     securitypolicy.ActionChallenge, Flow: securitypolicy.FlowStop,
				ActionConfig: securitypolicy.ActionConfig{Challenge: challenge},
				CountBy:      []securitypolicy.CountKey{{Key: securitypolicy.CountKeyClientCIDR, IPv4Prefix: 16, IPv6Prefix: 48}}},
		},
	}
}

func compileCountByFixture(t *testing.T) (source, compiled []byte, policy edgeconfig.CCV2Policy) {
	t.Helper()
	runtime, err := securitypolicy.CompileRuntimeSnapshot(countByPolicyForTest(), testSiteID)
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
	canonical, err := edgeconfig.CanonicalCCV2Policy(result.Site.CCV2.Policy)
	if err != nil {
		t.Fatal(err)
	}
	return runtime.CanonicalJSON, canonical, result.Site.CCV2.Policy
}

func TestCompileCCV2CountByMatchesAgentParityFixture(t *testing.T) {
	source, compiled, policy := compileCountByFixture(t)
	if output := os.Getenv("CDNCA_WRITE_CC_FIXTURES"); output != "" {
		for name, content := range map[string][]byte{"count-by.source.json": source, "count-by.compiled.json": compiled} {
			if err := os.WriteFile(filepath.Join(output, name), content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, required := range []string{
		`"count_by":[{"key":"client_cidr","ipv4_prefix":24,"ipv6_prefix":64},{"key":"uri"}]`,
		`"action":{"kind":"temporary_ban","ban_seconds":300,"target":"count_key"}`,
		`"count_by":[{"key":"host"},{"key":"uri_path"}],"limit":{"algorithm":"leaky_bucket"`,
		`"count_by":[{"key":"client_cidr","ipv4_prefix":16,"ipv6_prefix":48}],"limit":{"algorithm":"fixed_window","requests":30,"window_seconds":10}`,
	} {
		if !strings.Contains(string(compiled), required) {
			t.Fatalf("compiled policy missing %s:\n%s", required, compiled)
		}
	}
	if edgeconfig.CCV2PolicyAPIVersion(policy) != 4 {
		t.Fatalf("count_by policy CC API v%d", edgeconfig.CCV2PolicyAPIVersion(policy))
	}
	for name, content := range map[string][]byte{"count-by.source.json": source, "count-by.compiled.json": compiled} {
		want, err := os.ReadFile(filepath.Join(countByParityFixtures, name))
		if err != nil {
			t.Fatalf("parity fixture (regenerate with CDNCA_WRITE_CC_FIXTURES): %v", err)
		}
		if !bytes.Equal(content, want) {
			t.Fatalf("%s drifted from the agent parity fixture:\n got %s\nwant %s", name, content, want)
		}
	}
}

// TestCompileCCV2DefaultCountKeepsBytes: a rule saved as count_by
// [client_ip] is the pre-v4 rule, byte for byte, and needs no CC v4.
func TestCompileCCV2DefaultCountKeepsBytes(t *testing.T) {
	plain := ccV2PolicyForTest()
	explicit := mutateCCV2Policy(plain, func(policy *securitypolicy.Policy) {
		for index := range policy.Rules {
			policy.Rules[index].CountBy = []securitypolicy.CountKey{{Key: securitypolicy.CountKeyClientIP}}
		}
	})
	if err := securitypolicy.ValidatePublishablePolicy(explicit); err != nil {
		t.Fatal(err)
	}
	compile := func(policy securitypolicy.Policy) []byte {
		runtime, err := securitypolicy.CompileRuntimeSnapshot(policy, testSiteID)
		if err != nil {
			t.Fatal(err)
		}
		binding := ActiveBinding{BindingID: uuid.MustParse("018f1000-0000-7000-8000-000000000030"), BindingRevision: 1,
			PublicationID:         uuid.MustParse("018f1000-0000-7000-8000-000000000031"),
			RuntimeSnapshotSHA256: runtime.SHA256, Snapshot: runtime.Snapshot}
		result, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{binding})
		if err != nil {
			t.Fatal(err)
		}
		canonical, err := edgeconfig.CanonicalCCV2Policy(result.Site.CCV2.Policy)
		if err != nil {
			t.Fatal(err)
		}
		return append(runtime.CanonicalJSON, canonical...)
	}
	if !bytes.Equal(compile(plain), compile(explicit)) {
		t.Fatal("explicit count_by [client_ip] changed the runtime or compiled bytes")
	}
}
