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

// autoSwitchPolicyForTest: a 5 s / 300 rate limit with a temporary ban, an
// auto switch at 200 requests or 20 5xx per second to a JS challenge (both
// from the catalog), site durations ban 900 s / pass 7200 s.
func autoSwitchPolicyForTest() securitypolicy.Policy {
	challenge := &securitypolicy.ChallengeConfig{Type: "js", FailureWindowSeconds: 60, MaxFailures: 5,
		PassSeconds: 3600, BanSeconds: 600, PowBits: 16, ChallengeSeconds: 120, BindIPv4Prefix: 24,
		BindIPv6Prefix: 64, KeyRotateSeconds: 3600}
	return securitypolicy.Policy{
		ID: uuid.MustParse("018f1000-0000-7000-8000-000000000040"), ScopeID: testTenantScopeID,
		Kind: securitypolicy.KindCC, Name: "auto-switch", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 2,
		Rules: []securitypolicy.Rule{{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000041"), Name: "relaxed",
			Priority: 10, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
			Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
			ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window",
				WindowSeconds: 5, MaxRequests: 300, ResponseAction: "temporary_ban", BanSeconds: 360}}}},
		CCSettings: &securitypolicy.CCSettings{
			BanSeconds:  &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingCustom, Seconds: 900},
			PassSeconds: &securitypolicy.CCDuration{Mode: securitypolicy.CCSettingSystem, Seconds: 7200},
			AutoSwitch: &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingCustom, QPSTotal: 200, QPS5xx: 20,
				RecoverSeconds: 300, RuleGroups: []string{"cc_rule:1"},
				Rules: []securitypolicy.Rule{{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000042"), Name: "js",
					Priority: 10, Enabled: true,
					Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}},
					Action:     securitypolicy.ActionChallenge, Flow: securitypolicy.FlowStop,
					ActionConfig: securitypolicy.ActionConfig{Challenge: challenge}}}},
		},
	}
}

func compileAutoSwitchFixture(t *testing.T, policy securitypolicy.Policy) (source, compiled []byte, result edgeconfig.CCV2Policy) {
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

func TestCompileCCV2AutoSwitchMatchesAgentParityFixture(t *testing.T) {
	source, compiled, policy := compileAutoSwitchFixture(t, autoSwitchPolicyForTest())
	if output := os.Getenv("CDNCA_WRITE_CC_FIXTURES"); output != "" {
		for name, content := range map[string][]byte{"auto-switch.source.json": source, "auto-switch.compiled.json": compiled} {
			if err := os.WriteFile(filepath.Join(output, name), content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, required := range []string{
		// Site durations replace the rules' ban and pass (NF30); the key
		// outlives the longer pass.
		`"action":{"kind":"temporary_ban","ban_seconds":900}`,
		`"auto_switch":{"qps_total":200,"qps_5xx":20,"recover_seconds":300,"rules":[`,
		`"action":{"kind":"challenge","ban_seconds":900,"challenge":{"mode":"js","failure_window_seconds":60,"max_failures":5,"pass_seconds":7200,"pow_bits":16,"challenge_seconds":120,"bind_ipv4_prefix":24,"bind_ipv6_prefix":64,"key_rotate_seconds":7200}}`,
	} {
		if !strings.Contains(string(compiled), required) {
			t.Fatalf("compiled policy missing %s:\n%s", required, compiled)
		}
	}
	if !strings.Contains(string(source), `"auto_switch":{"qps_total":200,"qps_5xx":20,"recover_seconds":300,"rules":[`) {
		t.Fatalf("runtime snapshot lacks the auto switch:\n%s", source)
	}
	if edgeconfig.CCV2PolicyAPIVersion(policy) != 5 {
		t.Fatalf("auto switch policy CC API v%d, want 5", edgeconfig.CCV2PolicyAPIVersion(policy))
	}
	for name, content := range map[string][]byte{"auto-switch.source.json": source, "auto-switch.compiled.json": compiled} {
		want, err := os.ReadFile(filepath.Join(countByParityFixtures, name))
		if err != nil {
			t.Fatalf("parity fixture (regenerate with CDNCA_WRITE_CC_FIXTURES): %v", err)
		}
		if !bytes.Equal(content, want) {
			t.Fatalf("%s drifted from the agent parity fixture:\n got %s\nwant %s", name, content, want)
		}
	}
}

// A disabled policy, or an auto switch whose rules are all disabled, compiles
// without it (and needs no CC v5).
func TestCompileCCV2InactiveAutoSwitchIsOmitted(t *testing.T) {
	for name, mutate := range map[string]func(*securitypolicy.Policy){
		"policy disabled": func(policy *securitypolicy.Policy) { policy.Enabled = false },
		"rules disabled":  func(policy *securitypolicy.Policy) { policy.CCSettings.AutoSwitch.Rules[0].Enabled = false },
		"system resolved off": func(policy *securitypolicy.Policy) {
			policy.CCSettings.AutoSwitch = &securitypolicy.CCAutoSwitch{Mode: securitypolicy.CCSettingSystem,
				RuleGroups: []string{}, Rules: []securitypolicy.Rule{}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := autoSwitchPolicyForTest()
			mutate(&policy)
			_, compiled, result := compileAutoSwitchFixture(t, policy)
			if result.AutoSwitch != nil || strings.Contains(string(compiled), "auto_switch") ||
				edgeconfig.CCV2PolicyAPIVersion(result) == 5 {
				t.Fatalf("inactive auto switch compiled:\n%s", compiled)
			}
		})
	}
}

// Without CCSettings a policy's runtime and compiled bytes are unchanged.
func TestCompileCCV2WithoutSettingsKeepsBytes(t *testing.T) {
	policy := autoSwitchPolicyForTest()
	policy.CCSettings = nil
	source, compiled, _ := compileAutoSwitchFixture(t, policy)
	if strings.Contains(string(source), "auto_switch") || !strings.Contains(string(compiled), `"ban_seconds":360`) {
		t.Fatalf("settings leaked:\n%s\n%s", source, compiled)
	}
}

func TestCCSettingsValidation(t *testing.T) {
	for name, mutate := range map[string]func(*securitypolicy.CCSettings){
		"no threshold":      func(value *securitypolicy.CCSettings) { value.AutoSwitch.QPSTotal, value.AutoSwitch.QPS5xx = 0, 0 },
		"recover too short": func(value *securitypolicy.CCSettings) { value.AutoSwitch.RecoverSeconds = 30 },
		"no rules custom":   func(value *securitypolicy.CCSettings) { value.AutoSwitch.Rules = []securitypolicy.Rule{} },
		"unknown mode":      func(value *securitypolicy.CCSettings) { value.AutoSwitch.Mode = "inherit" },
		"ban out of range":  func(value *securitypolicy.CCSettings) { value.BanSeconds.Seconds = 0 },
		"pass out of range": func(value *securitypolicy.CCSettings) { value.PassSeconds.Seconds = 59 },
		"shared rule id": func(value *securitypolicy.CCSettings) {
			value.AutoSwitch.Rules[0].ID = uuid.MustParse("018f1000-0000-7000-8000-000000000041")
		},
		"nil rule groups": func(value *securitypolicy.CCSettings) { value.AutoSwitch.RuleGroups = nil },
		"block in switch": func(value *securitypolicy.CCSettings) { value.AutoSwitch.Rules[0].Action = securitypolicy.ActionBlock },
		"duplicate group": func(value *securitypolicy.CCSettings) {
			value.AutoSwitch.RuleGroups = []string{"cc_rule:1", "cc_rule:1"}
		},
		"empty system extra": func(value *securitypolicy.CCSettings) {
			value.AutoSwitch.Rules, value.AutoSwitch.Mode = []securitypolicy.Rule{}, "system"
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := autoSwitchPolicyForTest()
			mutate(policy.CCSettings)
			if _, err := securitypolicy.CompileRuntimeSnapshot(policy, testSiteID); err == nil {
				t.Fatal("invalid settings compiled")
			}
		})
	}
	policy := autoSwitchPolicyForTest()
	policy.Kind = securitypolicy.KindWAF
	if _, err := securitypolicy.CompileRuntimeSnapshot(policy, testSiteID); err == nil {
		t.Fatal("WAF policy with CC settings compiled")
	}
}

func TestValidateRuntimeSnapshotAcceptsAutoSwitch(t *testing.T) {
	runtime, err := securitypolicy.CompileRuntimeSnapshot(autoSwitchPolicyForTest(), testSiteID)
	if err != nil {
		t.Fatal(err)
	}
	if err := securitypolicy.ValidateRuntimeSnapshot(runtime.Snapshot); err != nil {
		t.Fatalf("ValidateRuntimeSnapshot: %v", err)
	}
}
