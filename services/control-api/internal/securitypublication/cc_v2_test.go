package securitypublication

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func TestCompileCCV2ProducesExactCanonicalContract(t *testing.T) {
	policy := ccV2PolicyForTest()
	binding := activeBinding(t, policy)
	binding.BindingID = uuid.MustParse("018f1000-0000-7000-8000-000000000030")
	binding.PublicationID = uuid.MustParse("018f1000-0000-7000-8000-000000000031")
	binding.BindingRevision = 4
	compiled, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{binding})
	if err != nil {
		t.Fatalf("CompileSiteSecurityBindings: %v", err)
	}
	if compiled.Site.CCV2 == nil {
		t.Fatal("CC v2 binding was not projected into the site")
	}
	canonical, err := edgeconfig.CanonicalCCV2Policy(compiled.Site.CCV2.Policy)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema_version":"cdnca.edge.cc/v2","tenant_scope_id":"018f1000-0000-7000-8000-000000000001","site_id":"018f1000-0000-7000-8000-000000000002","policy_id":"018f1000-0000-7000-8000-000000000020","policy_version":6,"binding_id":"018f1000-0000-7000-8000-000000000030","binding_revision":4,"publication_id":"018f1000-0000-7000-8000-000000000031","enabled":true,"trusted_proxies":[],"allowlist":[],"rules":[{"rule_id":"018f1000-0000-7000-8000-000000000021","priority":10,"flow":"continue","match":{"host":"security.example.test","port":8080,"method":"GET","path":{"kind":"prefix","value":"/api"}},"dimension":"client_ip","limit":{"algorithm":"fixed_window","requests":2,"window_seconds":60},"action":{"kind":"log"}},{"rule_id":"018f1000-0000-7000-8000-000000000022","priority":20,"flow":"stop","match":{"path":{"kind":"exact","value":"/"},"source_cidr":"198.51.100.0/24"},"dimension":"client_ip","limit":{"algorithm":"leaky_bucket","rate_per_second":3,"burst":4},"action":{"kind":"temporary_ban","ban_seconds":30}}]}`
	if string(canonical) != want {
		t.Fatalf("canonical CC v2 bytes:\n%s\nwant:\n%s", canonical, want)
	}
	if compiled.Site.CCV2.SourceSHA256 != strings.Repeat("0", 0)+strings.ToLower(compiled.Site.CCV2.SourceSHA256) || len(compiled.Site.CCV2.SourceSHA256) != 64 || len(compiled.Site.CCV2.CompiledSHA256) != 64 {
		t.Fatalf("CC v2 digests = %#v", compiled.Site.CCV2)
	}
}

func TestCompileCCV2AccessPortIsListenerFilteredWithoutByteDivergence(t *testing.T) {
	portBinding := activeBinding(t, ccV2PolicyForTest())
	binding := activeBinding(t, ccV2PolicyForTest())
	binding.BindingID = portBinding.BindingID
	binding.PublicationID = portBinding.PublicationID
	binding.BindingRevision = portBinding.BindingRevision
	binding.Snapshot.Rules[0].Conditions[3].Field = "access_port"
	encoded, err := json.Marshal(binding.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	binding.RuntimeSnapshotSHA256 = sha256.Sum256(encoded)
	var canonical []byte
	for _, listenPort := range []uint16{8080, 8081} {
		site := baseSite()
		site.ListenPort = listenPort
		compiled, err := compileCCV2(site, nil, binding)
		if err != nil {
			t.Fatalf("listener %d rejected site-wide access_port rule: %v", listenPort, err)
		}
		content, err := edgeconfig.CanonicalCCV2Policy(compiled.Policy)
		if err != nil {
			t.Fatal(err)
		}
		if compiled.Policy.Rules[0].Match.Port != 8080 {
			t.Fatalf("listener %d compiled port = %d, want runtime filter 8080", listenPort,
				compiled.Policy.Rules[0].Match.Port)
		}
		if canonical == nil {
			canonical = content
		} else if string(content) != string(canonical) {
			t.Fatalf("listener %d produced divergent signed bytes\n%s\nwant\n%s", listenPort, content, canonical)
		}
	}
	portCompiled, err := compileCCV2(baseSite(), nil, portBinding)
	if err != nil {
		t.Fatal(err)
	}
	portCanonical, err := edgeconfig.CanonicalCCV2Policy(portCompiled.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != string(portCanonical) {
		t.Fatalf("access_port and port produced divergent canonical bytes\naccess_port: %s\nport: %s", canonical, portCanonical)
	}

	for _, value := range []string{"0", "08080", "65536"} {
		invalid := activeBinding(t, ccV2PolicyForTest())
		invalid.Snapshot.Rules[0].Conditions[3] = securitypolicy.Condition{
			Field: "access_port", Operator: "number_eq", Values: []string{value},
		}
		if _, err := compileCCV2(baseSite(), nil, invalid); !errors.Is(err, ErrUnsupportedRuntime) {
			t.Errorf("noncanonical access_port %q error = %v, want ErrUnsupportedRuntime", value, err)
		}
	}
}

func TestCompileCCV2RejectsUnsupportedOrNonterminalSemantics(t *testing.T) {
	base := ccV2PolicyForTest()
	tests := map[string]func(*securitypolicy.Policy){
		"reject may not continue": func(value *securitypolicy.Policy) {
			value.Rules[0].ActionConfig.RateLimit.ResponseAction = "reject_429"
		},
		"temporary ban may not continue": func(value *securitypolicy.Policy) {
			value.Rules[0].ActionConfig.RateLimit.ResponseAction = "temporary_ban"
			value.Rules[0].ActionConfig.RateLimit.BanSeconds = 30
		},
		"adaptive": func(value *securitypolicy.Policy) {
			value.Rules[1].ActionConfig.RateLimit.Algorithm = "adaptive"
			value.Rules[1].ActionConfig.RateLimit.Adaptive = &securitypolicy.AdaptiveRateLimitConfig{Profile: "simple", Enforcement: "shadow"}
		},
		"gcra": func(value *securitypolicy.Policy) { value.Rules[1].ActionConfig.RateLimit.Algorithm = "gcra" },
		"challenge may not continue": func(value *securitypolicy.Policy) {
			value.Rules[1].Action = securitypolicy.ActionChallenge
			value.Rules[1].Flow = securitypolicy.FlowContinue
			value.Rules[1].ActionConfig = securitypolicy.ActionConfig{Challenge: &securitypolicy.ChallengeConfig{Type: "captcha"}}
		},
		"unsupported client condition": func(value *securitypolicy.Policy) {
			value.Rules[1].Conditions = []securitypolicy.Condition{{Field: "client_ip", Operator: "not_equals", Values: []string{"192.0.2.1"}}}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			policy := mutateCCV2Policy(base, mutate)
			compiled, err := securitypolicy.CompileRuntimeSnapshot(policy, testSiteID)
			if err != nil {
				// GCRA/challenge may be rejected by the source contract before edge compilation.
				return
			}
			binding := ActiveBinding{BindingID: uuid.New(), PublicationID: uuid.New(), BindingRevision: 1,
				RuntimeSnapshotSHA256: compiled.SHA256, Snapshot: compiled.Snapshot}
			if _, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{binding}); !errors.Is(err, ErrUnsupportedRuntime) && !errors.Is(err, ErrInvalidBinding) {
				t.Fatalf("error = %v, want a fail-closed edge compilation error", err)
			}
		})
	}
}

func ccV2PolicyForTest() securitypolicy.Policy {
	return securitypolicy.Policy{
		ID: uuid.MustParse("018f1000-0000-7000-8000-000000000020"), ScopeID: testTenantScopeID,
		Kind: securitypolicy.KindCC, Name: "cc-v2", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 6,
		Rules: []securitypolicy.Rule{
			{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000021"), Name: "observe", Priority: 10, Enabled: true,
				Conditions: []securitypolicy.Condition{{Field: "host", Operator: "equals", Values: []string{"security.example.test"}}, {Field: "method", Operator: "equals", Values: []string{"GET"}}, {Field: "path", Operator: "prefix", Values: []string{"/api"}}, {Field: "port", Operator: "number_eq", Values: []string{"8080"}}},
				Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowContinue,
				ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 2, ResponseAction: "log"}}},
			{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000022"), Name: "ban", Priority: 20, Enabled: true,
				Conditions: []securitypolicy.Condition{{Field: "path", Operator: "equals", Values: []string{"/"}}, {Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"198.51.100.0/24"}}},
				Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
				ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "leaky_bucket", RatePerSecond: 3, Burst: 4, ResponseAction: "temporary_ban", BanSeconds: 30}}},
		},
	}
}

func mutateCCV2Policy(source securitypolicy.Policy, mutate func(*securitypolicy.Policy)) securitypolicy.Policy {
	value := source
	value.Rules = append([]securitypolicy.Rule(nil), source.Rules...)
	for index := range value.Rules {
		value.Rules[index].Conditions = append([]securitypolicy.Condition(nil), source.Rules[index].Conditions...)
		if source.Rules[index].ActionConfig.RateLimit != nil {
			copy := *source.Rules[index].ActionConfig.RateLimit
			value.Rules[index].ActionConfig.RateLimit = &copy
		}
	}
	mutate(&value)
	return value
}

func TestCompileCCV2ChallengeCarriesEveryPolicyValue(t *testing.T) {
	config := securitypolicy.ChallengeConfig{Type: "five_second", FailureWindowSeconds: 45, MaxFailures: 7,
		PassSeconds: 7200, BanSeconds: 900, PowBits: 19, DelaySeconds: 4, ChallengeSeconds: 90, BindIPv4Prefix: 28,
		BindIPv6Prefix: 56, KeyRotateSeconds: 43200, PassWindowSeconds: 5, PassMaxRequests: 300, PassMaxRequestsPerURI: 50}
	compile := func(config securitypolicy.ChallengeConfig) (*edgeconfig.CCV2Rule, error) {
		policy := mutateCCV2Policy(ccV2PolicyForTest(), func(value *securitypolicy.Policy) {
			value.Rules[1].Action = securitypolicy.ActionChallenge
			value.Rules[1].Flow = securitypolicy.FlowStop
			value.Rules[1].ActionConfig = securitypolicy.ActionConfig{Challenge: &config}
		})
		compiled, err := securitypolicy.CompileRuntimeSnapshot(policy, testSiteID)
		if err != nil {
			return nil, err
		}
		site, err := CompileSiteSecurityBindings(baseSite(), testTenantScopeID, testSiteID, []ActiveBinding{{BindingID: uuid.New(),
			PublicationID: uuid.New(), BindingRevision: 1, RuntimeSnapshotSHA256: compiled.SHA256, Snapshot: compiled.Snapshot}})
		if err != nil {
			return nil, err
		}
		for index := range site.Site.CCV2.Policy.Rules {
			if site.Site.CCV2.Policy.Rules[index].Action.Kind == edgeconfig.CCV2ActionChallenge {
				return &site.Site.CCV2.Policy.Rules[index], nil
			}
		}
		return nil, errors.New("challenge rule missing")
	}
	rule, err := compile(config)
	if err != nil {
		t.Fatal(err)
	}
	want := edgeconfig.CCV2Challenge{Mode: "delay", DelaySeconds: 4, FailureWindowSeconds: 45, MaxFailures: 7, PassSeconds: 7200,
		PowBits: 19, ChallengeSeconds: 90, BindIPv4Prefix: 28, BindIPv6Prefix: 56, KeyRotateSeconds: 43200,
		PassLimit: &edgeconfig.CCV2Limit{Algorithm: edgeconfig.CCV2AlgorithmFixedWindow, Requests: 300, PerURI: 50, WindowSeconds: 5}}
	got := *rule.Action.Challenge
	if got.PassLimit == nil || *got.PassLimit != *want.PassLimit {
		t.Fatalf("pass limit = %+v, want %+v", got.PassLimit, want.PassLimit)
	}
	got.PassLimit, want.PassLimit = nil, nil
	if got != want || rule.Action.BanSeconds != 900 || rule.Limit.Algorithm != edgeconfig.CCV2AlgorithmAlways {
		t.Fatalf("challenge = %+v ban=%d limit=%+v", got, rule.Action.BanSeconds, rule.Limit)
	}
	// No value is defaulted: a challenge without its parameters is rejected.
	for name, mutate := range map[string]func(*securitypolicy.ChallengeConfig){
		"no pow":            func(value *securitypolicy.ChallengeConfig) { value.PowBits = 0 },
		"no pass seconds":   func(value *securitypolicy.ChallengeConfig) { value.PassSeconds = 0 },
		"no ip binding":     func(value *securitypolicy.ChallengeConfig) { value.BindIPv4Prefix = 0 },
		"short rotation":    func(value *securitypolicy.ChallengeConfig) { value.KeyRotateSeconds = 3600 },
		"no delay":          func(value *securitypolicy.ChallengeConfig) { value.DelaySeconds = 0 },
		"no page lifetime":  func(value *securitypolicy.ChallengeConfig) { value.ChallengeSeconds = 0 },
		"ban without block": func(value *securitypolicy.ChallengeConfig) { value.BanSeconds = 0 },
	} {
		broken := config
		mutate(&broken)
		if _, err := compile(broken); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// TestWriteEdgeCatalogParityFixtures regenerates the edge-agent parity
// fixtures from the real catalog expansion and compile chain:
// CDNCA_WRITE_CC_FIXTURES=<edge-agent>/internal/ccv2/testdata.
func TestWriteEdgeCatalogParityFixtures(t *testing.T) {
	output := os.Getenv("CDNCA_WRITE_CC_FIXTURES")
	if output == "" {
		t.Skip("CDNCA_WRITE_CC_FIXTURES not set")
	}
	items := map[string]rulecatalog.Item{}
	for _, item := range rulecatalog.CurrentSeed() {
		items[item.SystemKey] = item
	}
	rules := make([]securitypolicy.Rule, 0, 2)
	for _, key := range []string{"cc_rule:10001", "cc_rule:6"} {
		expanded, err := securitypolicy.ExpandCCRuleGroup(items, key)
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, expanded...)
	}
	for index := range rules {
		rules[index].ID = uuid.MustParse(fmt.Sprintf("018f1000-0000-7000-8000-0000000000%02d", 21+index))
		rules[index].Priority = index + 1
	}
	scope, site := uuid.MustParse("018f1000-0000-7000-8000-000000000001"), uuid.MustParse("018f1000-0000-7000-8000-000000000002")
	policy := securitypolicy.Policy{ID: uuid.MustParse("018f1000-0000-7000-8000-000000000020"), ScopeID: scope,
		Kind: securitypolicy.KindCC, Name: "catalog", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 1, Rules: rules}
	compiled, err := securitypolicy.CompileRuntimeSnapshot(policy, site)
	if err != nil {
		t.Fatal(err)
	}
	edgeSite := baseSite()
	edgeSite.ID = site.String()
	result, err := CompileSiteSecurityBindings(edgeSite, scope, site, []ActiveBinding{{
		BindingID: uuid.MustParse("018f1000-0000-7000-8000-000000000030"), BindingRevision: 1,
		PublicationID: uuid.MustParse("018f1000-0000-7000-8000-000000000031"),
		RuntimeSnapshotSHA256: compiled.SHA256, Snapshot: compiled.Snapshot}})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := edgeconfig.CanonicalCCV2Policy(result.Site.CCV2.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "catalog-5s-relaxed.source.json"), compiled.CanonicalJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "catalog-5s-relaxed.compiled.json"), canonical, 0o644); err != nil {
		t.Fatal(err)
	}
}
