package securitypolicy

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestCompileRuntimeSnapshotIsCanonicalAndDoesNotMutateInput(t *testing.T) {
	policy := runtimePolicy(KindWAF)
	policy.Rules[0].Conditions = []Condition{
		{Field: "method", Operator: "in", Values: []string{" post ", "GET"}},
		{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"2001:db8:0:0::1/64", "10.0.0.18/24"}},
	}
	policy.Rules[1].Priority = 10
	policy.Rules[1].Conditions = []Condition{{Field: "host", Operator: "equals", Values: []string{" API.EXAMPLE "}}}
	originalFirstValue := policy.Rules[0].Conditions[0].Values[0]

	first, err := CompileRuntimeSnapshot(policy, runtimeSiteID)
	if err != nil {
		t.Fatalf("CompileRuntimeSnapshot: %v", err)
	}
	second, err := CompileRuntimeSnapshot(policy, runtimeSiteID)
	if err != nil {
		t.Fatalf("CompileRuntimeSnapshot repeat: %v", err)
	}
	if !bytes.Equal(first.CanonicalJSON, second.CanonicalJSON) || first.SHA256 != second.SHA256 {
		t.Fatal("same immutable version did not produce identical bytes and digest")
	}
	if policy.Rules[0].Conditions[0].Values[0] != originalFirstValue {
		t.Fatal("compiler mutated the immutable input policy")
	}

	want := `{"schema_version":"cdnca.security-policy.runtime/v1","tenant_scope_id":"018f0000-0000-7000-8000-000000000010","site_id":"018f0000-0000-7000-8000-000000000020","policy_id":"018f0000-0000-7000-8000-000000000030","policy_version":7,"kind":"waf","enabled":true,"default_action":"allow","rules":[{"id":"018f0000-0000-7000-8000-000000000002","priority":10,"enabled":true,"conditions":[{"field":"host","operator":"equals","values":["api.example"]}],"action":"allow","flow":"stop","action_config":{}},{"id":"018f0000-0000-7000-8000-000000000001","priority":100,"enabled":true,"conditions":[{"field":"client_ip","operator":"ip_in_cidr","values":["10.0.0.0/24","2001:db8::/64"]},{"field":"method","operator":"in","values":["GET","POST"]}],"action":"block","flow":"continue","action_config":{}}]}`
	if string(first.CanonicalJSON) != want {
		t.Fatalf("canonical JSON mismatch\n got: %s\nwant: %s", first.CanonicalJSON, want)
	}

	equivalent := runtimePolicy(KindWAF)
	equivalent.Rules[1].Priority = 10
	equivalent.Rules[1].Conditions = []Condition{{Field: "host", Operator: "equals", Values: []string{"api.example"}}}
	equivalent.Rules[0].Conditions = []Condition{
		{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"10.0.0.0/24", "2001:db8::/64"}},
		{Field: "method", Operator: "in", Values: []string{"GET", "POST"}},
	}
	equivalent.Rules[0], equivalent.Rules[1] = equivalent.Rules[1], equivalent.Rules[0]
	compiledEquivalent, err := CompileRuntimeSnapshot(equivalent, runtimeSiteID)
	if err != nil {
		t.Fatalf("CompileRuntimeSnapshot equivalent: %v", err)
	}
	if !bytes.Equal(first.CanonicalJSON, compiledEquivalent.CanonicalJSON) || first.SHA256 != compiledEquivalent.SHA256 {
		t.Fatal("semantically equivalent policy did not canonicalize identically")
	}
}

func TestCompileRuntimeSnapshotSemanticChangesAlterDigest(t *testing.T) {
	base := runtimePolicy(KindCC)
	compiled, err := CompileRuntimeSnapshot(base, runtimeSiteID)
	if err != nil {
		t.Fatalf("CompileRuntimeSnapshot: %v", err)
	}

	tests := []struct {
		name   string
		policy Policy
		siteID uuid.UUID
	}{
		{name: "tenant scope", policy: mutateRuntimePolicy(base, func(value *Policy) {
			value.ScopeID = uuid.MustParse("018f0000-0000-7000-8000-000000000011")
		}), siteID: runtimeSiteID},
		{name: "site", policy: base, siteID: uuid.MustParse("018f0000-0000-7000-8000-000000000021")},
		{name: "kind", policy: mutateRuntimePolicy(base, func(value *Policy) { value.Kind = KindACL }), siteID: runtimeSiteID},
		{name: "default action", policy: mutateRuntimePolicy(base, func(value *Policy) { value.DefaultAction = ActionBlock }), siteID: runtimeSiteID},
		{name: "rule action", policy: mutateRuntimePolicy(base, func(value *Policy) { value.Rules[0].Action = ActionAllow }), siteID: runtimeSiteID},
		{name: "rule flow", policy: mutateRuntimePolicy(base, func(value *Policy) { value.Rules[0].Flow = FlowStop }), siteID: runtimeSiteID},
		{name: "condition", policy: mutateRuntimePolicy(base, func(value *Policy) { value.Rules[0].Conditions[0].Values = []string{"POST"} }), siteID: runtimeSiteID},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed, err := CompileRuntimeSnapshot(test.policy, test.siteID)
			if err != nil {
				t.Fatalf("CompileRuntimeSnapshot: %v", err)
			}
			if changed.SHA256 == compiled.SHA256 {
				t.Fatal("semantic change retained the previous digest")
			}
		})
	}
}

func TestCompileRuntimeSnapshotCanonicalizesAndDigestsAdaptiveContract(t *testing.T) {
	policy := runtimePolicy(KindCC)
	policy.Rules = policy.Rules[:1]
	policy.Rules[0].Action = ActionRateLimit
	policy.Rules[0].Flow = FlowStop
	policy.Rules[0].Conditions = []Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"}}}
	policy.Rules[0].ActionConfig.RateLimit = &RateLimitConfig{
		Algorithm: "adaptive", RatePerSecond: 100, Burst: 200, ResponseAction: "temporary_ban", BanSeconds: 60,
		Adaptive: &AdaptiveRateLimitConfig{
			Profile: "expert", Enforcement: "auto", AutoApproved: true, Frozen: true,
			MinSamples: 8, MaxSamples: 64, SampleFreshnessSeconds: 30,
			EWMAAlphaPermille: 250, MADMultiplierMilli: 2500,
			MinRatePerSecond: 10, MaxRatePerSecond: 1000, MinBurst: 20, MaxBurst: 2000,
			MaxStepPermille: 100, HysteresisPermille: 50, CooldownSeconds: 10, MaxGroups: 1000,
		},
	}
	first, err := CompileRuntimeSnapshot(policy, runtimeSiteID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompileRuntimeSnapshot(policy, runtimeSiteID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.CanonicalJSON, second.CanonicalJSON) || first.SHA256 != second.SHA256 {
		t.Fatal("adaptive runtime contract is not canonical")
	}
	changed := mutateRuntimePolicy(policy, func(value *Policy) {
		value.Rules[0].ActionConfig.RateLimit.Adaptive.MaxStepPermille++
	})
	compiledChanged, err := CompileRuntimeSnapshot(changed, runtimeSiteID)
	if err != nil {
		t.Fatal(err)
	}
	if first.SHA256 == compiledChanged.SHA256 {
		t.Fatal("expert semantic change retained the previous digest")
	}
	if err := ValidateRuntimeSnapshot(first.Snapshot); err != nil {
		t.Fatalf("ValidateRuntimeSnapshot: %v", err)
	}
}

func TestCompileRuntimeSnapshotAcceptsWAFCCAndACL(t *testing.T) {
	for _, kind := range []string{KindWAF, KindCC, KindACL} {
		t.Run(kind, func(t *testing.T) {
			compiled, err := CompileRuntimeSnapshot(runtimePolicy(kind), runtimeSiteID)
			if err != nil || compiled.Snapshot.Kind != kind {
				t.Fatalf("CompileRuntimeSnapshot(%q) = (%#v, %v)", kind, compiled, err)
			}
		})
	}
}

func TestCompileRuntimeSnapshotRejectsInvalidScopeAndUnsafeExpressions(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		siteID uuid.UUID
	}{
		{name: "missing tenant scope", policy: mutateRuntimePolicy(runtimePolicy(KindWAF), func(value *Policy) { value.ScopeID = uuid.Nil }), siteID: runtimeSiteID},
		{name: "missing site scope", policy: runtimePolicy(KindWAF), siteID: uuid.Nil},
		{name: "missing immutable policy ID", policy: mutateRuntimePolicy(runtimePolicy(KindWAF), func(value *Policy) { value.ID = uuid.Nil }), siteID: runtimeSiteID},
		{name: "missing immutable revision", policy: mutateRuntimePolicy(runtimePolicy(KindWAF), func(value *Policy) { value.Revision = 0 }), siteID: runtimeSiteID},
		{name: "missing persisted rule ID", policy: mutateRuntimePolicy(runtimePolicy(KindWAF), func(value *Policy) { value.Rules[0].ID = uuid.Nil }), siteID: runtimeSiteID},
		{name: "unknown type", policy: mutateRuntimePolicy(runtimePolicy(KindWAF), func(value *Policy) { value.Kind = "managed" }), siteID: runtimeSiteID},
		{name: "unknown operator", policy: mutateRuntimePolicy(runtimePolicy(KindWAF), func(value *Policy) { value.Rules[0].Conditions[0].Operator = "regex" }), siteID: runtimeSiteID},
		{name: "unknown action", policy: mutateRuntimePolicy(runtimePolicy(KindWAF), func(value *Policy) { value.Rules[0].Action = "exec" }), siteID: runtimeSiteID},
		{name: "legacy TLS expression", policy: mutateRuntimePolicy(runtimePolicy(KindWAF), func(value *Policy) {
			value.Rules[0].Conditions[0] = Condition{Field: "tls_version", Operator: "in", Values: []string{"SSLv3", "TLSv1"}}
		}), siteID: runtimeSiteID},
		// A contiguous dotted netmask is accepted (NF27); a non-contiguous one is not.
		{name: "non-contiguous netmask expression", policy: mutateRuntimePolicy(runtimePolicy(KindACL), func(value *Policy) {
			value.Rules[0].Conditions[0] = Condition{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"10.0.0.1/255.0.255.0"}}
		}), siteID: runtimeSiteID},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CompileRuntimeSnapshot(test.policy, test.siteID)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("CompileRuntimeSnapshot error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestCompileRuntimeSnapshotDoesNotCarryControlPlaneMetadata(t *testing.T) {
	policy := runtimePolicy(KindACL)
	policy.Name = "private policy name"
	policy.Description = "private description"
	policy.Owner = &OwnerReference{ID: uuid.New(), DisplayName: "private owner"}
	compiled, err := CompileRuntimeSnapshot(policy, runtimeSiteID)
	if err != nil {
		t.Fatalf("CompileRuntimeSnapshot: %v", err)
	}
	for _, forbidden := range []string{"private policy name", "private description", "private owner", "owner", "created_at", "updated_at"} {
		if strings.Contains(string(compiled.CanonicalJSON), forbidden) {
			t.Fatalf("runtime snapshot leaked control-plane metadata %q", forbidden)
		}
	}
}

func TestValidateRuntimeSnapshotRejectsNonCanonicalOrUnknownRuntimeData(t *testing.T) {
	compiled, err := CompileRuntimeSnapshot(runtimePolicy(KindWAF), runtimeSiteID)
	if err != nil {
		t.Fatalf("CompileRuntimeSnapshot: %v", err)
	}
	if err := ValidateRuntimeSnapshot(compiled.Snapshot); err != nil {
		t.Fatalf("ValidateRuntimeSnapshot: %v", err)
	}

	nonCanonical := compiled.Snapshot
	nonCanonical.Rules = append([]RuntimeRule(nil), nonCanonical.Rules...)
	nonCanonical.Rules[0], nonCanonical.Rules[1] = nonCanonical.Rules[1], nonCanonical.Rules[0]
	if err := ValidateRuntimeSnapshot(nonCanonical); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("non-canonical rule order error = %v, want ErrInvalidInput", err)
	}

	unknown := compiled.Snapshot
	unknown.Rules = append([]RuntimeRule(nil), unknown.Rules...)
	unknown.Rules[0].Action = "exec"
	if err := ValidateRuntimeSnapshot(unknown); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown runtime action error = %v, want ErrInvalidInput", err)
	}
}

var runtimeSiteID = uuid.MustParse("018f0000-0000-7000-8000-000000000020")

func runtimePolicy(kind string) Policy {
	return Policy{
		ID:      uuid.MustParse("018f0000-0000-7000-8000-000000000030"),
		ScopeID: uuid.MustParse("018f0000-0000-7000-8000-000000000010"),
		Kind:    kind, Name: "runtime", Enabled: true, DefaultAction: ActionAllow, Revision: 7,
		Rules: []Rule{
			{ID: uuid.MustParse("018f0000-0000-7000-8000-000000000001"), Name: "block", Priority: 100, Enabled: true,
				Conditions: []Condition{{Field: "method", Operator: "equals", Values: []string{"GET"}}},
				Action:     ActionBlock, Flow: FlowContinue},
			{ID: uuid.MustParse("018f0000-0000-7000-8000-000000000002"), Name: "allow", Priority: 200, Enabled: true,
				Conditions: []Condition{{Field: "host", Operator: "equals", Values: []string{"api.example"}}},
				Action:     ActionAllow, Flow: FlowStop},
		},
	}
}

func mutateRuntimePolicy(policy Policy, mutate func(*Policy)) Policy {
	policy.Rules = cloneRules(policy.Rules)
	mutate(&policy)
	return policy
}
