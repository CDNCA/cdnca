package securityactivation

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func TestCIDRRecoveryIntentNormalizesDualStackWithoutMutation(t *testing.T) {
	input := &CIDRRecoveryIntent{
		Operation:  RecoveryOperationCIDRUnlock,
		ReasonCode: RecoveryReasonFalsePositiveConfirmed,
		CIDRs:      []string{" 2001:db8:1::f/64 ", "192.0.2.129/25"},
	}
	original := append([]string(nil), input.CIDRs...)

	got, err := normalizeCIDRRecoveryIntent(input)
	if err != nil {
		t.Fatalf("normalize recovery intent: %v", err)
	}
	want := &CIDRRecoveryIntent{
		Operation:  "cidr_unlock",
		ReasonCode: "false_positive_confirmed",
		CIDRs:      []string{"192.0.2.128/25", "2001:db8:1::/64"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized intent = %#v, want %#v", got, want)
	}
	if !reflect.DeepEqual(input.CIDRs, original) {
		t.Fatalf("normalization mutated caller CIDRs: got %v, want %v", input.CIDRs, original)
	}
	if got == input || &got.CIDRs[0] == &input.CIDRs[0] {
		t.Fatal("normalized intent aliases caller storage")
	}
	if legacy, err := normalizeCIDRRecoveryIntent(nil); err != nil || legacy != nil {
		t.Fatalf("nil legacy intent = %#v, %v; want nil, nil", legacy, err)
	}
}

func TestCIDRRecoveryIntentRejectsUnsafeOrAmbiguousValues(t *testing.T) {
	valid := func(cidrs ...string) *CIDRRecoveryIntent {
		return &CIDRRecoveryIntent{
			Operation: RecoveryOperationCIDRUnlock, ReasonCode: RecoveryReasonFalsePositiveConfirmed,
			CIDRs: cidrs,
		}
	}
	tooMany := make([]string, 65)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("10.0.0.%d/32", index)
	}
	tests := []struct {
		name  string
		value *CIDRRecoveryIntent
	}{
		{name: "empty list", value: valid()},
		{name: "empty prefix", value: valid("")},
		{name: "address without prefix", value: valid("192.0.2.1")},
		{name: "invalid prefix", value: valid("192.0.2.999/24")},
		{name: "duplicate canonical prefix", value: valid("192.0.2.1/24", "192.0.2.200/24")},
		{name: "mapped address", value: valid("::ffff:192.0.2.1/128")},
		{name: "IPv4 default route", value: valid("0.0.0.0/0")},
		{name: "IPv6 default route", value: valid("::/0")},
		{name: "IPv4 multicast", value: valid("224.0.0.0/4")},
		{name: "IPv6 multicast", value: valid("ff00::/8")},
		{name: "unbounded list", value: valid(tooMany...)},
		{name: "wrong operation", value: &CIDRRecoveryIntent{Operation: "allow", ReasonCode: RecoveryReasonFalsePositiveConfirmed, CIDRs: []string{"192.0.2.0/24"}}},
		{name: "wrong reason", value: &CIDRRecoveryIntent{Operation: RecoveryOperationCIDRUnlock, ReasonCode: "operator_override", CIDRs: []string{"192.0.2.0/24"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := normalizeCIDRRecoveryIntent(test.value); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("normalize error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestCIDRRecoveryStartRequiresExpectedActiveVersion(t *testing.T) {
	now := time.Date(2026, 8, 6, 1, 2, 3, 0, time.UTC)
	actor := securitypolicy.Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	input := StartInput{
		TenantScopeID: actor.ScopeID, SiteID: uuid.New(), PolicyID: uuid.New(), PolicyVersion: 1,
		ExpectedBindingRevision: 0, ExpectedActivePolicyVersion: 0, TargetNodeIDs: []uuid.UUID{uuid.New()},
		CanarySize: 1, IdempotencyKey: "fp-recovery-cas", RequestID: uuid.NewString(), ExpiresAt: now.Add(time.Minute),
		Recovery: &CIDRRecoveryIntent{Operation: RecoveryOperationCIDRUnlock,
			ReasonCode: RecoveryReasonFalsePositiveConfirmed, CIDRs: []string{"192.0.2.0/24"}},
	}
	if validStart(actor, input, now, time.Hour) {
		t.Fatal("recovery without an expected active version was accepted")
	}
	input.ExpectedActivePolicyVersion = 7
	input.PolicyVersion = 8
	if !validStart(actor, input, now, time.Hour) {
		t.Fatal("valid recovery start was rejected")
	}
}

func TestCIDRRecoveryPolicyAllowsOnlyExactBlockCIDRRemoval(t *testing.T) {
	active, candidate, intent := recoveryPolicyFixture(t)
	if err := validateCIDRRecoveryPolicy(active, candidate, intent); err != nil {
		t.Fatalf("exact recovery candidate rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*securitypolicy.Policy, *securitypolicy.Policy, *CIDRRecoveryIntent)
	}{
		{name: "target absent", mutate: func(_, _ *securitypolicy.Policy, value *CIDRRecoveryIntent) {
			value.CIDRs = []string{"198.51.100.0/24"}
		}},
		{name: "wrong policy ID", mutate: func(_, value *securitypolicy.Policy, _ *CIDRRecoveryIntent) { value.ID = uuid.New() }},
		{name: "wrong tenant scope", mutate: func(_, value *securitypolicy.Policy, _ *CIDRRecoveryIntent) { value.ScopeID = uuid.New() }},
		{name: "wrong kind", mutate: func(_, value *securitypolicy.Policy, _ *CIDRRecoveryIntent) { value.Kind = securitypolicy.KindWAF }},
		{name: "non monotonic version", mutate: func(old, value *securitypolicy.Policy, _ *CIDRRecoveryIntent) { value.Revision = old.Revision }},
		{name: "skipped version", mutate: func(old, value *securitypolicy.Policy, _ *CIDRRecoveryIntent) { value.Revision = old.Revision + 2 }},
		{name: "default block", mutate: func(_, value *securitypolicy.Policy, _ *CIDRRecoveryIntent) {
			value.DefaultAction = securitypolicy.ActionBlock
		}},
		{name: "disabled policy", mutate: func(_, value *securitypolicy.Policy, _ *CIDRRecoveryIntent) { value.Enabled = false }},
		{name: "unrelated metadata drift", mutate: func(_, value *securitypolicy.Policy, _ *CIDRRecoveryIntent) { value.Name = "changed" }},
		{name: "target retained", mutate: func(_, value *securitypolicy.Policy, _ *CIDRRecoveryIntent) {
			value.Rules[0].Conditions[0].Values = append(value.Rules[0].Conditions[0].Values, "192.0.2.0/24")
		}},
		{name: "extra CIDR removed", mutate: func(_, value *securitypolicy.Policy, _ *CIDRRecoveryIntent) {
			value.Rules[0].Conditions[0].Values = nil
		}},
		{name: "emptied block rule retained", mutate: func(old, value *securitypolicy.Policy, _ *CIDRRecoveryIntent) {
			value.Rules = append(value.Rules, cloneRecoveryPolicy(t, *old).Rules[1])
		}},
		{name: "unrelated rule drift", mutate: func(_, value *securitypolicy.Policy, _ *CIDRRecoveryIntent) {
			value.Rules[1].Flow = securitypolicy.FlowContinue
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			old := cloneRecoveryPolicy(t, active)
			got := cloneRecoveryPolicy(t, candidate)
			request := *intent
			request.CIDRs = append([]string(nil), intent.CIDRs...)
			test.mutate(&old, &got, &request)
			if err := validateCIDRRecoveryPolicy(old, got, &request); !errors.Is(err, ErrConflict) {
				t.Fatalf("validation error = %v, want ErrConflict", err)
			}
		})
	}
}

func TestCIDRRecoveryRejectsTargetsOutsideEnabledBlockCIDRRules(t *testing.T) {
	active, candidate, intent := recoveryPolicyFixture(t)
	active.Rules[0].Action = securitypolicy.ActionAllow
	if err := validateCIDRRecoveryPolicy(active, candidate, intent); !errors.Is(err, ErrConflict) {
		t.Fatalf("allow-rule target error = %v, want ErrConflict", err)
	}
	active, candidate, intent = recoveryPolicyFixture(t)
	active.Rules[0].Enabled = false
	if err := validateCIDRRecoveryPolicy(active, candidate, intent); !errors.Is(err, ErrConflict) {
		t.Fatalf("disabled-rule target error = %v, want ErrConflict", err)
	}
}

func TestCIDRRecoveryAuditPayloadAndResultReasonsAreStable(t *testing.T) {
	intent, err := normalizeCIDRRecoveryIntent(&CIDRRecoveryIntent{
		Operation: RecoveryOperationCIDRUnlock, ReasonCode: RecoveryReasonFalsePositiveConfirmed,
		CIDRs: []string{"2001:db8:1::9/64", "192.0.2.129/25"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if RecoveryOperationCIDRUnlock != "cidr_unlock" || RecoveryReasonFalsePositiveConfirmed != "false_positive_confirmed" ||
		RecoveryResultClaimed != "recovery_claimed" || RecoveryResultReplayed != "recovery_replayed" {
		t.Fatalf("unstable recovery codes: %q %q %q %q", RecoveryOperationCIDRUnlock,
			RecoveryReasonFalsePositiveConfirmed, RecoveryResultClaimed, RecoveryResultReplayed)
	}
	want := map[string]any{
		"operation": "cidr_unlock", "reason_code": "false_positive_confirmed",
		"cidrs":              []string{"192.0.2.128/25", "2001:db8:1::/64"},
		"result_reason_code": "recovery_claimed",
	}
	if got := cidrRecoveryAuditPayload(intent, RecoveryResultClaimed); !reflect.DeepEqual(got, want) {
		t.Fatalf("audit payload = %#v, want %#v", got, want)
	}
	claimed := StartResult{ReasonCode: RecoveryResultClaimed}
	replayed := StartResult{Replayed: true, ReasonCode: RecoveryResultReplayed}
	if claimed.Replayed || claimed.ReasonCode != "recovery_claimed" || !replayed.Replayed || replayed.ReasonCode != "recovery_replayed" {
		t.Fatalf("recovery result reasons are not distinguishable: claimed=%+v replayed=%+v", claimed, replayed)
	}
}

func TestStartDigestLegacyCompatibilityAndRecoveryBinding(t *testing.T) {
	input := StartInput{
		TenantScopeID: uuid.New(), SiteID: uuid.New(), PolicyID: uuid.New(), PolicyVersion: 8,
		ExpectedBindingRevision: 4, ExpectedActivePolicyVersion: 7,
		TargetNodeIDs: []uuid.UUID{uuid.New(), uuid.New()}, CanarySize: 1,
		ExpiresAt: time.Date(2026, 8, 6, 1, 2, 3, 456000000, time.UTC),
	}
	legacy, err := startDigest(input)
	if err != nil {
		t.Fatal(err)
	}
	wantLegacy, err := canonicalDigest(struct {
		TenantScopeID               uuid.UUID   `json:"tenant_scope_id"`
		SiteID                      uuid.UUID   `json:"site_id"`
		PolicyID                    uuid.UUID   `json:"policy_id"`
		PolicyVersion               int64       `json:"policy_version"`
		ExpectedBindingRevision     int64       `json:"expected_binding_revision"`
		ExpectedActivePolicyVersion int64       `json:"expected_active_policy_version"`
		TargetNodeIDs               []uuid.UUID `json:"target_node_ids"`
		CanarySize                  int         `json:"canary_size"`
		ExpiresAt                   string      `json:"expires_at"`
	}{input.TenantScopeID, input.SiteID, input.PolicyID, input.PolicyVersion,
		input.ExpectedBindingRevision, input.ExpectedActivePolicyVersion, input.TargetNodeIDs,
		input.CanarySize, input.ExpiresAt.UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	if legacy != wantLegacy {
		t.Fatalf("nil-recovery start digest drifted: got %x, want %x", legacy, wantLegacy)
	}

	left := input
	left.Recovery = &CIDRRecoveryIntent{Operation: RecoveryOperationCIDRUnlock,
		ReasonCode: RecoveryReasonFalsePositiveConfirmed, CIDRs: []string{"2001:db8:1::/64", "192.0.2.0/24"}}
	right := input
	right.Recovery = &CIDRRecoveryIntent{Operation: RecoveryOperationCIDRUnlock,
		ReasonCode: RecoveryReasonFalsePositiveConfirmed, CIDRs: []string{"192.0.2.9/24", "2001:db8:1::9/64"}}
	left.Recovery, err = normalizeCIDRRecoveryIntent(left.Recovery)
	if err != nil {
		t.Fatal(err)
	}
	right.Recovery, err = normalizeCIDRRecoveryIntent(right.Recovery)
	if err != nil {
		t.Fatal(err)
	}
	leftDigest, err := startDigest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := startDigest(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest || leftDigest == legacy {
		t.Fatalf("recovery digest is not canonical and separately bound: left=%x right=%x legacy=%x", leftDigest, rightDigest, legacy)
	}
	right.SiteID = uuid.New()
	scopedDigest, err := startDigest(right)
	if err != nil {
		t.Fatal(err)
	}
	if scopedDigest == leftDigest {
		t.Fatal("recovery digest does not bind the site")
	}
}

func recoveryPolicyFixture(t *testing.T) (securitypolicy.Policy, securitypolicy.Policy, *CIDRRecoveryIntent) {
	t.Helper()
	active := securitypolicy.Policy{
		ID: uuid.New(), ScopeID: uuid.New(), Kind: securitypolicy.KindACL, Name: "edge ACL",
		Description: "preserve", Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 7,
		Rules: []securitypolicy.Rule{
			{ID: uuid.New(), Name: "mixed block", Priority: 10, Enabled: true, Action: securitypolicy.ActionBlock,
				Flow: securitypolicy.FlowStop, Conditions: []securitypolicy.Condition{
					{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24", "2001:db8::/32"}},
					{Field: "method", Operator: "in", Values: []string{"GET", "POST"}},
				}},
			{ID: uuid.New(), Name: "single block", Priority: 20, Enabled: true, Action: securitypolicy.ActionBlock,
				Flow: securitypolicy.FlowStop, Conditions: []securitypolicy.Condition{
					{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"2001:db8:1::/64"}},
					{Field: "path", Operator: "prefix", Values: []string{"/admin"}},
				}},
			{ID: uuid.New(), Name: "allow health", Priority: 30, Enabled: true, Action: securitypolicy.ActionAllow,
				Flow: securitypolicy.FlowStop, Conditions: []securitypolicy.Condition{
					{Field: "path", Operator: "equals", Values: []string{"/health"}},
				}},
		},
	}
	candidate := cloneRecoveryPolicy(t, active)
	candidate.Revision++
	candidate.Rules[0].Conditions[0].Values = []string{"2001:db8::/32"}
	candidate.Rules = append(candidate.Rules[:1], candidate.Rules[2:]...)
	intent := &CIDRRecoveryIntent{Operation: RecoveryOperationCIDRUnlock,
		ReasonCode: RecoveryReasonFalsePositiveConfirmed, CIDRs: []string{"192.0.2.0/24", "2001:db8:1::/64"}}
	return active, candidate, intent
}

func cloneRecoveryPolicy(t *testing.T, input securitypolicy.Policy) securitypolicy.Policy {
	t.Helper()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var output securitypolicy.Policy
	if err := json.Unmarshal(encoded, &output); err != nil {
		t.Fatal(err)
	}
	return output
}
