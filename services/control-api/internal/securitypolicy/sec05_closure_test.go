package securitypolicy

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSEC05ACLImportCanonicalizesAllowFirstCommentsAndExpiry(t *testing.T) {
	rules, err := ParseACLImport(strings.Join([]string{
		"# legacy compatible comment line",
		"block 192.0.2.9/24 expires=2030-01-02T03:04:05Z # temporary office deny",
		"allow 192.0.2.42 # trusted operator",
		"block 2001:db8::9/32",
	}, "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 || rules[0].Action != ActionAllow || rules[0].Priority >= rules[1].Priority ||
		rules[0].Conditions[0].Values[0] != "192.0.2.42/32" || rules[0].Comment != "trusted operator" ||
		rules[1].Conditions[0].Values[0] != "192.0.2.0/24" || rules[1].Comment != "temporary office deny" ||
		rules[1].ExpiresAt != "2030-01-02T03:04:05Z" || rules[2].Conditions[0].Values[0] != "2001:db8::/32" {
		t.Fatalf("rules=%#v", rules)
	}
}

func TestSEC05ACLImportReturnsEveryLineErrorWithoutPartialRules(t *testing.T) {
	rules, err := ParseACLImport(strings.Join([]string{
		"deny 192.0.2.1",
		"block 2001:db8::/129",
		"allow 192.0.2.1 expires=2030-01-02T03:04:05+00:00",
		"allow 192.0.2.1 # " + strings.Repeat("x", 257),
	}, "\n"))
	var imported *ACLImportError
	if len(rules) != 0 || !errors.As(err, &imported) {
		t.Fatalf("rules=%#v err=%v", rules, err)
	}
	want := []ACLImportLineError{
		{Line: 1, Code: "invalid_action"},
		{Line: 2, Code: "invalid_cidr"},
		{Line: 3, Code: "invalid_expiry"},
		{Line: 4, Code: "invalid_comment"},
	}
	if !reflect.DeepEqual(imported.Lines, want) {
		t.Fatalf("line errors=%#v want=%#v", imported.Lines, want)
	}
}

func TestSEC05ACLMetadataAndAllowPriorityValidation(t *testing.T) {
	valid := PolicyFields{Kind: KindACL, Name: "ACL", Enabled: true, DefaultAction: ActionAllow, Rules: []Rule{
		{Name: "trusted", Priority: 1, Enabled: true, Comment: "office allow", ExpiresAt: "2030-01-02T03:04:05Z", Conditions: []Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.1"}}}, Action: ActionAllow, Flow: FlowStop},
		{Name: "blocked", Priority: 2, Enabled: true, Conditions: []Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"}}}, Action: ActionBlock, Flow: FlowStop},
	}}
	if err := normalizeFields(&valid, true); err != nil || valid.Rules[0].Conditions[0].Values[0] != "192.0.2.1/32" {
		t.Fatalf("valid ACL normalization=(%#v,%v)", valid, err)
	}
	if err := validateACLFields(valid.Rules); err != nil {
		t.Fatalf("valid ACL publication=%v", err)
	}
	for name, mutate := range map[string]func(*PolicyFields){
		"block before allow": func(value *PolicyFields) { value.Rules[0].Priority, value.Rules[1].Priority = 2, 1 },
		"offset expiry":      func(value *PolicyFields) { value.Rules[0].ExpiresAt = "2030-01-02T03:04:05+00:00" },
		"empty comment":      func(value *PolicyFields) { value.Rules[0].Comment = " " },
		"metadata on WAF":    func(value *PolicyFields) { value.Kind = KindWAF },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			candidate.Rules = cloneRules(valid.Rules)
			mutate(&candidate)
			err := normalizeFields(&candidate, true)
			if err == nil && candidate.Kind == KindACL {
				err = validateACLFields(candidate.Rules)
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestSEC05EvaluateAtClearsExpiredAllowAndExposesStableIDs(t *testing.T) {
	expiry := "2030-01-02T03:04:05Z"
	allowID, blockID := uuid.New(), uuid.New()
	policy := Policy{ID: uuid.New(), Revision: 7, Enabled: true, DefaultAction: ActionAllow, Rules: []Rule{
		{ID: allowID, Priority: 1, Enabled: true, ExpiresAt: expiry, Conditions: []Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.1/32"}}}, Action: ActionAllow, Flow: FlowStop},
		{ID: blockID, Priority: 2, Enabled: true, Conditions: []Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"}}}, Action: ActionBlock, Flow: FlowStop},
	}}
	before, err := evaluateAt(policy, RequestFacts{ClientIP: "192.0.2.1"}, time.Date(2030, 1, 2, 3, 4, 4, 0, time.UTC))
	if err != nil || before.Action != ActionAllow || before.TerminalRuleID == nil || *before.TerminalRuleID != allowID {
		t.Fatalf("before=%#v err=%v", before, err)
	}
	atExpiry, err := evaluateAt(policy, RequestFacts{ClientIP: "192.0.2.1"}, time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil || atExpiry.Action != ActionBlock || atExpiry.TerminalRuleID == nil || *atExpiry.TerminalRuleID != blockID ||
		!reflect.DeepEqual(atExpiry.ExpiredRuleIDs, []uuid.UUID{allowID}) {
		t.Fatalf("at expiry=%#v err=%v", atExpiry, err)
	}
}

func TestSEC05RuntimeSnapshotCarriesCanonicalListMetadata(t *testing.T) {
	policy := Policy{ID: uuid.New(), ScopeID: uuid.New(), Kind: KindACL, Name: "ACL", Enabled: true, DefaultAction: ActionAllow, Revision: 3,
		Rules: []Rule{{ID: uuid.New(), Name: "temporary", Priority: 1, Enabled: true, Comment: "temporary deny", ExpiresAt: "2030-01-02T03:04:05Z",
			Conditions: []Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"}}}, Action: ActionBlock, Flow: FlowStop}}}
	compiled, err := CompileRuntimeSnapshot(policy, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.Snapshot.Rules) != 1 || compiled.Snapshot.Rules[0].Comment != "temporary deny" ||
		compiled.Snapshot.Rules[0].ExpiresAt != "2030-01-02T03:04:05Z" ||
		!strings.Contains(string(compiled.CanonicalJSON), `"expires_at":"2030-01-02T03:04:05Z"`) {
		t.Fatalf("snapshot=%#v json=%s", compiled.Snapshot, compiled.CanonicalJSON)
	}
}
