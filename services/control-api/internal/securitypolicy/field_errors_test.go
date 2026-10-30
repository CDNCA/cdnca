package securitypolicy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

// fix-fielderr-be3: a refused policy write names the field as sent
// (rules[n] in request order, even for checks run after the rules are sorted
// by priority) and stays ErrInvalidInput.
func TestPolicyWriteLocatesRefusedField(t *testing.T) {
	tenant := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	wafRule := func(name string, priority int, conditions ...Condition) Rule {
		return Rule{Name: name, Priority: priority, Enabled: true, Action: ActionBlock, Flow: FlowStop, Conditions: conditions}
	}
	pathPrefix := Condition{Field: "path", Operator: "prefix", Values: []string{"/a"}}
	ccLimit := func(config RateLimitConfig) Rule {
		return Rule{Name: "limit", Priority: 1, Enabled: true, Action: ActionRateLimit, Flow: FlowContinue,
			Conditions: []Condition{pathPrefix}, ActionConfig: ActionConfig{RateLimit: &config}}
	}
	aclRule := func(priority int, action, cidr string) Rule {
		return Rule{Name: "acl", Priority: priority, Enabled: true, Action: action, Flow: FlowStop,
			Conditions: []Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{cidr}}}}
	}
	nineConditions := make([]Condition, 9)
	for index := range nineConditions {
		nineConditions[index] = Condition{Field: "args", Key: "k" + string(rune('a'+index)), Operator: "contains", Values: []string{"x"}}
	}
	cases := []struct {
		name   string
		fields PolicyFields
		field  string
		reason string
	}{
		{"name too long", PolicyFields{Kind: KindWAF, Name: strings.Repeat("n", 129), DefaultAction: ActionAllow,
			Rules: []Rule{wafRule("r", 1, pathPrefix)}}, "name", fielderr.TooLong},
		{"no rules", PolicyFields{Kind: KindWAF, Name: "p", DefaultAction: ActionAllow}, "rules", fielderr.Required},
		{"second rule bad CIDR", PolicyFields{Kind: KindWAF, Name: "p", DefaultAction: ActionAllow, Rules: []Rule{
			wafRule("ok", 1, pathPrefix),
			wafRule("bad", 2, Condition{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"999.1.1.1"}})}},
			"rules[1].conditions[0].values", fielderr.InvalidFormat},
		{"empty rule name", PolicyFields{Kind: KindWAF, Name: "p", DefaultAction: ActionAllow, Rules: []Rule{wafRule(" ", 1, pathPrefix)}},
			"rules[0].name", fielderr.Required},
		{"CC window out of range", PolicyFields{Kind: KindCC, Name: "p", DefaultAction: ActionAllow,
			Rules: []Rule{ccLimit(RateLimitConfig{WindowSeconds: 0, MaxRequests: 10})}},
			"rules[0].action_config.rate_limit.window_seconds", fielderr.OutOfRange},
		// Checked after sorting: the rule sent first (priority 5) sorts last.
		{"too many WAF conditions, sorted", PolicyFields{Kind: KindWAF, Name: "p", DefaultAction: ActionAllow, Rules: []Rule{
			wafRule("many", 5, nineConditions...), wafRule("ok", 1, pathPrefix)}},
			"rules[0].conditions", fielderr.OutOfRange},
		{"ACL overlap, sorted", PolicyFields{Kind: KindACL, Name: "p", DefaultAction: ActionAllow, Rules: []Rule{
			aclRule(2, ActionBlock, "10.0.0.0/24"), aclRule(1, ActionAllow, "10.0.0.0/16")}},
			"rules[0].conditions[0].values", fielderr.Duplicate},
		{"WAF auto block window", PolicyFields{Kind: KindWAF, Name: "p", DefaultAction: ActionAllow, Rules: []Rule{wafRule("r", 1, pathPrefix)},
			WAFSettings: &WAFSettings{Mode: WAFModeDefend, AutoBlock: &WAFAutoBlock{WindowSeconds: 0, HitThreshold: 1, BlockSeconds: 1}}},
			"waf_settings.auto_block.window_seconds", fielderr.OutOfRange},
		{"CC cookie domain", PolicyFields{Kind: KindCC, Name: "p", DefaultAction: ActionAllow,
			Rules:      []Rule{ccLimit(RateLimitConfig{WindowSeconds: 10, MaxRequests: 10})},
			CCSettings: &CCSettings{ChallengeCookieDomain: "not a domain"}},
			"cc_settings.challenge_cookie_domain", fielderr.InvalidFormat},
	}
	service := &Service{}
	for _, item := range cases {
		_, err := service.create(context.Background(), tenant, CreateRequest{Fields: item.fields, IdempotencyKey: "k", RequestID: "r"})
		located, ok := fielderr.As(err)
		if !ok || !errors.Is(err, ErrInvalidInput) || located.Field != item.field || located.Reason != item.reason {
			t.Errorf("%s: want %s/%s, got %v", item.name, item.field, item.reason, err)
		}
	}

	// Update refuses the sent rules before reading the stored policy.
	_, err := service.update(context.Background(), tenant, UpdateRequest{ID: uuid.New(), ExpectedRevision: 1,
		IdempotencyKey: "k", RequestID: "r", Fields: PolicyFields{Kind: KindWAF, Name: "p", DefaultAction: ActionAllow,
			Rules: []Rule{wafRule("ok", 1, pathPrefix), wafRule("bad", 2, Condition{Field: "method", Operator: "equals", Values: []string{"G1"}})}}})
	if located, ok := fielderr.As(err); !ok || located.Field != "rules[1].conditions[0].values" || located.Reason != fielderr.InvalidFormat {
		t.Fatalf("update: got %v", err)
	}
}

// Policies the client did not send (generated, stored, copied) are refused
// without a field: the path would name another request's body.
func TestGeneratedPolicyRefusalNamesNoField(t *testing.T) {
	policy := Policy{Kind: KindWAF, Name: strings.Repeat("n", 129), Enabled: true, DefaultAction: ActionAllow,
		Rules: []Rule{{Name: "r", Priority: 1, Action: ActionBlock, Flow: FlowStop,
			Conditions: []Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}}}}}
	err := ValidatePublishablePolicy(policy)
	if _, located := fielderr.As(err); located || !errors.Is(err, ErrInvalidInput) || err.Error() != ErrInvalidInput.Error() {
		t.Fatalf("ValidatePublishablePolicy: %v", err)
	}
	if _, err := NormalizePublishableWAFRules(policy.Rules[:0]); errors.Is(err, ErrInvalidInput) {
		if _, located := fielderr.As(err); located {
			t.Fatalf("NormalizePublishableWAFRules located: %v", err)
		}
	} else {
		t.Fatalf("NormalizePublishableWAFRules: %v", err)
	}
	if err := ValidateACLRules([]Rule{{Action: "x"}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("ValidateACLRules: %v", err)
	} else if _, located := fielderr.As(err); located {
		t.Fatalf("ValidateACLRules located: %v", err)
	}
}

func TestPolicyFieldNamingEdges(t *testing.T) {
	tenant := Actor{UserID: uuid.New(), ScopeID: uuid.New(), ScopeKind: "tenant"}
	service := &Service{}
	pathPrefix := Condition{Field: "path", Operator: "prefix", Values: []string{"/a"}}
	locate := func(err error) string {
		if located, ok := fielderr.As(err); ok {
			return located.Field + "/" + located.Reason
		}
		return "unlocated: " + func() string {
			if err == nil {
				return "nil"
			}
			return err.Error()
		}()
	}

	// An imported ACL rule the ACL checks refuse is the import's, not rules[n].
	_, err := service.create(context.Background(), tenant, CreateRequest{IdempotencyKey: "k", RequestID: "r",
		Fields: PolicyFields{Kind: KindACL, Name: "p", DefaultAction: ActionAllow, ACLImport: "allow 10.0.0.0/16\nblock 10.0.0.0/24"}})
	if got := locate(err); got != "acl_import/duplicate" {
		t.Fatalf("acl import: %s", got)
	}

	// A custom auto switch rule is named under cc_settings.auto_switch.
	ccRule := Rule{Name: "r", Priority: 1, Enabled: true, Action: ActionRateLimit, Flow: FlowContinue, Conditions: []Condition{pathPrefix},
		ActionConfig: ActionConfig{RateLimit: &RateLimitConfig{WindowSeconds: 10, MaxRequests: 10}}}
	badSwitch := ccRule
	badSwitch.Name = ""
	_, err = service.create(context.Background(), tenant, CreateRequest{IdempotencyKey: "k", RequestID: "r",
		Fields: PolicyFields{Kind: KindCC, Name: "p", DefaultAction: ActionAllow, Rules: []Rule{ccRule},
			CCSettings: &CCSettings{AutoSwitch: &CCAutoSwitch{Mode: CCSettingCustom, QPSTotal: 100, RecoverSeconds: 600,
				RuleGroups: []string{}, Rules: []Rule{ccRule, badSwitch}}}}})
	if got := locate(err); got != "cc_settings.auto_switch.rules[1].name/required" {
		t.Fatalf("auto switch: %s", got)
	}

	// Sent quick block rules are dropped before the check: rules[n] would
	// not be as sent, so the refusal names no rule.
	policyID := uuid.New()
	quick := Rule{ID: QuickBlockRuleID(policyID, 1), Name: "qb", Priority: 1, Enabled: true, Action: ActionBlock, Flow: FlowStop, Conditions: []Condition{pathPrefix}}
	bad := Rule{Name: "", Priority: 2, Enabled: true, Action: ActionBlock, Flow: FlowStop, Conditions: []Condition{pathPrefix}}
	_, err = service.update(context.Background(), tenant, UpdateRequest{ID: policyID, ExpectedRevision: 1, IdempotencyKey: "k", RequestID: "r",
		Fields: PolicyFields{Kind: KindWAF, Name: "p", DefaultAction: ActionAllow, Rules: []Rule{quick, bad}}})
	if got := locate(err); got != "unlocated: invalid security policy input" {
		t.Fatalf("quick block sent: %s", got)
	}
	// A field outside the rules is still named.
	_, err = service.update(context.Background(), tenant, UpdateRequest{ID: policyID, ExpectedRevision: 1, IdempotencyKey: "k", RequestID: "r",
		Fields: PolicyFields{Kind: KindWAF, Name: "", DefaultAction: ActionAllow, Rules: []Rule{quick, {Name: "ok", Priority: 2,
			Enabled: true, Action: ActionBlock, Flow: FlowStop, Conditions: []Condition{pathPrefix}}}}})
	if got := locate(err); got != "name/required" {
		t.Fatalf("quick block sent, bad name: %s", got)
	}

	// Challenge parameters name their own field.
	challenge := ChallengeConfig{Type: "js", FailureWindowSeconds: 60, MaxFailures: 5, PassSeconds: 30, BanSeconds: 600, PowBits: 16,
		ChallengeSeconds: 300, BindIPv4Prefix: 24, BindIPv6Prefix: 64, KeyRotateSeconds: 3600}
	_, err = service.create(context.Background(), tenant, CreateRequest{IdempotencyKey: "k", RequestID: "r",
		Fields: PolicyFields{Kind: KindCC, Name: "p", DefaultAction: ActionAllow, Rules: []Rule{{Name: "c", Priority: 1, Enabled: true,
			Action: ActionChallenge, Flow: FlowStop, Conditions: []Condition{pathPrefix}, ActionConfig: ActionConfig{Challenge: &challenge}}}}})
	if got := locate(err); got != "rules[0].action_config.challenge.pass_seconds/out_of_range" {
		t.Fatalf("challenge: %s", got)
	}
}
