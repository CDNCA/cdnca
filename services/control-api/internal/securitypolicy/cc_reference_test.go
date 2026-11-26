package securitypolicy

import (
	"errors"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
	"github.com/google/uuid"
)

func referenceRule(matcher, filter1 uuid.UUID, filter2 *uuid.UUID, action string) Rule {
	return Rule{Name: "ref", Priority: 1, Enabled: true, Flow: FlowContinue, Action: ActionBlock,
		Conditions: []Condition{{Field: "host", Operator: "equals", Values: []string{"ignored.example"}}},
		CountBy:    []CountKey{{Key: "ja4"}},
		CCReference: &CCReference{MatcherID: matcher, Filter1ID: filter1, Filter2ID: filter2, Action: action,
			MatcherVersion: 99}}
}

func referenceRows(matcher, rate, verify uuid.UUID) ccReferenceRows {
	return ccReferenceRows{
		matchers: map[uuid.UUID]ccReferenceRow{matcher: {Revision: 3, Name: "login", Field: "path", Operator: "prefix",
			Values: []string{"/login"}}},
		filters: map[uuid.UUID]ccReferenceRow{
			rate:   {Revision: 2, Name: "rate", Type: "req_rate", Parameters: []byte(`{"within_second":10,"max_req":30}`)},
			verify: {Revision: 5, Name: "five", Type: "five_second", Parameters: []byte(`{"within_second":60,"max_req":3,"ban_seconds":600}`)},
		},
	}
}

func fieldOf(t *testing.T, err error) (string, string) {
	t.Helper()
	located, ok := fielderr.As(err)
	if !ok {
		t.Fatalf("error %v names no field", err)
	}
	return located.Field, located.Reason
}

func TestExpandCCReferencesRateLimitBlock(t *testing.T) {
	matcher, rate, verify := uuid.New(), uuid.New(), uuid.New()
	rules := []Rule{referenceRule(matcher, rate, nil, ActionBlock)}
	if err := expandCCReferences(KindCC, rules, referenceRows(matcher, rate, verify)); err != nil {
		t.Fatal(err)
	}
	rule := rules[0]
	if len(rule.Conditions) != 1 || rule.Conditions[0].Field != "path" || rule.Conditions[0].Values[0] != "/login" ||
		rule.CountBy != nil || rule.Action != ActionRateLimit || rule.Flow != FlowStop {
		t.Fatalf("rule = %#v", rule)
	}
	limit := rule.ActionConfig.RateLimit
	if limit == nil || limit.WindowSeconds != 10 || limit.MaxRequests != 30 || limit.ResponseAction != "temporary_ban" ||
		limit.BanSeconds != 360 || rule.ActionConfig.Challenge != nil {
		t.Fatalf("rate limit = %#v", limit)
	}
	if ref := rule.CCReference; ref.MatcherVersion != 3 || ref.Filter1Version != 2 || ref.Filter2Version != 0 {
		t.Fatalf("versions = %#v", ref)
	}
	fields := PolicyFields{Kind: KindCC, Name: "p", Enabled: true, DefaultAction: ActionAllow, Rules: rules}
	if err := normalizePublishableFields(&fields, true); err != nil {
		t.Fatalf("expanded rule is not publishable: %v", err)
	}
}

func TestExpandCCReferencesLogKeepsMatchMode(t *testing.T) {
	matcher, rate, verify := uuid.New(), uuid.New(), uuid.New()
	rules := []Rule{referenceRule(matcher, rate, nil, ActionLog)}
	if err := expandCCReferences(KindCC, rules, referenceRows(matcher, rate, verify)); err != nil {
		t.Fatal(err)
	}
	if rules[0].Flow != FlowContinue || rules[0].ActionConfig.RateLimit.ResponseAction != "log" {
		t.Fatalf("rule = %#v", rules[0])
	}
}

func TestExpandCCReferencesFilterPairAndParams(t *testing.T) {
	matcher, rate, verify := uuid.New(), uuid.New(), uuid.New()
	rules := []Rule{referenceRule(matcher, rate, &verify, ActionBlock)}
	if err := expandCCReferences(KindCC, rules, referenceRows(matcher, rate, verify)); err != nil {
		t.Fatal(err)
	}
	challenge := rules[0].ActionConfig.Challenge
	// five_second takes delay_jump_filter's catalog defaults with ban_seconds overridden.
	if rules[0].Action != ActionChallenge || challenge == nil || challenge.Type != "five_second" || challenge.BanSeconds != 600 ||
		challenge.DelaySeconds != 5 || challenge.PowBits != 18 || challenge.FailureWindowSeconds != 60 || challenge.MaxFailures != 3 ||
		challenge.TriggerWindowSeconds != 10 || challenge.TriggerMaxRequests != 30 {
		t.Fatalf("challenge = %#v", challenge)
	}
	if rules[0].CCReference.Filter2Version != 5 {
		t.Fatalf("filter 2 version = %#v", rules[0].CCReference)
	}
	fields := PolicyFields{Kind: KindCC, Name: "p", Enabled: true, DefaultAction: ActionAllow, Rules: rules}
	if err := normalizePublishableFields(&fields, true); err != nil {
		t.Fatalf("expanded rule is not publishable: %v", err)
	}
}

func TestExpandCCReferencesRefusals(t *testing.T) {
	matcher, rate, verify := uuid.New(), uuid.New(), uuid.New()
	missing := uuid.New()
	cases := []struct {
		name   string
		kind   string
		rule   Rule
		rows   func(ccReferenceRows)
		field  string
		reason string
	}{
		{"not a CC policy", KindWAF, referenceRule(matcher, rate, nil, ActionBlock), nil, "rules[0].cc_reference", fielderr.Invalid},
		{"bad action", KindCC, referenceRule(matcher, rate, nil, "allow"), nil, "rules[0].cc_reference.action", fielderr.Invalid},
		{"matcher unavailable (other scope / deleted / disabled / system)", KindCC, referenceRule(missing, rate, nil, ActionBlock), nil,
			"rules[0].cc_reference.matcher_id", CCReferenceUnavailable},
		{"filter unavailable", KindCC, referenceRule(matcher, missing, nil, ActionBlock), nil,
			"rules[0].cc_reference.filter1_id", CCReferenceUnavailable},
		{"same filter twice", KindCC, referenceRule(matcher, rate, &rate, ActionBlock), nil,
			"rules[0].cc_reference.filter2_id", fielderr.Duplicate},
		{"node has no url_auth filter", KindCC, referenceRule(matcher, rate, nil, ActionBlock), func(rows ccReferenceRows) {
			rows.filters[rate] = ccReferenceRow{Revision: 1, Type: "url_auth", Parameters: []byte(`{}`)}
		}, "rules[0].cc_reference.filter1_id", CCReferenceUnsupported},
		{"unknown parameter", KindCC, referenceRule(matcher, rate, nil, ActionBlock), func(rows ccReferenceRows) {
			rows.filters[rate] = ccReferenceRow{Revision: 1, Type: "req_rate", Parameters: []byte(`{"max_req":5,"burst":3}`)}
		}, "rules[0].cc_reference.filter1_id", CCReferenceUnsupported},
		{"pair needs a rate then a verification", KindCC, referenceRule(matcher, verify, &rate, ActionBlock), nil,
			"rules[0].cc_reference.filter2_id", CCReferenceUnsupported},
		{"matcher operator the node lacks", KindCC, referenceRule(matcher, rate, nil, ActionBlock), func(rows ccReferenceRows) {
			rows.matchers[matcher] = ccReferenceRow{Revision: 1, Field: "path", Operator: "regex", Values: []string{".*"}}
		}, "rules[0].cc_reference.matcher_id", CCReferenceUnsupported},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			rows := referenceRows(matcher, rate, verify)
			if item.rows != nil {
				item.rows(rows)
			}
			err := expandCCReferences(item.kind, []Rule{item.rule}, rows)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err = %v", err)
			}
			if field, reason := fieldOf(t, err); field != item.field || reason != item.reason {
				t.Fatalf("field = %s %s, want %s %s", field, reason, item.field, item.reason)
			}
		})
	}
}

func TestLocateCCReferenceErrorMovesExpandedFields(t *testing.T) {
	referenced := map[int]bool{1: true}
	cases := map[string]string{
		"rules[1].conditions[0].values":                  "rules[1].cc_reference.matcher_id",
		"rules[1].action_config.rate_limit.max_requests": "rules[1].cc_reference.filter1_id",
		"rules[1].name":                 "rules[1].name",
		"rules[0].conditions[0].values": "rules[0].conditions[0].values",
	}
	for field, want := range cases {
		got, _ := fieldOf(t, locateCCReferenceError(refuse(field, fielderr.OutOfRange), referenced))
		if got != want {
			t.Errorf("%s -> %s, want %s", field, got, want)
		}
	}
}

func TestExpandCCReferencesEqualContentIsUnchanged(t *testing.T) {
	matcher, rate, verify := uuid.New(), uuid.New(), uuid.New()
	rows := referenceRows(matcher, rate, verify)
	first := []Rule{referenceRule(matcher, rate, nil, ActionBlock)}
	if err := expandCCReferences(KindCC, first, rows); err != nil {
		t.Fatal(err)
	}
	stored := Policy{Kind: KindCC, Name: "p", Enabled: true, DefaultAction: ActionAllow, Rules: cloneRules(first)}
	again := cloneRules(first)
	if err := expandCCReferences(KindCC, again, rows); err != nil {
		t.Fatal(err)
	}
	same, err := sameStoredContent(stored, PolicyFields{Kind: KindCC, Name: "p", Enabled: true, DefaultAction: ActionAllow, Rules: again})
	if err != nil || !same {
		t.Fatalf("re-expansion of unchanged references must be equal: %v %v", same, err)
	}
}
