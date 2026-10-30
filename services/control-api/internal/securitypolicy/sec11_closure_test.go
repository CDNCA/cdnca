package securitypolicy

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestSEC11CountMatchersNormalizeAndPreviewExactEdgeFacts(t *testing.T) {
	fields := validFields(Condition{Field: "distinct_user_agents", Operator: "number_gte", Values: []string{"3"}})
	fields.Kind = KindCC
	fields.Rules[0].Action = ActionRateLimit
	fields.Rules[0].Flow = FlowStop
	fields.Rules[0].ActionConfig = ActionConfig{RateLimit: &RateLimitConfig{
		Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 10, ResponseAction: "reject_429",
	}}
	fields.Rules[0].Conditions = append(fields.Rules[0].Conditions,
		Condition{Field: "status_404_count", Operator: "number_gte", Values: []string{"2"}},
		Condition{Field: "port", Operator: "number_eq", Values: []string{"8443"}},
	)
	if err := normalizeFields(&fields, false); err != nil {
		t.Fatalf("normalize SEC-11 fields: %v", err)
	}
	policy := Policy{ID: uuid.New(), Revision: 7, Kind: KindCC, Enabled: true,
		DefaultAction: ActionAllow, Rules: fields.Rules}
	for _, test := range []struct {
		name  string
		facts RequestFacts
		want  string
	}{
		{name: "all facts match", facts: RequestFacts{DistinctUserAgents: 3, Status404Count: 2, Port: 8443}, want: ActionRateLimit},
		{name: "UA below threshold", facts: RequestFacts{DistinctUserAgents: 2, Status404Count: 2, Port: 8443}, want: ActionAllow},
		{name: "404 below threshold", facts: RequestFacts{DistinctUserAgents: 3, Status404Count: 1, Port: 8443}, want: ActionAllow},
		{name: "listener differs", facts: RequestFacts{DistinctUserAgents: 3, Status404Count: 2, Port: 443}, want: ActionAllow},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := evaluate(policy, test.facts)
			if err != nil {
				t.Fatal(err)
			}
			if got.Action != test.want {
				t.Fatalf("action = %q, want %q", got.Action, test.want)
			}
		})
	}
}

func TestSEC11CountMatchersFailClosedOutsideBoundedCCFixedWindow(t *testing.T) {
	base := validFields(Condition{Field: "distinct_user_agents", Operator: "number_gte", Values: []string{"3"}})
	base.Kind = KindCC
	base.Rules[0].Action = ActionRateLimit
	base.Rules[0].Flow = FlowStop
	base.Rules[0].ActionConfig = ActionConfig{RateLimit: &RateLimitConfig{
		Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 10, ResponseAction: "reject_429",
	}}
	tests := map[string]func(*PolicyFields){
		"WAF has no count carrier": func(value *PolicyFields) { value.Kind = KindWAF },
		"leaky bucket has no observation window": func(value *PolicyFields) {
			value.Rules[0].ActionConfig.RateLimit = &RateLimitConfig{Algorithm: "leaky_bucket", RatePerSecond: 1, Burst: 1, ResponseAction: "reject_429"}
		},
		"zero threshold": func(value *PolicyFields) { value.Rules[0].Conditions[0].Values = []string{"0"} },
		"over capacity":  func(value *PolicyFields) { value.Rules[0].Conditions[0].Values = []string{"1025"} },
		"duplicate state dimension": func(value *PolicyFields) {
			value.Rules[0].Conditions = append(value.Rules[0].Conditions,
				Condition{Field: "distinct_user_agents", Operator: "number_gte", Values: []string{"4"}})
		},
		"unsupported equality": func(value *PolicyFields) { value.Rules[0].Conditions[0].Operator = "number_eq" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := base
			value.Rules = cloneRules(base.Rules)
			mutate(&value)
			if err := normalizeFields(&value, false); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestSEC11PreviewPreservesCanonicalMultiValueHeaders(t *testing.T) {
	policy := Policy{ID: uuid.New(), Revision: 9, Kind: KindWAF, Enabled: true, DefaultAction: ActionAllow,
		Rules: []Rule{{ID: uuid.New(), Enabled: true, Priority: 1, Action: ActionBlock, Flow: FlowStop,
			Conditions: []Condition{{Field: "header", Operator: "equals", Key: "x-mode", Values: []string{"strict"}}}}}}

	single, err := evaluate(policy, RequestFacts{Headers: HeaderValues{"X-Mode": {"strict"}}})
	if err != nil || single.Action != ActionBlock {
		t.Fatalf("single canonical header: decision=%#v error=%v", single, err)
	}
	for name, headers := range map[string]HeaderValues{
		"multi value":    {"X-Mode": {"strict", "relaxed"}},
		"case collision": {"X-Mode": {"strict"}, "x-mode": {"relaxed"}},
	} {
		t.Run(name, func(t *testing.T) {
			decision, evaluateErr := evaluate(policy, RequestFacts{Headers: headers})
			if evaluateErr != nil || decision.Action != ActionAllow || !decision.UsedDefault {
				t.Fatalf("decision=%#v error=%v", decision, evaluateErr)
			}
		})
	}
}

func TestSEC11NormalizeRejectsConditionsMissingFromSelectedRuntime(t *testing.T) {
	tests := map[string]struct {
		kind       string
		condition  Condition
		additional []Condition
	}{
		// CC matches headers with equals/prefix/contains/regex (CC API v6).
		"CC header in": {kind: KindCC, condition: Condition{Field: "header", Operator: "in", Key: "x-mode", Values: []string{"strict"}}},
		// fix-ja4rule ③: CC v7 takes ja4 equals / in, never not_in.
		"CC JA4 not_in":      {kind: KindCC, condition: Condition{Field: "ja4", Operator: "not_in", Values: []string{"t13d1516h2_8daaf6152771_02713d6af862"}}},
		"WAF host":           {kind: KindWAF, condition: Condition{Field: "host", Operator: "equals", Values: []string{"example.test"}}},
		"WAF JA4 not_equals": {kind: KindWAF, condition: Condition{Field: "ja4", Operator: "not_equals", Values: []string{"t13d1516h2_8daaf6152771_e5627efa2ab1"}}},
		"WAF header in":      {kind: KindWAF, condition: Condition{Field: "header", Operator: "in", Key: "x-mode", Values: []string{"strict"}}},
		"WAF port range": {kind: KindWAF,
			condition: Condition{Field: "port", Operator: "number_gte", Values: []string{"443"}}},
		"WAF duplicate field": {kind: KindWAF,
			condition:  Condition{Field: "method", Operator: "equals", Values: []string{"GET"}},
			additional: []Condition{{Field: "method", Operator: "equals", Values: []string{"POST"}}}},
		// ge-waf: a WAF rule takes MaxWAFRuleConditions (8) conditions.
		"WAF ninth condition": {kind: KindWAF,
			condition: Condition{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"}},
			additional: []Condition{
				{Field: "method", Operator: "equals", Values: []string{"GET"}},
				{Field: "path", Operator: "equals", Values: []string{"/"}},
				{Field: "header", Operator: "equals", Key: "x-mode", Values: []string{"strict"}},
				{Field: "port", Operator: "number_eq", Values: []string{"443"}},
				{Field: "args", Operator: "contains", Key: "a", Values: []string{"1"}},
				{Field: "args", Operator: "contains", Key: "b", Values: []string{"2"}},
				{Field: "query", Operator: "not_contains", Values: []string{"ok"}},
				{Field: "cookie", Operator: "regex", Key: "sid", Values: []string{"^x"}},
			}},
		"WAF repeated native field": {kind: KindWAF,
			condition:  Condition{Field: "method", Operator: "equals", Values: []string{"GET"}},
			additional: []Condition{{Field: "method", Operator: "equals", Values: []string{"POST"}}}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fields := validFields(test.condition)
			fields.Kind = test.kind
			fields.Rules[0].Conditions = append(fields.Rules[0].Conditions, test.additional...)
			if test.kind == KindCC {
				fields.Rules[0].Action = ActionRateLimit
				fields.Rules[0].ActionConfig = ActionConfig{RateLimit: &RateLimitConfig{
					Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 10, ResponseAction: "reject_429",
				}}
			}
			if err := normalizePublishableFields(&fields, false); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error=%v, want ErrInvalidInput", err)
			}
		})
	}
}

func TestSEC11NormalizeAcceptsOnlyPublishedMatcherShapes(t *testing.T) {
	tests := map[string]struct {
		kind      string
		condition Condition
	}{
		"WAF exact header":  {kind: KindWAF, condition: Condition{Field: "header", Operator: "equals", Key: "X-Mode", Values: []string{"strict"}}},
		"WAF listener port": {kind: KindWAF, condition: Condition{Field: "port", Operator: "number_eq", Values: []string{"8443"}}},
		"CC listener port":  {kind: KindCC, condition: Condition{Field: "port", Operator: "number_eq", Values: []string{"8443"}}},
		"CC distinct UA":    {kind: KindCC, condition: Condition{Field: "distinct_user_agents", Operator: "number_gte", Values: []string{"3"}}},
		"CC completed 404":  {kind: KindCC, condition: Condition{Field: "status_404_count", Operator: "number_gte", Values: []string{"2"}}},
		"WAF JA4 equals":    {kind: KindWAF, condition: Condition{Field: "ja4", Operator: "equals", Values: []string{"t13d1516h2_8daaf6152771_e5627efa2ab1"}}},
		"WAF JA4 set": {kind: KindWAF, condition: Condition{Field: "ja4", Operator: "in",
			Values: []string{"t13d1516h2_8daaf6152771_e5627efa2ab1", "t13d3112h2_e8f1e7e78f70_6bebaf5329ac"}}},
		"CC JA4 (v7)": {kind: KindCC, condition: Condition{Field: "ja4", Operator: "in", Values: []string{"t13d1516h2_8daaf6152771_02713d6af862"}}},
		// fix-ja4rule ②: not in list (WAF_JA4_NEGATION).
		"WAF JA4 not in set": {kind: KindWAF, condition: Condition{Field: "ja4", Operator: "not_in",
			Values: []string{"t13d1516h2_8daaf6152771_e5627efa2ab1", "t13d3112h2_e8f1e7e78f70_6bebaf5329ac"}}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fields := validFields(test.condition)
			fields.Kind = test.kind
			if test.kind == KindCC {
				fields.Rules[0].Action = ActionRateLimit
				fields.Rules[0].ActionConfig = ActionConfig{RateLimit: &RateLimitConfig{
					Algorithm: "fixed_window", WindowSeconds: 60, MaxRequests: 10, ResponseAction: "reject_429",
				}}
			}
			if err := normalizePublishableFields(&fields, false); err != nil {
				t.Fatalf("normalize: %v", err)
			}
		})
	}
}
