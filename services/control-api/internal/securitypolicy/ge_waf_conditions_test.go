package securitypolicy

import (
	"errors"
	"testing"
)

// ge-waf S1: WAF rules take named values, upload / length /
// header-name fields, negated and number operators, filters and the body
// overflow choice; the publish gate refuses every inconsistent combination.
func TestGEWAFContentConditionsPublishGate(t *testing.T) {
	waf := func(conditions ...Condition) PolicyFields {
		fields := validFields(conditions[0])
		fields.Kind = KindWAF
		fields.Rules[0].Conditions = conditions
		return fields
	}
	accepted := map[string][]Condition{
		"named query":       {{Field: "query", Key: "id", Operator: "regex", Values: []string{`^\d+ or`}}},
		"form key case":     {{Field: "body", Key: "UserName", Operator: "equals", Values: []string{"admin"}}},
		"json path":         {{Field: "body", Key: "user.roles.0", Operator: "equals", Values: []string{"root"}}},
		"cookie name":       {{Field: "cookie", Key: "sid", Operator: "not_regex", Values: []string{"^[a-f0-9]{32}$"}}},
		"upload extension":  {{Field: "upload_extension", Operator: "equals", Values: []string{"php", "jsp"}}},
		"upload overflow":   {{Field: "upload_filename", Operator: "suffix", Values: []string{".php"}, BodyOverflow: "match"}},
		"request length":    {{Field: "request_length", Operator: "number_gt", Values: []string{"1048576"}}},
		"header max length": {{Field: "header_max_length", Operator: "number_gte", Values: []string{"8192"}}},
		"empty UA":          {{Field: "user_agent", Operator: "number_eq", Values: []string{"0"}, Filters: []string{"length"}}},
		"decode then detect": {{Field: "args", Operator: "detect", Values: []string{"xss"},
			Filters: []string{"base64_decode", "html_unescape"}}},
		"two args keys": {
			{Field: "args", Key: "a", Operator: "contains", Values: []string{"1"}},
			{Field: "args", Key: "b", Operator: "contains", Values: []string{"2"}}},
		"contains and not_contains": {
			{Field: "user_agent", Operator: "contains", Values: []string{"bot"}},
			{Field: "user_agent", Operator: "not_contains", Values: []string{"googlebot"}}},
		"body overflow": {{Field: "body", Operator: "contains_all", Values: []string{"union", "select"}, BodyOverflow: "match"}},
	}
	for name, conditions := range accepted {
		fields := waf(conditions...)
		if err := normalizePublishableFields(&fields, false); err != nil {
			t.Fatalf("%s refused: %v", name, err)
		}
		if name == "form key case" && fields.Rules[0].Conditions[0].Key != "UserName" {
			t.Fatalf("form key lower-cased: %+v", fields.Rules[0].Conditions[0])
		}
	}
	refused := map[string]Condition{
		"key on UA":               {Field: "user_agent", Key: "x", Operator: "contains", Values: []string{"a"}},
		"bad key":                 {Field: "cookie", Key: "a b", Operator: "contains", Values: []string{"a"}},
		"number op on text":       {Field: "path", Operator: "number_gt", Values: []string{"3"}},
		"text op on length":       {Field: "request_length", Operator: "contains", Values: []string{"3"}},
		"length not last":         {Field: "path", Operator: "number_gt", Values: []string{"3"}, Filters: []string{"length", "lowercase"}},
		"unknown filter":          {Field: "path", Operator: "contains", Values: []string{"a"}, Filters: []string{"md5"}},
		"filter on number field":  {Field: "uri_length", Operator: "number_gt", Values: []string{"3"}, Filters: []string{"lowercase"}},
		"overflow on path":        {Field: "path", Operator: "contains", Values: []string{"a"}, BodyOverflow: "match"},
		"overflow value":          {Field: "body", Operator: "contains", Values: []string{"a"}, BodyOverflow: "block"},
		"two numbers":             {Field: "request_length", Operator: "number_gt", Values: []string{"1", "2"}},
		"bad not_regex":           {Field: "path", Operator: "not_regex", Values: []string{"("}},
		"filters on native field": {Field: "method", Operator: "equals", Values: []string{"GET"}, Filters: []string{"lowercase"}},
	}
	for name, condition := range refused {
		fields := waf(condition)
		if err := normalizePublishableFields(&fields, false); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
}
