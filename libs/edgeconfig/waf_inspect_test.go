package edgeconfig

import (
	"strings"
	"testing"
)

// ge-waf S1: named values, upload / length / header-name
// targets, negated and number operators, decoding filters and the body
// overflow choice are accepted; every inconsistent combination is refused.
func TestNormalizeWAFInspectExtendedTargetsOperatorsFilters(t *testing.T) {
	accepted := []WAFInspect{
		{Target: "args", Key: "id", Operator: "regex", Values: []string{`^\d+`}},
		{Target: "query", Key: "q", Operator: "not_contains", Values: []string{"ok"}},
		{Target: "body", Key: "user.roles.0", Operator: "equals", Values: []string{"root"}},
		{Target: "cookie", Key: "sid", Operator: "not_regex", Values: []string{"^[a-f0-9]{32}$"}},
		{Target: "upload_extension", Operator: "equals", Values: []string{"php", "jsp"}, BodyOverflow: WAFInspectBodyOverflowMatch},
		{Target: "upload_filename", Operator: "suffix", Values: []string{".php"}},
		{Target: "header_names", Operator: "equals", Values: []string{"x-evil"}},
		{Target: "request_length", Operator: "gt", Values: []string{"1048576"}},
		{Target: "header_max_length", Operator: "gte", Values: []string{"8192"}},
		{Target: "body", Operator: "contains_all", Values: []string{"union", "select"}, BodyOverflow: WAFInspectBodyOverflowMatch},
		{Target: "query", Key: "p", Operator: "detect", Values: []string{"xss"}, Filters: []string{"base64_decode", "html_unescape"}},
		{Target: "user_agent", Operator: "eq", Values: []string{"0"}, Filters: []string{"length"}},
		{Target: "header", Key: "x-a", Operator: "prefix", Values: []string{"evil"}, Filters: []string{"unicode_decode", "lowercase"}},
	}
	for _, value := range accepted {
		normalized, err := normalizeWAFInspect([]WAFInspect{value})
		if err != nil {
			t.Fatalf("%+v refused: %v", value, err)
		}
		if encoded := wafInspectJSON(normalized[0]); !strings.Contains(encoded, `"target":"`+value.Target+`"`) {
			t.Fatalf("JSON %s", encoded)
		}
	}
	refused := []WAFInspect{
		{Target: "header", Operator: "contains", Values: []string{"a"}},                                         // header needs a key
		{Target: "user_agent", Key: "x", Operator: "contains", Values: []string{"a"}},                           // no key for user_agent
		{Target: "cookie", Key: "bad key", Operator: "contains", Values: []string{"a"}},                         // key characters
		{Target: "request_length", Operator: "contains", Values: []string{"a"}},                                 // number target, text operator
		{Target: "path", Operator: "gt", Values: []string{"3"}},                                                 // text target, number operator
		{Target: "path", Operator: "gt", Values: []string{"3", "4"}, Filters: []string{"length"}},               // one number
		{Target: "path", Operator: "gt", Values: []string{"-1"}, Filters: []string{"length"}},                   // non-negative
		{Target: "path", Operator: "gt", Values: []string{"07"}, Filters: []string{"length"}},                   // canonical
		{Target: "path", Operator: "contains", Values: []string{"a"}, Filters: []string{"length"}},              // length needs a number operator
		{Target: "path", Operator: "contains", Values: []string{"a"}, Filters: []string{"length", "lowercase"}}, // length last
		{Target: "path", Operator: "contains", Values: []string{"a"}, Filters: []string{"md5"}},                 // unknown filter
		{Target: "uri_length", Operator: "gt", Values: []string{"3"}, Filters: []string{"lowercase"}},           // no filters on numbers
		{Target: "path", Operator: "contains", Values: []string{"a"}, BodyOverflow: "match"},                    // overflow only on body targets
		{Target: "body", Operator: "contains", Values: []string{"a"}, BodyOverflow: "block"},                    // unknown overflow
		{Target: "body", Operator: "detect", Values: []string{"rce"}},                                           // unknown detector
		{Target: "body", Operator: "like", Values: []string{"a"}},                                               // unknown operator
	}
	for _, value := range refused {
		if _, err := normalizeWAFInspect([]WAFInspect{value}); err == nil {
			t.Fatalf("%+v accepted", value)
		}
	}
	many := make([]WAFInspect, MaxWAFInspectPerRule+1)
	for index := range many {
		many[index] = WAFInspect{Target: "path", Operator: "contains", Values: []string{"a"}}
	}
	if _, err := normalizeWAFInspect(many); err == nil {
		t.Fatal("too many inspect clauses accepted")
	}
	if _, err := normalizeWAFInspect(many[:MaxWAFInspectPerRule]); err != nil {
		t.Fatalf("%d clauses refused: %v", MaxWAFInspectPerRule, err)
	}
}

// The legacy clause JSON is unchanged (no new fields leak into the inspect
// cache key of existing rules).
func TestWAFInspectJSONOmitsUnsetExtensions(t *testing.T) {
	encoded := wafInspectJSON(WAFInspect{Target: "args", Operator: "contains", Values: []string{"<script"}})
	if encoded != `{"target":"args","operator":"contains","values":["\u003cscript"]}` {
		t.Fatalf("JSON %s", encoded)
	}
}
