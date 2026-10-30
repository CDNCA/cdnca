package edgeconfig

import (
	"errors"
	"testing"
)

// content_type (text operators) and http_version (equals /
// not_equals on 1.0 / 1.1 / 2 / 3, no filters) inspect targets; a release
// using them needs CAPABILITY_NAME_WAF v4.
func TestNormalizeWAFInspectContentTypeAndHTTPVersion(t *testing.T) {
	valid := []WAFInspect{
		{Target: "content_type", Operator: "prefix", Values: []string{"application/json"}},
		{Target: "content_type", Operator: "equals", Values: []string{"text/plain; charset=utf-8"}},
		{Target: "content_type", Operator: "regex", Values: []string{`(?i)^multipart/`}},
		{Target: "content_type", Operator: "contains", Values: []string{"xml"}, Filters: []string{"lowercase"}},
		{Target: "http_version", Operator: "equals", Values: []string{"1.0"}},
		{Target: "http_version", Operator: "not_equals", Values: []string{"1.1", "2", "3"}},
	}
	for _, value := range valid {
		if _, err := normalizeOneWAFInspect(value); err != nil {
			t.Errorf("%+v: %v", value, err)
		}
	}
	invalid := []WAFInspect{
		{Target: "content_type", Key: "x", Operator: "prefix", Values: []string{"a"}},
		{Target: "http_version", Operator: "prefix", Values: []string{"1"}},
		{Target: "http_version", Operator: "equals", Values: []string{"1"}},
		{Target: "http_version", Operator: "equals", Values: []string{"HTTP/1.1"}},
		{Target: "http_version", Operator: "equals", Values: []string{"2"}, Filters: []string{"lowercase"}},
		{Target: "http_version", Operator: "regex", Values: []string{"^1"}},
		{Target: "http_version", Operator: "eq", Values: []string{"1"}, Filters: []string{"length"}},
	}
	for _, value := range invalid {
		if _, err := normalizeOneWAFInspect(value); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%+v accepted (%v)", value, err)
		}
	}
	inspect, ok, err := WAFInspectPolicyCondition("http_version", "equals", "", []string{"2"}, nil, "")
	if !ok || err != nil || inspect.Target != "http_version" {
		t.Fatalf("policy condition %+v %v %v", inspect, ok, err)
	}
}

func TestListenerSecurityWAFAPIVersionConditions(t *testing.T) {
	plain := SecurityPolicy{Rules: []WAFRule{{Match: WAFMatch{Inspect: []WAFInspect{{Target: "user_agent", Operator: "contains", Values: []string{"x"}}}}}}}
	if got := ListenerSecurityWAFAPIVersion(&ListenerSecurity{Policies: []SecurityPolicy{plain}}); got != 1 {
		t.Fatalf("plain %d", got)
	}
	for _, target := range []string{"content_type", "http_version"} {
		values := []string{"1.0"}
		policy := SecurityPolicy{Rules: []WAFRule{{Match: WAFMatch{Inspect: []WAFInspect{{Target: target, Operator: "equals", Values: values}}}}}}
		// Even with a managed WAF (v3) the v4 condition decides.
		if got := ListenerSecurityWAFAPIVersion(&ListenerSecurity{Policies: []SecurityPolicy{policy}, ManagedWAF: &ManagedWAF{}}); got != WAFConditionsAPIVersion {
			t.Fatalf("%s %d", target, got)
		}
	}
	// The node now implements v5 (multipart targets).
	if WAFNodeAPIVersion != WAFMultipartAPIVersion {
		t.Fatalf("node advertises WAF v%d", WAFNodeAPIVersion)
	}
}
