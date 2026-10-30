package edgeconfig

import (
	"errors"
	"testing"
)

// multipart_field_names (text), multipart_part_count and
// multipart_field_max_length (numbers) inspect targets read the request body
// (body_overflow allowed) and need CAPABILITY_NAME_WAF v5.
func TestNormalizeWAFInspectMultipartTargets(t *testing.T) {
	valid := []WAFInspect{
		{Target: "multipart_field_names", Operator: "equals", Values: []string{"php_session_upload_progress"}, Filters: []string{"lowercase"}},
		{Target: "multipart_field_names", Operator: "contains", Values: []string{"upload_progress"}, BodyOverflow: "match"},
		{Target: "multipart_part_count", Operator: "gt", Values: []string{"1000"}},
		{Target: "multipart_part_count", Operator: "gt", Values: []string{"1000"}, BodyOverflow: "match"},
		{Target: "multipart_field_max_length", Operator: "gt", Values: []string{"1048576"}},
	}
	for _, value := range valid {
		if _, err := normalizeOneWAFInspect(value); err != nil {
			t.Errorf("%+v: %v", value, err)
		}
	}
	invalid := []WAFInspect{
		{Target: "multipart_field_names", Key: "a", Operator: "equals", Values: []string{"a"}},
		{Target: "multipart_part_count", Operator: "contains", Values: []string{"1"}},
		{Target: "multipart_part_count", Operator: "gt", Values: []string{"1"}, Filters: []string{"lowercase"}},
		{Target: "multipart_field_max_length", Operator: "gt", Values: []string{"-1"}},
		{Target: "multipart_field_names", Operator: "gt", Values: []string{"1"}},
	}
	for _, value := range invalid {
		if _, err := normalizeOneWAFInspect(value); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%+v accepted (%v)", value, err)
		}
	}
	for _, target := range []string{"multipart_field_names", "multipart_part_count", "multipart_field_max_length"} {
		if !WAFInspectReadsBody(target) {
			t.Errorf("%s does not read the body", target)
		}
	}
	inspect, ok, err := WAFInspectPolicyCondition("multipart_part_count", "number_gt", "", []string{"1000"}, nil, "")
	if !ok || err != nil || inspect.Operator != "gt" {
		t.Fatalf("policy condition %+v %v %v", inspect, ok, err)
	}
}

func TestListenerSecurityWAFAPIVersionMultipart(t *testing.T) {
	if WAFMultipartAPIVersion != 5 {
		t.Fatalf("WAFMultipartAPIVersion %d", WAFMultipartAPIVersion)
	}
	for _, inspect := range []WAFInspect{
		{Target: "multipart_field_names", Operator: "equals", Values: []string{"x"}},
		{Target: "multipart_part_count", Operator: "gt", Values: []string{"1000"}},
		{Target: "multipart_field_max_length", Operator: "gt", Values: []string{"1048576"}},
	} {
		// A v4 condition in another rule does not lower the requirement.
		policy := SecurityPolicy{Rules: []WAFRule{
			{Match: WAFMatch{Inspect: []WAFInspect{{Target: "content_type", Operator: "prefix", Values: []string{"text/"}}}}},
			{Match: WAFMatch{Inspect: []WAFInspect{inspect}}}}}
		if got := ListenerSecurityWAFAPIVersion(&ListenerSecurity{Policies: []SecurityPolicy{policy}, ManagedWAF: &ManagedWAF{}}); got != WAFMultipartAPIVersion {
			t.Fatalf("%s %d", inspect.Target, got)
		}
	}
	upload := SecurityPolicy{Rules: []WAFRule{{Match: WAFMatch{Inspect: []WAFInspect{{Target: "upload_extension", Operator: "equals", Values: []string{"php"}}}}}}}
	if got := ListenerSecurityWAFAPIVersion(&ListenerSecurity{Policies: []SecurityPolicy{upload}}); got != 1 {
		t.Fatalf("upload_extension %d", got)
	}
}
