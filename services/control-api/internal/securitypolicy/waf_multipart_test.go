package securitypolicy

import (
	"errors"
	"testing"
)

// Multipart field names / part count / longest field.
func TestWAFMultipartConditionsPublishGate(t *testing.T) {
	waf := func(condition Condition) PolicyFields {
		fields := validFields(condition)
		fields.Kind = KindWAF
		fields.Rules[0].Conditions = []Condition{condition}
		return fields
	}
	accepted := map[string]Condition{
		"field name":     {Field: "multipart_field_names", Operator: "equals", Values: []string{"php_session_upload_progress"}, Filters: []string{"lowercase"}},
		"field regex":    {Field: "multipart_field_names", Operator: "regex", Values: []string{`(?i)^php_session_upload_progress$`}},
		"part count":     {Field: "multipart_part_count", Operator: "number_gt", Values: []string{"1000"}},
		"field length":   {Field: "multipart_field_max_length", Operator: "number_gt", Values: []string{"1048576"}},
		"count overflow": {Field: "multipart_part_count", Operator: "number_gt", Values: []string{"1000"}, BodyOverflow: "match"},
	}
	for name, condition := range accepted {
		fields := waf(condition)
		if err := normalizePublishableFields(&fields, false); err != nil {
			t.Fatalf("%s refused: %v", name, err)
		}
	}
	refused := map[string]Condition{
		"text op on count":   {Field: "multipart_part_count", Operator: "contains", Values: []string{"1"}},
		"filter on count":    {Field: "multipart_part_count", Operator: "number_gt", Values: []string{"1"}, Filters: []string{"lowercase"}},
		"key on field names": {Field: "multipart_field_names", Key: "a", Operator: "equals", Values: []string{"a"}},
		"in on field names":  {Field: "multipart_field_names", Operator: "in", Values: []string{"a"}},
	}
	for name, condition := range refused {
		fields := waf(condition)
		if err := normalizePublishableFields(&fields, false); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s accepted (%v)", name, err)
		}
	}
	if !runtimeConditionSupported(KindWAF, Condition{Field: "multipart_field_names", Operator: "equals"}) ||
		!runtimeConditionSupported(KindWAF, Condition{Field: "multipart_part_count", Operator: "number_gt"}) {
		t.Fatal("runtime does not support multipart conditions")
	}
}
