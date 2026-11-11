package securitypolicy

import (
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/fielderr"
)

const testSetID = "0190a000-0000-7000-8000-0000000000c7"

// / 0026: the string set operators and the browser, version, device
// and request time fields are WAF conditions with their own value rules.
func TestNormalizeAcceptsB1Conditions(t *testing.T) {
	for name, condition := range map[string]Condition{
		"user agent in set":    {Field: "user_agent", Operator: "in_string_set", Values: []string{testSetID}},
		"host not in set":      {Field: "host", Operator: "not_in_string_set", Values: []string{testSetID}},
		"header in set":        {Field: "header", Key: "X-Client", Operator: "in_string_set", Values: []string{testSetID}},
		"ja4 in set":           {Field: "ja4", Operator: "in_string_set", Values: []string{testSetID}},
		"browser":              {Field: "browser", Operator: "in", Values: []string{"google_chrome", "Microsoft_Edge"}},
		"device":               {Field: "device", Operator: "not_in", Values: []string{"bot"}},
		"browser version":      {Field: "browser_version", Key: "google_chrome", Operator: "version_lt", Values: []string{"100"}},
		"weekly":               {Field: "request_time", Key: "Asia/Shanghai", Operator: "in_time_range", Values: []string{"mon,tue,wed,thu,fri 09:00-18:00"}},
		"range default zone":   {Field: "request_time", Operator: "not_in_time_range", Values: []string{"2026-11-11T00:00:00 / 2026-11-12T00:00:00"}},
		"weekly past midnight": {Field: "request_time", Key: "America/New_York", Operator: "in_time_range", Values: []string{"fri 22:00-02:00"}},
	} {
		t.Run(name, func(t *testing.T) {
			fields := validFields(condition)
			fields.Kind = KindWAF
			if err := normalizePublishableFields(&fields, false); err != nil {
				t.Fatalf("normalize: %v", err)
			}
			got := fields.Rules[0].Conditions[0]
			if got.Field == "request_time" && got.Key == "" {
				t.Fatal("request_time key must default to the zone")
			}
			if got.Field == "header" && got.Key != "x-client" {
				t.Fatalf("header key = %q", got.Key)
			}
		})
	}
}

func TestNormalizeRefusesInvalidB1Conditions(t *testing.T) {
	for name, test := range map[string]struct {
		condition Condition
		field     string
	}{
		"set id not uuid":   {Condition{Field: "path", Operator: "in_string_set", Values: []string{"abc"}}, "values"},
		"two sets one cond": {Condition{Field: "path", Operator: "in_string_set", Values: []string{testSetID, "0190a000-0000-7000-8000-0000000000c8"}}, "values"},
		"set with filters":  {Condition{Field: "path", Operator: "in_string_set", Values: []string{testSetID}, Filters: []string{"lowercase"}}, "filters"},
		"set on args":       {Condition{Field: "args", Operator: "in_string_set", Values: []string{testSetID}}, "operator"},
		"unknown browser":   {Condition{Field: "browser", Operator: "in", Values: []string{"netscape"}}, "values"},
		"version on 360":    {Condition{Field: "browser_version", Key: "360_browser", Operator: "version_eq", Values: []string{"10"}}, "key"},
		"bad version":       {Condition{Field: "browser_version", Key: "firefox", Operator: "version_gte", Values: []string{"v100"}}, "values"},
		"unknown zone":      {Condition{Field: "request_time", Key: "Mars/Olympus", Operator: "in_time_range", Values: []string{"mon 09:00-18:00"}}, "key"},
		"empty slot":        {Condition{Field: "request_time", Operator: "in_time_range", Values: []string{"mon 09:00-09:00"}}, "values"},
		"mixed forms":       {Condition{Field: "request_time", Operator: "in_time_range", Values: []string{"mon 09:00-18:00", "2026-11-11T00:00:00 / 2026-11-12T00:00:00"}}, "values"},
	} {
		t.Run(name, func(t *testing.T) {
			fields := validFields(test.condition)
			fields.Kind = KindWAF
			err := normalizePublishableFields(&fields, false)
			located, ok := fielderr.As(err)
			if !ok || located.Field != "rules[0].conditions[0]."+test.field {
				t.Fatalf("err = %v, want field %s", err, test.field)
			}
		})
	}
}

// At most 4 string set conditions per rule; they may repeat on one field.
func TestStringSetConditionsRepeatUpToFour(t *testing.T) {
	condition := Condition{Field: "user_agent", Operator: "not_in_string_set", Values: []string{testSetID}}
	ids := []string{testSetID, "0190a000-0000-7000-8000-0000000000c8", "0190a000-0000-7000-8000-0000000000c9",
		"0190a000-0000-7000-8000-0000000000ca", "0190a000-0000-7000-8000-0000000000cb"}
	fields := validFields(condition)
	fields.Kind = KindWAF
	fields.Rules[0].Conditions = nil
	for _, id := range ids[:4] {
		fields.Rules[0].Conditions = append(fields.Rules[0].Conditions, Condition{Field: "user_agent", Operator: "not_in_string_set", Values: []string{id}})
	}
	if err := normalizePublishableFields(&fields, false); err != nil {
		t.Fatalf("four sets: %v", err)
	}
	fields.Rules[0].Conditions = append(fields.Rules[0].Conditions, Condition{Field: "path", Operator: "in_string_set", Values: []string{ids[4]}})
	if err := normalizePublishableFields(&fields, false); err == nil {
		t.Fatal("a fifth string set condition must be refused")
	}
}

// CC rules do not take the new conditions.
func TestCCRefusesB1Conditions(t *testing.T) {
	fields := validFields(Condition{Field: "user_agent", Operator: "in_string_set", Values: []string{testSetID}})
	fields.Kind = KindCC
	if err := normalizePublishableFields(&fields, false); err == nil {
		t.Fatal("CC string set condition must be refused")
	}
}
