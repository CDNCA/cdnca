package securitypolicy

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// an update whose normalized
// content equals the stored version is a no-op; any difference is written.
func TestSameStoredContent(t *testing.T) {
	ruleID := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	stored := Policy{
		ID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), Kind: KindWAF, Name: "Edge WAF", Description: "",
		Enabled: true, DefaultAction: ActionAllow, Revision: 1,
		Rules: []Rule{{ID: ruleID, Name: "Block bad IP", Priority: 1, Enabled: true, Action: "block", Flow: "stop",
			Conditions: []Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"192.0.2.0/24"}}}}},
		WAFSettings: &WAFSettings{Mode: ""},
	}
	// The stored row comes back through its jsonb column.
	raw, err := json.Marshal(stored.Rules)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded []Rule
	if err := json.Unmarshal(raw, &reloaded); err != nil {
		t.Fatal(err)
	}
	current := stored
	current.Rules = reloaded
	same := func() PolicyFields {
		return PolicyFields{Kind: stored.Kind, Name: stored.Name, Description: stored.Description, Enabled: stored.Enabled,
			DefaultAction: stored.DefaultAction, Rules: cloneRules(stored.Rules), WAFSettings: cloneWAFSettings(stored.WAFSettings)}
	}

	cases := []struct {
		name   string
		change func(*PolicyFields)
		want   bool
	}{
		{"equal", func(*PolicyFields) {}, true},
		{"name", func(fields *PolicyFields) { fields.Name = "Edge WAF 2" }, false},
		{"enabled", func(fields *PolicyFields) { fields.Enabled = false }, false},
		{"rule value", func(fields *PolicyFields) { fields.Rules[0].Conditions[0].Values = []string{"192.0.2.0/25"} }, false},
		{"rule order", func(fields *PolicyFields) {
			fields.Rules = append(fields.Rules, Rule{ID: uuid.New(), Name: "Second", Priority: 2, Enabled: true, Action: "block", Flow: "stop",
				Conditions: []Condition{{Field: "path", Operator: "prefix", Values: []string{"/admin"}}}})
		}, false},
		{"waf settings", func(fields *PolicyFields) { fields.WAFSettings = &WAFSettings{Mode: "observe"} }, false},
		{"cc settings added", func(fields *PolicyFields) { fields.CCSettings = &CCSettings{ChallengeCookieDomain: "example.com"} }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fields := same()
			tc.change(&fields)
			got, err := sameStoredContent(current, fields)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("sameStoredContent = %v, want %v", got, tc.want)
			}
		})
	}
}
