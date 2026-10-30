package securitypolicy

import "testing"

func TestFeatureLossAllowsOnlyUnchangedDisable(t *testing.T) {
	current := runtimePolicy(KindCC)
	fields := PolicyFields{Kind: current.Kind, Name: current.Name, Description: current.Description,
		Enabled: false, DefaultAction: current.DefaultAction, Rules: cloneRules(current.Rules)}
	if !disableOnly(current, fields) {
		t.Fatal("unchanged disable must remain available")
	}
	changed := fields
	changed.Name = "edited"
	if disableOnly(current, changed) {
		t.Fatal("disable cannot conceal a content update")
	}
	changed = fields
	changed.Rules = cloneRules(fields.Rules)
	changed.Rules[0].Action = ActionAllow
	if disableOnly(current, changed) {
		t.Fatal("disable cannot conceal a rule update")
	}
	current.Enabled = false
	if disableOnly(current, fields) {
		t.Fatal("disabled draft updates still require custom CC")
	}
}
