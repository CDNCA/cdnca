package wafreport

import (
	"encoding/json"
	"strings"
	"testing"
)

// A site policy whose managed_waf rule has no conditions.
const managedSitePolicy = `{"id":"01a1b548-aee3-79ae-8b01-8c0c2df3fb17","scope_id":"01a1b548-aee3-79ae-8b01-8c0c2df3fb10","kind":"waf","name":"本站防护","description":"","enabled":true,"default_action":"allow","version":4,"rules":[` +
	`{"id":"01a1b548-aee3-79ae-8b01-8c0c2df3fb18","name":"托管 WAF（由网站页设置）","priority":1,"enabled":true,"conditions":[],"action":"managed_waf","flow":"continue","action_config":{"managed_waf":{"profile":"system/crs-pl1"}}},` +
	`{"id":"01a1b548-aee3-79ae-8b01-8c0c2df3fb19","name":"args","priority":2,"enabled":true,"conditions":[{"field":"args","operator":"contains","values":["union"],"filters":["lowercase"],"body_overflow":"match"},{"field":"jwt_claim","operator":"exists","key":"sub","values":[]}],"action":"block","flow":"stop","action_config":{}}]}`

const blockAllPolicy = `{"id":"01a1b548-aee3-79ae-8b01-8c0c2df3fb20","kind":"waf","name":"x","enabled":true,"default_action":"allow","rules":[{"id":"01a1b548-aee3-79ae-8b01-8c0c2df3fb21","name":"all","priority":1,"enabled":true,"conditions":[],"action":"block","flow":"stop","action_config":{}}]}`

func TestReportablePoliciesKeepsControlShapesAndSkipsRefused(t *testing.T) {
	kept, skipped := reportablePolicies([]json.RawMessage{json.RawMessage(managedSitePolicy), json.RawMessage(blockAllPolicy)})
	if len(kept) != 1 || !strings.Contains(string(kept[0]), "fb17") {
		t.Fatalf("kept = %s", kept)
	}
	if len(skipped) != 1 || skipped[0].ID != "01a1b548-aee3-79ae-8b01-8c0c2df3fb20" || !strings.Contains(skipped[0].Reason, "rules[0]") {
		t.Fatalf("skipped = %#v", skipped)
	}
	for name, policy := range map[string]string{
		"no rules":          `{"id":"01a1b548-aee3-79ae-8b01-8c0c2df3fb30","kind":"waf","rules":[]}`,
		"unknown field":     `{"id":"01a1b548-aee3-79ae-8b01-8c0c2df3fb31","kind":"waf","rules":[{"conditions":[{"field":"host","operator":"equals","values":["a"]}]}],"cc_settings":{}}`,
		"count_by":          `{"id":"01a1b548-aee3-79ae-8b01-8c0c2df3fb32","kind":"waf","rules":[{"conditions":[{"field":"host","operator":"equals","values":["a"]}],"count_by":[]}]}`,
		"empty values":      `{"id":"01a1b548-aee3-79ae-8b01-8c0c2df3fb33","kind":"waf","rules":[{"conditions":[{"field":"host","operator":"equals","values":[]}]}]}`,
		"null conditions":   `{"id":"01a1b548-aee3-79ae-8b01-8c0c2df3fb34","kind":"waf","rules":[{"conditions":null,"action":"block"}]}`,
		"non-string filter": `{"id":"01a1b548-aee3-79ae-8b01-8c0c2df3fb35","kind":"waf","rules":[{"conditions":[{"field":"args","operator":"contains","values":["a"],"filters":[1]}]}]}`,
	} {
		if kept, _ := reportablePolicies([]json.RawMessage{json.RawMessage(policy)}); len(kept) != 0 {
			t.Errorf("%s kept", name)
		}
	}
}
