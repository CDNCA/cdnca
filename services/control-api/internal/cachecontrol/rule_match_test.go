package cachecontrol

import (
	"encoding/json"
	"strings"
	"testing"
)

// ge36: cache rules match a path regular expression and the response
// Content-Type (schema v2 only).
func TestPolicyRulePathRegexAndContentTypes(t *testing.T) {
	document, err := normalizePolicy(PolicyDocument{
		SchemaVersion: PolicySchemaV2, schemaVersionExplicit: true, Mode: PolicyOverride,
		Rules: []Rule{
			{Order: 1, PathRegex: `^/v[0-9]+/assets/`, ContentTypes: []string{" Image/* ", "text/css"},
				Action: RuleActionCache, TTLSeconds: 600, actionExplicit: true, browserTTLExplicit: true},
			{Order: 2, Extensions: []string{".html"}, Action: RuleActionNoCache, actionExplicit: true, browserTTLExplicit: true},
		},
		QueryMode: QueryPreserve, DiskQuotaBytes: minDiskQuotaBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(document.Rules[0].ContentTypes, ","); got != "image/*,text/css" {
		t.Fatalf("content types %q", got)
	}
	raw, err := json.Marshal(document.Rules[0])
	if err != nil || !strings.Contains(string(raw), `"path_regex":"^/v[0-9]+/assets/"`) ||
		!strings.Contains(string(raw), `"content_types":["image/*","text/css"]`) {
		t.Fatalf("json %s %v", raw, err)
	}
	decoded, err := decodeRuleJSON(raw, true)
	if err != nil || decoded.PathRegex != document.Rules[0].PathRegex || len(decoded.ContentTypes) != 2 {
		t.Fatalf("decoded %+v %v", decoded, err)
	}
	if rule := MatchRule(document, RequestFacts{Path: "/v2/assets/a.png", ContentType: "image/png", StatusCode: 200}); rule == nil || rule.Order != 1 {
		t.Fatalf("image matched %+v", rule)
	}
	if rule := MatchRule(document, RequestFacts{Path: "/v2/assets/a.js", ContentType: "application/javascript"}); rule != nil {
		t.Fatalf("javascript matched %+v", rule)
	}
	if rule := MatchRule(document, RequestFacts{Path: "/assets/a.png", ContentType: "image/png"}); rule != nil {
		t.Fatalf("regex ignored %+v", rule)
	}

	bad := func(rule Rule, schema int) {
		t.Helper()
		rule.Order = 1
		if schema == PolicySchemaV2 {
			rule.Action, rule.TTLSeconds, rule.actionExplicit, rule.browserTTLExplicit = RuleActionCache, 60, true, true
		} else {
			rule.TTLSeconds = 60
		}
		if _, err := normalizePolicy(PolicyDocument{SchemaVersion: schema, schemaVersionExplicit: schema == PolicySchemaV2,
			Mode: PolicyOverride, Rules: []Rule{rule}, QueryMode: QueryPreserve, DiskQuotaBytes: minDiskQuotaBytes}); err == nil {
			t.Errorf("accepted %+v", rule)
		}
	}
	bad(Rule{PathRegex: `(a+)+`}, PolicySchemaV2)
	bad(Rule{PathRegex: `[`}, PolicySchemaV2)
	bad(Rule{PathRegex: strings.Repeat("a", 257)}, PolicySchemaV2)
	bad(Rule{ContentTypes: []string{}}, PolicySchemaV2)
	bad(Rule{ContentTypes: []string{"text"}}, PolicySchemaV2)
	// schema v1: allowed, exempt from the no-overlap rule
	v1, err := normalizePolicy(PolicyDocument{Mode: PolicyOverride, Rules: []Rule{
		{Order: 1, PathRegex: `^/a`, TTLSeconds: 60}, {Order: 2, ContentTypes: []string{"image/*"}, TTLSeconds: 60},
		{Order: 3, TTLSeconds: 30},
	}, QueryMode: QueryPreserve, DiskQuotaBytes: minDiskQuotaBytes})
	if err != nil || v1.Rules[0].PathRegex != `^/a` || len(v1.Rules[1].ContentTypes) != 1 {
		t.Fatalf("schema v1 conditions: %+v %v", v1.Rules, err)
	}
	if raw, _ := json.Marshal(v1.Rules[1]); !strings.Contains(string(raw), `"content_types":["image/*"]`) || strings.Contains(string(raw), "action") {
		t.Fatalf("schema v1 json %s", raw)
	}

	many := make([]Rule, 9)
	for index := range many {
		many[index] = Rule{Order: index + 1, PathRegex: `^/x`, Extensions: []string{"." + string(rune('a'+index))},
			Action: RuleActionCache, TTLSeconds: 60, actionExplicit: true, browserTTLExplicit: true}
	}
	if _, err := normalizePolicy(PolicyDocument{SchemaVersion: PolicySchemaV2, schemaVersionExplicit: true, Mode: PolicyOverride,
		Rules: many, QueryMode: QueryPreserve, DiskQuotaBytes: minDiskQuotaBytes}); err == nil {
		t.Fatal("9 conditional rules accepted")
	}
}
