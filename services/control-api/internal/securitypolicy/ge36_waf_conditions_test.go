package securitypolicy

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// WAF rules on the request Content-Type and HTTP version.
func TestGE36WAFContentTypeAndHTTPVersionConditions(t *testing.T) {
	waf := func(condition Condition) PolicyFields {
		fields := validFields(condition)
		fields.Kind = KindWAF
		fields.Rules[0].Conditions = []Condition{condition}
		return fields
	}
	accepted := []Condition{
		{Field: "content_type", Operator: "prefix", Values: []string{"application/json"}},
		{Field: "content_type", Operator: "equals", Values: []string{"text/xml", "application/xml"}},
		{Field: "content_type", Operator: "regex", Values: []string{`(?i)^multipart/form-data`}},
		{Field: "content_type", Operator: "number_gt", Values: []string{"200"}, Filters: []string{"length"}},
		{Field: "http_version", Operator: "equals", Values: []string{"1.0"}},
		{Field: "http_version", Operator: "not_equals", Values: []string{"2", "3"}},
	}
	for _, condition := range accepted {
		fields := waf(condition)
		if err := normalizePublishableFields(&fields, false); err != nil {
			t.Fatalf("%+v refused: %v", condition, err)
		}
	}
	refused := []Condition{
		{Field: "http_version", Operator: "prefix", Values: []string{"1"}},
		{Field: "http_version", Operator: "equals", Values: []string{"1"}},
		{Field: "http_version", Operator: "equals", Values: []string{"HTTP/2"}},
		{Field: "http_version", Operator: "equals", Values: []string{"2"}, Filters: []string{"lowercase"}},
		{Field: "content_type", Key: "x", Operator: "prefix", Values: []string{"a"}},
	}
	for _, condition := range refused {
		fields := waf(condition)
		if err := normalizePublishableFields(&fields, false); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%+v accepted (%v)", condition, err)
		}
	}
}

// "client in IP list" conditions name one list by ID.
func TestGE36WAFIPListCondition(t *testing.T) {
	const list = "0190a000-0000-7000-8000-000000000001"
	for _, condition := range []Condition{
		{Field: "ip_list", Operator: "in_ip_list", Values: []string{list}},
		{Field: "ip_list", Operator: "not_in_ip_list", Values: []string{strings.ToUpper(list)}},
	} {
		fields := validFields(condition)
		fields.Kind = KindWAF
		fields.Rules[0].Conditions = []Condition{condition}
		if err := normalizePublishableFields(&fields, false); err != nil {
			t.Fatalf("%+v refused: %v", condition, err)
		}
		if got := fields.Rules[0].Conditions[0].Values[0]; got != list {
			t.Fatalf("value not canonical: %s", got)
		}
		if ids := IPListReferences(fields.Rules); len(ids) != 1 || ids[0].String() != list {
			t.Fatalf("references %v", ids)
		}
	}
	for _, condition := range []Condition{
		{Field: "ip_list", Operator: "in_ip_list", Values: []string{"x"}},
		{Field: "ip_list", Operator: "in_ip_list", Values: []string{list, "0190a000-0000-7000-8000-000000000002"}},
		{Field: "ip_list", Operator: "equals", Values: []string{list}},
		{Field: "ip_list", Key: "a", Operator: "in_ip_list", Values: []string{list}},
	} {
		fields := validFields(condition)
		fields.Kind = KindWAF
		fields.Rules[0].Conditions = []Condition{condition}
		if err := normalizePublishableFields(&fields, false); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%+v accepted (%v)", condition, err)
		}
	}
	lists := ResolvedIPLists{}
	if _, ok := lists.Condition(Condition{Field: "ip_list", Operator: "in_ip_list", Values: []string{list}}); ok {
		t.Fatal("unresolved list compiled")
	}
}

// The per-policy "same client over threshold → ban"
// (waf_settings.auto_block, default off): window 1..86400 s, hits
// 1..1000000, ban 1..604800 s, WAF policies only; an off switch with
// defend mode stores nothing.
func TestGE36WAFAutoBlockSettings(t *testing.T) {
	waf := func(settings *WAFSettings) PolicyFields {
		fields := validFields(Condition{Field: "path", Operator: "prefix", Values: []string{"/admin"}})
		fields.Kind = KindWAF
		fields.WAFSettings = settings
		return fields
	}
	block := func(window, hits, seconds int) *WAFSettings {
		return &WAFSettings{AutoBlock: &WAFAutoBlock{WindowSeconds: window, HitThreshold: hits, BlockSeconds: seconds}}
	}
	for _, settings := range []*WAFSettings{block(1, 1, 1), block(86_400, 1_000_000, 7*86_400), block(60, 10, 600)} {
		fields := waf(settings)
		if err := normalizePublishableFields(&fields, false); err != nil {
			t.Fatalf("%+v refused: %v", *settings.AutoBlock, err)
		}
		if fields.WAFSettings == nil || *fields.WAFSettings.AutoBlock != *settings.AutoBlock {
			t.Fatalf("auto block not kept: %+v", fields.WAFSettings)
		}
	}
	for _, settings := range []*WAFSettings{block(0, 1, 1), block(86_401, 1, 1), block(60, 0, 1), block(60, 1_000_001, 1),
		block(60, 1, 0), block(60, 1, 7*86_400+1)} {
		fields := waf(settings)
		if err := normalizePublishableFields(&fields, false); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%+v accepted (%v)", *settings.AutoBlock, err)
		}
	}
	cc := waf(block(60, 10, 600))
	cc.Kind = KindCC
	if err := normalizePublishableFields(&cc, false); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("auto block accepted on a CC policy (%v)", err)
	}
	off := waf(&WAFSettings{})
	if err := normalizePublishableFields(&off, false); err != nil || off.WAFSettings != nil {
		t.Fatalf("default off not normalized to nil: %+v %v", off.WAFSettings, err)
	}
}

// The control OpenAPI documents what the WAF policy API accepts
// (waf_settings, the ban action and the WAF action parameters); every
// schema there is additionalProperties: false.
func TestGE36WAFOpenAPIDocumentsWAFSettings(t *testing.T) {
	raw, err := os.ReadFile("../../../../api/openapi/v1/control.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	section := func(name string) string {
		start := strings.Index(text, "\n    "+name+":\n")
		if start < 0 {
			t.Fatalf("schema %s missing", name)
		}
		rest := text[start+1:]
		if next := strings.Index(rest[1:], "\n    S"); next >= 0 {
			rest = rest[:next+1]
		}
		return rest
	}
	for name, wants := range map[string][]string{
		"SecurityPolicyFields":       {"waf_settings: {$ref: '#/components/schemas/SecurityPolicyWAFSettings'}"},
		"SecurityPolicyWAFSettings":  {"mode:", "auto_block: {$ref: '#/components/schemas/SecurityPolicyWAFAutoBlock'}"},
		"SecurityPolicyWAFAutoBlock": {"window_seconds: {type: integer, minimum: 1, maximum: 86400}", "hit_threshold: {type: integer, minimum: 1, maximum: 1000000}", "block_seconds: {type: integer, minimum: 1, maximum: 604800}"},
		"SecurityPolicyAction":       {"ban"},
		"SecurityPolicyActionConfig": {"waf_ban:", "waf_challenge:"},
	} {
		body := section(name)
		for _, want := range wants {
			if !strings.Contains(body, want) {
				t.Errorf("%s lacks %q", name, want)
			}
		}
	}
}
