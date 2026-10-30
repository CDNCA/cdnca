package analyticslog

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fixedEventNames struct {
	names  EventNames
	tenant *string
	refs   *[]EventNameRef
}

func (lookup fixedEventNames) Lookup(_ context.Context, tenantID string, refs []EventNameRef) EventNames {
	*lookup.tenant, *lookup.refs = tenantID, refs
	return lookup.names
}

// P14: a block row names its site by domain and its rule by the policy rule
// name; an unknown name is "" (the page shows a short ID instead), and the
// query the node logged (already redacted) is returned as uri_query.
func TestHandlerNamesBlockEventSiteAndRule(t *testing.T) {
	now := time.Date(2026, 10, 24, 4, 0, 0, 0, time.UTC)
	policyA, ruleA := "018f0000-0000-7000-8000-0000000000a1", "018f0000-0000-7000-8000-0000000000b1"
	ccRule := "018f0000-0000-7000-8000-0000000000c1"
	store := &recordingStore{blockPage: BlockEventPage{Items: []BlockEvent{
		{EventID: "block-a", OccurredAt: now.Add(-time.Minute), SiteID: siteA, NodeID: nodeA, ConfigVersion: configA,
			Host: "example.test", URIPath: "/login", URIQuery: "user=a&password=***", ClientIP: "8.8.8.8", EventType: "waf",
			Action: "block", Severity: "high", RuleID: strings.ToUpper(ruleA), PolicyID: policyA, StatusCode: 403},
		{EventID: "block-b", OccurredAt: now.Add(-2 * time.Minute), SiteID: siteA, NodeID: nodeA, ConfigVersion: configA,
			Host: "example.test", URIPath: "/", ClientIP: "8.8.8.8", EventType: "cc",
			Action: "block", Severity: "high", RuleID: ccRule, StatusCode: 429},
		{EventID: "block-c", OccurredAt: now.Add(-3 * time.Minute), SiteID: siteA, NodeID: nodeA, ConfigVersion: configA,
			Host: "example.test", URIPath: "/", ClientIP: "8.8.8.8", EventType: "waf",
			Action: "block", Severity: "high", RuleID: policyA + ":default", PolicyID: policyA, StatusCode: 403},
	}}}
	actor := Actor{ScopeKind: "tenant", TenantID: tenantA, Permissions: []string{ReadPermission}}
	handler := newTestHandler(t, store, actor, HandlerConfig{})
	values := queryValues(now.Add(-time.Hour), now)

	type row struct {
		SiteDomain string `json:"site_domain"`
		RuleName   string `json:"rule_name"`
		URIPath    string `json:"uri_path"`
		URIQuery   string `json:"uri_query"`
	}
	decode := func(t *testing.T) []row {
		t.Helper()
		response := doGET(handler, "/v1/analytics/logs/block-events", values)
		var body struct{ Data []row }
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || len(body.Data) != 3 {
			t.Fatalf("block events = %d %s", response.Code, response.Body.String())
		}
		return body.Data
	}

	// Without a lookup the site names are empty and a UUID rule gets the
	// fallback name, never the bare UUID (fix-wafname).
	for index, item := range decode(t) {
		want := []string{"未命名规则（018f0000）", "未命名规则（018f0000）", "默认动作（策略 018f0000）"}[index]
		if item.SiteDomain != "" || item.RuleName != want {
			t.Fatalf("names without lookup: %+v", item)
		}
	}

	var tenant string
	var refs []EventNameRef
	handler.SetEventNameLookup(fixedEventNames{tenant: &tenant, refs: &refs, names: EventNames{
		Sites: map[string]string{siteA: "www.example.test"},
		Rules: map[string]map[string]string{
			policyA:                                {ruleA: "拦截 SQL 注入"},
			"018f0000-0000-7000-8000-0000000000a2": {ccRule: "登录限频"},
		},
	}})
	got := decode(t)
	if tenant != tenantA || len(refs) != 3 || refs[0].PolicyID != policyA || refs[1].PolicyID != "" || refs[1].RuleID != ccRule {
		t.Fatalf("lookup called with %q %+v", tenant, refs)
	}
	want := []row{
		{SiteDomain: "www.example.test", RuleName: "拦截 SQL 注入", URIPath: "/login", URIQuery: "user=a&password=***"},
		{SiteDomain: "www.example.test", RuleName: "登录限频", URIPath: "/"},
		{SiteDomain: "www.example.test", RuleName: "默认动作（策略 018f0000）", URIPath: "/"},
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("row %d = %+v, want %+v", index, got[index], want[index])
		}
	}
}

// A policy's rule keeps the name of its newest version that has one; rows
// of malformed documents are skipped.
func TestMergeRuleNamesNewestFirst(t *testing.T) {
	rules := map[string]map[string]string{}
	mergeRuleNames(rules, "p", []byte(`[{"id":"R1","name":"新名"},{"id":"r2","name":""}]`))
	mergeRuleNames(rules, "p", []byte(`[{"id":"r1","name":"旧名"},{"id":"r2","name":"旧名2"}]`))
	mergeRuleNames(rules, "p", []byte(`{"not":"an array"}`))
	if rules["p"]["r1"] != "新名" || rules["p"]["r2"] != "旧名2" || len(rules["p"]) != 2 {
		t.Fatalf("rules = %v", rules)
	}
}

func TestEventNameIDsDistinctCanonical(t *testing.T) {
	policy := "018f0000-0000-7000-8000-0000000000a1"
	sites, policies, orphans := eventNameIDs([]EventNameRef{
		{SiteID: strings.ToUpper(siteA), PolicyID: policy, RuleID: "x"},
		{SiteID: siteA, PolicyID: strings.ToUpper(policy), RuleID: "018f0000-0000-7000-8000-0000000000b1"},
		{SiteID: "not-a-uuid", RuleID: "018f0000-0000-7000-8000-0000000000c1"},
		{SiteID: siteA, RuleID: "edgeconfig-waf-0001"},
		{SiteID: siteA, RuleID: "018f0000-0000-7000-8000-0000000000c1"},
	})
	if len(sites) != 1 || sites[0] != siteA || len(policies) != 1 || policies[0] != policy ||
		len(orphans) != 1 || orphans[0] != "018f0000-0000-7000-8000-0000000000c1" {
		t.Fatalf("ids = %v %v %v", sites, policies, orphans)
	}
}

// uri_query is the node's redacted query: printable ASCII without "#", at
// most 512 bytes.
func TestValidOutputQuery(t *testing.T) {
	for _, item := range []struct {
		value string
		want  bool
	}{
		{"", true},
		{"a=1&token=***", true},
		{strings.Repeat("a", 512), true},
		{strings.Repeat("a", 513), false},
		{"a=1#frag", false},
		{"a=1 b", false},
		{"a=é", false},
		{"a=\x01", false},
	} {
		if got := validOutputQuery(item.value); got != item.want {
			t.Fatalf("validOutputQuery(%q) = %v", item.value, got)
		}
	}
}
