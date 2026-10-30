package wafsubscription

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/rulepackcontrol"
	"github.com/google/uuid"
)

// competitorSample is a sample subscription document.
const competitorSample = `{
  "version": "20260809",
  "generated_at": "2026-08-09T09:00:00+08:00",
  "rules": [
    {
      "id": "cve-2017-5638-struts-s2-045",
      "name": "CVE-2017-5638 Apache Struts S2-045",
      "enable": 1,
      "action": "protect",
      "action_config": {"status": "403"},
      "matcher_groups": [
        {"matcher": [
          {"field": "header", "key": "Content-Type", "op": "contain", "value": "%{", "transform": "lower"}
        ]}
      ]
    }
  ]
}`

func TestCompileCompetitorSample(t *testing.T) {
	feed, err := Compile([]byte(competitorSample))
	if err != nil {
		t.Fatal(err)
	}
	if feed.Version != "20260809" || feed.GeneratedAt != "2026-08-09T09:00:00+08:00" || len(feed.Rules) != 1 {
		t.Fatalf("feed = %+v", feed)
	}
	rule := feed.Rules[0]
	want := edgeconfig.WAFRule{Match: edgeconfig.WAFMatch{Inspect: []edgeconfig.WAFInspect{
		{Target: "header", Key: "content-type", Operator: "contains", Values: []string{"%{"}}}},
		Action: edgeconfig.WAFBlock, Control: edgeconfig.WAFStop}
	if rule.ID != "r0001" || rule.Name != "CVE-2017-5638 Apache Struts S2-045" || rule.WAF == nil ||
		fmt.Sprint(*rule.WAF) != fmt.Sprint(want) {
		t.Fatalf("rule = %+v (waf %+v)", rule, rule.WAF)
	}
	if feed.SHA256 == ([32]byte{}) {
		t.Fatal("missing rules digest")
	}
}

func TestCompileActionsGroupsAndTransforms(t *testing.T) {
	feed, err := Compile([]byte(`{"version":"v2","generated_at":"","rules":[
	  {"id":"a","name":"放行健康检查","enable":1,"action":"pass","matcher_groups":[
	    {"matcher":[{"field":"uri","op":"prefix","value":"/healthz"},{"field":"method","op":"equal","value":"get"}]}]},
	  {"id":"b","name":"观察扫描器","enable":true,"action":"observe","matcher_groups":[
	    {"matcher":[{"field":"user_agent","op":"regex","value":"sqlmap","transform":"lower"}]},
	    {"matcher":[{"field":"ip","op":"ip_range","value":"203.0.113.0/24"}]}]},
	  {"id":"c","name":"停用","enable":0,"action":"protect","matcher_groups":[{"matcher":[{"field":"args","op":"contain","value":"x"}]}]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(feed.Rules) != 3 {
		t.Fatalf("rules = %+v", feed.Rules)
	}
	pass, observe, cidr := feed.Rules[0], feed.Rules[1], feed.Rules[2]
	if pass.ID != "r0001" || pass.WAF.Action != edgeconfig.WAFAllow || pass.WAF.Control != edgeconfig.WAFStop ||
		pass.WAF.Match.Path == nil || pass.WAF.Match.Path.Kind != edgeconfig.WAFPathPrefix ||
		pass.WAF.Match.Path.Value != "/healthz" || pass.WAF.Match.Method != "GET" {
		t.Fatalf("pass = %+v / %+v", pass, pass.WAF)
	}
	if observe.ID != "r0002" || observe.WAF.Action != edgeconfig.WAFLog || observe.WAF.Control != edgeconfig.WAFContinue ||
		len(observe.WAF.Match.Inspect) != 1 || observe.WAF.Match.Inspect[0].Values[0] != "(?i)sqlmap" ||
		!strings.HasSuffix(observe.Name, "#1") {
		t.Fatalf("observe = %+v / %+v", observe, observe.WAF)
	}
	if cidr.ID != "r0003" || cidr.WAF.Action != edgeconfig.WAFLog || cidr.WAF.Match.SourceCIDR != "203.0.113.0/24" ||
		!strings.HasSuffix(cidr.Name, "#2") {
		t.Fatalf("second group = %+v / %+v", cidr, cidr.WAF)
	}
}

// The compiled rules are a valid user layer pack: the version a subscriber
// gets compiles with libs/rulepack, every rule is exported and the rules
// run in document order.
func TestCompiledFeedIsAUserRulePack(t *testing.T) {
	feed, err := Compile([]byte(`{"version":"v1","rules":[
	  {"id":"a","name":"放行","enable":1,"action":"pass","matcher_groups":[{"matcher":[{"field":"uri","op":"prefix","value":"/ok"}]}]},
	  {"id":"b","name":"拦截\t注入","enable":1,"action":"protect","matcher_groups":[{"matcher":[{"field":"args","op":"contain","value":"union"}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	tenant, subscription := uuid.New(), uuid.New()
	compiled, err := rulepack.CompilePack(Pack(tenant, subscription, "订阅\n库", "说明", Revision{Major: 3, Minor: 1}, feed.Rules))
	if err != nil {
		t.Fatal(err)
	}
	pack := compiled.Pack
	if pack.PackID != "user/"+tenant.String()+"/waf-sub-"+strings.ReplaceAll(subscription.String(), "-", "") ||
		pack.Layer != rulepack.LayerUser || pack.Version != "3.1.0" || pack.Name != "订阅 库" ||
		strings.Join(pack.Exports, ",") != "r0001,r0002" || pack.Rules[1].Name != "拦截 注入" {
		t.Fatalf("pack = %+v", pack)
	}
	if !rulepackcontrol.IsSubscriptionPack(pack.PackID) || rulepackcontrol.IsSubscriptionPack("user/"+tenant.String()+"/mine") {
		t.Fatal("subscription pack naming")
	}
	if revision, ok := parseRevision("12.3.0"); !ok || revision != (Revision{Major: 12, Minor: 3}) {
		t.Fatalf("parse = %+v %v", revision, ok)
	}
	if _, ok := parseRevision("1.0.1"); ok {
		t.Fatal("patch version parsed")
	}
	if latestVersion([]string{"2.0.0", "10.0.0", "10.2.0", "9.9.0"}) != "10.2.0" {
		t.Fatal("latest version is not by number")
	}
}

// A rule an earlier stopping rule fully covers would never run on a node;
// a document that needs more regexes than a rule pack may hold is refused
// whole (the rule pack budget), not truncated.
func TestCompileRefusesShadowedRulesAndPackBudget(t *testing.T) {
	_, err := Compile([]byte(`{"version":"1","rules":[
	  {"id":"all","name":"放行全部 GET","enable":1,"action":"pass","matcher_groups":[{"matcher":[{"field":"method","op":"equal","value":"GET"}]}]},
	  {"id":"admin","name":"拦截 GET /admin","enable":1,"action":"protect","matcher_groups":[{"matcher":[{"field":"method","op":"equal","value":"GET"},{"field":"uri","op":"prefix","value":"/admin"}]}]}]}`))
	var failure *CompileError
	if !errors.As(err, &failure) || !strings.Contains(failure.Reason, "earlier stopping rule") {
		t.Fatalf("shadowed: %v", err)
	}
	var rules []string
	for index := 0; index < 65; index++ {
		rules = append(rules, fmt.Sprintf(`{"id":"r%d","name":"n%d","enable":1,"action":"protect","matcher_groups":[{"matcher":[{"field":"args","op":"regex","value":"a%db"}]}]}`, index, index, index))
	}
	if _, err := Compile([]byte(`{"version":"1","rules":[` + strings.Join(rules, ",") + `]}`)); !errors.Is(err, ErrInvalidDocument) ||
		!strings.Contains(err.Error(), "rule pack") {
		t.Fatalf("65 regexes: %v", err)
	}
	if _, err := Compile([]byte(`{"version":"1","rules":[` + strings.Join(rules[:64], ",") + `]}`)); err != nil {
		t.Fatalf("64 regexes: %v", err)
	}
}

func TestRedactURL(t *testing.T) {
	for raw, want := range map[string]string{
		"https://rules.example.com/feed.json":              "https://rules.example.com/feed.json",
		"https://rules.example.com/feed.json?token=s3cr3t": "https://rules.example.com/feed.json?…",
		"": "",
	} {
		if got := RedactURL(raw); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", raw, got, want)
		}
	}
	changes := inputChanges(&Input{Name: "a", SourceURL: "https://x.example/f?k=1", IntervalMinutes: 5},
		Input{Name: "b", SourceURL: "https://x.example/f?k=2", IntervalMinutes: 5})
	if fmt.Sprint(changes["name"]) != "map[from:a to:b]" || changes["interval_minutes"] != nil ||
		!strings.Contains(fmt.Sprint(changes["source_url"]), "query_changed:true") || strings.Contains(fmt.Sprint(changes), "k=") {
		t.Fatalf("changes = %v", changes)
	}
}

// Every enabled rule must compile exactly; one that cannot fails the whole
// document (the last good snapshot stays) instead of being dropped.
func TestCompileRejectsWhatTheNodeCannotEnforce(t *testing.T) {
	rule := func(action, config, matcher string) string {
		return `{"version":"1","rules":[{"id":"r1","name":"n","enable":1,"action":"` + action + `"` + config +
			`,"matcher_groups":[{"matcher":[` + matcher + `]}]}]}`
	}
	ok := `{"field":"args","op":"contain","value":"x"}`
	for name, document := range map[string]string{
		"status 404":         rule("protect", `,"action_config":{"status":"404"}`, ok),
		"redirect":           rule("protect", `,"action_config":{"status":"302","url":"https://x"}`, ok),
		"unknown action":     rule("captcha", "", ok),
		"province field":     rule("protect", "", `{"field":"province","op":"equal","value":"广东"}`),
		"not contain":        rule("protect", "", `{"field":"args","op":"not_contain","value":"x"}`),
		"length transform":   rule("protect", "", `{"field":"body","op":"contain","value":"1","transform":"length"}`),
		"keyed cookie":       rule("protect", "", `{"field":"cookie","key":"sid","op":"contain","value":"x"}`),
		"lower on equals":    rule("protect", "", `{"field":"uri","op":"equal","value":"/a","transform":"lower"}`),
		"bad regex":          rule("protect", "", `{"field":"args","op":"regex","value":"(?<=a)b"}`),
		"nine conditions":    rule("protect", "", strings.TrimSuffix(strings.Repeat(ok+",", 9), ",")),
		"header without key": rule("protect", "", `{"field":"header","op":"contain","value":"x"}`),
		"no groups":          `{"version":"1","rules":[{"id":"r1","name":"n","enable":1,"action":"protect","matcher_groups":[]}]}`,
		"no enabled rules":   `{"version":"1","rules":[{"id":"r1","name":"n","enable":0,"action":"protect","matcher_groups":[{"matcher":[` + ok + `]}]}]}`,
		"missing version":    `{"rules":[{"id":"r1","name":"n","enable":1,"action":"protect","matcher_groups":[{"matcher":[` + ok + `]}]}]}`,
		"duplicate rule id":  `{"version":"1","rules":[{"id":"r1","name":"n","enable":1,"action":"protect","matcher_groups":[{"matcher":[` + ok + `]}]},{"id":"r1","name":"m","enable":1,"action":"protect","matcher_groups":[{"matcher":[` + ok + `]}]}]}`,
		"enable string":      `{"version":"1","rules":[{"id":"r1","name":"n","enable":"yes","action":"protect","matcher_groups":[{"matcher":[` + ok + `]}]}]}`,
		"trailing data":      rule("protect", "", ok) + `{}`,
		"not json":           `<html>`,
	} {
		if _, err := Compile([]byte(document)); err == nil {
			t.Errorf("%s: compiled", name)
		}
	}
}

// Since ge-waf S1 the node runs up to edgeconfig.MaxWAFInspectPerRule (8)
// inspect clauses per rule, content conditions may repeat a field, and every
// clause must hold: a group of five conditions, or of two on one field,
// compiles to one rule of those inspect clauses. Node evidence:
// scripts/security/waf-multi-condition-smoke.sh (real OpenResty, v7
// renderer) and cdnca_rule_interp.lua (rule packs: AND over the conditions).
func TestCompileAcceptsWhatTheNodeEnforcesSinceS1(t *testing.T) {
	for name, matcher := range map[string]string{
		"duplicate field": `{"field":"args","op":"contain","value":"x"},{"field":"args","op":"regex","value":"y"}`,
		"five conditions": `{"field":"args","op":"contain","value":"1"},{"field":"query","op":"contain","value":"1"},{"field":"body","op":"contain","value":"1"},{"field":"cookie","op":"contain","value":"1"},{"field":"referer","op":"contain","value":"1"}`,
	} {
		feed, err := Compile([]byte(`{"version":"1","rules":[{"id":"r1","name":"n","enable":1,"action":"protect","matcher_groups":[{"matcher":[` +
			matcher + `]}]}]}`))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want := strings.Count(matcher, `"field"`)
		if len(feed.Rules) != 1 || feed.Rules[0].WAF == nil || len(feed.Rules[0].WAF.Match.Inspect) != want {
			t.Fatalf("%s: compiled %+v, want one rule of %d inspect clauses", name, feed.Rules, want)
		}
	}
}

func TestCompileErrorNamesTheRule(t *testing.T) {
	_, err := Compile([]byte(`{"version":"1","rules":[{"id":"nday-42","name":"n","enable":1,"action":"protect",
	  "matcher_groups":[{"matcher":[{"field":"asn","op":"equal","value":"1"}]}]}]}`))
	var failure *CompileError
	if !errors.As(err, &failure) || failure.RuleID != "nday-42" || !strings.Contains(err.Error(), "nday-42") {
		t.Fatalf("err = %v", err)
	}
}

func TestCompileLimits(t *testing.T) {
	group := `{"matcher":[{"field":"args","op":"contain","value":"x"}]}`
	var rules []string
	for index := 0; index < 101; index++ {
		rules = append(rules, fmt.Sprintf(`{"id":"r%d","name":"n%d","enable":1,"action":"protect","matcher_groups":[%s]}`, index, index, group))
	}
	_, err := Compile([]byte(`{"version":"1","rules":[` + strings.Join(rules, ",") + `]}`))
	if err == nil || !strings.Contains(err.Error(), "100") {
		t.Fatalf("101 compiled rules: %v", err)
	}
	if _, err := Compile([]byte(`{"version":"1","rules":[` + strings.Join(rules[:100], ",") + `]}`)); err != nil {
		t.Fatalf("100 compiled rules: %v", err)
	}
	if _, err := Compile(make([]byte, MaxDocumentBytes+1)); err == nil {
		t.Fatal("oversized document compiled")
	}
}

func TestCompileDigestIsStable(t *testing.T) {
	first, err := Compile([]byte(competitorSample))
	if err != nil {
		t.Fatal(err)
	}
	reformatted := strings.ReplaceAll(competitorSample, "\n", " ")
	second, err := Compile([]byte(reformatted))
	if err != nil || second.SHA256 != first.SHA256 {
		t.Fatalf("digest changed with formatting: %v", err)
	}
}
