package edgeconfig

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

const tuningTestAudit = "/var/log/cdnca/modsecurity-audit.log"

func tuningEntry(id, paranoia, rule int, targets ...CRSTuningTarget) CRSTuningEntry {
	return CRSTuningEntry{ID: id, CRSTuning: CRSTuning{MinParanoia: paranoia, Rule: rule, Targets: targets}}
}

// The official CRS tuning (ADR 0011 RI-13) in the node rules: without
// entries the file is unchanged byte for byte (the managed-waf golden);
// entries render literal ctl:ruleRemoveTargetById targets per paranoia
// section and block, before CRS, with unique rule IDs.
func TestDynamicWAFTuningRules(t *testing.T) {
	release := dynamicTestRelease(t)
	plain, err := RenderDynamicWAFRules(release, tuningTestAudit)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := RenderDynamicWAFRulesTuned(release, tuningTestAudit, nil)
	if err != nil || !bytes.Equal(plain, empty) || strings.Contains(string(plain), "cdnca_tuning_off \"") {
		t.Fatalf("no tuning changes the node rules (%v)", err)
	}
	entries := []CRSTuningEntry{
		tuningEntry(1, 1, 942100, CRSTuningTarget{"args", "q"}, CRSTuningTarget{"cookie", "sid"}),
		tuningEntry(2, 2, 941100, CRSTuningTarget{"args", "json.body"}),
		tuningEntry(7, 1, 942430, CRSTuningTarget{"header", "X-Token"}),
	}
	rules, err := RenderDynamicWAFRulesTuned(release, tuningTestAudit, entries)
	if err != nil {
		t.Fatal(err)
	}
	text := string(rules)
	for _, want := range []string{
		`SecRule TX:cdnca_tuning_off "@contains ,0," "id:60000,phase:1,pass,nolog,t:none,skipAfter:CDNCA-TU-END"`,
		`SecRule TX:blocking_paranoia_level "@lt 1" "id:60001,phase:1,pass,nolog,t:none,skipAfter:CDNCA-TU-END"`,
		`SecRule TX:cdnca_tuning_off "!@pm ,1, ,7," "id:60002,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942100;ARGS:q,` +
			`ctl:ruleRemoveTargetById=942100;REQUEST_COOKIES:sid,ctl:ruleRemoveTargetById=942430;REQUEST_HEADERS:X-Token,skipAfter:CDNCA-TU-1"`,
		`SecRule TX:cdnca_tuning_off "!@contains ,1," "id:60003,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942100;ARGS:q,` +
			`ctl:ruleRemoveTargetById=942100;REQUEST_COOKIES:sid"`,
		`SecRule TX:cdnca_tuning_off "!@contains ,7," "id:60004,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942430;REQUEST_HEADERS:X-Token"`,
		"SecMarker \"CDNCA-TU-1\"\nSecRule TX:blocking_paranoia_level \"@lt 2\" \"id:60005,",
		`ctl:ruleRemoveTargetById=941100;ARGS:json.body,skipAfter:CDNCA-TU-2"`,
		"SecMarker \"CDNCA-TU-2\"\nSecMarker \"CDNCA-TU-END\"\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("node rules lack %q", want)
		}
	}
	// before CRS (phase 1, the targets are removed before any CRS rule runs)
	if strings.Index(text, "CDNCA-TU-END") > strings.Index(text, "Include ") {
		t.Fatal("tuning after CRS")
	}
	// no wildcard / regex target ever reaches a ctl
	for _, line := range regexp.MustCompile(`ruleRemoveTargetById=[^,"]*`).FindAllString(text, -1) {
		if strings.ContainsAny(line, "/*|!") {
			t.Fatalf("non-literal target %s", line)
		}
	}
	ids := map[string]bool{}
	for _, match := range regexp.MustCompile(`id:([0-9]+)`).FindAllStringSubmatch(text, -1) {
		if ids[match[1]] {
			t.Fatalf("rule id %s twice", match[1])
		}
		ids[match[1]] = true
	}
	// deterministic
	again, _ := RenderDynamicWAFRulesTuned(release, tuningTestAudit, entries)
	if !bytes.Equal(rules, again) {
		t.Fatal("not deterministic")
	}
}

func TestDynamicWAFTuningRefusesInvalidEntries(t *testing.T) {
	release := dynamicTestRelease(t)
	valid := tuningEntry(1, 1, 942100, CRSTuningTarget{"args", "q"})
	for name, entries := range map[string][]CRSTuningEntry{
		"entry 0":       {tuningEntry(0, 1, 942100, CRSTuningTarget{"args", "q"})},
		"unsorted":      {tuningEntry(2, 1, 942100, CRSTuningTarget{"args", "q"}), valid},
		"repeated":      {valid, valid},
		"paranoia 5":    {tuningEntry(1, 5, 942100, CRSTuningTarget{"args", "q"})},
		"not CRS rule":  {tuningEntry(1, 1, 12345, CRSTuningTarget{"args", "q"})},
		"no target":     {tuningEntry(1, 1, 942100)},
		"wildcard name": {tuningEntry(1, 1, 942100, CRSTuningTarget{"args", "*"})},
		"regex name":    {tuningEntry(1, 1, 942100, CRSTuningTarget{"args", "/^q/"})},
		"quote name":    {tuningEntry(1, 1, 942100, CRSTuningTarget{"args", `q"`})},
		"location":      {tuningEntry(1, 1, 942100, CRSTuningTarget{"body", "q"})},
		"targets order": {tuningEntry(1, 1, 942100, CRSTuningTarget{"cookie", "a"}, CRSTuningTarget{"args", "b"})},
	} {
		if _, err := RenderDynamicWAFRulesTuned(release, tuningTestAudit, entries); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	targets := make([]CRSTuningTarget, DynamicWAFMaxTuningTargets+1)
	for index := range targets {
		targets[index] = CRSTuningTarget{"args", fmt.Sprintf("p%02d", index)}
	}
	if _, err := RenderDynamicWAFRulesTuned(release, tuningTestAudit, []CRSTuningEntry{tuningEntry(1, 1, 942100, targets...)}); err == nil {
		t.Fatal("too many targets accepted")
	}
}

// Blocks hold at most dynamicWAFTuningBatch targets: many entries make many
// blocks, every entry still has its own hook.
func TestDynamicWAFTuningBlocks(t *testing.T) {
	release := dynamicTestRelease(t)
	var entries []CRSTuningEntry
	for index := 1; index <= 200; index++ {
		entries = append(entries, tuningEntry(index, 1+index%2, 942100, CRSTuningTarget{"args", fmt.Sprintf("p%d", index)}))
	}
	rules, err := RenderDynamicWAFRulesTuned(release, tuningTestAudit, entries)
	if err != nil {
		t.Fatal(err)
	}
	text := string(rules)
	if got := strings.Count(text, `"!@pm `); got != 4 { // 100 + 100 entries, 64 per block
		t.Fatalf("%d blocks", got)
	}
	if got := strings.Count(text, `SecRule TX:cdnca_tuning_off "!@contains ,`); got != 200 {
		t.Fatalf("%d entry hooks", got)
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.Contains(line, `"!@pm `) && strings.Count(line, "ctl:ruleRemoveTargetById") > dynamicWAFTuningBatch {
			t.Fatalf("block over %d targets", dynamicWAFTuningBatch)
		}
	}
}

// u=,0, (no tuning pack on the site) parses, only alone.
func TestDynamicWAFContextTuningAllOff(t *testing.T) {
	context := testDynamicWAFContext()
	context.TuningOff = []int{DynamicWAFTuningAllOff}
	text := context.String()
	if !strings.Contains(text, ";u=,0,;") {
		t.Fatalf("context %s", text)
	}
	parsed, ok := ParseDynamicWAFContext(text)
	if !ok || len(parsed.TuningOff) != 1 || parsed.TuningOff[0] != 0 {
		t.Fatalf("parse %v %+v", ok, parsed)
	}
	for _, rule := range nodeContextRules() {
		if !rule.MatchString(text) {
			t.Fatalf("node pattern %s refuses %s", rule, text)
		}
	}
	if _, ok := ParseDynamicWAFContext(strings.Replace(text, ";u=,0,;", ";u=,0,3,;", 1)); ok {
		t.Fatal("0 with other entries accepted")
	}
}
