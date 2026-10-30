package edgeconfig

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// retest-n4: the node's log phase (cdnca_managed_waf.lua record/decision)
// turns a managed WAF set decision into the $cdnca_security_* event by the
// rule IDs $modsecurity_rule_ids lists. Its DECISION table must name the
// IDs renderManagedSetEvaluation gives the block and log decisions.
func TestManagedWAFDecisionIDsMatchLua(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "edge", "openresty", "dynroute", "cdnca_managed_waf.lua"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	table := regexp.MustCompile(`local DECISION = \{([^}]*)\}`).FindStringSubmatch(source)
	if table == nil {
		t.Fatal("no DECISION table in cdnca_managed_waf.lua")
	}
	values := map[string]int{}
	for _, field := range regexp.MustCompile(`(\w+) = (\d+)`).FindAllStringSubmatch(table[1], -1) {
		values[field[1]], _ = strconv.Atoi(field[2])
	}
	want := map[string]int{"strong": dynamicWAFSetID, "combined": dynamicWAFSetID + 500, "sets": dynamicWAFMaxSetKeys,
		"crs_first": 900000, "crs_last": 949000}
	for key, value := range want {
		if values[key] != value {
			t.Errorf("DECISION.%s = %d, want %d", key, values[key], value)
		}
	}
	// the ranges stay below the adaptive rules and do not overlap
	if dynamicWAFSetID+dynamicWAFMaxSetKeys*2 > dynamicWAFSetID+500 || dynamicWAFSetID+500+dynamicWAFMaxSetKeys*3 > dynamicWAFAdaptID {
		t.Fatal("set decision ID ranges overlap")
	}

	// the rendered decisions: deny,status:403 at the block IDs, pass at the log IDs
	var output strings.Builder
	position := 3
	renderManagedSetEvaluation(&output, "waf_set:test", dynamicWAFSetID+position*2, dynamicWAFSetID+500+position*3)
	text := output.String()
	strong, combined := dynamicWAFSetID+position*2, dynamicWAFSetID+500+position*3
	for id, action := range map[int]string{strong: "deny,status:403,log", strong + 1: "pass,log",
		combined + 1: "deny,status:403,log", combined + 2: "pass,log", combined: "pass,nolog"} {
		if !strings.Contains(text, "id:"+strconv.Itoa(id)+",phase:2,"+action) {
			t.Errorf("rule %d is not %q:\n%s", id, action, text)
		}
	}

	// the module writes the event the telemetry logs, as the rule plan's WAF block does
	for _, line := range []string{`ngx_var.cdnca_security_emit = "1"`, `ngx_var.cdnca_security_type = "waf"`,
		`ngx_var.cdnca_security_action = verdict`, `ngx_var.cdnca_security_rule_id = rule_id`,
		`ngx_var.cdnca_security_severity = "high"`, `ngx_var.cdnca_security_block_page = "1"`,
		`ngx_var.cdnca_security_severity = "info"`, `local ids = ngx_var.modsecurity_rule_ids`} {
		if !strings.Contains(source, line) {
			t.Errorf("cdnca_managed_waf.lua lacks %s", line)
		}
	}
	// DynamicRoutingTelemetry declares the variables the module writes
	for _, name := range []string{"cdnca_security_emit", "cdnca_security_type", "cdnca_security_action",
		"cdnca_security_severity", "cdnca_security_rule_id", "cdnca_security_block_page"} {
		if !strings.Contains(strings.Join(DynamicRoutingTelemetryVariables, " "), name) {
			t.Errorf("telemetry does not declare %s", name)
		}
	}
}
