package edgeconfig

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The aggregated security line cdnca_telemetry.lua builds (sec-log-agg) has
// the plain dynamic routing security line's fields in its order, then
// "count", then the attribution object: the Agent reads it as that line.
func TestDynamicRoutingAggregateLineFields(t *testing.T) {
	raw, err := os.ReadFile("../../edge/openresty/dynroute/cdnca_telemetry.lua")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	begin := strings.Index(text, "local function aggregate_line(")
	end := strings.Index(text, "local function attribution_json(")
	if begin < 0 || end < begin {
		t.Fatal("aggregate_line missing")
	}
	var lua []string
	for _, match := range regexp.MustCompile(`[{,]\\?"([a-z_0-9]+)\\?":`).FindAllStringSubmatch(text[begin:end], -1) {
		lua = append(lua, match[1])
	}
	lua = append(lua, "count", DynamicRoutingAttribution)
	plain, _ := lineFields(t, strings.TrimSuffix(dynamicRoutingLine(telemetrySecurityJSON), dynamicRoutingAttributionJSON)+"}")
	want := append(slices.Clone(plain), "count", DynamicRoutingAttribution)
	if !slices.Equal(lua, want) {
		t.Fatalf("aggregate line fields\n got %v\nwant %v", lua, want)
	}
	if !strings.Contains(text, `_M.AGGREGATE_FLUSH_PATH = "`+DynamicRoutingSecurityFlushPath+`"`) {
		t.Fatal("flush path differs from DynamicRoutingSecurityFlushPath")
	}
	if !strings.Contains(text, `',"count":' .. string.format("%d", count) .. ',' .. attribution`) {
		t.Fatal("count must precede the attribution object")
	}
}

// CC marks a challenge page / 429 as aggregated with the declared variable;
// a temporary ban (emit) stays one line per request.
func TestCCAggregatesChallengeAnd429(t *testing.T) {
	raw, err := os.ReadFile("../../edge/openresty/ccv2/engine.lua")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !slices.Contains(DynamicRoutingTelemetryVariables, "cdnca_security_aggregate") ||
		!strings.Contains(text, `aggregate = "cdnca_security_aggregate"`) {
		t.Fatal("aggregate variable not declared")
	}
	for _, want := range []string{`aggregate(rule, "challenge", "medium")`, `if rule then aggregate(rule, "block", "high") end`,
		`return reject429(rule.action.kind ~= "temporary_ban" and rule or nil)`} {
		if !strings.Contains(text, want) {
			t.Fatalf("engine.lua lacks %q", want)
		}
	}
	if strings.Count(text, "return reject429(rule)") != 2 || strings.Contains(text, "return reject429()") {
		t.Fatal("every 429 of a rule must be aggregated except the ban's own request")
	}
}
