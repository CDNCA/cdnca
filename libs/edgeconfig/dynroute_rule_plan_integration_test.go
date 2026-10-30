//go:build integration

package edgeconfig

// The dynamic routing rule plan (edge/openresty/dynroute/cdnca_rule_plan.lua)
// must be CompileSecurityRulePlan in Lua: a site object carries the bound
// policies (edgesite.RulePlan) and the node derives the D6 plan from them at
// request time. Random rule sets (the D6 generator) are compiled both ways;
// the plans must be equal as JSON values. LuaJIT of the node image, one --rm
// container with --network none:
//
//	go -C libs/edgeconfig test -tags integration -run TestDynrouteRulePlanMatchesGo -count=1 .
//
//	CDNCA_DYNROUTE_PLAN_SEEDS   comma-separated seeds (default the D6 regression seeds)
//	CDNCA_DYNROUTE_PLAN_SETS    rule sets per seed (default 300)
//	CDNCA_DYNROUTE_PLAN_IMAGE   image with /usr/local/openresty/luajit (default cdnca-native-runtime:edge-golden)

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type dynroutePlanCase struct {
	// Rules is edgesite.RulePlan as JSON (header_overflow + policies); the
	// edgesite type lives in a sub-package, so its JSON form is written here.
	Rules struct {
		HeaderOverflow string           `json:"header_overflow"`
		Policies       []SecurityPolicy `json:"policies"`
	} `json:"rules"`
	Telemetry bool     `json:"telemetry"`
	SiteID    string   `json:"site_id"` // WAF v2 ban scope (edgesite.Site.SiteID)
	Plan      RulePlan `json:"plan"`
}

func TestDynrouteRulePlanMatchesGo(t *testing.T) {
	image := os.Getenv("CDNCA_DYNROUTE_PLAN_IMAGE")
	if image == "" {
		image = "cdnca-native-runtime:edge-golden"
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	if output, err := exec.Command("docker", "image", "inspect", image).CombinedOutput(); err != nil {
		t.Skipf("image %s: %v %s", image, err, output)
	}
	seeds := ruleDiffRegressionSeeds
	if raw := os.Getenv("CDNCA_DYNROUTE_PLAN_SEEDS"); raw != "" {
		seeds = nil
		for _, field := range strings.Split(raw, ",") {
			seed, err := strconv.ParseUint(strings.TrimSpace(field), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			seeds = append(seeds, seed)
		}
	}
	sets := ruleDiffEnvInt("CDNCA_DYNROUTE_PLAN_SETS", 300)
	var cases []dynroutePlanCase
	rules, headers, inspects, intel, lists, actions := 0, 0, 0, 0, 0, 0
	for _, seed := range seeds {
		generator := newFuzzGenerator(seed)
		for len(cases) < sets*len(seeds) {
			set := generator.ruleset(false)
			policies, plan, err := set.compile()
			if err != nil {
				continue
			}
			var value dynroutePlanCase
			value.Rules.HeaderOverflow = "no_match"
			if set.OverflowBlocks {
				value.Rules.HeaderOverflow = "block"
			}
			// The site object holds normalized policies (edgesite validates
			// NormalizeSecurityRule's form); the plan compiles from them.
			value.Rules.Policies = policies
			if value.Rules.Policies == nil {
				value.Rules.Policies = []SecurityPolicy{}
			}
			value.Telemetry, value.SiteID, value.Plan = set.Telemetry, fuzzSiteID, plan
			for _, policy := range policies {
				if SecurityPolicyUsesWAFActions(policy) {
					actions++
				}
				for _, rule := range policy.Rules {
					rules++
					if rule.Match.Header != nil {
						headers++
					}
					inspects += len(rule.Match.Inspect)
					intel += len(rule.Match.IPIntel)
					lists += len(rule.Match.IPLists)
				}
			}
			cases = append(cases, value)
			if len(cases)%sets == 0 {
				break
			}
		}
	}
	work := t.TempDir()
	encoded, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "cases.json"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	script := `
package.path = "/plan/?.lua;/usr/local/openresty/lualib/?.lua;" .. package.path
package.cpath = "/usr/local/openresty/lualib/?.so;" .. package.cpath
local cjson = require "cjson.safe"
cjson.encode_empty_table_as_object(false)
local plan = require "cdnca_rule_plan"
local cases = assert(cjson.decode(assert(io.open("/w/cases.json")):read("*a")))
local out = {}
for index, case in ipairs(cases) do
  local got, problem = plan.plan(case.rules, case.telemetry, case.site_id)
  out[index] = got or { error = problem }
end
io.open("/w/out.json", "w"):write(cjson.encode(out))
`
	if err := os.WriteFile(filepath.Join(work, "run.lua"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("chmod", "-R", "a+rwX", work).Run(); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("docker", "run", "--rm", "--network", "none",
		"-v", work+":/w", "-v", filepath.Join(repo, "edge/openresty/dynroute")+":/plan:ro",
		"--entrypoint", "/usr/local/openresty/luajit/bin/luajit", image, "/w/run.lua").CombinedOutput()
	if err != nil {
		t.Fatalf("luajit: %v\n%s", err, output)
	}
	raw, err := os.ReadFile(filepath.Join(work, "out.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got []any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(cases) {
		t.Fatalf("%d plans for %d cases", len(got), len(cases))
	}
	for index, value := range cases {
		wantJSON, _ := json.Marshal(value.Plan)
		var want any
		_ = json.Unmarshal(wantJSON, &want)
		if !reflect.DeepEqual(normalizePlanJSON(want), normalizePlanJSON(got[index])) {
			gotJSON, _ := json.Marshal(got[index])
			t.Fatalf("case %d differs\n go: %s\nlua: %s", index, wantJSON, gotJSON)
		}
	}
	if actions == 0 || lists == 0 {
		t.Fatal("no WAF v2 segment (action spec) or IP list condition generated")
	}
	t.Logf("%d rule sets, %d rules (%d header, %d inspect, %d ip_intel, %d ip_list conditions), %d WAF v2 segments: Lua plan = Go plan",
		len(cases), rules, headers, inspects, intel, lists, actions)
}

// normalizePlanJSON: cjson encodes an empty array as {} unless told
// otherwise and has no omitempty; empty lists and absent optional fields are
// the same plan.
func normalizePlanJSON(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := map[string]any{}
		for key, item := range typed {
			item = normalizePlanJSON(item)
			if list, ok := item.([]any); ok && len(list) == 0 {
				continue
			}
			if item == "" && (key == "layer" || key == "name" || key == "value") {
				continue
			}
			result[key] = item
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = normalizePlanJSON(item)
		}
		return result
	}
	return value
}
