package main

// -only tuning: the official CRS tuning pack (ADR 0011 RI-13,
// system/crs-tuning) on a real node. The entries go through the pack
// compiler (rulepack.TuningEntries) and the node rules
// (RenderDynamicWAFRulesTuned); an entry removes exactly its target:
//   - 942100 on ARGS:q (PL1): the SQLi probe on q passes, on id / Q (case)
//     / q in a cookie still blocks, 942100 still runs for other values;
//   - from paranoia 2, 942100 on ARGS:note: not on 标准防护 (PL1); on
//     严格防护 (PL2) the SQLi probe fires PL2 rules besides 942100, so the
//     sections are checked with the grey zone value (941380 alone, PL2):
//     941380 on ARGS:note (min 2) and ARGS:g1 (min 1) pass for a browser,
//     ARGS:p3 (min 3) and another parameter are still challenged;
//   - REQUEST_COOKIES / REQUEST_HEADERS targets.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/rulepack"
)

func tuningPack() (*rulepack.CompiledPack, error) {
	entry := func(id string, paranoia, rule int, targets ...map[string]string) map[string]any {
		return map[string]any{"id": id, "name": "排除 " + id, "tuning": map[string]any{"min_paranoia": paranoia, "rule": rule, "targets": targets}}
	}
	document := map[string]any{"schema": rulepack.Schema, "pack_id": rulepack.CRSTuningPackID, "version": "1.0.0", "layer": "system",
		"engine": "modsecurity", "engine_min_version": 1, "name": "CRS 官方调优", "description": "", "params_schema": map[string]any{},
		"exports": []string{"1", "2", "3", "4", "5", "6"}, "defaults": map[string]any{},
		"rules": []any{
			entry("1", 1, 942100, map[string]string{"loc": "args", "name": "q"}),
			entry("2", 2, 942100, map[string]string{"loc": "args", "name": "note"}),
			entry("3", 3, 941380, map[string]string{"loc": "args", "name": "p3"}),
			entry("4", 1, 942100, map[string]string{"loc": "cookie", "name": "pref"}, map[string]string{"loc": "header", "name": "X-Query"}),
			entry("5", 2, 941380, map[string]string{"loc": "args", "name": "note"}),
			entry("6", 1, 941380, map[string]string{"loc": "args", "name": "g1"}),
		}}
	encoded, _ := json.Marshal(document)
	return rulepack.Compile(encoded)
}

// mountTuning mounts the tuning pack on a site as the control plane
// publishes it (every entry in force: no params.exclusions) and writes the
// mount's rule plan under root as the agent does (a modsecurity pack adds
// no rule plan segment: the plan is empty). Without the mount the node
// turns the whole pack off for the site (u=,0,).
func mountTuning(site edgesite.Site, pack *rulepack.CompiledPack, root string) (edgesite.Site, error) {
	resolution := rulepack.Resolve([]rulepack.MountRequest{{Pack: pack, Priority: rulepack.DefaultPriority}}, rulepack.Target{})
	if resolution.Security == nil {
		return site, fmt.Errorf("tuning mount conflicts %v", resolution.Conflicts)
	}
	encoded, _ := json.Marshal(resolution.Security)
	var security edgesite.Security
	if err := json.Unmarshal(encoded, &security); err != nil {
		return site, err
	}
	plan, err := rulepack.MountRulePlan(resolution.Rules, func(string) string { return pack.SHA256 }, false)
	if err != nil {
		return site, err
	}
	planJSON, err := edgeconfig.EncodeRulePlan(plan)
	if err != nil {
		return site, err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return site, err
	}
	if err := os.WriteFile(filepath.Join(root, security.ResolvedSHA256+".json"), planJSON, 0o644); err != nil {
		return site, err
	}
	site.Security.Mounts, site.Security.ResolvedSHA256 = security.Mounts, security.ResolvedSHA256
	return site, nil
}

func tuningRun() {
	pack, err := tuningPack()
	var entries []edgeconfig.CRSTuningEntry
	if err == nil {
		entries, err = rulepack.TuningEntries(pack)
	}
	if err != nil {
		check("tuning pack", false, "%v", err)
		return
	}
	all := profiles()
	pl1, pl2 := profileNamed(all, "system/crs-pl1"), profileNamed(all, "system/crs-pl2")
	rulePlanRoot = filepath.Join(filepath.Dir(*state), "tuning-plans")
	defer func() { nodeTuning, rulePlanRoot = nil, "" }()
	sites := []edgesite.Site{}
	for _, s := range []edgesite.Site{
		makeSite(70, "t1.waf.test", &wafSpec{profile: pl1}),
		makeSite(71, "t2.waf.test", &wafSpec{profile: pl2}),
	} {
		mounted, err := mountTuning(s, pack, rulePlanRoot)
		if err != nil {
			check("tuning mount", false, "%v", err)
			return
		}
		sites = append(sites, mounted)
	}
	nodeTuning = entries
	if _, err := startNode(sites, true); err != nil {
		check("tuning start", false, "%v", err)
		return
	}
	defer stop()
	// the PL2 site challenges its grey zone (waf_adapt, as the agent writes it)
	status, text := controlPost("/waf-adapt/", map[string]any{"sites": []any{map[string]any{"site_id": siteID(71),
		"grey_challenge": true, "typed_params": []any{}, "targets": []any{}}}})
	check("tuning waf-adapt", status == 204, "POST /waf-adapt/ %d %s", status, text)
	payload, grey := url.QueryEscape("1' OR '1'='1"), url.QueryEscape(greyValue)
	browser := map[string]string{"Accept": "text/html"}
	probe := func(host, path string, headers map[string]string) int {
		return send(http.MethodGet, host, path, "", headers).status
	}
	type want struct {
		name, host, path string
		headers          map[string]string
		status           int
	}
	cases := []want{
		{"clean", "t1.waf.test", "/t?q=hello", nil, 200},
		{"target q excluded", "t1.waf.test", "/t?q=" + payload, nil, 200},
		{"other parameter id", "t1.waf.test", "/t?id=" + payload, nil, 403},
		{"case Q is another name", "t1.waf.test", "/t?Q=" + payload, nil, 403},
		{"q excluded, id still inspected", "t1.waf.test", "/t?q=" + payload + "&id=" + payload, nil, 403},
		{"cookie pref excluded", "t1.waf.test", "/t", map[string]string{"Cookie": "pref=" + payload}, 200},
		{"cookie other", "t1.waf.test", "/t", map[string]string{"Cookie": "other=" + payload}, 403},
		{"header X-Query excluded", "t1.waf.test", "/t", map[string]string{"X-Query": "1' OR '1'='1"}, 200},
		{"q cookie is not ARGS:q", "t1.waf.test", "/t", map[string]string{"Cookie": "q=" + payload}, 403},
		{"PL1 min paranoia 2 not applied", "t1.waf.test", "/t?note=" + payload, nil, 403},
		{"PL2 grey other parameter challenged", "t2.waf.test", "/t?other=" + grey, browser, 503},
		{"PL2 min paranoia 2 applied", "t2.waf.test", "/t?note=" + grey, browser, 200},
		{"PL2 min paranoia 1 applied", "t2.waf.test", "/t?g1=" + grey, browser, 200},
		{"PL2 min paranoia 3 not applied", "t2.waf.test", "/t?p3=" + grey, browser, 503},
		{"PL2 SQLi other parameter", "t2.waf.test", "/t?id=" + payload, nil, 403},
	}
	for _, c := range cases {
		got := probe(c.host, c.path, c.headers)
		check("tuning "+c.name, got == c.status, "%s %s = %d, want %d", c.host, c.path, got, c.status)
	}
	// a form body parameter is ARGS too
	form := send(http.MethodPost, "t1.waf.test", "/t", "q="+payload, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	check("tuning form body q", form.status == 200, "POST q= %d", form.status)
	formOther := send(http.MethodPost, "t1.waf.test", "/t", "id="+payload, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	check("tuning form body id", formOther.status == 403, "POST id= %d", formOther.status)
	for _, line := range errorLines() {
		check("tuning error log", false, "%s", line)
	}
}
