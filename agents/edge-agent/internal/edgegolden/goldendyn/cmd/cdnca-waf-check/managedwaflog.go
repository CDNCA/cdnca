package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cdnca/cdnca/agents/edge-agent/internal/edgegolden/goldendyn"
	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
)

// nodeTelemetry renders the node-level access/security logs (D12) into the
// skeleton (-only managedwaflog).
var nodeTelemetry bool

// managedWAFLogRun (-only managedwaflog, retest-n4): a managed WAF (CRS)
// denial is a security log line as a rule plan WAF block is: type waf,
// action block, the CRS rule that matched as rule_id, the site, path and
// redacted query (managed-waf-block-logged). A log-only site's hit is
// action log; a clean request writes nothing.
//   b.waf.test: PL1 block     d.waf.test: PL1 observe-only (log)
func managedWAFLogRun() {
	all := profiles()
	pl1, observe := profileNamed(all, "system/crs-pl1"), profileNamed(all, "system/crs-pl1-log")
	telemetry := func(site edgesite.Site) edgesite.Site {
		site.Telemetry = &edgesite.Telemetry{Capture: siteobject.TelemetryCapture{Methods: []string{}, URIPrefixes: []string{},
			RequestHeaderAllowlist: []string{}, ResponseHeaderAllowlist: []string{}, RequestBodyFieldAllowlist: []string{},
			ResponseBodyFieldAllowlist: []string{}}}
		return site
	}
	sites := []edgesite.Site{telemetry(makeSite(2, "b.waf.test", &wafSpec{profile: pl1})),
		telemetry(makeSite(4, "d.waf.test", &wafSpec{profile: observe}))}
	nodeTelemetry = true
	defer func() { nodeTelemetry = false }()
	n, err := startNode(sites, true)
	if err != nil {
		check("managed-waf-block-logged start", false, "%v", err)
		return
	}
	defer stop()
	if err := n.activate(sites); err != nil {
		check("managed-waf-block-logged activate", false, "%v", err)
		return
	}
	_, path := edgeconfig.DynamicRoutingTelemetryPaths(filepath.Join(*state, goldendyn.SharedDirectory))
	lines := func(before int64) []map[string]any {
		time.Sleep(300 * time.Millisecond)
		raw, _ := os.ReadFile(path)
		if int64(len(raw)) < before {
			return nil
		}
		var result []map[string]any
		for _, line := range strings.Split(string(raw[before:]), "\n") {
			var record map[string]any
			if json.Unmarshal([]byte(line), &record) == nil {
				result = append(result, record)
			}
		}
		return result
	}
	// one line of host with the expected action; its rule_id must be a CRS rule
	logged := func(host, probe, action, rulePrefix string) (int, map[string]any) {
		before := fileSize(path)
		status := get(host, probe+"&token=secret1")
		for _, record := range lines(before) {
			if record["host"] == host && record["action"] == action {
				if id, _ := record["rule_id"].(string); strings.HasPrefix(id, rulePrefix) {
					return status, record
				}
			}
		}
		return status, nil
	}
	for _, probe := range []struct{ name, path, rule string }{{"sqli", sqli, "942"}, {"xss", xss, "941"}} {
		status, record := logged("b.waf.test", probe.path, "block", probe.rule)
		ok := status == 403 && record != nil && record["security_type"] == "waf" && record["severity"] == "high" &&
			record["site_id"] == siteID(2) && strings.HasPrefix(record["path"].(string), "/q?") &&
			strings.Contains(record["path"].(string), "token=***") && !strings.Contains(record["path"].(string), "secret1")
		check("managed-waf-block-logged "+probe.name, ok, "status %d, security line %v", status, record)
	}
	status, record := logged("d.waf.test", sqli, "log", "942")
	check("managed-waf-block-logged observe", status == 200 && record != nil && record["severity"] == "info",
		"observe-only status %d, security line %v", status, record)
	before := fileSize(path)
	clean := get("b.waf.test", "/hello?q=world")
	extra := 0
	for _, record := range lines(before) {
		if record["host"] == "b.waf.test" {
			extra++
		}
	}
	check("managed-waf-block-logged clean", clean == 200 && extra == 0, "clean status %d, %d security lines", clean, extra)
}
