package main

import (
	"fmt"
	"math/rand"

	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
)

// Two tenants on one node (waf-share, -only tenants): 73 adm-fix-a2 found
// tenant B refused 349 times on node 667d0b7b because tenant A's site there
// ran the managed WAF ("one rule set per node", a rule of the deleted
// siteruntimev2). On dynamic routing every scope's sites are one site index
// and one managed WAF; this runs that on the real engine: each tenant's site
// in its own configuration scope and tenant, in different tiers (CRS
// profile pack, request body limit) with different exclusions, normal and
// attack requests interleaved.
//
//	a  (tenant A): 默认防护 PL1, 1 MiB, excludes 942100 (the SQLi probe's rule)
//	b1 (tenant B): 默认防护 PL1, 64 KiB (another tier), excludes the XSS probe's rules
//	b2 (tenant B): 严格防护 PL2, nothing excluded
//
// (PL2 has XSS rules beyond the probe's four, so an XSS exclusion shows on
// a PL1 tier only, as in functional.)
func tenantsRun() {
	all := profiles()
	pl1, pl2 := profileNamed(all, "system/crs-pl1"), profileNamed(all, "system/crs-pl2")
	xssRules := []int{941100, 941110, 941160, 941390}
	a := makeSite(41, "a.tenant.test", &wafSpec{profile: pl1, exclusions: []int{942100}})
	b1 := makeSite(42, "b1.tenant.test", &wafSpec{profile: pl1, body: 64 << 10, exclusions: xssRules})
	b2 := makeSite(43, "b2.tenant.test", &wafSpec{profile: pl2})
	a.ConfigurationScopeID, a.TenantID = "0d110000-0000-4000-8000-0000000000a1", "0d110000-0000-4000-8000-0000000000a2"
	for _, site := range []*edgesite.Site{&b1, &b2} {
		site.ConfigurationScopeID, site.TenantID = "0d110000-0000-4000-8000-0000000000b1", "0d110000-0000-4000-8000-0000000000b2"
	}
	sites := []edgesite.Site{a, b1, b2}
	n, err := startNode(sites, true)
	if err != nil {
		check("tenants start", false, "%v", err)
		return
	}
	defer stop()
	check("tenants tiers", len(n.waf.Skeleton.Tiers) == 3, "tiers=%d (A PL1 1M, B PL1 64K, B PL2 1M)", len(n.waf.Skeleton.Tiers))
	type want struct {
		host, path string
		status     int
	}
	cases := []want{
		{"a.tenant.test", "/hello?q=world", 200}, {"b1.tenant.test", "/hello?q=world", 200}, {"b2.tenant.test", "/hello?q=world", 200},
		{"a.tenant.test", sqli, 200}, {"b1.tenant.test", sqli, 403}, {"b2.tenant.test", sqli, 403}, // A's exclusion is A's only
		{"a.tenant.test", xss, 403}, {"b1.tenant.test", xss, 200}, {"b2.tenant.test", xss, 403}, // B's exclusions are b1's only
		{"a.tenant.test", pl2Probe, 200}, {"b1.tenant.test", pl2Probe, 200}, {"b2.tenant.test", pl2Probe, 403}, // PL2 rules: b2 only
	}
	mismatches := []string{}
	for round := range 6 {
		for _, index := range rand.New(rand.NewSource(int64(40 + round))).Perm(len(cases)) {
			c := cases[index]
			if got := get(c.host, c.path); got != c.status {
				mismatches = append(mismatches, fmt.Sprintf("r%d %s %s=%d want %d", round, c.host, c.path, got, c.status))
			}
		}
	}
	check("tenants isolation", len(mismatches) == 0, "%d requests over 2 tenants (3 sites) x 6 rounds in random order; mismatches %v",
		6*len(cases), mismatches)
	// A changes its exclusions (a new site object, no reload): B is untouched
	before := pids()
	a.Revision++
	a.Security.ManagedWAF.Exclusions = xssRules
	if err := n.activate([]edgesite.Site{a, b1, b2}); err != nil {
		check("tenants live-change", false, "activate: %v", err)
		return
	}
	aSQLi, aXSS := get("a.tenant.test", sqli), get("a.tenant.test", xss)
	b1SQLi, b1XSS, b2XSS := get("b1.tenant.test", sqli), get("b1.tenant.test", xss), get("b2.tenant.test", xss)
	check("tenants live-change", aSQLi == 403 && aXSS == 200 && b1SQLi == 403 && b1XSS == 200 && b2XSS == 403 && pids() == before,
		"A now excludes the XSS rules: sqli %d xss %d; B unchanged: b1 sqli %d xss %d, b2 xss %d; nginx pids same: %v",
		aSQLi, aXSS, b1SQLi, b1XSS, b2XSS, pids() == before)
	if lines := errorLines(); len(lines) != 0 {
		check("tenants error-log", false, "%d crit/alert/emerg lines: %v", len(lines), lines[:min(3, len(lines))])
	} else {
		check("tenants error-log", true, "no crit/alert/emerg")
	}
}
