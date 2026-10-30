package securitypublication

// Rule enforcement release (tests/dynroute-cc): with CDNCA_RULE_AUDIT_OUT set,
// every CC rule group of the signed system catalog, the WAF engine
// combinations (self-developed / OWASP CRS / both, block and log only) and
// the benchmark sites go through the real compile chain
// (securitypolicy.CompileRuntimeSnapshot -> CompileSiteSecurityBindings) into
// one signed site runtime v2 release under <out>/signed-release. The test
// script converts it with the control plane's own site object conversion
// (cmd/cdnca-site-objects-v2) and serves the site objects on a real
// OpenResty dynamic routing node (agents/edge-agent .../cmd/cdnca-cc-check).

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func TestRuleEnforcementAuditRelease(t *testing.T) {
	output := os.Getenv("CDNCA_RULE_AUDIT_OUT")
	if output == "" {
		t.Skip("CDNCA_RULE_AUDIT_OUT not set (tests/dynroute-cc/run.sh sets it)")
	}
	sites := auditReleaseSites(t, auditCatalog(), catalogAuditBuilder{})
	writeAuditRelease(t, output, sites)
}

type auditReleaseSite struct {
	Domain    string `json:"domain"`
	Requested string `json:"requested"`
	Published string `json:"published"`
	Error     string `json:"error,omitempty"`
}

var auditReleaseLog []auditReleaseSite

func auditReleaseSites(t *testing.T, catalog map[string]rulecatalog.Item, builder auditPolicyBuilder) []edgeconfig.Site {
	t.Helper()
	type plan struct {
		domain, requested string
		policy            func() (securitypolicy.Policy, error)
	}
	waf := func(action string) func() (securitypolicy.Policy, error) {
		return func() (securitypolicy.Policy, error) {
			policy, err := builder.wafPolicy(catalog, []string{"waf_set:crs_sqli", "waf_set:crs_xss"}, action)
			policy.Rules = append([]securitypolicy.Rule{adminPathRule(1)}, policy.Rules...)
			for index := range policy.Rules {
				policy.Rules[index].Priority = index + 1
			}
			return policy, err
		}
	}
	cc := func(key string) func() (securitypolicy.Policy, error) {
		return func() (securitypolicy.Policy, error) { return builder.ccPolicy(catalog, key) }
	}
	plans := []plan{
		{"cc.audit.example.test", "CC 规则组 cc_rule:10001 5秒盾", cc("cc_rule:10001")},
		{"rate.audit.example.test", "CC 规则组 cc_rule:6 宽松", cc("cc_rule:6")},
		{"uri.audit.example.test", "CC 规则组 cc_rule:6 宽松", cc("cc_rule:6")},
		{"waf.audit.example.test", "WAF /admin + CRS SQL注入 + CRS XSS (block)", waf(securitypolicy.ActionBlock)},
		{"log.audit.example.test", "WAF /admin + CRS SQL注入 + CRS XSS (log)", waf(securitypolicy.ActionLog)},
		{"wafall.audit.example.test", "WAF 全部 10 个 OWASP CRS 规则集 (block)", func() (securitypolicy.Policy, error) {
			policy, err := builder.wafPolicy(catalog, auditWAFKeys(catalog, true), securitypolicy.ActionBlock)
			// A rich-text site posts HTML by design: tags trip 941160
			// (NoScript HTML injection) and Chinese UTF-8 text plus tags
			// trips 941310 (US-ASCII malformed encoding). The site excludes
			// only those two (site-wide, PA-12); script / event-handler rules
			// (941100, 941110, ...) still apply.
			if err == nil {
				managedWAF(policy).Exclusions = []int{941160, 941310}
			}
			return policy, err
		}},
	}
	// One site per verification rule group: g<legacy id>.audit.example.test.
	for _, key := range []string{"cc_rule:1", "cc_rule:10000", "cc_rule:10003", "cc_rule:10004", "cc_rule:10005", "cc_rule:2", "cc_rule:4"} {
		plans = append(plans, plan{"g" + catalog[key].LegacyID + ".audit.example.test", "CC 规则组 " + key + " " + catalog[key].Name, cc(key)})
	}
	// The same rule groups with changed catalog values: behaviour must follow.
	plans = append(plans, plan{"params.audit.example.test", "5秒盾（目录参数改为 PoW 20 位/等待 2 秒/失败 2 次/拉黑 30 秒/绑定 /32）",
		func() (securitypolicy.Policy, error) {
			modified := make(map[string]rulecatalog.Item, len(catalog))
			for key, item := range catalog {
				modified[key] = item
			}
			filter := modified["cc_filter:10001"]
			body := *filter.Body.CCFilter
			params := *body.Params
			params.PowBits, params.DelaySeconds, params.BanSeconds, params.BindIPv4Prefix = 20, 2, 30, 32
			body.Params, body.MaxReq = &params, 2
			filter.Body = rulecatalog.ItemBody{CCFilter: &body}
			modified["cc_filter:10001"] = filter
			return builder.ccPolicy(modified, "cc_rule:10001")
		}})
	// sec-log-agg: 5秒盾 that never bans in the check (1000 failures), so
	// one client's challenge pages are only aggregated.
	plans = append(plans, plan{"agg.audit.example.test", "5秒盾（失败 1000 次才拉黑：挑战页按分钟聚合日志）",
		func() (securitypolicy.Policy, error) {
			modified := make(map[string]rulecatalog.Item, len(catalog))
			for key, item := range catalog {
				modified[key] = item
			}
			filter := modified["cc_filter:10001"]
			body := *filter.Body.CCFilter
			body.MaxReq = 1000
			filter.Body = rulecatalog.ItemBody{CCFilter: &body}
			modified["cc_filter:10001"] = filter
			return builder.ccPolicy(modified, "cc_rule:10001")
		}})
	plans = append(plans, plan{"wafpl2.audit.example.test", "WAF CRS 增强档位（PL2）",
		func() (securitypolicy.Policy, error) {
			policy, err := builder.wafPolicy(catalog, []string{"waf_set:crs_sqli"}, "")
			if err == nil {
				managedWAF(policy).Profile = "system/crs-pl2"
			}
			return policy, err
		}})
	// Benchmark: all 10 CRS sets at PL2 and PL3 (the retired bench's rows).
	for _, level := range []string{"pl2", "pl3"} {
		plans = append(plans, plan{"wafall" + level + ".audit.example.test", "WAF 全部 10 个 OWASP CRS 规则集 " + level + "（性能对比）",
			func() (securitypolicy.Policy, error) {
				policy, err := builder.wafPolicy(catalog, auditWAFKeys(catalog, true), securitypolicy.ActionBlock)
				if err == nil {
					managedWAF(policy).Profile = "system/crs-" + level
				}
				return policy, err
			}})
	}
	both := []string{"waf_set:sqli", "waf_set:xss", "waf_set:crs_sqli", "waf_set:crs_xss"}
	plans = append(plans,
		plan{"self.audit.example.test", "WAF 自研检测 SQL注入 + XSS (block)", func() (securitypolicy.Policy, error) {
			return builder.wafPolicy(catalog, []string{"waf_set:sqli", "waf_set:xss"}, securitypolicy.ActionBlock)
		}},
		plan{"selfall.audit.example.test", "WAF 全部 10 个自研检测规则集 (block)", func() (securitypolicy.Policy, error) {
			return builder.wafPolicy(catalog, auditWAFKeys(catalog, false), securitypolicy.ActionBlock)
		}},
		plan{"dual.audit.example.test", "WAF 自研检测 + OWASP CRS（SQL注入、XSS，block）", func() (securitypolicy.Policy, error) {
			return builder.wafPolicy(catalog, both, securitypolicy.ActionBlock)
		}},
		plan{"duallog.audit.example.test", "WAF 自研检测 + OWASP CRS（SQL注入、XSS，仅记录）", func() (securitypolicy.Policy, error) {
			return builder.wafPolicy(catalog, both, securitypolicy.ActionLog)
		}})
	plans = append(plans, plan{"plain.audit.example.test", "无安全策略（性能基线）", nil})
	sites := make([]edgeconfig.Site, 0, len(plans))
	auditReleaseLog = nil
	for index, item := range plans {
		siteID := uuid.MustParse(fmt.Sprintf("018f1000-0000-7000-8000-0000000000%02x", 0xa1+index))
		site := auditSite(siteID, item.domain)
		record := auditReleaseSite{Domain: item.domain, Requested: item.requested, Published: item.requested}
		policies := []securitypolicy.Policy{}
		if item.policy != nil {
			policy, err := item.policy()
			if err != nil {
				t.Fatalf("policy %s: %v", item.domain, err)
			}
			policies = append(policies, policy)
		}
		// Every catalog item compiles since catalog expansion (the audit
		// test above records it); a refusal here is a regression.
		compiled, err := auditCompile(site, siteID, policies...)
		if err != nil {
			t.Fatalf("compile %s: %v", item.domain, err)
		}
		auditReleaseLog = append(auditReleaseLog, record)
		sites = append(sites, compiled.Site)
	}
	return sites
}

// writeAuditRelease writes the signed site runtime v2 release of sites (each
// one plain listener on 8080 carrying its compiled security) under
// output/signed-release, as the publication builds it: the document, the
// signed telemetry identity and the CRS rule text and profile packs its
// managed WAF loads; output/audit.json lists the sites.
func writeAuditRelease(t *testing.T, output string, sites []edgeconfig.Site) {
	t.Helper()
	rules, err := securitypolicy.EdgeCRSRuleText(*rulecatalog.CRSRulesBundle())
	if err != nil {
		t.Fatal(err)
	}
	profiles := auditCRSProfiles()
	const versionID = "0a1b0000-0000-4000-8000-0000000000c1"
	scopeID := testTenantScopeID.String()
	var listeners []edgeconfig.SecurityListener
	documentSites := make([]map[string]any, 0, len(sites))
	sorted := append([]edgeconfig.Site(nil), sites...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left].ID < sorted[right].ID })
	required := map[string]uint32{"http1": 1, "ipv4": 1, "site_runtime": edgeconfig.MinSiteRuntimeVersion, "websocket": 1}
	for _, site := range sorted {
		security := edgeconfig.ListenerSecurity{Policies: site.SecurityPolicies, CC: site.CCV2}
		if site.ManagedWAF != nil {
			if security.ManagedWAF, err = edgeconfig.CanonicalListenerManagedWAF(*site.ManagedWAF); err != nil {
				t.Fatal(err)
			}
			required["waf"] = 1
		}
		if len(security.Policies) > 0 {
			required["waf"] = 1
		}
		if security.CC != nil {
			required["cc"] = max(required["cc"], edgeconfig.CCV2PolicyAPIVersion(security.CC.Policy))
		}
		if edgeconfig.SecurityPoliciesUseIPIntel(security.Policies) {
			required["ip_intel"] = edgeconfig.IPIntelCapabilityVersion
		}
		listeners = append(listeners, edgeconfig.SecurityListener{SiteID: site.ID, Domain: site.Domain, Port: site.ListenPort,
			Protocol: edgeconfig.ProtocolHTTP, Security: security})
		documentSites = append(documentSites, map[string]any{
			"id": site.ID, "revision": 1, "domains": []string{site.Domain}, "default_pool_id": "primary",
			"websocket": false, "range": true,
			"listeners": []any{map[string]any{"id": "public-8080", "position": 0, "address_family": "ipv4", "port": 8080,
				"protocols": []string{"http1"}, "security": security}},
			"origin_pools": []any{map[string]any{"id": "primary", "position": 0, "kind": "origin", "algorithm": "round_robin",
				"origins": []any{map[string]any{"id": "origin", "position": 0, "tier": "origin", "scheme": "http",
					"host": "127.0.0.1", "port": 9000, "weight": 1}},
				"retry": map[string]any{"methods": []string{"GET", "HEAD"}, "bodyless_only": true, "response_not_started": true,
					"retry_on":     []string{"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"},
					"max_attempts": 1, "connect_timeout_ms": 250, "read_timeout_ms": 2000, "total_budget_ms": 2250}}},
			"l2": map[string]any{"enabled": false, "probe_interval_ms": 10000, "failure_threshold": 3, "recovery_threshold": 3,
				"single_half_open_probe": true, "max_hops": 1},
		})
	}
	names := make([]string, 0, len(required))
	for name := range required {
		names = append(names, name)
	}
	sort.Strings(names)
	capabilities := make([]map[string]any, len(names))
	for index, name := range names {
		capabilities[index] = map[string]any{"name": name, "api_version": required[name]}
	}
	document, err := json.Marshal(map[string]any{
		"schema": "cdnca.edge.site-runtime/v2", "configuration_scope_id": scopeID, "config_version_id": versionID,
		"source_revision": 1, "sites": documentSites, "required_capabilities": capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"site-runtime.v2.json": document, edgeconfig.TelemetryIdentityManifestPath: auditTelemetry(t, scopeID, versionID, sorted)}
	if refs, err := edgeconfig.ListenerCRSProfiles(listeners); err != nil {
		t.Fatal(err)
	} else if len(refs) != 0 {
		byDigest := map[string]securitypolicy.CRSProfile{}
		for _, profile := range profiles {
			byDigest[profile.Profile.Ref.SHA256] = profile
		}
		var selected []edgeconfig.CRSProfile
		for _, ref := range refs {
			profile, ok := byDigest[ref.SHA256]
			if !ok {
				t.Fatalf("no CRS profile pack %s", ref.SHA256)
			}
			selected = append(selected, profile.Profile)
			files[edgeconfig.ListenerCRSProfilePath(ref.SHA256)] = profile.Content
		}
		crs, err := edgeconfig.ListenerCRSReleaseFiles(listeners, rules, selected)
		if err != nil {
			t.Fatalf("CRS release files: %v", err)
		}
		for path, content := range crs {
			files[path] = content
		}
	}
	for name, content := range files {
		path := filepath.Join(output, "signed-release", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	encoded, _ := json.MarshalIndent(map[string]any{"release": auditReleaseLog}, "", "  ")
	if err := os.WriteFile(filepath.Join(output, "audit.json"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

// auditTelemetry is the signed telemetry identity of the audit sites'
// listeners under the deployment root /runtime.
func auditTelemetry(t *testing.T, tenantID, versionID string, sites []edgeconfig.Site) []byte {
	t.Helper()
	manifest := edgeconfig.TelemetryIdentityManifest{SchemaVersion: 1, ConfigVersionID: versionID, ConfigRevision: 1, TenantID: tenantID,
		CapturePolicy: edgeconfig.TelemetryCapturePolicyManifest{SchemaVersion: 1}, SourceCapabilities: edgeconfig.TelemetrySourceCapabilities{SchemaVersion: 1}}
	byDomain := append([]edgeconfig.Site(nil), sites...)
	sort.Slice(byDomain, func(left, right int) bool { return byDomain[left].Domain < byDomain[right].Domain })
	for _, site := range byDomain {
		access, security := edgeconfig.TelemetryLogPaths("/runtime", versionID, site.ID, 8080)
		manifest.Sites = append(manifest.Sites, edgeconfig.TelemetrySiteIdentity{SiteID: site.ID, Domain: site.Domain, ListenPort: 8080,
			NamespaceID: edgeconfig.CacheSiteNamespaceID(tenantID, site.ID), AccessLogPath: access, SecurityLogPath: security})
		manifest.CapturePolicy.Sites = append(manifest.CapturePolicy.Sites, edgeconfig.TelemetrySiteCapturePolicy{
			SiteID: site.ID, Domain: site.Domain, ListenPort: 8080, Methods: []string{}, URIPrefixes: []string{},
			RequestHeaderAllowlist: []string{}, ResponseHeaderAllowlist: []string{}, RequestBodyFieldAllowlist: []string{},
			ResponseBodyFieldAllowlist: []string{}, MaxValueBytes: 4096, MaxBodyBytes: 64 << 10, MaxEventBytes: 1 << 20})
	}
	content, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	content = append(content, '\n')
	if _, err := edgeconfig.ParseTelemetryIdentityManifest(content); err != nil {
		t.Fatalf("telemetry identity: %v", err)
	}
	return content
}
