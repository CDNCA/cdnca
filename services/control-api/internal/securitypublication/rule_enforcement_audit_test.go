package securitypublication

// Rule enforcement audit harness (docs/security/rule-enforcement-audit.md).
//
// It pushes every CC rule group and WAF rule set of the signed system rule
// catalog through the real management/node compile chain
// (securitypolicy.CompileRuntimeSnapshot -> CompileSiteSecurityBindings ->
// edgeconfig.Build) and records, per item, whether the chain can represent it.
// Request behaviour on a node is checked by tests/dynroute-waf. A policy
// the chain rejects is published the way production would end up: the site
// keeps running without it (edge publish fails with
// ErrUnsupportedSecurityPolicy and the node keeps the previous version).

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

type ruleAuditResult struct {
	SystemKey string `json:"system_key"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Compiled  bool   `json:"compiled"`
	Error     string `json:"error,omitempty"`
}

// auditPolicyBuilder turns catalog items into a security policy the same way
// the product does (or, before catalog expansion existed, the closest manual
// equivalent an operator could type).
type auditPolicyBuilder interface {
	ccPolicy(catalog map[string]rulecatalog.Item, groupKey string) (securitypolicy.Policy, error)
	wafPolicy(catalog map[string]rulecatalog.Item, setKeys []string, action string) (securitypolicy.Policy, error)
}

func auditCatalog() map[string]rulecatalog.Item {
	items := map[string]rulecatalog.Item{}
	for _, item := range rulecatalog.CurrentSeed() {
		items[item.SystemKey] = item
	}
	return items
}

func auditSite(id uuid.UUID, domain string) edgeconfig.Site {
	return edgeconfig.Site{
		ID: id.String(), Domain: domain, ListenPort: 8080, Protocol: edgeconfig.ProtocolHTTP,
		Origins: []edgeconfig.Origin{{Host: "127.0.0.1", Port: 9000, Weight: 1}}, Balance: edgeconfig.BalanceRoundRobin,
		FailoverTries: 1, ConnectTimeout: 250 * time.Millisecond, ReadTimeout: 2 * time.Second,
		ACL: edgeconfig.ACLPolicy{DefaultAction: edgeconfig.ACLAllow},
	}
}

func auditCompile(site edgeconfig.Site, siteID uuid.UUID, policies ...securitypolicy.Policy) (CompiledSiteSecurity, error) {
	bindings := make([]ActiveBinding, 0, len(policies))
	for _, policy := range policies {
		policy.ScopeID = testTenantScopeID
		compiled, err := securitypolicy.CompileRuntimeSnapshot(policy, siteID)
		if err != nil {
			return CompiledSiteSecurity{}, err
		}
		if err := securitypolicy.ValidatePublishablePolicy(policy); err != nil {
			return CompiledSiteSecurity{}, err
		}
		binding := ActiveBinding{BindingID: uuid.New(), PublicationID: uuid.New(), BindingRevision: 1,
			RuntimeSnapshotSHA256: compiled.SHA256, Snapshot: compiled.Snapshot}
		if securitypolicy.PolicyManagedWAF(policy) != nil {
			binding.CRS = &CRSInputs{Profiles: auditCRSProfiles()}
		}
		bindings = append(bindings, binding)
	}
	return CompileSiteSecurityBindings(site, testTenantScopeID, siteID, bindings)
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// manualAuditBuilder is what an operator could express before catalog
// expansion existed: every catalog filter mapped to the closest
// security-policy vocabulary, every WAF matcher to a policy condition.
type manualAuditBuilder struct{}

func (manualAuditBuilder) ccPolicy(catalog map[string]rulecatalog.Item, groupKey string) (securitypolicy.Policy, error) {
	policy := securitypolicy.Policy{ID: uuid.New(), Kind: securitypolicy.KindCC, Name: catalog[groupKey].Name,
		Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 1}
	for index, entry := range catalog[groupKey].Body.CCRuleGroup.Entries {
		filter := catalog[entry.Filter1Key].Body.CCFilter
		rule := securitypolicy.Rule{ID: uuid.New(), Name: "catalog", Priority: index + 1, Enabled: true, Flow: securitypolicy.FlowStop,
			Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/"}}}}
		if filter.Type == "req_rate" {
			rule.Action = securitypolicy.ActionRateLimit
			rule.ActionConfig.RateLimit = &securitypolicy.RateLimitConfig{WindowSeconds: filter.WithinSecond, MaxRequests: filter.MaxReq}
		} else {
			rule.Action = securitypolicy.ActionChallenge
			rule.ActionConfig.Challenge = &securitypolicy.ChallengeConfig{Type: map[string]string{
				"browser_verify_auto": "js", "delay_jump_filter": "five_second", "click_filter": "click",
				"easy_click_filter": "simple_click", "slide_filter": "slider", "easy_slide_filter": "simple_slider",
				"captcha_filter": "captcha", "rotate_filter": "rotate_image", "302_challenge": "js"}[filter.Type]}
		}
		policy.Rules = append(policy.Rules, rule)
	}
	return policy, nil
}

func (manualAuditBuilder) wafPolicy(catalog map[string]rulecatalog.Item, setKeys []string, action string) (securitypolicy.Policy, error) {
	policy := securitypolicy.Policy{ID: uuid.New(), Kind: securitypolicy.KindWAF, Name: "catalog waf",
		Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 1}
	for _, key := range setKeys {
		for _, catalogRule := range catalog[key].Body.WAFRuleSet.Rules {
			rule := securitypolicy.Rule{ID: uuid.New(), Name: catalogRule.Name, Priority: len(policy.Rules) + 1,
				Enabled: true, Action: action, Flow: securitypolicy.FlowStop}
			for _, matcher := range catalogRule.MatcherGroups[0].Matchers {
				field := map[string]string{"req_uri": "path", "uri": "path"}[matcher.Field]
				if field == "" {
					field = matcher.Field
				}
				operator := map[string]string{"contain": "contains"}[matcher.Operator]
				if operator == "" {
					operator = matcher.Operator
				}
				rule.Conditions = append(rule.Conditions, securitypolicy.Condition{Field: field, Operator: operator, Values: []string{matcher.Value}})
			}
			policy.Rules = append(policy.Rules, rule)
		}
	}
	return policy, nil
}

// adminPathRule is the strongest WAF rule the chain accepted before this
// change: block a path prefix.
func adminPathRule(priority int) securitypolicy.Rule {
	return securitypolicy.Rule{ID: uuid.New(), Name: "custom /admin", Priority: priority, Enabled: true,
		Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
		Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/admin"}}}}
}

// catalogAuditBuilder uses the product expansion (securitypolicy.Expand*).
type catalogAuditBuilder struct{ manualAuditBuilder }

func (catalogAuditBuilder) ccPolicy(catalog map[string]rulecatalog.Item, groupKey string) (securitypolicy.Policy, error) {
	rules, err := securitypolicy.ExpandCCRuleGroup(catalog, groupKey)
	for index := range rules {
		rules[index].ID = uuid.New()
	}
	return securitypolicy.Policy{ID: uuid.New(), Kind: securitypolicy.KindCC, Name: catalog[groupKey].Name,
		Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 1, Rules: rules}, err
}

// wafPolicy is what the site WAF editor saves after "从系统规则导入":
// securitypolicy.CatalogWAFRules of the keys (self-developed sets expand to
// policy rules, OWASP CRS sets become one managed_waf rule), with every
// value from the catalog; action "" keeps it, log/block overrides every rule
// and CRS set.
func (catalogAuditBuilder) wafPolicy(catalog map[string]rulecatalog.Item, setKeys []string, action string) (securitypolicy.Policy, error) {
	items := make([]rulecatalog.Item, 0, len(catalog))
	for _, item := range catalog {
		items = append(items, item)
	}
	rules, err := securitypolicy.CatalogWAFRules(items, setKeys)
	for index := range rules {
		rule := &rules[index]
		rule.ID = uuid.New()
		switch {
		case action == "":
		case rule.Action == securitypolicy.ActionManagedWAF:
			// CRS actions are the profile's: log-only is the pl1-log profile.
			if action == securitypolicy.ActionLog {
				rule.ActionConfig.ManagedWAF.Profile = "system/crs-pl1-log"
			}
		default:
			rule.Action, rule.Flow = action, securitypolicy.FlowContinue
			if action == securitypolicy.ActionBlock {
				rule.Flow = securitypolicy.FlowStop
			}
		}
	}
	return securitypolicy.Policy{ID: uuid.New(), Kind: securitypolicy.KindWAF, Name: "catalog waf",
		Enabled: true, DefaultAction: securitypolicy.ActionAllow, Revision: 1, Rules: rules}, err
}

// managedWAF returns the policy's managed_waf (OWASP CRS) configuration.
func managedWAF(policy securitypolicy.Policy) *securitypolicy.ManagedWAFConfig {
	for _, rule := range policy.Rules {
		if rule.Action == securitypolicy.ActionManagedWAF {
			return rule.ActionConfig.ManagedWAF
		}
	}
	return nil
}

// auditWAFKeys lists the catalog's visible WAF sets of one engine.
func auditWAFKeys(catalog map[string]rulecatalog.Item, crs bool) []string {
	keys := make([]string, 0, 10)
	for key, item := range catalog {
		if item.Kind == rulecatalog.KindWAFRuleSet && !item.Hidden && (item.Body.WAFRuleSet.Engine != nil) == crs {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// auditBuilder: RULE_AUDIT_BUILDER=manual reproduces the pre-fix state.
func auditBuilder() auditPolicyBuilder {
	if os.Getenv("RULE_AUDIT_BUILDER") == "manual" {
		return manualAuditBuilder{}
	}
	return catalogAuditBuilder{}
}

func TestRuleEnforcementAuditCatalogThroughRealCompileChain(t *testing.T) {
	catalog, builder := auditCatalog(), auditBuilder()
	results := make([]ruleAuditResult, 0, 31)
	for key, item := range catalog {
		var policy securitypolicy.Policy
		var err error
		switch item.Kind {
		case rulecatalog.KindCCRuleGroup:
			if len(item.Body.CCRuleGroup.Entries) == 0 {
				results = append(results, ruleAuditResult{SystemKey: key, Name: item.Name, Kind: item.Kind, Compiled: true,
					Error: "no entries: the rule group means CC off"})
				continue
			}
			policy, err = builder.ccPolicy(catalog, key)
		case rulecatalog.KindWAFRuleSet:
			if item.Hidden {
				continue // CRS engine defaults and rule text, not rule sets
			}
			policy, err = builder.wafPolicy(catalog, []string{key}, securitypolicy.ActionBlock)
		default:
			continue
		}
		if err == nil {
			_, err = auditCompile(auditSite(testSiteID, "audit.example.test"), testSiteID, policy)
		}
		results = append(results, ruleAuditResult{SystemKey: key, Name: item.Name, Kind: item.Kind, Compiled: err == nil, Error: errorText(err)})
	}
	sort.Slice(results, func(left, right int) bool { return results[left].SystemKey < results[right].SystemKey })
	if len(results) != 39 {
		t.Fatalf("audited %d items, want 14 rule groups (3 rate-trigger templates) + 14 self-developed + 11 OWASP CRS WAF sets (waf-gap5 added crs_generic)", len(results))
	}
	for _, result := range results {
		t.Logf("%-30s %-12s compiled=%-5v %s", result.SystemKey, result.Name, result.Compiled, result.Error)
	}
}

// auditCRSProfiles are the system/crs-* packs libs/rulepack generates.
func auditCRSProfiles() securitypolicy.CRSProfiles {
	paths, _ := filepath.Glob("../../../../libs/rulepack/testdata/crs-profiles/crs-*.json")
	profiles := securitypolicy.CRSProfiles{}
	for _, path := range paths {
		content, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}
		sum := sha256.Sum256(content)
		_, profile, err := rulepack.LoadCRSProfile(content, hex.EncodeToString(sum[:]))
		if err != nil {
			panic(err)
		}
		profiles[profile.Ref.PackID] = securitypolicy.CRSProfile{Profile: profile, Content: content}
	}
	return profiles
}
