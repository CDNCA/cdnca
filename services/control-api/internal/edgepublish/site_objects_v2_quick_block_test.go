package edgepublish

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// Dynamic routing D7: a site's quick block override (inherit / on with its
// own values / off) reaches the site object as the
// effective quick block rules of its WAF policy, exactly the rules v7 runs
// for that site. Three sites share one WAF library with a quick block; the
// node runs whatever rules the object carries (cdnca_security rewrite), so
// the override semantics are the object's content.
func TestSiteObjectsV2CarryQuickBlockSiteOverride(t *testing.T) {
	block := securitypolicy.QuickBlock{BlockIDCCN: true, Carriers: []string{"carrier:cn-mobile"},
		AllowedCrawlers: []securitypolicy.TrustedCrawler{{Networks: []string{"66.249.64.0/19"}, UserAgentPrefixes: []string{"Googlebot"}}}}
	if err := securitypolicy.NormalizeQuickBlock(&block); err != nil {
		t.Fatal(err)
	}
	inherit := uuid.MustParse("41111111-1111-4111-8111-1111111111a1")
	on := uuid.MustParse("41111111-1111-4111-8111-1111111111a2")
	off := uuid.MustParse("41111111-1111-4111-8111-1111111111a3")
	user := securitypolicy.Rule{ID: uuid.MustParse("018f7a5e-0000-7000-8000-00000000b001"), Name: "admin", Priority: 2, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/admin"}}},
		Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop}
	library := securityPolicyForEdgeTest(inherit, securitypolicy.KindWAF, securitypolicy.ActionAllow, nil)
	library.Rules = securitypolicy.MergeQuickBlockRules(library.ID, []securitypolicy.Rule{user}, &block)
	library.QuickBlock = &block

	carriers := []string{"carrier:cn-unicom"}
	overrides := map[uuid.UUID]securitypolicy.QuickBlockOverride{
		on:  {BlockIDCCN: boolPointer(false), BlockIDCGlobal: boolPointer(true), Carriers: &carriers, AllowedCrawlers: &[]securitypolicy.TrustedCrawler{}},
		off: {BlockIDCCN: boolPointer(false), Carriers: &[]string{}},
	}
	bindings := map[uuid.UUID][]securityBindingFact{}
	for _, siteID := range []uuid.UUID{inherit, on, off} {
		bindings[siteID] = []securityBindingFact{securityBindingForEdgeTest(t, library, siteID, 1)}
	}
	applySiteQuickBlockOverrides(bindings, overrides)

	var base siteRuntimeV2Document
	if err := json.Unmarshal(siteRuntimeV2DocumentFixture(), &base); err != nil {
		t.Fatal(err)
	}
	template := base.Sites[0]
	disabled := false
	template.L2.Enabled, template.L2.DirectFallbackPoolID = &disabled, nil
	template.OriginPools = slices.Clone(template.OriginPools[:1])
	template.DefaultPoolID = template.OriginPools[0].ID
	origin := template.OriginPools[0].Origins[0]
	origin.Scheme, origin.Port, origin.SNI, origin.TrustRef = "http", 80, nil, nil
	template.OriginPools[0].Origins = []siteRuntimeV2Origin{origin}
	listener := template.Listeners[0]
	listener.ID, listener.Port, listener.Protocols, listener.TLS = "public-8080", 8080, []string{"http1"}, nil
	document := siteRuntimeV2Document{Schema: siteRuntimeV2Schema, ConfigurationScopeID: richScopeID.String(),
		SourceRevision: 9, ConfigVersionID: "018f47a2-5b9c-7d31-8a60-104c9c0b7e11"}
	v7 := map[string][]edgeconfig.WAFRule{}
	for index, siteID := range []uuid.UUID{inherit, on, off} {
		fact := siteRuntimeSecurityTestFact(siteID)
		fact.domain = fmt.Sprintf("q%d.example.test", index)
		fact.domains = []string{fact.domain}
		security, err := siteRuntimeV2ListenerSecurity(richScopeID, richTenantID, fact, 8080, bindings[siteID])
		if err != nil {
			t.Fatal(err)
		}
		site := template
		site.ID, site.Revision, site.Domains = siteID.String(), 1, []string{fact.domain}
		site.Listeners = []siteRuntimeV2Listener{listener}
		site.Listeners[0].Security = security
		document.Sites = append(document.Sites, site)
		v7[siteID.String()] = security.Policies[0].Rules
	}
	slices.SortFunc(document.Sites, func(left, right siteRuntimeV2Site) int { return strings.Compare(left.ID, right.ID) })
	document.RequiredCapabilities = []siteRuntimeV2Capability{{Name: "http1", APIVersion: 1}, {Name: "ipv4", APIVersion: 1},
		{Name: "ipv6", APIVersion: 1}, {Name: "site_runtime", APIVersion: edgeconfig.MinSiteRuntimeVersion}, {Name: "websocket", APIVersion: 1}}
	setSiteRuntimeV2SecurityCapabilities(&document)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, _, _, err := compileSiteRuntimeV2Document(raw)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := buildSiteRuntimeV2Bundle(canonical, nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	publication, err := siteObjectsV2SourceFromBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	objects, err := buildSiteObjectsV2(publication, richTenantID, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]edgeconfig.WAFRule{}
	for _, object := range objects.Sites {
		decoded, err := edgesite.Decode(object.Plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if len(decoded.Security.Rules.Policies) != 1 {
			t.Fatalf("site %s policies %+v", object.SiteID, decoded.Security.Rules.Policies)
		}
		got[object.SiteID] = decoded.Security.Rules.Policies[0].Rules
	}
	slot := func(n int) string { return securitypolicy.QuickBlockRuleID(library.ID, n).String() }
	for siteID, rules := range got {
		// One listener: the object holds the v7 rules with the port the
		// listener pins them to dropped (edgesite RulePlan).
		want := slices.Clone(v7[siteID])
		for index := range want {
			want[index].Match.Port = 0
		}
		wantJSON, _ := json.Marshal(want)
		gotJSON, _ := json.Marshal(rules)
		if string(wantJSON) != string(gotJSON) {
			t.Fatalf("site %s object rules differ from v7:\nobject %s\nv7     %s", siteID, gotJSON, wantJSON)
		}
	}
	// Inherit: the library's idc:cn, cn-mobile, crawler allow, then the user rule.
	if rules := got[inherit.String()]; len(rules) != 4 || rules[0].RuleID != slot(1) || rules[0].Match.IPIntel[0].Values[0] != "idc:cn" ||
		rules[1].Match.IPIntel[0].Values[0] != "carrier:cn-mobile" || rules[2].Action != edgeconfig.WAFAllow || rules[3].RuleID != user.ID.String() {
		t.Fatalf("inherit = %+v", rules)
	}
	// On with its own values: idc:global, cn-unicom, no crawler.
	if rules := got[on.String()]; len(rules) != 3 || rules[0].Match.IPIntel[0].Values[0] != "idc:global" ||
		rules[1].Match.IPIntel[0].Values[0] != "carrier:cn-unicom" || rules[2].RuleID != user.ID.String() {
		t.Fatalf("on = %+v", rules)
	}
	// Off: the user rule only.
	if rules := got[off.String()]; len(rules) != 1 || rules[0].RuleID != user.ID.String() {
		t.Fatalf("off = %+v", rules)
	}
}
