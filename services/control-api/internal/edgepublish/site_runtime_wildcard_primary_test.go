package edgepublish

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

// A site whose primary domain is a wildcard (sites.domain = "*.x.example")
// compiles into a site runtime v2 document: the listener security (WAF
// policy, managed WAF, CC v2) validates, the CC v2 registry keys the site on
// the wildcard, and the telemetry identity names it. (Its JS challenge:
// TestSiteRuntimeV2WildcardPrimaryCarriesItsChallenge.)
func TestSiteRuntimeV2CompilesWildcardPrimaryWithSecurityAndTelemetry(t *testing.T) {
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	tenantID := uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	const primary = "*.x.example"
	fact := siteRuntimeSecurityTestFact(siteID)
	fact.domain, fact.domains = primary, []string{"x.example", primary}
	cc := securityPolicyForEdgeTest(siteID, securitypolicy.KindCC, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("66666666-6666-4666-8666-666666666666"), Name: "limit", Priority: 1, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "path", Operator: "prefix", Values: []string{"/limited"}}},
		Action:     securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
		ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window",
			WindowSeconds: 60, MaxRequests: 2, ResponseAction: "reject_429"}},
	}})
	ccBinding := securityBindingForEdgeTest(t, cc, siteID, 3)
	ccBinding.bindingID = uuid.MustParse("77777777-7777-4777-8777-777777777777")
	security, err := siteRuntimeV2ListenerSecurity(scopeID, tenantID, fact, 8443, []securityBindingFact{
		securityBindingForEdgeTest(t, managedWAFPolicyForEdgeTest(siteID), siteID, 2), ccBinding})
	if err != nil {
		t.Fatalf("siteRuntimeV2ListenerSecurity(wildcard primary) error = %v", err)
	}
	if security == nil || security.CC == nil || security.ManagedWAF == nil || len(security.Policies) != 1 {
		t.Fatalf("listener security = %+v", security)
	}
	// The WAF rule is scoped by the wildcard server, not by a host that no
	// request carries.
	if rules := security.Policies[0].Rules; len(rules) != 1 || rules[0].Match.Host != "" || rules[0].Match.Port != 8443 {
		t.Fatalf("WAF rules = %+v", rules)
	}

	document := siteRuntimeSecurityDocument(t, security)
	document.Sites[0].Domains = siteRuntimeV2Domains(fact)
	if document.Sites[0].Domains[0] != primary {
		t.Fatalf("primary domain is not first: %v", document.Sites[0].Domains)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); err != nil {
		t.Fatalf("compileSiteRuntimeV2Document(wildcard primary) error = %v", err)
	}
	fragments, err := siteRuntimeSecurityFragments(document)
	if err != nil {
		t.Fatal(err)
	}
	if fragments.CCV2Registry == nil || len(fragments.CCV2Registry.Entries) != 1 ||
		fragments.CCV2Registry.Entries[0].Hostname != primary {
		t.Fatalf("CC v2 registry = %+v", fragments.CCV2Registry)
	}

	configID := uuid.MustParse(document.ConfigVersionID)
	stateRoot := filepath.Join(t.TempDir(), "edge")
	content, err := buildSiteRuntimeV2TelemetryManifest(scopeID, tenantID, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7183"),
		configID, document.SourceRevision, document, nil, nil, noAccessLogFields, stateRoot)
	if err != nil {
		t.Fatalf("buildSiteRuntimeV2TelemetryManifest(wildcard primary) error = %v", err)
	}
	manifest, err := edgeconfig.ParseTelemetryIdentityManifest(content)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Sites) != 1 || manifest.Sites[0].Domain != primary || manifest.Sites[0].SiteID != siteID.String() ||
		manifest.CapturePolicy.Sites[0].Domain != primary {
		t.Fatalf("telemetry identity = %+v", manifest)
	}
}

// A WAF host condition is decided against the site's primary domain at
// compile time: for a wildcard primary it holds for no single host, so it is
// refused instead of silently never (or always) matching. A CC host
// condition is compared with the request host by the engine, which matches a
// wildcard domain as server_name does: it compiles to that match.host.
func TestSiteRuntimeV2RefusesHostConditionOnWildcardPrimary(t *testing.T) {
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fact := siteRuntimeSecurityTestFact(siteID)
	fact.domain = "*.x.example"
	host := []securitypolicy.Condition{{Field: "host", Operator: "equals", Values: []string{fact.domain}}}
	cc := securityPolicyForEdgeTest(siteID, securitypolicy.KindCC, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("66666666-6666-4666-8666-666666666666"), Name: "limit", Priority: 1, Enabled: true,
		Conditions: host, Action: securitypolicy.ActionRateLimit, Flow: securitypolicy.FlowStop,
		ActionConfig: securitypolicy.ActionConfig{RateLimit: &securitypolicy.RateLimitConfig{Algorithm: "fixed_window",
			WindowSeconds: 60, MaxRequests: 2, ResponseAction: "reject_429"}},
	}})
	waf := securityPolicyForEdgeTest(siteID, securitypolicy.KindWAF, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), Name: "host", Priority: 1, Enabled: true,
		Conditions: host,
		Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
	}})
	if _, err := siteRuntimeV2ListenerSecurity(scopeID, uuid.New(), fact, 8443,
		[]securityBindingFact{securityBindingForEdgeTest(t, waf, siteID, 3)}); err == nil {
		t.Fatal("a WAF host condition on a wildcard primary was accepted")
	}
	ccSecurity, err := siteRuntimeV2ListenerSecurity(scopeID, uuid.New(), fact, 8443,
		[]securityBindingFact{securityBindingForEdgeTest(t, cc, siteID, 3)})
	if err != nil || ccSecurity.CC == nil || ccSecurity.CC.Policy.Rules[0].Match.Host != fact.domain {
		t.Fatalf("CC host condition on a wildcard primary = %+v, %v", ccSecurity, err)
	}
	// An exact primary keeps its implicit host scope.
	fact.domain = "cdn.example.test"
	exact := securityPolicyForEdgeTest(siteID, securitypolicy.KindWAF, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), Name: "header", Priority: 1, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "header", Key: "x-bad", Operator: "equals", Values: []string{"1"}}},
		Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
	}})
	security, err := siteRuntimeV2ListenerSecurity(scopeID, uuid.New(), fact, 8443,
		[]securityBindingFact{securityBindingForEdgeTest(t, exact, siteID, 3)})
	if err != nil || len(security.Policies) != 1 || security.Policies[0].Rules[0].Match.Host != fact.domain {
		t.Fatalf("exact primary WAF = %+v, %v", security, err)
	}
	// The WAF refusal is the wildcard's: the same host condition compiles on
	// an exact primary, and a wildcard primary's match carries no host.
	if matches, err := compileSecurityRuleMatches("cdn.example.test", 8443, host[:0:0]); err != nil ||
		len(matches) != 1 || matches[0].Host != "cdn.example.test" {
		t.Fatalf("exact primary matches = %+v, %v", matches, err)
	}
	exactHost := []securitypolicy.Condition{{Field: "host", Operator: "equals", Values: []string{"cdn.example.test"}}}
	if matches, err := compileSecurityRuleMatches("cdn.example.test", 8443, exactHost); err != nil || len(matches) != 1 {
		t.Fatalf("exact primary host condition = %+v, %v", matches, err)
	}
	if matches, err := compileSecurityRuleMatches("*.x.example", 8443, nil); err != nil || len(matches) != 1 || matches[0].Host != "" {
		t.Fatalf("wildcard primary matches = %+v, %v", matches, err)
	}
	if _, err := compileSecurityRuleMatches("*.x.example", 8443, host); err == nil {
		t.Fatal("a host condition was decided against a wildcard primary")
	}
}

// A wildcard site's JS challenge binding names one host under the wildcard
// (its policy's, 053/345); the listener carries the challenge, which the node
// matches by site identity for every host the site serves.
func TestSiteRuntimeV2WildcardPrimaryCarriesItsChallenge(t *testing.T) {
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	tenantID := uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	policyID := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	fact := siteRuntimeSecurityTestFact(siteID)
	fact.domain, fact.domains = "*.x.example", []string{"*.x.example", "alias.example.test"}
	fact.challenge = &challengeBindingFact{tenantScopeID: scopeID, siteID: siteID, policyID: policyID,
		secretConfigVersionID: uuid.MustParse("66666666-6666-4666-8666-666666666666"),
		host:                  "www.x.example", policyRevision: 3, bindingRevision: 2}
	security, err := siteRuntimeV2ListenerSecurity(scopeID, tenantID, fact, 8443, nil)
	if err != nil {
		t.Fatalf("siteRuntimeV2ListenerSecurity(wildcard challenge) error = %v", err)
	}
	if security == nil || security.Challenge == nil || security.Challenge.PolicyID != policyID.String() ||
		security.Challenge.PolicyVersion != 3 || security.Challenge.TenantID != tenantID.String() {
		t.Fatalf("listener challenge = %+v", security)
	}
	// A binding for a host the site does not serve is refused.
	fact.challenge.host = "www.other.example"
	if _, err := siteRuntimeV2ListenerSecurity(scopeID, tenantID, fact, 8443, nil); err == nil {
		t.Fatal("challenge bound to a host outside the wildcard was accepted")
	}
}
