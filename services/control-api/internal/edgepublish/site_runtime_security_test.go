package edgepublish

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

func siteRuntimeSecurityTestFact(siteID uuid.UUID) siteFact {
	return siteFact{id: siteID, revision: 7, domain: "cdn.example.test", balance: string(edgeconfig.BalanceRoundRobin),
		failoverTries: 1, connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 8080, Weight: 1}}}
}

func managedWAFPolicyForEdgeTest(siteID uuid.UUID) securitypolicy.Policy {
	return securityPolicyForEdgeTest(siteID, securitypolicy.KindWAF, securitypolicy.ActionAllow, []securitypolicy.Rule{{
		ID: uuid.MustParse("22222222-2222-4222-8222-222222222222"), Name: "crs", Priority: 1, Enabled: true,
		Action: securitypolicy.ActionManagedWAF, Flow: securitypolicy.FlowContinue,
		ActionConfig: securitypolicy.ActionConfig{ManagedWAF: &securitypolicy.ManagedWAFConfig{
			RequestBodyLimit: 1 << 20, RequestBodyNoFilesLimit: 128 << 10, RequestBodyLimitAction: "reject",
			ArgumentsLimit: 1000, JSONDepthLimit: 512, PCREMatchLimit: 100000, InspectionLimitAction: "block",
			Profile: securitypolicy.DefaultCRSProfile, Exclusions: []int{942100},
		}},
	}, {
		ID: uuid.MustParse("33333333-3333-4333-8333-333333333333"), Name: "bad header", Priority: 2, Enabled: true,
		Conditions: []securitypolicy.Condition{{Field: "header", Key: "x-bad", Operator: "equals", Values: []string{"1"}}},
		Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
	}})
}

// The listener carries what the legacy site carries: the bound policies, the
// managed WAF (until now dropped by site runtime v2) and the JS challenge
// (until now never loaded for site runtime v2).
func TestSiteRuntimeV2ListenerSecurityCarriesManagedWAFAndChallenge(t *testing.T) {
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	tenantID := uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fact := siteRuntimeSecurityTestFact(siteID)
	policyID := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	fact.challenge = &challengeBindingFact{tenantScopeID: scopeID, siteID: siteID, host: fact.domain, policyID: policyID,
		policyRevision: 7, bindingRevision: 2, secretConfigVersionID: uuid.New()}
	bindings := []securityBindingFact{securityBindingForEdgeTest(t, managedWAFPolicyForEdgeTest(siteID), siteID, 2)}

	security, err := siteRuntimeV2ListenerSecurity(scopeID, tenantID, fact, 8080, bindings)
	if err != nil {
		t.Fatal(err)
	}
	_, legacy, err := compileSiteFact(scopeID, fact, 8080, nil, bindings, nil)
	if err != nil || legacy.ManagedWAF == nil || legacy.Challenge == nil {
		t.Fatalf("legacy fixture: %+v %v", legacy, err)
	}
	if security == nil || len(security.Policies) != 1 || security.ManagedWAF == nil || security.Challenge == nil ||
		security.ManagedWAF.InspectionLimitAction != "block" || security.ManagedWAF.PolicyID != legacy.ManagedWAF.PolicyID ||
		*security.Challenge != (edgeconfig.ListenerChallenge{TenantID: tenantID.String(), PolicyID: legacy.Challenge.PolicyID,
			PolicyVersion: legacy.Challenge.PolicyVersion}) {
		t.Fatalf("listener security = %+v", security)
	}
	canonical, err := edgeconfig.CanonicalListenerManagedWAF(*legacy.ManagedWAF)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(security.ManagedWAF)
	want, _ := json.Marshal(canonical)
	if string(got) != string(want) {
		t.Fatalf("managed WAF differs from the legacy site's\n%s\n%s", got, want)
	}

	fact.challenge = nil
	if onlyPolicies, err := siteRuntimeV2ListenerSecurity(scopeID, tenantID, fact, 8080, bindings); err != nil ||
		onlyPolicies.Challenge != nil || onlyPolicies.ManagedWAF == nil {
		t.Fatalf("without challenge: %+v %v", onlyPolicies, err)
	}
	// The managed WAF rule is not a Lua rule: only the header rule is.
	if rules := security.Policies[0].Rules; len(rules) != 1 || rules[0].Action != edgeconfig.WAFBlock || rules[0].Match.Header == nil {
		t.Fatalf("WAF policy rules = %+v", rules)
	}
	if none, err := siteRuntimeV2ListenerSecurity(scopeID, tenantID, fact, 8080, nil); err != nil || none != nil {
		t.Fatalf("no security: %+v %v", none, err)
	}
	fact.challenge = &challengeBindingFact{tenantScopeID: scopeID, siteID: siteID, host: fact.domain, policyID: policyID,
		policyRevision: 7, bindingRevision: 2, secretConfigVersionID: uuid.New()}
	if onlyChallenge, err := siteRuntimeV2ListenerSecurity(scopeID, tenantID, fact, 8080, nil); err != nil ||
		onlyChallenge == nil || onlyChallenge.Challenge == nil || len(onlyChallenge.Policies) != 0 || onlyChallenge.ManagedWAF != nil {
		t.Fatalf("challenge only: %+v %v", onlyChallenge, err)
	}
}

func siteRuntimeSecurityDocument(t *testing.T, security *edgeconfig.ListenerSecurity) siteRuntimeV2Document {
	t.Helper()
	var document siteRuntimeV2Document
	if err := json.Unmarshal(siteRuntimeV2DocumentFixture(), &document); err != nil {
		t.Fatal(err)
	}
	document.Sites[0].ID = "11111111-1111-4111-8111-111111111111"
	document.ConfigurationScopeID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	// Without L2 (an L2 site's bundle also needs its origin route bundle).
	disabled := false
	document.Sites[0].L2.Enabled, document.Sites[0].L2.DirectFallbackPoolID = &disabled, nil
	document.Sites[0].OriginPools = document.Sites[0].OriginPools[:1]
	document.Sites[0].DefaultPoolID = document.Sites[0].OriginPools[0].ID
	// 8443: binding security to a TLS listener on 443 fails earlier, in
	// compileSiteFact (it validates the site as plain HTTP; reported).
	document.Sites[0].Listeners[0].Port, document.Sites[0].Listeners[0].ID = 8443, "public-8443"
	document.Sites[0].Listeners[0].Security = security
	setSiteRuntimeV2SecurityCapabilities(&document)
	return document
}

func siteRuntimeCapability(capabilities []*agentv1.Capability, name agentv1.CapabilityName) uint32 {
	for _, capability := range capabilities {
		if capability.Name == name {
			return capability.ApiVersion
		}
	}
	return 0
}

func TestSiteRuntimeV2DocumentRequiresV6ForManagedWAFAndChallenge(t *testing.T) {
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	fact := siteRuntimeSecurityTestFact(siteID)
	fact.challenge = &challengeBindingFact{tenantScopeID: scopeID, siteID: siteID, host: fact.domain,
		policyID: uuid.MustParse("55555555-5555-4555-8555-555555555555"), policyRevision: 7, bindingRevision: 2,
		secretConfigVersionID: uuid.New()}
	security, err := siteRuntimeV2ListenerSecurity(scopeID, uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), fact, 8443,
		[]securityBindingFact{securityBindingForEdgeTest(t, managedWAFPolicyForEdgeTest(siteID), siteID, 2)})
	if err != nil {
		t.Fatal(err)
	}
	document := siteRuntimeSecurityDocument(t, security)
	raw, _ := json.Marshal(document)
	_, _, capabilities, _, err := compileSiteRuntimeV2Document(raw)
	if err != nil {
		t.Fatalf("site runtime v6 document rejected: %v", err)
	}
	if got := siteRuntimeCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME); got != 6 {
		t.Fatalf("site_runtime requirement = %d, want 6", got)
	}
	// a managed WAF needs the c3 context (ADR 0011 RI-03)
	if got := siteRuntimeCapability(capabilities, agentv1.CapabilityName_CAPABILITY_NAME_WAF); got != edgeconfig.WAFAdaptiveAPIVersion {
		t.Fatalf("waf requirement = %d", got)
	}
	for index := range document.RequiredCapabilities {
		if document.RequiredCapabilities[index].Name == "site_runtime" {
			document.RequiredCapabilities[index].APIVersion = 5
		}
	}
	raw, _ = json.Marshal(document)
	if _, _, _, _, err := compileSiteRuntimeV2Document(raw); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("a v5 requirement for v6 security was accepted: %v", err)
	}
	// A v5 node (HTTP/3 ready) gets a readable refusal naming the 1.0.35 baseline.
	refusal := targetCapabilityError(uuid.New(), "1.0.34", capabilities, []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: 5},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_QUIC, ApiVersion: 1},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: edgeconfig.WAFAdaptiveAPIVersion}})
	if !errors.Is(refusal, ErrTargetIneligible) || !strings.Contains(refusal.Error(), "1.0.35") {
		t.Fatalf("v5 node refusal = %v", refusal)
	}
}

func TestSiteRuntimeV2BundleCarriesExactlyTheCRSFilesTheManagedWAFLoads(t *testing.T) {
	siteID := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	scopeID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	security, err := siteRuntimeV2ListenerSecurity(scopeID, uuid.New(), siteRuntimeSecurityTestFact(siteID), 8443,
		[]securityBindingFact{securityBindingForEdgeTest(t, managedWAFPolicyForEdgeTest(siteID), siteID, 2)})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(siteRuntimeSecurityDocument(t, security))
	canonical, _, _, _, err := compileSiteRuntimeV2Document(raw)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := securitypolicy.EdgeCRSRuleText(*rulecatalog.CRSRulesBundle())
	if err != nil {
		t.Fatal(err)
	}
	crs, err := siteRuntimeV2CRSFiles(canonical, rules, crsProfilesForEdgeTest(t), nil)
	if err != nil || len(crs) == 0 {
		t.Fatalf("CRS files = %d, %v", len(crs), err)
	}
	wire, err := marshalSiteRuntimeV2BundleWithSecurity(canonical, nil, nil, nil, nil, crs)
	if err != nil {
		t.Fatalf("bundle with CRS files: %v", err)
	}
	bundle, err := edgeconfig.UnmarshalBundle(wire)
	if err != nil {
		t.Fatal(err)
	}
	for path := range crs {
		if string(bundle.Files[path]) != string(crs[path]) {
			t.Fatalf("bundle lacks %s", path)
		}
	}
	if _, err := marshalSiteRuntimeV2BundleWithSecurity(canonical, nil, nil, nil, nil, nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("managed WAF bundle without CRS text: %v", err)
	}
	// The default profile loads every CRS rule file: an extra one is a file
	// outside the rule text.
	extra := map[string][]byte{edgeconfig.ListenerCRSReleasePath("REQUEST-999-EXTRA.conf"): rules.Files["REQUEST-932-APPLICATION-ATTACK-RCE.conf"]}
	for path, content := range crs {
		extra[path] = content
	}
	if _, err := marshalSiteRuntimeV2BundleWithSecurity(canonical, nil, nil, nil, nil, extra); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bundle with an unused CRS file: %v", err)
	}
	// PA-12: the release carries the bytes of exactly the profile it selects.
	packs := 0
	for path := range crs {
		if _, ok := edgeconfig.ListenerCRSProfileDigest(path); ok {
			packs++
		}
	}
	if packs != 1 {
		t.Fatalf("release carries %d CRS profile packs", packs)
	}
	pl2 := crsProfilesForEdgeTest(t)["system/crs-pl2"]
	wrongPack := map[string][]byte{edgeconfig.ListenerCRSProfilePath(pl2.Profile.Ref.SHA256): pl2.Content}
	for path, content := range crs {
		if _, ok := edgeconfig.ListenerCRSProfileDigest(path); !ok {
			wrongPack[path] = content
		}
	}
	if _, err := marshalSiteRuntimeV2BundleWithSecurity(canonical, nil, nil, nil, nil, wrongPack); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bundle with another profile pack: %v", err)
	}
	plain, _, _, _, err := compileSiteRuntimeV2Document(siteRuntimeV2DocumentFixture())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := marshalSiteRuntimeV2BundleWithSecurity(plain, nil, nil, nil, nil, crs); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("CRS text without a managed WAF: %v", err)
	}
}

// A JS challenge or managed WAF on site runtime v2 needs site_runtime v6:
// the refusal names every target below v6, including a node known only by
// its enrollment snapshot (no session row yet), which used to fall back to a
// bare ErrTargetIneligible naming nobody and recording no capability hold.
func TestSiteRuntimeV2RefusalNamesEveryNodeBelowV6(t *testing.T) {
	required := []*agentv1.Capability{
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: edgeconfig.ListenerRuntimeSecuritySiteRuntimeVersion},
		{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 1},
	}
	withSiteRuntime := func(version uint32) []*agentv1.Capability {
		return []*agentv1.Capability{
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: version},
			{Name: agentv1.CapabilityName_CAPABILITY_NAME_WAF, ApiVersion: 1},
		}
	}
	session := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	enrolled := uuid.MustParse("00000000-0000-4000-8000-000000000002")
	ready := uuid.MustParse("00000000-0000-4000-8000-000000000003")
	advertised := map[uuid.UUID][]*agentv1.Capability{session: withSiteRuntime(5), enrolled: withSiteRuntime(5), ready: withSiteRuntime(6)}
	sessions := map[uuid.UUID]*agentv1.AgentCapabilities{
		session: {AgentVersion: "1.0.35-old", Features: withSiteRuntime(5)},
		ready:   {AgentVersion: "1.0.35", Features: withSiteRuntime(6)},
	}
	if err := validateSiteRuntimeV2TargetCapabilities(required, false, advertised, nil); !errors.Is(err, ErrTargetIneligible) {
		t.Fatalf("v5 targets accepted: %v", err)
	}
	err := siteRuntimeV2CapabilityRefusal([]uuid.UUID{ready, session, enrolled}, required, advertised, sessions)
	var refusal *TargetCapabilityError
	if !errors.As(err, &refusal) || !errors.Is(err, ErrTargetIneligible) || refusal.NodeID != session ||
		refusal.AgentVersion != "1.0.35-old" || refusal.Required != 6 || refusal.Advertised != 5 ||
		len(refusal.OtherNodeIDs) != 1 || refusal.OtherNodeIDs[0] != enrolled ||
		!strings.Contains(err.Error(), "1.0.35 website runtime") || !strings.Contains(err.Error(), enrolled.String()) ||
		strings.Contains(err.Error(), ready.String()) {
		t.Fatalf("refusal = %v (%+v)", err, refusal)
	}
	// Only the enrollment-only node lacks v6: it is the one named.
	err = siteRuntimeV2CapabilityRefusal([]uuid.UUID{ready, enrolled}, required, advertised, sessions)
	if !errors.As(err, &refusal) || refusal.NodeID != enrolled || refusal.AgentVersion != "" || len(refusal.OtherNodeIDs) != 0 {
		t.Fatalf("enrollment-only refusal = %v (%+v)", err, refusal)
	}
	if err := siteRuntimeV2CapabilityRefusal([]uuid.UUID{ready}, required, advertised, sessions); err != nil {
		t.Fatalf("v6 node refused: %v", err)
	}
	// A shortfall no gated feature explains (here: no WAF) is left to the
	// caller's generic refusal.
	advertised[enrolled] = []*agentv1.Capability{{Name: agentv1.CapabilityName_CAPABILITY_NAME_SITE_RUNTIME, ApiVersion: 6}}
	if err := siteRuntimeV2CapabilityRefusal([]uuid.UUID{ready, enrolled}, required, advertised, sessions); err != nil {
		t.Fatalf("ungated shortfall named as a gated feature: %v", err)
	}
}
