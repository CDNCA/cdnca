package edgepublish

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/cdnca/cdnca/libs/edgeconfig/siteobject"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
	"github.com/cdnca/cdnca/services/control-api/internal/securitypolicy"
	"github.com/google/uuid"
)

var (
	richScopeID  = uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	richTenantID = uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	goldenTenant = uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7d01")
)

func goldenPublication(t *testing.T, configID uuid.UUID, count, policies int) siteObjectsV2Source {
	t.Helper()
	stateRoot := filepath.Join(t.TempDir(), "edge")
	return mustSiteObjectsV2Source(t, goldenSiteRuntimeV2ReleaseWith(t, configID, 41, count, stateRoot, policies))
}

func mustSiteObjectsV2Source(t *testing.T, bundle edgeconfig.Bundle) siteObjectsV2Source {
	t.Helper()
	source, err := siteObjectsV2SourceFromBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return source
}

// richSiteRuntimeV2Publication compiles count sites whose security comes from
// the production compiler (siteRuntimeV2ListenerSecurity): a WAF policy with
// a managed WAF, a header rule and a rule for port 8443 only, an ACL policy,
// a JS challenge; every ccEvery-th site also binds CC on both ports
// (the CC v2 registry holds at most 1000 listeners per scope). Each site has
// a plain (8080) and a TLS (8443) listener, a cache policy, a package
// connection limit, forced HTTPS and an origin keepalive override.
func richSiteRuntimeV2Publication(t *testing.T, offset, count, ccEvery int) siteObjectsV2Source {
	t.Helper()
	return mustSiteObjectsV2Source(t, richSiteRuntimeV2Bundle(t, offset, count, ccEvery, nil))
}

// richSiteRuntimeV2Bundle is richSiteRuntimeV2Publication's release; mutate
// (may be nil) edits each site after its security is compiled.
func richSiteRuntimeV2Bundle(t *testing.T, offset, count, ccEvery int, mutate func(int, *siteRuntimeV2Site)) edgeconfig.Bundle {
	t.Helper()
	var base siteRuntimeV2Document
	if err := json.Unmarshal(siteRuntimeV2DocumentFixture(), &base); err != nil {
		t.Fatal(err)
	}
	template := base.Sites[0]
	disabled := false
	template.L2.Enabled, template.L2.DirectFallbackPoolID = &disabled, nil
	template.OriginPools = template.OriginPools[:1]
	template.DefaultPoolID = template.OriginPools[0].ID
	idle := int64(60000)
	template.OriginPools[0].KeepaliveIdleTimeoutMS = &idle
	plain := template.Listeners[0]
	plain.ID, plain.Port, plain.Protocols, plain.TLS = "public-8080", 8080, []string{"http1"}, nil
	tls := template.Listeners[0]
	tls.ID, tls.Position, tls.Port = "public-8443", 1, 8443
	document := siteRuntimeV2Document{Schema: siteRuntimeV2Schema, ConfigurationScopeID: richScopeID.String(),
		SourceRevision: 41, ConfigVersionID: "018f47a2-5b9c-7d31-8a60-104c9c0b7e10"}
	challengePolicy := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	for index := offset; index < offset+count; index++ {
		siteID := uuid.MustParse(fmt.Sprintf("11111111-1111-4111-8111-%012x", 0x100000+index))
		fact := siteRuntimeSecurityTestFact(siteID)
		fact.domain = fmt.Sprintf("r%05d.example.test", index)
		fact.domains = []string{fact.domain, "*.img." + fact.domain}
		fact.challenge = &challengeBindingFact{tenantScopeID: richScopeID, siteID: siteID, host: fact.domain,
			policyID: challengePolicy, policyRevision: 7, bindingRevision: 2, secretConfigVersionID: uuid.New()}
		acl := securityPolicyForEdgeTest(siteID, securitypolicy.KindACL, securitypolicy.ActionAllow, []securitypolicy.Rule{{
			ID: uuid.NewSHA1(siteID, []byte("acl-rule")), Name: "deny net", Priority: 1, Enabled: true,
			Conditions: []securitypolicy.Condition{{Field: "client_ip", Operator: "ip_in_cidr", Values: []string{"203.0.113.0/24"}}},
			Action:     securitypolicy.ActionBlock, Flow: securitypolicy.FlowStop,
		}})
		waf := managedWAFPolicyForEdgeTest(siteID)
		waf.Rules = append(slices.Clone(waf.Rules), securitypolicy.Rule{
			ID: uuid.NewSHA1(siteID, []byte("tls-rule")), Name: "tls only", Priority: 3, Enabled: true,
			Conditions: []securitypolicy.Condition{
				{Field: "port", Operator: "number_eq", Values: []string{"8443"}},
				{Field: "path", Operator: "prefix", Values: []string{"/admin"}},
			},
			Action: securitypolicy.ActionBlock, Flow: securitypolicy.FlowContinue,
		})
		bindings := []securityBindingFact{
			securityBindingForEdgeTest(t, waf, siteID, 2),
			securityBindingForEdgeTest(t, acl, siteID, 3),
		}
		site := template
		site.ID, site.Revision, site.Domains = siteID.String(), int64(1+index%5), slices.Clone(fact.domains)
		site.Listeners = []siteRuntimeV2Listener{plain, tls}
		var cc *edgeconfig.CCV2SiteBinding
		if ccEvery > 0 && index%ccEvery == 0 {
			cc = richCCBinding(t, richScopeID.String(), siteID.String())
		}
		for listenerIndex := range site.Listeners {
			listener := &site.Listeners[listenerIndex]
			security, err := siteRuntimeV2ListenerSecurity(richScopeID, richTenantID, fact, uint16(listener.Port), bindings)
			if err != nil {
				t.Fatal(err)
			}
			security.CC = cc
			listener.Security = security
		}
		site.Cache = &edgeconfig.SiteRuntimeCache{TenantID: richTenantID.String(), Domain: fact.domain,
			Policy: edgeconfig.CachePolicyDocument{Revision: 4, Mode: edgeconfig.CacheOverride, QueryMode: edgeconfig.CacheQueryPreserve,
				DiskQuotaBytes: 128 << 20, Rules: []edgeconfig.CacheRuleDocument{{Order: 1, Extensions: []string{".css", ".js"}, TTLSeconds: 3600}},
				QueryNames: []string{}, VaryHeaders: []string{}}}
		site.PackageLimits = &edgeconfig.PackageConnectionLimit{SubscriptionID: uuid.NewSHA1(siteID, []byte("subscription")).String(), Connections: 200,
			MaxConnections: 10, NewPerSecond: 5, QPS: 100}
		site.ForceHTTPS = &siteRuntimeV2ForceHTTPS{RedirectPort: 8443}
		if mutate != nil {
			mutate(index, &site)
		}
		document.Sites = append(document.Sites, site)
	}
	document.RequiredCapabilities = []siteRuntimeV2Capability{{Name: "site_runtime", APIVersion: edgeconfig.MinSiteRuntimeVersion}}
	setSiteRuntimeV2SecurityCapabilities(&document)
	for _, name := range []string{"http1", "http2", "http3", "ipv4", "ipv6", "subscription_limits", "websocket"} {
		document.RequiredCapabilities = append(document.RequiredCapabilities, siteRuntimeV2Capability{Name: name, APIVersion: 1})
	}
	slices.SortFunc(document.RequiredCapabilities, func(left, right siteRuntimeV2Capability) int { return strings.Compare(left.Name, right.Name) })
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, _, _, err := compileSiteRuntimeV2Document(raw)
	if err != nil {
		t.Fatalf("compileSiteRuntimeV2Document: %v", err)
	}
	rules, err := securitypolicy.EdgeCRSRuleText(*rulecatalog.CRSRulesBundle())
	if err != nil {
		t.Fatal(err)
	}
	crs, err := siteRuntimeV2CRSFiles(canonical, rules, crsProfilesForEdgeTest(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := buildSiteRuntimeV2Bundle(canonical, nil, nil, nil, nil, crs)
	if err != nil {
		t.Fatalf("buildSiteRuntimeV2Bundle: %v", err)
	}
	return bundle
}

func richCCBinding(t *testing.T, scopeID, siteID string) *edgeconfig.CCV2SiteBinding {
	t.Helper()
	policy := edgeconfig.CCV2Policy{
		SchemaVersion: edgeconfig.CCV2SchemaVersion, TenantScopeID: scopeID, SiteID: siteID,
		PolicyID: "cc200000-0000-4000-8000-000000000001", PolicyVersion: 1,
		BindingID: "cc200000-0000-4000-8000-000000000002", BindingRevision: 1,
		PublicationID: "cc200000-0000-4000-8000-000000000003", Enabled: true,
		TrustedProxies: []string{}, Allowlist: []string{},
		Rules: []edgeconfig.CCV2Rule{{
			RuleID: "cc200000-0000-4000-8000-000000000004", Priority: 10, Flow: edgeconfig.CCV2FlowStop,
			Match:     edgeconfig.CCV2Match{Path: &edgeconfig.CCV2PathMatch{Kind: edgeconfig.CCV2PathPrefix, Value: "/limited"}},
			Dimension: edgeconfig.CCV2DimensionClientIP,
			Limit:     edgeconfig.CCV2Limit{Algorithm: edgeconfig.CCV2AlgorithmFixedWindow, Requests: 2, WindowSeconds: 60},
			Action:    edgeconfig.CCV2Action{Kind: edgeconfig.CCV2ActionTemporaryBan, BanSeconds: 120},
		}},
	}
	canonical, err := edgeconfig.CanonicalCCV2Policy(policy)
	if err != nil {
		t.Fatal(err)
	}
	return &edgeconfig.CCV2SiteBinding{SourceSHA256: strings.Repeat("a", 64), CompiledSHA256: siteobject.Digest(canonical), Policy: policy}
}

// Every site of control's golden release (HTTP policies, firewall actions,
// origin routes, telemetry with capture and package subscriptions) converts,
// encodes canonically and keeps its references resolvable.
func TestSiteObjectsV2FromGoldenRelease(t *testing.T) {
	publication := goldenPublication(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 30, 30)
	objects, err := buildSiteObjectsV2(publication, goldenTenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(objects.Sites) != 30 {
		t.Fatalf("%d site objects", len(objects.Sites))
	}
	withHTTP, withFirewall, withTelemetry, withSubscription := 0, 0, 0, 0
	for _, object := range objects.Sites {
		decoded, err := edgesite.Decode(object.Plaintext)
		if err != nil || edgesite.Digest(object.Plaintext) != object.SHA256 {
			t.Fatalf("site %s: %v", object.SiteID, err)
		}
		site := decoded
		for _, ref := range siteObjectV2Refs(site) {
			if ref.SHA256 != "" && objects.Referenced[ref.SHA256] == nil {
				t.Fatalf("site %s: %s %s is not among the referenced objects", site.SiteID, ref.Kind, ref.SHA256)
			}
		}
		if site.HTTP != nil {
			withHTTP++
			if site.Limits.MaxBodyBytes != 1024 {
				t.Fatalf("HTTP policy upload limit %d", site.Limits.MaxBodyBytes)
			}
		} else if site.Limits.MaxBodyBytes != 0 {
			t.Fatalf("a site without HTTP policy has its own body limit %d", site.Limits.MaxBodyBytes)
		}
		if site.Security.FirewallAction != nil {
			withFirewall++
		}
		if site.Telemetry != nil {
			withTelemetry++
			if site.Telemetry.PackageSubscriptionID != "" {
				withSubscription++
			}
		}
		if site.Hosts.Primary == "" || len(site.Hosts.Aliases) != 1 || len(site.Origin.Pools) != 1 {
			t.Fatalf("site %s hosts/origin: %+v %+v", site.SiteID, site.Hosts, site.Origin)
		}
	}
	if withHTTP != 10 || withFirewall != 8 || withTelemetry != 30 || withSubscription != 15 {
		t.Fatalf("http %d firewall %d telemetry %d subscription %d", withHTTP, withFirewall, withTelemetry, withSubscription)
	}
	if len(objects.Ports) != 1 || objects.Ports[0] != (edgesite.PortProfile{Port: 443, TLS: true, HTTP2: true, HTTP3: true,
		IPv4: true, IPv6: true, SiteCount: 30}) {
		t.Fatalf("ports %+v", objects.Ports)
	}
}

func siteObjectV2Refs(site edgesite.Site) []edgesite.Ref {
	var refs []edgesite.Ref
	for _, binding := range site.Security.CC {
		refs = append(refs, binding.Policy)
	}
	for _, ref := range []*edgesite.Ref{site.HTTP, site.Security.FirewallAction, site.Security.Challenge} {
		if ref != nil {
			refs = append(refs, *ref)
		}
	}
	return refs
}

// Same sites, same digests: twice from one publication, and across
// publications that differ only in config version and source revision.
func TestSiteObjectsV2DigestsAreStableAcrossPublications(t *testing.T) {
	first, err := buildSiteObjectsV2(goldenPublication(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 30, 30), goldenTenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	again, err := buildSiteObjectsV2(goldenPublication(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 30, 30), goldenTenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := buildSiteObjectsV2(goldenPublication(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e02"), 30, 30), goldenTenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := range first.Sites {
		if first.Sites[index].SHA256 != again.Sites[index].SHA256 || first.Sites[index].SHA256 != other.Sites[index].SHA256 {
			t.Fatalf("site %s digest changed", first.Sites[index].SiteID)
		}
	}
	if fmt.Sprint(keys(first.Referenced)) != fmt.Sprint(keys(other.Referenced)) {
		t.Fatal("referenced objects changed with only the config version")
	}
}

func keys(values map[string][]byte) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	slices.Sort(result)
	return result
}

// Security compiled per listener by the production compiler becomes one
// site plan that decides each port as that port's v7 listener does.
func TestSiteObjectsV2SecurityFromProductionCompiler(t *testing.T) {
	publication := richSiteRuntimeV2Publication(t, 0, 3, 1)
	objects, err := buildSiteObjectsV2(publication, richTenantID, nil)
	if err != nil {
		t.Fatal(err)
	}
	runtimes := siteRuntimesByID(t, publication)
	for _, object := range objects.Sites {
		site, runtime := object.Site, runtimes[object.SiteID]
		security := site.Security
		if len(security.Rules.Policies) != 2 || security.Rules.HeaderOverflow != edgesite.HeaderOverflowBlock ||
			security.ManagedWAF == nil || security.Challenge == nil || security.Challenge.Revision != 7 ||
			len(security.CC) != 1 || !slices.Equal(security.CC[0].Ports, []int{8080, 8443}) {
			t.Fatalf("security %+v", security)
		}
		for _, listener := range runtime.Listeners {
			for policyIndex, policy := range listener.Security.Policies {
				want, _ := json.Marshal(effectiveRules(t, policy.Rules, uint16(listener.Port)))
				got, _ := json.Marshal(effectiveRules(t, security.Rules.Policies[policyIndex].Rules, uint16(listener.Port)))
				if !bytes.Equal(got, want) {
					t.Fatalf("site %s port %d %s policy differs:\nv2 %s\nv7 %s", site.SiteID, listener.Port, policy.Kind, got, want)
				}
			}
		}
		// ACL rules hold on both ports: once, port-free. The WAF policy has a
		// rule for 8443 only: every rule pinned to its listener's port.
		acl, waf := security.Rules.Policies[0], security.Rules.Policies[1]
		if acl.Kind != edgeconfig.SecurityACL || len(acl.Rules) != 1 || acl.Rules[0].Match.Port != 0 ||
			waf.Kind != edgeconfig.SecurityWAF || len(waf.Rules) != 3 || waf.Rules[0].Match.Port != 8080 ||
			waf.Rules[1].Match.Port != 8443 || waf.Rules[2].Match.Port != 8443 || waf.Rules[2].Match.Path == nil {
			t.Fatalf("plan %+v", security.Rules)
		}
		if site.Cache == nil || site.Cache.KeyPrefix != edgesite.CacheKeyPrefix(richTenantID.String(), site.SiteID) ||
			site.Limits.Connections == nil || site.Limits.Connections.Max != 200 ||
			site.Limits.Connections.MaxConnections != 10 || site.Limits.Connections.NewPerSecond != 5 || site.Limits.Connections.QPS != 100 || site.ForceHTTPS == nil ||
			site.Origin.Pools[0].KeepaliveIdleTimeoutMS == nil || site.Hosts.Aliases[0] != "*.img."+site.Hosts.Primary {
			t.Fatalf("site %+v", site)
		}
		tlsEndpoint := site.Origin.Pools[0].Endpoints[0]
		if tlsEndpoint.Scheme != "https" || tlsEndpoint.SNI != "origin.example.test" || !strings.HasPrefix(tlsEndpoint.TrustAnchor, "sha256:") {
			t.Fatalf("TLS endpoint %+v", tlsEndpoint)
		}
		if object.Site.Security.CC[0].Policy.SHA256 == "" || objects.Referenced[object.Site.Security.CC[0].Policy.SHA256] == nil {
			t.Fatal("CC policy is not referenced")
		}
	}
	if len(objects.Ports) != 2 || objects.Ports[0].TLS || !objects.Ports[1].HTTP2 || !objects.Ports[1].HTTP3 {
		t.Fatalf("ports %+v", objects.Ports)
	}
}

// effectiveRules is the rules that can match on port (port-free or pinned to
// it), in order, with the port condition dropped.
func effectiveRules(t *testing.T, rules []edgeconfig.WAFRule, port uint16) []edgeconfig.WAFRule {
	t.Helper()
	result := []edgeconfig.WAFRule{}
	for _, rule := range rules {
		normalized, err := edgeconfig.NormalizeSecurityRule(rule)
		if err != nil {
			t.Fatal(err)
		}
		if normalized.Match.Port == 0 || normalized.Match.Port == port {
			normalized.Match.Port = 0
			result = append(result, normalized)
		}
	}
	return result
}

func siteRuntimesByID(t *testing.T, source siteObjectsV2Source) map[string]siteRuntimeV2Site {
	t.Helper()
	return source.runtimes()
}

// The origin-route document overrides the pools it names as the agent's
// overlay does; TLS settings stay with their endpoint; a route may not move
// a TLS endpoint; L2 endpoints carry their mTLS identity.
func TestSiteObjectsV2OriginRouteOverlay(t *testing.T) {
	var document siteRuntimeV2Document
	if err := json.Unmarshal(siteRuntimeV2DocumentFixture(), &document); err != nil {
		t.Fatal(err)
	}
	runtime := document.Sites[0]
	route := siteOriginRouteDocument{Schema: siteOriginRouteSchemaV1, DefaultPoolID: "l2", DefaultFallbackPoolID: "primary",
		IngressSourceEnabled: true,
		Pools: []siteOriginRoutePool{
			{ID: "l2", Kind: "l2", BalanceMethod: "least_conn", Endpoints: []siteOriginRouteEndpoint{{ID: "l2-a", Tier: "l2",
				NodeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7105", TopologyRevision: 3, MTLSIdentitySHA256: "sha256:" + strings.Repeat("c", 64),
				Host: "2001:db8::10", Port: 8080, Weight: 100}}},
			{ID: "primary", Kind: "origin", BalanceMethod: "ip_hash", Endpoints: []siteOriginRouteEndpoint{
				{ID: "origin-a", Tier: "origin", Host: "192.0.2.10", Port: 443, Weight: 50}}},
			{ID: "static", Kind: "origin", BalanceMethod: "round_robin", Endpoints: []siteOriginRouteEndpoint{
				{ID: "static-0", Tier: "origin", Host: "static.example.test", Port: 80, Weight: 100}}},
		},
		Routes: []siteOriginRoute{{ID: "static", Priority: 5, PathPrefix: "/static", PoolID: "static", FallbackPoolID: "primary"}},
		Retry:  siteOriginRouteRetry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 2, ConnectTimeoutMS: 1000, ReadTimeoutMS: 2000, TotalBudgetMS: 5000},
	}
	raw, err := json.Marshal(route)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := convertSiteOriginV2(runtime, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(origin.Pools) != 3 || origin.DefaultPoolID != "l2" || origin.DefaultFallbackPoolID != "primary" || !origin.IngressSource ||
		len(origin.Routes) != 1 || origin.L2 == nil || origin.L2.DirectFallbackPoolID != "primary" {
		t.Fatalf("origin %+v", origin)
	}
	primary := origin.Pools[1]
	if primary.Algorithm != "ip_hash" || primary.Retry.MaxAttempts != 2 || primary.Retry.TotalBudgetMS != 5000 ||
		primary.Endpoints[0].Scheme != "https" || primary.Endpoints[0].Weight != 50 || primary.Endpoints[0].SNI != "origin.example.test" {
		t.Fatalf("primary %+v", primary)
	}
	if l2 := origin.Pools[0].Endpoints[0]; l2.MTLSIdentitySHA256 == "" || l2.TopologyRevision != 3 || l2.NodeID == "" {
		t.Fatalf("l2 endpoint %+v", l2)
	}
	moved := route
	moved.Pools = slices.Clone(route.Pools)
	moved.Pools[1].Endpoints = []siteOriginRouteEndpoint{{ID: "origin-a", Tier: "origin", Host: "192.0.2.11", Port: 443, Weight: 50}}
	raw, _ = json.Marshal(moved)
	if _, err := convertSiteOriginV2(runtime, raw, nil); err == nil {
		t.Fatal("a route moved a TLS endpoint to another address")
	}
	if _, err := convertSiteOriginV2(runtime, []byte(`{"schema":"x","unknown":1}`), nil); err == nil {
		t.Fatal("an origin route with an unknown field was accepted")
	}
}

// Facts outside the bundle (error pages, origin auth) enter sorted.
func TestSiteObjectsV2ExternalFacts(t *testing.T) {
	publication := goldenPublication(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e01"), 2, 2)
	plain, err := buildSiteObjectsV2(publication, goldenTenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	siteID := plain.Sites[0].SiteID
	page := []byte("<!doctype html><html><head><title>x</title></head><body><p>x</p></body></html>")
	asset := func(id string) edgesite.Ref {
		return edgesite.Ref{Kind: edgesite.RefErrorPageAsset, ID: id, Revision: 1, SHA256: siteobject.Digest(page)}
	}
	facts := map[string]siteObjectV2Facts{siteID: {
		ErrorAssets: map[string][]byte{siteobject.Digest(page): page},
		ErrorPages: []edgesite.ErrorPage{
			{Category: edgesite.ErrorOriginResponse, Status: 404, RuleID: "11111111-1111-4111-8111-111111111111", MIMEType: "text/html", Asset: asset("11111111-1111-4111-8111-111111111111")},
			{Category: edgesite.ErrorEdgeConnect, Status: 502, RuleID: "22222222-2222-4222-8222-222222222222", MIMEType: "text/html", Asset: asset("22222222-2222-4222-8222-222222222222")},
		},
		OriginAuth: []edgesite.OriginAuth{{PoolID: plain.Sites[0].Site.Origin.DefaultPoolID, Endpoint: "https://bucket.cos.example.test",
			Secret: edgesite.Ref{Kind: edgesite.RefOriginAuthSecret, ID: "33333333-3333-4333-8333-333333333333", Revision: 2}}},
	}}
	withFacts, err := buildSiteObjectsV2(publication, goldenTenant, facts)
	if err != nil {
		t.Fatal(err)
	}
	site := withFacts.Sites[0].Site
	if len(site.Errors) != 2 || site.Errors[0].Category != edgesite.ErrorEdgeConnect || len(site.Origin.Auth) != 1 {
		t.Fatalf("site %+v %+v", site.Errors, site.Origin.Auth)
	}
	if withFacts.Sites[0].SHA256 == plain.Sites[0].SHA256 || withFacts.Sites[1].SHA256 != plain.Sites[1].SHA256 {
		t.Fatal("facts changed the wrong site's digest")
	}
	if !bytes.Equal(withFacts.Referenced[siteobject.Digest(page)], page) {
		t.Fatal("the error page asset is not a referenced object")
	}
	missing := facts[siteID]
	missing.ErrorAssets = nil
	if _, err := buildSiteObjectsV2(publication, goldenTenant, map[string]siteObjectV2Facts{siteID: missing}); err == nil {
		t.Fatal("an error page without its asset was accepted")
	}
	if _, err := buildSiteObjectsV2(publication, uuid.Nil, nil); err == nil {
		t.Fatal("no tenant accepted")
	}
}

// 5000 sites through the v8 split and the v2 conversion. golden: control's
// golden release (HTTP policies on 20 sites, firewall actions, origin
// routes, telemetry), one scope. rich (CDNCA_SITE_OBJECTS_V2_RICH=1, about a
// minute): production-compiled security on two listeners, cache, limits, CC
// on every 10th site; 4.9 KB of v2 document per site, so 5000 exceed the
// 16 MiB v2 document bound and are built as 5 scopes of 1000.
func TestSiteObjectsV2FiveThousandSites(t *testing.T) {
	if testing.Short() {
		t.Skip("5000-site generation")
	}
	type variant struct {
		name   string
		build  func() []siteObjectsV2Source
		tenant uuid.UUID
	}
	variants := []variant{{"golden", func() []siteObjectsV2Source {
		return []siteObjectsV2Source{goldenPublication(t, uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7e03"), 5000, 20)}
	}, goldenTenant}}
	if os.Getenv("CDNCA_SITE_OBJECTS_V2_RICH") == "1" {
		variants = append(variants, variant{"rich", func() []siteObjectsV2Source {
			var publications []siteObjectsV2Source
			for chunk := range 5 {
				publications = append(publications, richSiteRuntimeV2Publication(t, chunk*1000, 1000, 10))
			}
			return publications
		}, richTenantID})
	}
	for _, variant := range variants {
		started := time.Now()
		publications := variant.build()
		v8 := time.Since(started)
		var sites []siteObjectV2
		referenced := map[string][]byte{}
		started = time.Now()
		for _, publication := range publications {
			objects, err := buildSiteObjectsV2(publication, variant.tenant, nil)
			if err != nil {
				t.Fatal(err)
			}
			sites = append(sites, objects.Sites...)
			for digest, content := range objects.Referenced {
				referenced[digest] = content
			}
		}
		v2 := time.Since(started)
		if len(sites) != 5000 {
			t.Fatalf("%d sites", len(sites))
		}
		total, largest := 0, 0
		sizes := make([]int, len(sites))
		for index, site := range sites {
			total += len(site.Plaintext)
			largest = max(largest, len(site.Plaintext))
			sizes[index] = len(site.Plaintext)
		}
		slices.Sort(sizes)
		referencedBytes := 0
		for _, content := range referenced {
			referencedBytes += len(content)
		}
		t.Logf("%s: release compile %v; v2 generate %v (%.1f µs/site); v2 site objects %d B, mean %d B, p50 %d B, max %d B; %d referenced objects %d B",
			variant.name, v8.Round(time.Millisecond), v2.Round(time.Millisecond),
			float64(v2.Microseconds())/5000, total, total/5000, sizes[len(sizes)/2], largest, len(referenced), referencedBytes)
	}
}

// The definition's policy extensions travel from the cache
// policy fact through the canonical site runtime document into the site
// object's cache.policy; slice_bytes changes the generation, the others do not.
func TestSiteObjectsV2CachePolicyCarriesExtensions(t *testing.T) {
	fact := siteRuntimeCacheTestFact()
	policy := *siteRuntimeCachePolicyFacts(fact.id)["rules"]
	convert := func(extensions edgeconfig.CachePolicyDocument) *edgesite.Cache {
		t.Helper()
		policy.extensions = extensions
		document := siteRuntimeCacheTestDocument(t, fact, &policy)
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		canonical, _, _, _, err := compileSiteRuntimeV2Document(raw)
		if err != nil {
			t.Fatalf("document rejected: %v", err)
		}
		var compiled siteRuntimeV2Document
		if err := json.Unmarshal(canonical, &compiled); err != nil {
			t.Fatal(err)
		}
		site := compiled.Sites[0]
		cache, err := convertSiteCacheV2(site, siteRuntimeCacheTestTenant)
		if err != nil {
			t.Fatal(err)
		}
		return cache
	}
	plain := convert(edgeconfig.CachePolicyDocument{})
	extended := edgeconfig.CachePolicyDocument{StaleIfError: true, BackgroundUpdate: true,
		MinObjectBytes: 1 << 10, MaxObjectBytes: 8 << 20}
	stale := convert(extended)
	got := stale.Policy
	if !got.StaleIfError || !got.BackgroundUpdate || got.MinObjectBytes != 1<<10 || got.MaxObjectBytes != 8<<20 || got.SliceBytes != 0 {
		t.Fatalf("site object policy %+v", got)
	}
	if stale.Generation != plain.Generation {
		t.Fatal("stale/background/size bounds changed the cache generation")
	}
	extended.SliceBytes = 1 << 20
	sliced := convert(extended)
	if sliced.Policy.SliceBytes != 1<<20 || sliced.Generation == plain.Generation {
		t.Fatalf("slice policy %+v generation %s (plain %s)", sliced.Policy, sliced.Generation, plain.Generation)
	}
	// The policy encoding carries every extension key.
	encoded, err := json.Marshal(sliced.Policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"stale_if_error":true`, `"background_update":true`, `"min_object_bytes":1024`,
		`"max_object_bytes":8388608`, `"slice_bytes":1048576`} {
		if !bytes.Contains(encoded, []byte(key)) {
			t.Fatalf("policy %s lacks %s", encoded, key)
		}
	}
}
