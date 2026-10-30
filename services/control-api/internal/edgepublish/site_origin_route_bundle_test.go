package edgepublish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

func TestSITE05060708ConditionalOriginFactsEnterSignedSiteRuntimeBundle(t *testing.T) {
	scopeID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7101")
	configID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7102")
	siteID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103")
	const identity = "sha256:8b5e6f57d8f47ec690b6e1e0ef2fd5d7fa6ef74d8d17eb9e9fc2f0901e21a61d"
	targetNodeID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7106")
	identityDigest := sha256.Sum256([]byte("l1-target-identity"))
	topology := &L2TopologySnapshot{Revision: 7, TargetIdentities: []L2TopologyIdentity{{
		NodeID: targetNodeID, MTLSIdentitySHA256: identityDigest,
	}}}
	fact := siteOriginRouteFact{siteID: siteID, siteRevision: 7, document: siteOriginRouteDocument{
		Schema: siteOriginRouteSchemaV1, IngressSourceEnabled: true,
		Pools: []siteOriginRoutePool{
			{ID: "primary", Kind: "origin", BalanceMethod: "round_robin", Endpoints: []siteOriginRouteEndpoint{
				{ID: "origin-a", Tier: "origin", Host: "192.0.2.10", Port: 443, Weight: 100},
			}},
			{ID: "l2", Kind: "l2", BalanceMethod: "least_conn", Endpoints: []siteOriginRouteEndpoint{
				{ID: "l2-a", Tier: "l2", NodeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7105", TopologyRevision: 7,
					MTLSIdentitySHA256: identity, Host: "2001:db8::10", Port: 8080, Weight: 100},
			}},
		},
		DefaultPoolID: "l2", DefaultFallbackPoolID: "primary",
		Routes: []siteOriginRoute{{
			ID: "private", Priority: 100, PathPrefix: "/private", NodeRegions: []string{"cn-east"},
			ClientCIDRs: []string{"203.0.113.0/24", "2001:db8:1::/48"}, PoolID: "l2", FallbackPoolID: "primary",
		}},
		Retry: siteOriginRouteRetry{
			Methods: []string{"GET", "HEAD"}, MaxAttempts: 3,
			ConnectTimeoutMS: 1000, ReadTimeoutMS: 2000, TotalBudgetMS: 6000,
		},
	}}

	originRoutes, err := compileSiteOriginRouteBundleWithTopology(scopeID, configID, 41, []siteOriginRouteFact{fact}, topology)
	if err != nil {
		t.Fatalf("compileSiteOriginRouteBundle() error = %v", err)
	}
	wire, err := marshalSiteRuntimeV2BundleWithOriginRoutes(
		siteRuntimeV2DocumentFixture(), nil, originRoutes,
	)
	if err != nil {
		t.Fatalf("marshalSiteRuntimeV2BundleWithOriginRoutes() error = %v", err)
	}
	bundle, err := edgeconfig.UnmarshalBundle(wire)
	if err != nil {
		t.Fatalf("UnmarshalBundle() error = %v", err)
	}
	got, ok := bundle.Files[siteOriginRouteBundlePath]
	if !ok || !bytes.Equal(got, originRoutes) {
		t.Fatalf("signed bundle origin-route file = %q, present=%v", got, ok)
	}
	var document siteOriginRouteBundleDocument
	if err := json.Unmarshal(got, &document); err != nil {
		t.Fatal(err)
	}
	if document.Schema != siteOriginRouteBundleSchema || document.ConfigurationScopeID != scopeID.String() ||
		document.ConfigVersionID != configID.String() || document.SourceRevision != 41 || len(document.Sites) != 1 ||
		len(document.Targets) != 1 || document.Targets[0].NodeID != targetNodeID.String() ||
		document.Targets[0].TopologyRevision != 7 || document.Targets[0].MTLSIdentitySHA256 != "sha256:"+hex.EncodeToString(identityDigest[:]) ||
		document.Sites[0].SiteID != siteID.String() || document.Sites[0].SiteRevision != 7 ||
		len(document.Sites[0].Document.Routes) != 1 ||
		document.Sites[0].Document.Routes[0].FallbackPoolID != "primary" ||
		!document.Sites[0].Document.IngressSourceEnabled ||
		document.Sites[0].Document.Retry.TotalBudgetMS != 6000 {
		t.Fatalf("origin-route identity or policy facts were lost: %+v", document)
	}

	changed := fact
	changed.document.Routes = append([]siteOriginRoute(nil), fact.document.Routes...)
	changed.document.Routes[0].Priority++
	changedRoutes, err := compileSiteOriginRouteBundleWithTopology(scopeID, configID, 41, []siteOriginRouteFact{changed}, topology)
	if err != nil {
		t.Fatal(err)
	}
	changedWire, err := marshalSiteRuntimeV2BundleWithOriginRoutes(
		siteRuntimeV2DocumentFixture(), nil, changedRoutes,
	)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(originRoutes, changedRoutes) || sha256.Sum256(wire) == sha256.Sum256(changedWire) {
		t.Fatal("route mutation did not change the canonical signed bundle identity")
	}
}

func TestSITE05OriginRouteBundleRejectsCrossScopeOrNonCanonicalFacts(t *testing.T) {
	scopeID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7101")
	configID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7102")
	siteID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103")
	valid := siteOriginRouteFact{siteID: siteID, siteRevision: 1, document: siteOriginRouteDocument{
		Schema: siteOriginRouteSchemaV1,
		Pools: []siteOriginRoutePool{{ID: "primary", BalanceMethod: "round_robin",
			Endpoints: []siteOriginRouteEndpoint{{ID: "origin", Host: "192.0.2.10", Port: 80, Weight: 1}}}},
		DefaultPoolID: "primary", Routes: []siteOriginRoute{},
		Retry: siteOriginRouteRetry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 1,
			ConnectTimeoutMS: 1000, ReadTimeoutMS: 1000, TotalBudgetMS: 2000},
	}}

	tests := []struct {
		name   string
		mutate func(*siteOriginRouteFact)
	}{
		{"nil site", func(value *siteOriginRouteFact) { value.siteID = uuid.Nil }},
		{"invalid revision", func(value *siteOriginRouteFact) { value.siteRevision = 0 }},
		{"noncanonical document", func(value *siteOriginRouteFact) { value.document.Pools[0].Endpoints[0].Host = "192.0.2.010" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			value.document.Pools = append([]siteOriginRoutePool(nil), valid.document.Pools...)
			value.document.Pools[0].Endpoints = append([]siteOriginRouteEndpoint(nil), valid.document.Pools[0].Endpoints...)
			test.mutate(&value)
			if _, err := compileSiteOriginRouteBundle(scopeID, configID, 1, []siteOriginRouteFact{value}); err == nil {
				t.Fatal("invalid origin-route fact was accepted")
			}
		})
	}
	if _, err := compileSiteOriginRouteBundle(uuid.Nil, configID, 1, []siteOriginRouteFact{valid}); err == nil {
		t.Fatal("nil scope was accepted")
	}

	valid.document.Routes = []siteOriginRoute{
		{ID: "root", Priority: 1, PathPrefix: "/", PoolID: "primary"},
		{ID: "region", Priority: 1, NodeRegions: []string{"cn-east"}, PoolID: "primary"},
	}
	ordered, err := normalizeSiteOriginRouteDocument(valid.document)
	if err != nil || len(ordered.Routes) != 2 || ordered.Routes[0].ID != "region" {
		t.Fatalf("root path changed the frozen route precedence: %+v, err=%v", ordered.Routes, err)
	}
}

func TestSITE050708OriginRouteBundleRequiresL2TopologyIdentity(t *testing.T) {
	const identity = "sha256:8b5e6f57d8f47ec690b6e1e0ef2fd5d7fa6ef74d8d17eb9e9fc2f0901e21a61d"
	valid := siteOriginRouteDocument{
		Schema: siteOriginRouteSchemaV1,
		Pools: []siteOriginRoutePool{
			{ID: "primary", Kind: "origin", BalanceMethod: "round_robin", Endpoints: []siteOriginRouteEndpoint{
				{ID: "origin-a", Tier: "origin", Host: "192.0.2.10", Port: 8080, Weight: 100},
			}},
			{ID: "l2", Kind: "l2", BalanceMethod: "least_conn", Endpoints: []siteOriginRouteEndpoint{
				{ID: "l2-a", Tier: "l2", NodeID: "018f47a2-5b9c-7d31-8a60-104c9c0b7105", TopologyRevision: 7,
					MTLSIdentitySHA256: identity, Host: "2001:db8::10", Port: 8080, Weight: 100},
			}},
		},
		DefaultPoolID: "l2", DefaultFallbackPoolID: "primary",
		Routes: []siteOriginRoute{{ID: "private", Priority: 10, PathPrefix: "/private", PoolID: "l2", FallbackPoolID: "primary"}},
		Retry: siteOriginRouteRetry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 3,
			ConnectTimeoutMS: 1000, ReadTimeoutMS: 2000, TotalBudgetMS: 6000},
	}
	normalized, err := normalizeSiteOriginRouteDocument(valid)
	if err != nil || normalized.Pools[0].Kind != "l2" && normalized.Pools[1].Kind != "l2" {
		t.Fatalf("valid topology-bound L2 document = %+v, %v", normalized, err)
	}

	tests := []struct {
		name   string
		mutate func(*siteOriginRouteEndpoint)
	}{
		{"node id", func(value *siteOriginRouteEndpoint) { value.NodeID = "" }},
		{"tier", func(value *siteOriginRouteEndpoint) { value.Tier = "" }},
		{"topology revision", func(value *siteOriginRouteEndpoint) { value.TopologyRevision = 0 }},
		{"mTLS identity", func(value *siteOriginRouteEndpoint) { value.MTLSIdentitySHA256 = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.Pools = append([]siteOriginRoutePool(nil), valid.Pools...)
			candidate.Pools[1].Endpoints = append([]siteOriginRouteEndpoint(nil), valid.Pools[1].Endpoints...)
			test.mutate(&candidate.Pools[1].Endpoints[0])
			if _, err := normalizeSiteOriginRouteDocument(candidate); err == nil {
				t.Fatal("incomplete L2 topology identity was accepted")
			}
		})
	}
}

func TestSITE04BasicSiteOriginsBecomeOriginRoutePolicy(t *testing.T) {
	// Basic site persistence has no site_origin_route_* rows, but it must still
	// publish the same signed policy contract consumed by the health-aware path.
	site := siteRuntimeV2Site{
		ID: "018f47a2-5b9c-7d31-8a60-104c9c0b7103", Revision: 7, DefaultPoolID: "primary",
		OriginPools: []siteRuntimeV2OriginPool{
			{ID: "primary", Position: 0, Kind: "origin", Algorithm: "", Origins: []siteRuntimeV2Origin{
				{ID: "origin-ip", Position: 0, Tier: "origin", Host: "192.0.2.10", Port: 8080, Weight: 80},
				{ID: "origin-dns", Position: 1, Tier: "origin", Host: "origin.example.com", Port: 8080, Weight: 20},
			}, Retry: siteRuntimeV2RetryPolicy{Methods: []string{"GET", "HEAD"}, BodylessOnly: boolPtr(true), ResponseNotStarted: boolPtr(true),
				RetryOn: []string{"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"}, MaxAttempts: 2, ConnectTimeoutMS: 1000, ReadTimeoutMS: 2000, TotalBudgetMS: 6000}},
		},
	}
	fact, err := basicSiteOriginRouteFact(site)
	if err != nil {
		t.Fatalf("basicSiteOriginRouteFact() error = %v", err)
	}
	if fact.document.Pools[0].BalanceMethod != "round_robin" {
		t.Fatalf("empty basic algorithm = %q, want round_robin", fact.document.Pools[0].BalanceMethod)
	}
	if got := fact.document.Pools[0].Endpoints[0].Host; got != "origin.example.com" {
		t.Fatalf("domain endpoint = %q", got)
	}
	if _, err := compileSiteOriginRouteBundle(
		uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7101"),
		uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7102"), 41, []siteOriginRouteFact{fact},
	); err != nil {
		t.Fatalf("compile mixed basic origin route = %v", err)
	}
}

func TestSITE04OriginRouteHostRejectsUnsafeAndNonFQDNHosts(t *testing.T) {
	for _, host := range []string{"localhost", "*.origin.example.com", "origin.example.com.", "0.0.0.0", "192.0.2.010"} {
		t.Run(host, func(t *testing.T) {
			if _, err := normalizeSiteOriginRouteHost(host); err == nil {
				t.Fatalf("normalizeSiteOriginRouteHost(%q) accepted unsafe host", host)
			}
		})
	}
	for _, host := range []string{"ORIGIN.EXAMPLE.COM", "origin.example.com"} {
		got, err := normalizeSiteOriginRouteHost(host)
		if err != nil || got != strings.ToLower(strings.TrimSuffix(host, ".")) {
			t.Fatalf("normalizeSiteOriginRouteHost(%q) = %q, %v", host, got, err)
		}
	}
}

func boolPtr(value bool) *bool { return &value }

// TestA15StoredConditionalOriginDNSEndpointsRenderForTheNode (Codex A15): a
// saved conditional-origin document with DNS endpoints (now storable, 485)
// compiles into the signed origin-route bundle unchanged and becomes the
// node's site-object origin pool with the DNS host, beside an IP endpoint.
func TestA15StoredConditionalOriginDNSEndpointsRenderForTheNode(t *testing.T) {
	site := siteRuntimeV2Site{
		ID: "018f47a2-5b9c-7d31-8a60-104c9c0b7103", Revision: 9, DefaultPoolID: "primary",
		L2: siteRuntimeV2L2Policy{Enabled: boolPtr(false)},
		OriginPools: []siteRuntimeV2OriginPool{
			{ID: "primary", Position: 0, Kind: "origin", Algorithm: "round_robin", Origins: []siteRuntimeV2Origin{
				{ID: "origin-0", Position: 0, Tier: "origin", Scheme: "http", Host: "192.0.2.10", Port: 80, Weight: 100},
			}, Retry: siteRuntimeV2RetryPolicy{Methods: []string{"GET", "HEAD"}, BodylessOnly: boolPtr(true), ResponseNotStarted: boolPtr(true),
				RetryOn:     []string{"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"},
				MaxAttempts: 2, ConnectTimeoutMS: 1000, ReadTimeoutMS: 2000, TotalBudgetMS: 6000}},
		},
	}
	stored := siteOriginRouteDocument{Schema: siteOriginRouteSchemaV1, DefaultPoolID: "default",
		Pools: []siteOriginRoutePool{{ID: "default", BalanceMethod: "least_conn", Endpoints: []siteOriginRouteEndpoint{
			{ID: "origin-01", Host: "origin.example.test", Port: 443, Weight: 10},
			{ID: "origin-02", Host: "2001:db8::20", Port: 80, Weight: 5},
		}}},
		Routes: []siteOriginRoute{},
		Retry:  siteOriginRouteRetry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 2, ConnectTimeoutMS: 1000, ReadTimeoutMS: 2000, TotalBudgetMS: 5000},
	}
	normalized, err := normalizeSiteOriginRouteDocument(stored)
	if err != nil {
		t.Fatalf("stored DNS document rejected: %v", err)
	}
	fact := siteOriginRouteFact{siteID: uuid.MustParse(site.ID), siteRevision: site.Revision, document: normalized}
	wire, err := compileSiteOriginRouteBundle(uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7101"),
		uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7102"), 41, []siteOriginRouteFact{fact})
	if err != nil {
		t.Fatalf("compile DNS origin route = %v", err)
	}
	var bundle siteOriginRouteBundleDocument
	if err := json.Unmarshal(wire, &bundle); err != nil {
		t.Fatal(err)
	}
	endpoints := bundle.Sites[0].Document.Pools[0].Endpoints
	if len(endpoints) != 2 || endpoints[0].Host != "origin.example.test" || endpoints[0].Tier != "origin" || endpoints[1].Host != "2001:db8::20" {
		t.Fatalf("bundle endpoints = %+v", endpoints)
	}
	raw, err := json.Marshal(bundle.Sites[0].Document)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := convertSiteOriginV2(site, raw, nil)
	if err != nil {
		t.Fatalf("convertSiteOriginV2() error = %v", err)
	}
	for _, pool := range origin.Pools {
		if pool.ID != "default" {
			continue
		}
		if pool.Algorithm != "least_conn" || len(pool.Endpoints) != 2 || pool.Endpoints[0].Host != "origin.example.test" ||
			pool.Endpoints[0].Port != 443 || pool.Endpoints[0].Scheme != "http" {
			t.Fatalf("node DNS origin pool = %+v", pool)
		}
		if origin.DefaultPoolID != "default" {
			t.Fatalf("default pool = %q", origin.DefaultPoolID)
		}
		return
	}
	t.Fatalf("node origin lacks the conditional default pool: %+v", origin.Pools)
}
