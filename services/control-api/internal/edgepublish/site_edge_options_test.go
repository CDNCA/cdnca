package edgepublish

import (
	"errors"
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
	"slices"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	"github.com/google/uuid"
)

// site-backend6: the site edit options reach the v2 document and need
// SITE_EDGE_OPTIONS; buffering on and no options add nothing.
func TestSiteEdgeOptionsForwarding(t *testing.T) {
	base := func() originForwardingFact {
		return originForwardingFact{requestHostMode: "visitor", scheme: "http", websocketEnabled: true,
			responseBuffering: true, requestBuffering: true, l2Mode: "package"}
	}
	plain := siteRuntimeV2Site{OriginPools: []siteRuntimeV2OriginPool{{ID: "primary", Kind: "origin"}}}
	fact := base()
	if err := applySiteRuntimeV2OriginForwarding(&plain, 0, siteFact{forwarding: &fact}); err != nil || plain.Forwarding.usesEdgeOptions() {
		t.Fatalf("plain site: %+v %v", plain.Forwarding, err)
	}
	site := siteRuntimeV2Site{DefaultPoolID: "primary", OriginPools: []siteRuntimeV2OriginPool{{ID: "primary", Kind: "origin",
		Retry: siteRuntimeV2RetryPolicy{MaxAttempts: 2}}}}
	fact = base()
	fact.searchEngineOrigin, fact.acmePassthrough, fact.defaultSite = "spider.example.test:8080", true, true
	fact.responseBuffering, fact.requestBuffering = false, false
	if err := applySiteRuntimeV2OriginForwarding(&site, 0, siteFact{forwarding: &fact}); err != nil {
		t.Fatal(err)
	}
	forwarding := site.Forwarding
	if forwarding == nil || forwarding.SearchEnginePoolID == nil || *forwarding.SearchEnginePoolID != "search-engine" ||
		!forwarding.ACMEPassthrough || !forwarding.DefaultSite ||
		!slices.Equal(forwarding.Unbuffered, []string{edgesite.UnbufferedRequest, edgesite.UnbufferedResponse}) {
		t.Fatalf("forwarding %+v", forwarding)
	}
	engine := site.OriginPools[len(site.OriginPools)-1]
	if engine.ID != "search-engine" || engine.Kind != "origin" || len(engine.Origins) != 1 ||
		engine.Origins[0].Host != "spider.example.test" || engine.Origins[0].Port != 8080 || engine.Retry.MaxAttempts != 2 {
		t.Fatalf("search engine pool %+v", engine)
	}
	pools := map[string]siteRuntimeV2OriginPool{}
	for _, pool := range site.OriginPools {
		pools[pool.ID] = pool
	}
	websocket := true
	site.WebSocket = &websocket
	if err := validateSiteRuntimeV2Forwarding(site, pools); err != nil {
		t.Fatalf("valid options refused: %v", err)
	}
	inferred := map[string]uint32{}
	if site.Forwarding.usesEdgeOptions() {
		inferred[edgeconfig.SiteEdgeOptionsCapability] = edgeconfig.SiteEdgeOptionsAPIVersion
	}
	if inferred[edgeconfig.SiteEdgeOptionsCapability] != 1 {
		t.Fatal("the options need SITE_EDGE_OPTIONS v1")
	}
	if name, ok := siteruntimecap.Name(edgeconfig.SiteEdgeOptionsCapability); !ok ||
		name.String() != "CAPABILITY_NAME_SITE_EDGE_OPTIONS" {
		t.Fatalf("capability %v", name)
	}
	site.Forwarding.Unbuffered = []string{edgesite.UnbufferedResponse, edgesite.UnbufferedRequest}
	if validateSiteRuntimeV2Forwarding(site, pools) == nil {
		t.Fatal("unsorted unbuffered accepted")
	}
}

// 网站 L2 配置: package keeps the target topology (or applies the line
// group's L2 configuration), off drops it, custom applies the site's L2
// configuration and is refused when none of its members is an endpoint.
func TestSiteL2Topology(t *testing.T) {
	first, second, other := uuid.New(), uuid.New(), uuid.New()
	topology := &L2TopologySnapshot{Revision: 3, Endpoints: []L2TopologyEndpoint{
		{EndpointID: uuid.New(), NodeID: first, Weight: 10}, {EndpointID: uuid.New(), NodeID: second, Weight: 10}}}
	config := func(nodes ...uuid.UUID) *L2TopologyConfig {
		value := &L2TopologyConfig{ID: uuid.New(), Mode: "global", LoadMethod: "rr"}
		for index, node := range nodes {
			value.Members = append(value.Members, L2TopologyMember{NodeID: node, Weight: 40 + index})
		}
		return value
	}
	with := func(mode string, value *L2TopologyConfig) siteFact {
		return siteFact{forwarding: &originForwardingFact{l2Mode: mode, l2Config: value}}
	}
	if got, err := siteL2Topology(topology, with("package", nil)); err != nil || got != topology {
		t.Fatalf("package: %v %v", got, err)
	}
	if got, err := siteL2Topology(topology, siteFact{}); err != nil || got != topology {
		t.Fatalf("no forwarding row: %v %v", got, err)
	}
	if got, err := siteL2Topology(topology, with("off", nil)); err != nil || got != nil {
		t.Fatalf("off: %v %v", got, err)
	}
	got, err := siteL2Topology(topology, with("custom", config(second, other)))
	if err != nil || len(got.Endpoints) != 1 || got.Endpoints[0].NodeID != second || got.Endpoints[0].Weight != 40 ||
		len(topology.Endpoints) != 2 || topology.Endpoints[1].Weight != 10 {
		t.Fatalf("custom: %+v %v", got, err)
	}
	if _, err := siteL2Topology(topology, with("custom", config(other))); !errors.Is(err, ErrSiteL2Unavailable) {
		t.Fatalf("custom without a target L2 node: %v", err)
	}
	if _, err := siteL2Topology(topology, with("custom", nil)); !errors.Is(err, ErrSiteL2Unavailable) {
		t.Fatalf("custom with a deleted configuration: %v", err)
	}
	if got, err := siteL2Topology(nil, with("custom", config(other))); err != nil || got != nil {
		t.Fatalf("no topology: %v %v", got, err)
	}
	// A19-a: the line group's L2 configuration is the package default:
	// member sort order (second before first) and member weights
	packaged := *topology
	packaged.Config = config(second, first)
	packaged.Config.LoadMethod = "url_hash"
	got, err = siteL2Topology(&packaged, with("package", nil))
	if err != nil || len(got.Endpoints) != 2 || got.Endpoints[0].NodeID != second || got.Endpoints[0].Weight != 40 ||
		got.Endpoints[1].NodeID != first || got.Endpoints[1].Weight != 41 || l2PoolAlgorithm(got.Config) != "url_hash" {
		t.Fatalf("package with a line group L2 configuration: %+v %v", got, err)
	}
	// a site's own configuration replaces the line group's
	got, err = siteL2Topology(&packaged, with("custom", config(first)))
	if err != nil || len(got.Endpoints) != 1 || got.Endpoints[0].NodeID != first || l2PoolAlgorithm(got.Config) != "round_robin" {
		t.Fatalf("custom over a line group configuration: %+v %v", got, err)
	}
	if l2PoolAlgorithm(nil) != "round_robin" {
		t.Fatal("no configuration must round robin")
	}
}
