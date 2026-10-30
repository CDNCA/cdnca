package edgepublish

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

// fix-autol2b fixture: a scope whose site uses line group G (L2 config C,
// members l2a and l2b), the publication targets l1, l2a (l2b is not a
// target: held or offline).
type autoL2Fixture struct {
	group                    siteL2LineGroup
	config                   *L2TopologyConfig
	l1, l2a, l2b             uuid.UUID
	identities               []L2TopologyIdentity
	nodes                    map[uuid.UUID]siteL2Node
	siteID, noGroup, offSite uuid.UUID
}

func newAutoL2Fixture() autoL2Fixture {
	f := autoL2Fixture{
		l1:      uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7f01"),
		l2a:     uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7f02"),
		l2b:     uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7f03"),
		siteID:  uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103"),
		noGroup: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7104"),
		offSite: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7105"),
	}
	configID := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7f10")
	f.config = &L2TopologyConfig{ID: configID, Mode: "global", LoadMethod: "rr",
		Members: []L2TopologyMember{{NodeID: f.l2b, Weight: 40}, {NodeID: f.l2a, Weight: 60}}}
	f.group = siteL2LineGroup{ID: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7f20"), Revision: 3,
		ProbeIntervalMS: 5000, FailureThreshold: 2, RecoveryThreshold: 4, ConfigID: &configID}
	f.identities = []L2TopologyIdentity{
		{NodeID: f.l1, MTLSIdentitySHA256: sha256.Sum256([]byte("l1"))},
		{NodeID: f.l2a, MTLSIdentitySHA256: sha256.Sum256([]byte("l2a"))},
	}
	f.nodes = map[uuid.UUID]siteL2Node{f.l2a: {Address: "203.0.113.20", MTLS: sha256.Sum256([]byte("l2a"))}}
	return f
}

func (f autoL2Fixture) resolve(t *testing.T, facts ...siteFact) (*L2TopologySnapshot, []siteL2PublicationSkip) {
	t.Helper()
	groups := map[uuid.UUID]siteL2LineGroup{f.siteID: f.group, f.offSite: f.group}
	topology, skipped, err := resolveSiteL2Publication(7, facts, groups,
		map[uuid.UUID]*L2TopologyConfig{f.config.ID: f.config}, f.identities, f.nodes)
	if err != nil {
		t.Fatal(err)
	}
	return topology, skipped
}

// 拓扑现算：站点线路组的 L2 配置，成员只取本次发布目标（并按成员排序、
// 权重），探测参数取线路组当前修订；关闭的站点、无线路分组的站点不带 L2，
// 后者写"未走 L2：无线路分组"。
func TestAutomaticPublicationResolvesSiteL2FromItsLineGroup(t *testing.T) {
	f := newAutoL2Fixture()
	site := l2RoutingFact()
	site.id = f.siteID
	noGroup := l2RoutingFact()
	noGroup.id = f.noGroup
	off := l2RoutingFact()
	off.id = f.offSite
	off.forwarding = &originForwardingFact{l2Mode: "off"}
	topology, skipped := f.resolve(t, site, noGroup, off)
	if topology == nil || !topology.Passthrough || topology.Revision != 7 || len(topology.Sites) != 1 {
		t.Fatalf("topology %+v", topology)
	}
	resolved := topology.Sites[f.siteID]
	if resolved == nil || resolved.SourceLineGroupID != f.group.ID || resolved.SourceRevision != 3 ||
		resolved.ProbeIntervalMS != 5000 || resolved.FailureThreshold != 2 || resolved.RecoveryThreshold != 4 ||
		len(resolved.Endpoints) != 1 || resolved.Endpoints[0].NodeID != f.l2a ||
		resolved.Endpoints[0].Address != "203.0.113.20" || resolved.Endpoints[0].Weight != 60 ||
		resolved.Endpoints[0].EndpointID != uuid.NewSHA1(f.config.ID, f.l2a[:]) {
		t.Fatalf("site L2 %+v", resolved)
	}
	if len(skipped) != 1 || skipped[0].SiteID != f.noGroup || skipped[0].Reason != SiteL2SkippedNoLineGroup {
		t.Fatalf("skipped %+v", skipped)
	}
}

// "未走 L2：L2 配置无可用节点"：成员都不是本次目标（或无地址/证书）时
// 该站点不带 L2，发布照常（不再整次失败）。
func TestAutomaticPublicationWithoutUsableL2NodeSkipsTheSite(t *testing.T) {
	f := newAutoL2Fixture()
	f.nodes = map[uuid.UUID]siteL2Node{}
	site := l2RoutingFact()
	site.id = f.siteID
	topology, skipped := f.resolve(t, site)
	if topology != nil {
		t.Fatalf("topology %+v", topology)
	}
	if len(skipped) != 1 || skipped[0].Reason != SiteL2SkippedNoL2Node {
		t.Fatalf("skipped %+v", skipped)
	}
	payload := siteL2SkippedPayload(skipped)
	if payload[0]["site_id"] != f.siteID.String() || payload[0]["reason"] != "no_l2_node" {
		t.Fatalf("audit payload %v", payload)
	}
	// a custom configuration deleted since: no usable node either
	custom := l2RoutingFact()
	custom.id = f.siteID
	custom.forwarding = &originForwardingFact{l2Mode: "custom"}
	if _, skipped := f.resolve(t, custom); len(skipped) != 1 || skipped[0].Reason != SiteL2SkippedNoL2Node {
		t.Fatalf("custom skipped %+v", skipped)
	}
}

// 端口透传：编译出的站点 L2 带 passthrough（L1 按访客协议端口连 L2，端点端口
// 为名义值），直连池为回落，需要 L2_ROUTING v2；站点对象 origin.l2.passthrough。
func TestAutomaticPublicationSiteL2IsPassthroughAndNeedsL2RoutingV2(t *testing.T) {
	f := newAutoL2Fixture()
	fact := l2RoutingFact()
	fact.id = f.siteID
	fact.httpPorts = []string{"8080"}
	topology, _ := f.resolve(t, fact)
	site, _, err := compileSiteRuntimeV2SiteFactWithTopology(nil, nil, uuid.New(), fact, topology, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !site.L2.Passthrough || site.DefaultPoolID != "l2-topology" || *site.L2.DirectFallbackPoolID != "primary" ||
		site.L2.ProbeIntervalMS != 5000 {
		t.Fatalf("L2 policy %+v default %s", site.L2, site.DefaultPoolID)
	}
	if l2 := site.OriginPools[0]; l2.Kind != "l2" || len(l2.Origins) != 1 || *l2.Origins[0].NodeID != f.l2a.String() ||
		l2.Origins[0].Port != siteL2NominalPort {
		t.Fatalf("L2 pool %+v", l2)
	}
	if edgeconfig.L2RoutingAPIVersion != 2 {
		t.Fatalf("L2_ROUTING version %d", edgeconfig.L2RoutingAPIVersion)
	}
	inferred := map[string]uint32{}
	if _, err := validateSiteRuntimeV2Site(site, inferred); err != nil {
		t.Fatalf("runtime site refused: %v", err)
	}
	if inferred[edgeconfig.L2RoutingCapability] != 2 {
		t.Fatalf("inferred %v", inferred)
	}
	route, err := basicSiteOriginRouteFactWithTopology(site, topology)
	if err != nil {
		t.Fatalf("route fact: %v", err)
	}
	raw, err := json.Marshal(route.document)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := convertSiteOriginV2(site, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if origin.L2 == nil || !origin.L2.Passthrough || origin.L2.DirectFallbackPoolID != "primary" {
		t.Fatalf("site object L2 %+v", origin.L2)
	}
	// a site the publication gives no L2 compiles direct, as before
	other := l2RoutingFact()
	other.id = f.noGroup
	direct, _, err := compileSiteRuntimeV2SiteFactWithTopology(nil, nil, uuid.New(), other, topology, time.Unix(1, 0).UTC())
	if err != nil || *direct.L2.Enabled || direct.L2.Passthrough || direct.DefaultPoolID != "primary" {
		t.Fatalf("site without L2 %+v %v", direct.L2, err)
	}
}
