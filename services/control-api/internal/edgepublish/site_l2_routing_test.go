package edgepublish

import (
	"encoding/json"
	"errors"
	"github.com/cdnca/cdnca/services/control-api/internal/siteruntimecap"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/cdnca/cdnca/libs/edgeconfig/edgesite"
	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/google/uuid"
)

func l2RoutingFact() siteFact {
	return siteFact{
		id: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103"), revision: 9, domain: "l2.example.test",
		httpPorts: []string{"80"}, balance: "round_robin", failoverTries: 1,
		connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 80, Weight: 100}},
	}
}

// A19-b: 模式=缓存 and the L2 conditions reach the runtime document and the
// site object; the L1 node rules are decided per target, the request rules
// go to the node; the site needs L2_ROUTING v1.
func TestSiteL2CacheModeAndConditionsReachTheSiteObject(t *testing.T) {
	topology, nodes := l2ConfigTopologyFixture()
	l1 := topology.TargetIdentities[0].NodeID
	second := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7a21")
	topology.TargetIdentities[0].Location = L2NodeLocation{DisplayID: "7", CountryCode: "US", ISP: "AWS"}
	topology.TargetIdentities = append(topology.TargetIdentities, L2TopologyIdentity{NodeID: second,
		MTLSIdentitySHA256: topology.TargetIdentities[0].MTLSIdentitySHA256,
		Location:           L2NodeLocation{DisplayID: "8", CountryCode: "CN", ISP: "电信"}})
	overseas := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7c01")
	images := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7c02")
	never := uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7c03")
	topology.Config = &L2TopologyConfig{ID: uuid.New(), Mode: "cache", LoadMethod: "rr",
		Members: []L2TopologyMember{
			{NodeID: nodes[0], Weight: 10, ConditionID: &overseas},
			{NodeID: nodes[1], Weight: 20, ConditionID: &images},
			{NodeID: nodes[2], Weight: 30, ConditionID: &never},
		},
		Conditions: map[uuid.UUID][]edgesite.L2Rule{
			overseas: {{Field: "node_country", Operator: "neq", Value: "cn"}},
			images:   {{Field: "uri", Operator: "regex", Value: `^/img/.*\.(png|jpg)$`}, {Field: "node_id", Operator: "eq", Value: "8"}},
			never:    {{Field: "node_isp", Operator: "eq", Value: "联通"}},
		},
	}
	site, _, err := compileSiteRuntimeV2SiteFactWithTopology(nil, nil, uuid.New(), l2RoutingFact(), topology, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	// the 联通 condition matches no target: its member is not published
	if l2 := site.OriginPools[0]; len(l2.Origins) != 2 || *l2.Origins[0].NodeID != nodes[0].String() ||
		*l2.Origins[1].NodeID != nodes[1].String() {
		t.Fatalf("L2 pool %+v", l2)
	}
	if !site.L2.CacheOnly || len(site.L2.Conditions) != 2 {
		t.Fatalf("L2 policy %+v", site.L2)
	}
	byID := map[string]siteRuntimeV2L2Condition{}
	for _, condition := range site.L2.Conditions {
		byID[condition.ID] = condition
	}
	if got := byID[overseas.String()]; len(got.Rules) != 0 || len(got.NodeIDs) != 1 || got.NodeIDs[0] != l1.String() ||
		len(got.EndpointIDs) != 1 || got.EndpointIDs[0] != topology.Endpoints[0].EndpointID.String() {
		t.Fatalf("海外节点 condition %+v", got)
	}
	if got := byID[images.String()]; len(got.Rules) != 1 || got.Rules[0].Field != "uri" ||
		len(got.NodeIDs) != 1 || got.NodeIDs[0] != second.String() || got.EndpointIDs[0] != topology.Endpoints[1].EndpointID.String() {
		t.Fatalf("image condition %+v", got)
	}
	if !site.L2.usesL2Routing() {
		t.Fatal("cache mode needs L2_ROUTING")
	}
	inferred := map[string]uint32{}
	if _, err := validateSiteRuntimeV2Site(site, inferred); err != nil {
		t.Fatalf("runtime site refused: %v", err)
	}
	if inferred[edgeconfig.L2RoutingCapability] != edgeconfig.L2RoutingAPIVersion {
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
	if origin.L2 == nil || !origin.L2.CacheOnly || len(origin.L2.Conditions) != 2 {
		t.Fatalf("site object L2 %+v", origin.L2)
	}
	var l2Pool edgesite.Pool
	for _, pool := range origin.Pools {
		if pool.Kind == edgesite.PoolL2 {
			l2Pool = pool
		}
	}
	if err := edgesite.ValidateL2Conditions(origin.L2.Conditions, l2Pool); err != nil {
		t.Fatalf("site object conditions refused: %v", err)
	}
	if !(edgesite.Site{Origin: origin}).UsesL2Routing() {
		t.Fatal("site object does not need L2_ROUTING")
	}
}

// 模式=全局 without conditions needs nothing new; a configuration all of
// whose members are on conditions no target matches leaves the site no L2.
func TestSiteL2GlobalModeNeedsNoCapabilityAndUnmatchedConditionsLeaveNoL2(t *testing.T) {
	topology, nodes := l2ConfigTopologyFixture()
	topology.Config = &L2TopologyConfig{ID: uuid.New(), Mode: "global", LoadMethod: "rr",
		Members: []L2TopologyMember{{NodeID: nodes[0], Weight: 10}}}
	site, _, err := compileSiteRuntimeV2SiteFactWithTopology(nil, nil, uuid.New(), l2RoutingFact(), topology, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if site.L2.usesL2Routing() {
		t.Fatalf("global mode needs L2_ROUTING: %+v", site.L2)
	}
	condition := uuid.New()
	topology.Config = &L2TopologyConfig{ID: uuid.New(), Mode: "global", LoadMethod: "rr",
		Members:    []L2TopologyMember{{NodeID: nodes[0], Weight: 10, ConditionID: &condition}},
		Conditions: map[uuid.UUID][]edgesite.L2Rule{condition: {{Field: "node_city", Operator: "eq", Value: "上海"}}}}
	if _, _, err := compileSiteRuntimeV2SiteFactWithTopology(nil, nil, uuid.New(), l2RoutingFact(), topology,
		time.Unix(1, 0).UTC()); !errors.Is(err, ErrSiteL2Unavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestL2NodeRuleMatches(t *testing.T) {
	target := L2TopologyIdentity{NodeID: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7a20"),
		Location: L2NodeLocation{DisplayID: "12", CountryCode: "HK", ISP: "PCCW", Province: "香港", City: "香港"}}
	unknown := L2TopologyIdentity{NodeID: uuid.New()}
	for _, tc := range []struct {
		rule   edgesite.L2Rule
		target L2TopologyIdentity
		want   bool
	}{
		{edgesite.L2Rule{Field: "node_country", Operator: "eq", Value: "hk"}, target, true},
		{edgesite.L2Rule{Field: "node_country", Operator: "neq", Value: "CN"}, target, true},
		{edgesite.L2Rule{Field: "node_country", Operator: "neq", Value: "CN"}, unknown, true},
		{edgesite.L2Rule{Field: "node_country", Operator: "eq", Value: "CN"}, unknown, false},
		{edgesite.L2Rule{Field: "node_id", Operator: "eq", Value: "12"}, target, true},
		{edgesite.L2Rule{Field: "node_id", Operator: "eq", Value: "018F47A2-5B9C-7D31-8A60-104C9C0B7A20"}, target, true},
		{edgesite.L2Rule{Field: "node_isp", Operator: "contains", Value: "CC"}, target, true},
		{edgesite.L2Rule{Field: "node_isp", Operator: "not_contains", Value: "CC"}, target, false},
		{edgesite.L2Rule{Field: "node_province", Operator: "prefix", Value: "香"}, target, true},
		{edgesite.L2Rule{Field: "node_city", Operator: "suffix", Value: "港"}, target, true},
		{edgesite.L2Rule{Field: "node_city", Operator: "regex", Value: "^(香港|澳门)$"}, target, true},
		{edgesite.L2Rule{Field: "node_city", Operator: "not_regex", Value: "^(香港|澳门)$"}, target, false},
	} {
		if got := l2NodeRuleMatches(tc.rule, tc.target); got != tc.want {
			t.Errorf("%+v on %+v = %v", tc.rule, tc.target.Location, got)
		}
	}
}

// A node without L2_ROUTING is refused with the readable reason.
func TestL2RoutingCapabilityGate(t *testing.T) {
	name, ok := siteruntimecap.Name(edgeconfig.L2RoutingCapability)
	if !ok || name != agentv1.CapabilityName_CAPABILITY_NAME_L2_ROUTING || int32(name) != 59 {
		t.Fatalf("capability %v", name)
	}
	required := []*agentv1.Capability{{Name: name, ApiVersion: edgeconfig.L2RoutingAPIVersion}}
	err := targetCapabilityError(uuid.New(), "1.0.35", required, nil)
	var refused *TargetCapabilityError
	if !errors.As(err, &refused) || !strings.Contains(err.Error(), "L2_ROUTING") || !strings.Contains(err.Error(), "缓存模式") {
		t.Fatalf("err = %v", err)
	}
	if err := targetCapabilityError(uuid.New(), "1.0.35", required, required); err != nil {
		t.Fatalf("declared node refused: %v", err)
	}
}
