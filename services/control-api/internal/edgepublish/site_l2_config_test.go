package edgepublish

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// l2ConfigTopologyFixture: a target topology of three L2 endpoints (line
// group endpoint weight 10 each) and one L1 target.
func l2ConfigTopologyFixture() (*L2TopologySnapshot, []uuid.UUID) {
	nodes := []uuid.UUID{
		uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7a01"),
		uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7a02"),
		uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7a03"),
	}
	topology := &L2TopologySnapshot{
		Revision: 4, SourceLineGroupID: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7a10"), SourceRevision: 2,
		ProbeIntervalMS: 10000, FailureThreshold: 3, RecoveryThreshold: 3,
		TargetIdentities: []L2TopologyIdentity{{NodeID: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7a20"),
			MTLSIdentitySHA256: sha256.Sum256([]byte("l1"))}},
	}
	for index, node := range nodes {
		topology.Endpoints = append(topology.Endpoints, L2TopologyEndpoint{
			EndpointID: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7b0" + string(rune('1'+index))),
			NodeID:     node, Address: "198.51.100." + string(rune('1'+index)), Port: 80, Weight: 10,
			MTLSIdentitySHA256: sha256.Sum256(node[:]),
		})
	}
	return topology, nodes
}

// A19-a: the line group's L2 configuration (package default) reaches the
// site object: URL哈希 → url_hash, only its enabled members, their weights,
// in member sort order (the route document's id order is undone).
func TestSiteL2ConfigurationReachesTheSiteObject(t *testing.T) {
	topology, nodes := l2ConfigTopologyFixture()
	topology.Config = &L2TopologyConfig{ID: uuid.New(), Mode: "global", LoadMethod: "url_hash", Members: []L2TopologyMember{
		{NodeID: nodes[2], Weight: 70}, {NodeID: nodes[0], Weight: 30},
	}}
	fact := siteFact{
		id: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103"), revision: 9, domain: "l2.example.test",
		httpPorts: []string{"80"}, balance: "round_robin", failoverTries: 1,
		connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 80, Weight: 100}},
	}
	site, _, err := compileSiteRuntimeV2SiteFactWithTopology(nil, nil, uuid.New(), fact, topology, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	l2 := site.OriginPools[0]
	if l2.Kind != "l2" || l2.Algorithm != "url_hash" || len(l2.Origins) != 2 ||
		*l2.Origins[0].NodeID != nodes[2].String() || l2.Origins[0].Weight != 70 ||
		*l2.Origins[1].NodeID != nodes[0].String() || l2.Origins[1].Weight != 30 {
		t.Fatalf("L2 pool %+v", l2)
	}
	route, err := basicSiteOriginRouteFactWithTopology(site, topology)
	if err != nil {
		t.Fatalf("route fact: %v", err)
	}
	if pool, ok := l2RoutePool(route); !ok || pool.BalanceMethod != "url_hash" {
		t.Fatalf("route L2 pool %+v", pool)
	}
	raw, err := json.Marshal(route.document)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := convertSiteOriginV2(site, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, pool := range origin.Pools {
		if pool.Kind != "l2" {
			continue
		}
		if pool.Algorithm != "url_hash" || len(pool.Endpoints) != 2 ||
			pool.Endpoints[0].NodeID != nodes[2].String() || pool.Endpoints[0].Weight != 70 ||
			pool.Endpoints[1].NodeID != nodes[0].String() || pool.Endpoints[1].Weight != 30 {
			t.Fatalf("site object L2 pool %+v", pool)
		}
		return
	}
	t.Fatalf("site object without an L2 pool: %+v", origin.Pools)
}

// Without a line group L2 configuration the pool stays as before: every L2
// endpoint, round robin by the line group endpoint weights.
func TestSiteL2WithoutConfigurationKeepsTheLineGroupEndpoints(t *testing.T) {
	topology, _ := l2ConfigTopologyFixture()
	fact := siteFact{
		id: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7103"), revision: 9, domain: "l2.example.test",
		httpPorts: []string{"80"}, balance: "round_robin", failoverTries: 1,
		connectTimeoutMS: 3000, readTimeoutMS: 30000,
		origins: []snapshotOrigin{{Host: "192.0.2.10", Port: 80, Weight: 100}},
	}
	site, _, err := compileSiteRuntimeV2SiteFactWithTopology(nil, nil, uuid.New(), fact, topology, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if l2 := site.OriginPools[0]; l2.Algorithm != "round_robin" || len(l2.Origins) != 3 || l2.Origins[0].Weight != 10 {
		t.Fatalf("L2 pool %+v", l2)
	}
}
