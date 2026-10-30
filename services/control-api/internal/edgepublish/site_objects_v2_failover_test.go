package edgepublish

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Origin failover in dynamic routing: the endpoint level and the pool's
// active level of the v2 document reach the site object (cdnca_origin.lua
// selects from pool.active_level by endpoint.level), through the basic
// origin-route fact every site publishes.
func TestSiteObjectsV2OriginFailoverLevelsReachSiteObject(t *testing.T) {
	level1, level2, active := int64(1), int64(2), int64(1)
	site := siteRuntimeV2Site{
		ID: "018f47a2-5b9c-7d31-8a60-104c9c0b7103", Revision: 7, DefaultPoolID: "primary",
		L2: siteRuntimeV2L2Policy{Enabled: boolPtr(false)},
		OriginPools: []siteRuntimeV2OriginPool{
			{ID: "primary", Position: 0, Kind: "origin", Algorithm: "round_robin", ActiveLevel: &active, Origins: []siteRuntimeV2Origin{
				{ID: "origin-0", Position: 0, Tier: "origin", Scheme: "http", Host: "192.0.2.10", Port: 8080, Weight: 100},
				{ID: "origin-1", Position: 1, Tier: "origin", Scheme: "http", Host: "192.0.2.11", Port: 8080, Weight: 100, Level: &level1},
				{ID: "origin-2", Position: 2, Tier: "origin", Scheme: "http", Host: "192.0.2.12", Port: 8080, Weight: 100, Level: &level2},
			}, Retry: siteRuntimeV2RetryPolicy{Methods: []string{"GET", "HEAD"}, BodylessOnly: boolPtr(true), ResponseNotStarted: boolPtr(true),
				RetryOn:     []string{"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"},
				MaxAttempts: 2, ConnectTimeoutMS: 1000, ReadTimeoutMS: 2000, TotalBudgetMS: 6000}},
		},
	}
	fact, err := basicSiteOriginRouteFact(site)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(fact.document)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := convertSiteOriginV2(site, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(origin.Pools) != 1 || origin.Pools[0].ActiveLevel != 1 || len(origin.Pools[0].Endpoints) != 3 {
		t.Fatalf("pools %+v", origin.Pools)
	}
	for index, want := range []int{0, 1, 2} {
		if got := origin.Pools[0].Endpoints[index].Level; got != want {
			t.Fatalf("endpoint %d level = %d, want %d", index, got, want)
		}
	}
}

// A custom origin route (site_origin_route_pools) replaces the endpoints of
// the pools it names: the levels of the site's origins (matched by host and
// port, unique per site) and the pool's active level still reach the site
// object, so multi-level failover keeps working under custom routes. A pool
// without a primary among them stays a plain pool.
func TestSiteObjectsV2OriginRouteKeepsFailoverLevels(t *testing.T) {
	level1, level2, active := int64(1), int64(2), int64(1)
	site := siteRuntimeV2Site{
		ID: "018f47a2-5b9c-7d31-8a60-104c9c0b7103", Revision: 7, DefaultPoolID: "primary",
		L2: siteRuntimeV2L2Policy{Enabled: boolPtr(false)},
		OriginPools: []siteRuntimeV2OriginPool{
			{ID: "primary", Position: 0, Kind: "origin", Algorithm: "round_robin", ActiveLevel: &active, Origins: []siteRuntimeV2Origin{
				{ID: "origin-0", Position: 0, Tier: "origin", Scheme: "http", Host: "192.0.2.10", Port: 8080, Weight: 100},
				{ID: "origin-1", Position: 1, Tier: "origin", Scheme: "http", Host: "192.0.2.11", Port: 8080, Weight: 100, Level: &level1},
				{ID: "origin-2", Position: 2, Tier: "origin", Scheme: "http", Host: "192.0.2.12", Port: 8080, Weight: 100, Level: &level2},
			}, Retry: siteRuntimeV2RetryPolicy{Methods: []string{"GET", "HEAD"}, BodylessOnly: boolPtr(true), ResponseNotStarted: boolPtr(true),
				RetryOn:     []string{"connect_error", "connect_timeout", "read_timeout", "http_502", "http_503", "http_504"},
				MaxAttempts: 2, ConnectTimeoutMS: 1000, ReadTimeoutMS: 2000, TotalBudgetMS: 6000}},
		},
	}
	endpoint := func(id, host string, weight int) siteOriginRouteEndpoint {
		return siteOriginRouteEndpoint{ID: id, Tier: "origin", Host: host, Port: 8080, Weight: weight}
	}
	route := siteOriginRouteDocument{Schema: siteOriginRouteSchemaV1, DefaultPoolID: "default",
		Pools: []siteOriginRoutePool{
			// the conditional-origin default document: every enabled origin, weights changed
			{ID: "default", Kind: "origin", BalanceMethod: "round_robin", Endpoints: []siteOriginRouteEndpoint{
				endpoint("origin-00", "192.0.2.10", 10), endpoint("origin-01", "192.0.2.11", 10), endpoint("origin-02", "192.0.2.12", 10)}},
			// same ID as the runtime pool, a new endpoint added
			{ID: "primary", Kind: "origin", BalanceMethod: "least_conn", Endpoints: []siteOriginRouteEndpoint{
				endpoint("a", "192.0.2.10", 50), endpoint("b", "192.0.2.11", 50), endpoint("c", "198.51.100.7", 50)}},
			// only backups of the site: no primary, a plain pool
			{ID: "backups", Kind: "origin", BalanceMethod: "round_robin", Endpoints: []siteOriginRouteEndpoint{
				endpoint("x", "192.0.2.11", 10), endpoint("y", "192.0.2.12", 10)}},
			// no site origin at all
			{ID: "static", Kind: "origin", BalanceMethod: "round_robin", Endpoints: []siteOriginRouteEndpoint{
				endpoint("s", "203.0.113.5", 10)}},
		},
		Routes: []siteOriginRoute{{ID: "r", Priority: 1, PathPrefix: "/s", PoolID: "static", FallbackPoolID: "backups"}},
		Retry:  siteOriginRouteRetry{Methods: []string{"GET", "HEAD"}, MaxAttempts: 2, ConnectTimeoutMS: 1000, ReadTimeoutMS: 2000, TotalBudgetMS: 5000},
	}
	raw, err := json.Marshal(route)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := convertSiteOriginV2(site, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		active int
		levels []int
	}{
		"default": {1, []int{0, 1, 2}},
		"primary": {1, []int{0, 1, 0}},
		"backups": {0, []int{0, 0}},
		"static":  {0, []int{0}},
	}
	if len(origin.Pools) != len(want) {
		t.Fatalf("pools %+v", origin.Pools)
	}
	for _, pool := range origin.Pools {
		expected, ok := want[pool.ID]
		if !ok || pool.ActiveLevel != expected.active || len(pool.Endpoints) != len(expected.levels) {
			t.Fatalf("pool %s: active %d endpoints %+v", pool.ID, pool.ActiveLevel, pool.Endpoints)
		}
		for index, level := range expected.levels {
			if got := pool.Endpoints[index].Level; got != level {
				t.Fatalf("pool %s endpoint %d level = %d, want %d", pool.ID, index, got, level)
			}
		}
	}
	// The real OpenResty case (tests/dynroute-origin/algorithms.lua) compiles
	// this origin with cdnca_origin.lua; the fixture is the converter's output.
	encoded, err := json.MarshalIndent(origin, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	fixture := filepath.Join("..", "..", "..", "..", "tests", "dynroute-origin", "route_levels.json")
	if os.Getenv("CDNCA_UPDATE_FIXTURES") == "1" {
		if err := os.WriteFile(fixture, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(fixture)
	if err != nil || !bytes.Equal(stored, encoded) {
		t.Fatalf("%s differs from the converter output (CDNCA_UPDATE_FIXTURES=1 rewrites it): %v", fixture, err)
	}
}
