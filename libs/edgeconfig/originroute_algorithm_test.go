package edgeconfig

import (
	"errors"
	"testing"
)

func TestNormalizeOriginRouteAlgorithmPolicyDefaultsAndSorts(t *testing.T) {
	policy := OriginRouteAlgorithmPolicy{
		TenantID:  "tenant-a",
		SiteID:    "site-a",
		VersionID: "route-v1",
		Pools: []OriginRoutePoolAlgorithm{
			{PoolID: "pool-b", Algorithm: OriginRouteAlgorithmRandom},
			{PoolID: "pool-a"},
		},
	}

	normalized, err := NormalizeOriginRouteAlgorithmPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	if normalized.Pools[0].PoolID != "pool-a" || normalized.Pools[0].Algorithm != OriginRouteAlgorithmRoundRobin ||
		normalized.Pools[1].PoolID != "pool-b" || normalized.Pools[1].Algorithm != OriginRouteAlgorithmRandom {
		t.Fatalf("normalized pools = %+v", normalized.Pools)
	}
	key, err := OriginRouteStateKey(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if key != "v1|tenant=tenant-a|site=site-a|version=route-v1" {
		t.Fatalf("state key = %q", key)
	}
}

func TestNormalizeOriginRouteAlgorithmPolicyFailsClosed(t *testing.T) {
	valid := OriginRouteAlgorithmPolicy{
		TenantID: "tenant-a", SiteID: "site-a", VersionID: "route-v1",
		Pools: []OriginRoutePoolAlgorithm{{PoolID: "pool-a"}},
	}
	tests := map[string]func(*OriginRouteAlgorithmPolicy){
		"empty tenant":      func(policy *OriginRouteAlgorithmPolicy) { policy.TenantID = "" },
		"empty site":        func(policy *OriginRouteAlgorithmPolicy) { policy.SiteID = "" },
		"empty version":     func(policy *OriginRouteAlgorithmPolicy) { policy.VersionID = "" },
		"unknown algorithm": func(policy *OriginRouteAlgorithmPolicy) { policy.Pools[0].Algorithm = "ketama" },
		"duplicate pool": func(policy *OriginRouteAlgorithmPolicy) {
			policy.Pools = append(policy.Pools, OriginRoutePoolAlgorithm{PoolID: "pool-a"})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			policy := valid
			policy.Pools = append([]OriginRoutePoolAlgorithm(nil), valid.Pools...)
			mutate(&policy)
			if _, err := NormalizeOriginRouteAlgorithmPolicy(policy); !errors.Is(err, ErrInvalidOriginRouteAlgorithmPolicy) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}
