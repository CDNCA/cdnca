package edgeconfig

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
)

const MaxOriginRouteAlgorithmPools = 64

var (
	ErrInvalidOriginRouteAlgorithmPolicy = errors.New("invalid origin route algorithm policy")
	originRouteScopeTokenPattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

type OriginRouteAlgorithm = BalanceMethod

const (
	OriginRouteAlgorithmRoundRobin OriginRouteAlgorithm = BalanceRoundRobin
	OriginRouteAlgorithmIPHash     OriginRouteAlgorithm = BalanceIPHash
	OriginRouteAlgorithmURLHash    OriginRouteAlgorithm = BalanceURLHash
	OriginRouteAlgorithmLeastConn  OriginRouteAlgorithm = BalanceLeastConn
	OriginRouteAlgorithmRandom     OriginRouteAlgorithm = BalanceRandom
)

type OriginRouteAlgorithmPolicy struct {
	TenantID  string                     `json:"tenant_id"`
	SiteID    string                     `json:"site_id"`
	VersionID string                     `json:"version_id"`
	Pools     []OriginRoutePoolAlgorithm `json:"pools"`
}

type OriginRoutePoolAlgorithm struct {
	PoolID    string               `json:"pool_id"`
	Algorithm OriginRouteAlgorithm `json:"algorithm"`
}

func NormalizeOriginRouteAlgorithmPolicy(input OriginRouteAlgorithmPolicy) (OriginRouteAlgorithmPolicy, error) {
	if !originRouteScopeTokenPattern.MatchString(input.TenantID) ||
		!originRouteScopeTokenPattern.MatchString(input.SiteID) ||
		!originRouteScopeTokenPattern.MatchString(input.VersionID) {
		return OriginRouteAlgorithmPolicy{}, invalidOriginRouteAlgorithm("tenant_id, site_id, and version_id are required")
	}
	if len(input.Pools) == 0 || len(input.Pools) > MaxOriginRouteAlgorithmPools {
		return OriginRouteAlgorithmPolicy{}, invalidOriginRouteAlgorithm("pool count must be between 1 and %d", MaxOriginRouteAlgorithmPools)
	}
	pools := make([]OriginRoutePoolAlgorithm, len(input.Pools))
	seen := make(map[string]struct{}, len(input.Pools))
	for index, pool := range input.Pools {
		if !originRouteScopeTokenPattern.MatchString(pool.PoolID) {
			return OriginRouteAlgorithmPolicy{}, invalidOriginRouteAlgorithm("pool %d id is invalid", index)
		}
		if _, exists := seen[pool.PoolID]; exists {
			return OriginRouteAlgorithmPolicy{}, invalidOriginRouteAlgorithm("duplicate pool id %q", pool.PoolID)
		}
		seen[pool.PoolID] = struct{}{}
		algorithm := pool.Algorithm
		if algorithm == "" {
			algorithm = OriginRouteAlgorithmRoundRobin
		}
		switch algorithm {
		case OriginRouteAlgorithmRoundRobin, OriginRouteAlgorithmIPHash, OriginRouteAlgorithmURLHash,
			OriginRouteAlgorithmLeastConn, OriginRouteAlgorithmRandom:
		default:
			return OriginRouteAlgorithmPolicy{}, invalidOriginRouteAlgorithm("pool %q algorithm is invalid", pool.PoolID)
		}
		pools[index] = OriginRoutePoolAlgorithm{PoolID: pool.PoolID, Algorithm: algorithm}
	}
	sort.Slice(pools, func(i, j int) bool { return pools[i].PoolID < pools[j].PoolID })
	return OriginRouteAlgorithmPolicy{
		TenantID: input.TenantID, SiteID: input.SiteID, VersionID: input.VersionID, Pools: pools,
	}, nil
}

func OriginRouteStateKey(input OriginRouteAlgorithmPolicy) (string, error) {
	policy, err := NormalizeOriginRouteAlgorithmPolicy(input)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("v1|tenant=%s|site=%s|version=%s", policy.TenantID, policy.SiteID, policy.VersionID), nil
}

func invalidOriginRouteAlgorithm(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidOriginRouteAlgorithmPolicy, fmt.Sprintf(format, arguments...))
}
