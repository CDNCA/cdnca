package originroute

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestOriginRouteAlgorithmContractDefaultsLegacyInput(t *testing.T) {
	policy := testPolicy()
	policy.TenantID = "tenant-a"
	policy.SiteID = "site-a"
	for index := range policy.Pools {
		policy.Pools[index].Algorithm = ""
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"algorithm"`) {
		t.Fatalf("legacy fixture unexpectedly contains algorithm: %s", raw)
	}

	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, pool := range parsed.Pools {
		if pool.Algorithm != AlgorithmRoundRobin {
			t.Fatalf("pool %q algorithm = %q", pool.ID, pool.Algorithm)
		}
	}
}

func TestOriginRouteAlgorithmContractScopesDigestAndState(t *testing.T) {
	policy := testPolicy()
	policy.TenantID = "tenant-a"
	policy.SiteID = "site-a"
	policy.Pools[0].Algorithm = AlgorithmIPHash
	policy.Pools[1].Algorithm = AlgorithmURLHash
	policy.Pools[2].Algorithm = AlgorithmLeastConn

	canonical, err := Canonical(policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`"tenant_id":"tenant-a"`, `"site_id":"site-a"`, `"version_id":"route-v1"`,
		`"algorithm":"ip_hash"`, `"algorithm":"url_hash"`, `"algorithm":"least_conn"`,
	} {
		if !strings.Contains(string(canonical), expected) {
			t.Fatalf("canonical policy missing %q: %s", expected, canonical)
		}
	}

	baseDigest, err := CanonicalDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Policy){
		func(value *Policy) { value.TenantID = "tenant-b" },
		func(value *Policy) { value.SiteID = "site-b" },
		func(value *Policy) { value.VersionID = "route-v2" },
		func(value *Policy) { value.Pools[0].Algorithm = AlgorithmRandom },
	}
	for _, mutate := range mutations {
		candidate := policy
		candidate.Pools = append([]Pool(nil), policy.Pools...)
		mutate(&candidate)
		digest, err := CanonicalDigest(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if digest == baseDigest {
			t.Fatal("scope or algorithm mutation did not change canonical digest")
		}
	}

	artifact, err := Compile(policy, "/var/lib/cdnca/originroute", "/opt/cdnca/originroute")
	if err != nil {
		t.Fatal(err)
	}
	const stateKey = "v1|tenant=tenant-a|site=site-a|version=route-v1"
	if artifact.StateKey != stateKey {
		t.Fatalf("artifact state key = %q", artifact.StateKey)
	}
	if !strings.Contains(string(artifact.Nginx), `set $cdnca_origin_state_key "`+stateKey+`";`) {
		t.Fatalf("compiled nginx missing scoped state key:\n%s", artifact.Nginx)
	}
}

func TestOriginRouteAlgorithmContractRejectsUnknownAndEmptyScope(t *testing.T) {
	policy := testPolicy()
	policy.TenantID = "tenant-a"
	policy.SiteID = "site-a"
	policy.Pools[0].Algorithm = "ketama"
	if _, err := Normalize(policy); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("unknown algorithm error = %v", err)
	}

	policy = testPolicy()
	policy.TenantID = ""
	if _, err := Normalize(policy); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("empty tenant scope error = %v", err)
	}
}
