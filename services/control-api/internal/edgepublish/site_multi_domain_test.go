package edgepublish

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSITE02RuntimeV2UsesEveryHistoricalSiteDomainFact(t *testing.T) {
	fact := siteFact{
		id:               uuid.New(),
		revision:         9,
		domain:           "api.example.test",
		domains:          []string{"*.example.test", "api.example.test", "xn--bcher-kva.example"},
		httpPorts:        []string{"80"},
		balance:          "round_robin",
		failoverTries:    1,
		connectTimeoutMS: 3000,
		readTimeoutMS:    30000,
		origins:          []snapshotOrigin{{Host: "192.0.2.10", Port: 80, Weight: 100}},
	}

	compiled, requiresTLS, err := compileSiteRuntimeV2SiteFact(nil, nil, uuid.New(), fact, time.Unix(1, 0).UTC())
	if err != nil || requiresTLS {
		t.Fatalf("compileSiteRuntimeV2SiteFact() = (%+v, %t, %v)", compiled, requiresTLS, err)
	}
	// Every historical fact, the primary domain first (siteRuntimeV2Domains).
	sorted := slices.Clone(compiled.Domains)
	slices.Sort(sorted)
	if !slices.Equal(sorted, fact.domains) || compiled.Domains[0] != fact.domain {
		t.Fatalf("runtime-v2 domains = %v, want historical facts %v with %s first", compiled.Domains, fact.domains, fact.domain)
	}
}
