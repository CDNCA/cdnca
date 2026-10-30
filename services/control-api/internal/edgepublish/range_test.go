package edgepublish

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig"
	"github.com/google/uuid"
)

func TestCompileSiteFactKeepsRangeCacheEnhancementDisabledByDefault(t *testing.T) {
	fact := siteFact{
		id:               uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		revision:         7,
		domain:           "cdn.example.com",
		balance:          string(edgeconfig.BalanceRoundRobin),
		failoverTries:    1,
		connectTimeoutMS: 3000,
		readTimeoutMS:    30000,
		origins: []snapshotOrigin{{
			Host: "192.0.2.10", Port: 8080, Weight: 1,
		}},
	}

	snapshot, site, err := compileSiteFact(uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), fact, 80, nil, nil, nil)
	if err != nil {
		t.Fatalf("compileSiteFact(, nil) error = %v", err)
	}
	if !site.Range || site.RangeCache != nil {
		t.Fatalf("ordinary site Range = %t, RangeCache = %+v, want true and nil", site.Range, site.RangeCache)
	}
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if strings.Contains(string(snapshotJSON), `"range_cache"`) {
		t.Fatalf("ordinary site snapshot unexpectedly activates Range cache: %s", snapshotJSON)
	}
}
