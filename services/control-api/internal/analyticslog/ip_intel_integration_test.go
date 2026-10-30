//go:build integration

package analyticslog

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement/ipintel"
	"github.com/cdnca/cdnca/services/control-api/internal/artifactsync/artifactsynctest"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
)

// TestPostgresIPIntelLookupFollowsTheStoredLibrary (G3-d) against the real
// schema: no library -> no answers; the stored LKG library answers; a newer
// revision is picked up after the refresh interval, a damaged row is never
// served (the last good table stays).
func TestPostgresIPIntelLookupFollowsTheStoredLibrary(t *testing.T) {
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		t.Skip("TEST_DATABASE_TEMPLATE is not set (scripts/control-api-integration-sharded.sh)")
	}
	ctx := t.Context()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	lookup := NewPostgresIPIntelLookup(pool, nil)
	lookup.now = func() time.Time { return now }
	if got := lookup.Lookup(ctx, []string{"1.0.0.7"}); got["1.0.0.7"] != nil {
		t.Fatalf("answer without a library: %+v", got)
	}

	store := func(revision uint64, carrier uint64, damage bool) {
		t.Helper()
		generated := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
		artifact, err := ipintel.Build(ipintel.BuildInput{Revision: revision, BuildID: fmt.Sprintf("ipintel-test-%04d", revision),
			GeneratedAt: generated, DataUpdatedAt: generated.Add(-time.Hour), StaleAfter: generated.Add(30 * 24 * time.Hour),
			Sources: []ipintel.Source{{ID: "fixture", Name: "fixture", URL: "https://example.test", License: "CC0-1.0", Ref: "1", Role: "test"}},
			Facts:   []ipintel.Fact{{Prefix: netip.MustParsePrefix("1.0.0.0/24"), Tags: carrier, Country: "CN"}}})
		if err != nil {
			t.Fatal(err)
		}
		bytes := artifact.Bytes
		if damage {
			// Same length, wrong content: the stored bytes no longer match the entry.
			bytes = append([]byte(nil), bytes...)
			bytes[len(bytes)-2] ^= 0xff
		}
		artifactsynctest.SeedDownloaded(t, pool, artifactsynctest.IPIntelBase(revision, fmt.Sprintf("ipintel-test-%04d", revision),
			artifact.SHA256, 2), bytes)
	}
	store(3, ipintel.TagCNTelecom, false)
	now = now.Add(time.Minute)
	if info := lookup.Lookup(ctx, []string{"1.0.0.7"})["1.0.0.7"]; info == nil || info.Carrier != "carrier:cn-telecom" || info.Revision != 3 {
		t.Fatalf("revision 3 answer = %+v", info)
	}
	store(4, ipintel.TagCNMobile, false)
	if info := lookup.Lookup(ctx, []string{"1.0.0.7"})["1.0.0.7"]; info == nil || info.Revision != 3 {
		t.Fatalf("revision checked before the refresh interval: %+v", info)
	}
	now = now.Add(time.Minute)
	if info := lookup.Lookup(ctx, []string{"1.0.0.7"})["1.0.0.7"]; info == nil || info.Carrier != "carrier:cn-mobile" || info.Revision != 4 {
		t.Fatalf("revision 4 answer = %+v", info)
	}
	store(5, ipintel.TagCNUnicom, true)
	now = now.Add(time.Minute)
	if info := lookup.Lookup(ctx, []string{"1.0.0.7"})["1.0.0.7"]; info == nil || info.Revision != 4 {
		t.Fatalf("damaged revision 5 served: %+v", info)
	}
}
