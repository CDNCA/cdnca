package sched302table

import (
	"net/netip"
	"testing"

	"github.com/cdnca/cdnca/libs/edgeconfig/sched302"
	"github.com/google/uuid"
)

var (
	nodeA = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	nodeB = uuid.MustParse("00000000-0000-4000-8000-00000000000b")
	nodeC = uuid.MustParse("00000000-0000-4000-8000-00000000000c")
	siteX = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	siteY = uuid.MustParse("22222222-2222-4222-8222-222222222222")
)

func testSite(id uuid.UUID, target string, endpoints ...Endpoint) Site {
	return Site{ID: id, Hosts: []string{"dl.example.test"}, Key: make([]byte, 32), Target: target, HTTPPorts: []int{80, 8080},
		Endpoints: endpoints}
}

func TestTables(t *testing.T) {
	sites := []Site{
		testSite(siteX, sched302.TargetAddress,
			Endpoint{NodeID: nodeA, Address: netip.MustParseAddr("2001:db8::a"), Region: "广东", Carrier: "中国电信", Weight: 10, Online: true},
			Endpoint{NodeID: nodeA, Address: netip.MustParseAddr("198.51.100.10"), Region: "广东", Carrier: "中国电信", Weight: 10, Online: true, Load: 35},
			Endpoint{NodeID: nodeB, Address: netip.MustParseAddr("198.51.100.11"), Region: "北京市", Carrier: "联通", Weight: 20, Online: false},
			Endpoint{NodeID: nodeC, Address: netip.MustParseAddr("203.0.113.12"), Region: "US", Carrier: "", Weight: 5, Online: true, Load: -1},
		),
		testSite(siteY, sched302.TargetHostname,
			Endpoint{NodeID: nodeA, Address: netip.MustParseAddr("198.51.100.10"), Weight: 10, Online: true, Hostname: "a.cdnca.com"},
			Endpoint{NodeID: nodeB, Address: netip.MustParseAddr("198.51.100.11"), Weight: 10, Online: true},
		),
	}
	tables := Tables(sites, 1_800_000_000)
	if len(tables) != 3 {
		t.Fatalf("tables for %d nodes", len(tables))
	}
	a := tables[nodeA]
	if len(a.Sites) != 2 || a.Sites[0].SiteID != siteX.String() || a.Sites[1].SiteID != siteY.String() {
		t.Fatalf("node A sites %+v", a.Sites)
	}
	candidates := a.Sites[0].Candidates
	if len(candidates) != 3 || candidates[0].Host != "198.51.100.10" || candidates[0].Carrier != "telecom" ||
		candidates[0].Country != "CN" || candidates[0].Province != 440000 || candidates[0].Load != 35 || candidates[0].HTTPPort != 80 {
		t.Fatalf("node A candidate %+v", candidates[0])
	}
	if candidates[1].Available || candidates[1].Province != 110000 || candidates[1].Carrier != "unicom" {
		t.Fatalf("node B candidate %+v", candidates[1])
	}
	if candidates[2].Country != "US" || candidates[2].Load != 0 {
		t.Fatalf("node C candidate %+v", candidates[2])
	}
	// target=hostname: a node without a direct hostname is no candidate.
	if hostname := a.Sites[1].Candidates; len(hostname) != 1 || hostname[0].Host != "a.cdnca.com" {
		t.Fatalf("hostname candidates %+v", hostname)
	}
	for nodeID, table := range tables {
		table.Revision = 1
		if _, err := sched302.Encode(table); err != nil {
			t.Fatalf("node %s table invalid: %v", nodeID, err)
		}
	}
	// The digest ignores revision and generated time.
	later := Tables(sites, 1_800_000_100)[nodeA]
	later.Revision = 9
	if Digest(later) != Digest(a) {
		t.Fatal("digest depends on revision or time")
	}
	sites[0].Endpoints[2].Online = true
	if Digest(Tables(sites, 1)[nodeA]) == Digest(a) {
		t.Fatal("digest misses availability")
	}
}

func TestRegion(t *testing.T) {
	for raw, want := range map[string]struct {
		country  string
		province uint32
	}{
		"广东": {"CN", 440000}, "中国广东省深圳": {"CN", 440000}, "内蒙古": {"CN", 150000}, "cn": {"CN", 0},
		"中国香港": {"HK", 0}, "US": {"US", 0}, "": {"", 0}, "火星": {"", 0},
	} {
		if country, province := Region(raw); country != want.country || province != want.province {
			t.Errorf("%q: %s %d", raw, country, province)
		}
	}
}
