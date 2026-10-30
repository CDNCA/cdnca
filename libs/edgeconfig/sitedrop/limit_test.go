package sitedrop

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Longest encodings the contract accepts.
const (
	limitIssued = int64(1<<63-1) - int64(MaxDuration/time.Second)
	limitTime   = int64(1<<63 - 1)
)

func limitSites(count int) []Site {
	sites := make([]Site, count)
	for index := range sites {
		sites[index] = Site{SiteID: fmt.Sprintf("%08x-0000-4000-8000-000000000000", index),
			TenantID: testTenant, Since: limitIssued, Until: limitTime}
	}
	return sites
}

// MaxSites/MaxSiteBytes/MaxEnvelopeBytes hold for the longest values, and a
// list of exactly MaxSites longest sites is signed and opened.
func TestLimitBoundsLongestEncoding(t *testing.T) {
	site, _ := json.Marshal(Site{SiteID: testSiteA, TenantID: testTenant, Since: limitTime, Until: limitTime})
	if len(site)+1 != MaxSiteBytes {
		t.Fatalf("longest site is %d bytes with separator, MaxSiteBytes %d", len(site)+1, MaxSiteBytes)
	}
	public, private := testKey(t)
	keyID := strings.Repeat("k", 128)
	list := List{NodeID: testNode, Revision: 1<<64 - 1, IssuedAt: limitIssued, Sites: limitSites(MaxSites)}
	encoded, err := Sign(list, keyID, private)
	if err != nil {
		t.Fatalf("exactly MaxSites longest sites: %v", err)
	}
	if len(encoded) > MaxListBytes || len(encoded) > MaxEnvelopeBytes+MaxSites*MaxSiteBytes {
		t.Fatalf("list %d bytes over the bound", len(encoded))
	}
	if _, err := Open(encoded, testNode, func(string) (ed25519.PublicKey, bool) { return public, true }); err != nil {
		t.Fatalf("open the largest list: %v", err)
	}
	list.Sites = limitSites(MaxSites + 1)
	if _, err := Sign(list, keyID, private); err == nil {
		t.Fatal("MaxSites+1 sites signed")
	}
}

// A list one byte over MaxListBytes is refused by Decode (node and gateway).
func TestDecodeRefusesOneByteOver(t *testing.T) {
	over := make([]byte, MaxListBytes+1)
	if _, err := Decode(over); err == nil {
		t.Fatal("MaxListBytes+1 accepted")
	}
	if MaxCarrierBytes > 1<<20 {
		t.Fatalf("carrier bound %d over the 1 MiB gRPC message limit", MaxCarrierBytes)
	}
}
