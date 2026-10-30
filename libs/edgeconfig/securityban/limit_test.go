package securityban

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const (
	limitTime   = int64(1<<63 - 1)
	limitClient = "2001:db8:1111:2222:3333:4444:5555:6666/127"
)

func limitList(entries int) List {
	list := List{Schema: Schema, NodeID: "11111111-1111-4111-8111-111111111111", Revision: 1<<64 - 1, IssuedAt: limitTime,
		Bans: []Ban{}, Releases: []Release{}, Algorithm: Algorithm, KeyID: strings.Repeat("k", 128)}
	for index := range entries {
		list.Bans = append(list.Bans, Ban{SiteID: fmt.Sprintf("%08x-0000-4000-8000-000000000000", index),
			Client: limitClient, Until: limitTime, Source: "autodefense"})
	}
	return list
}

// A list of exactly MaxEntries longest bans is signed and opened; one more is
// refused; the bound stays under the 1 MiB gRPC message limit.
func TestLimitBoundsLongestEncoding(t *testing.T) {
	ban, _ := json.Marshal(Ban{SiteID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", Client: limitClient, Until: limitTime, Source: "autodefense"})
	if len(ban)+1 > MaxEntryBytes {
		t.Fatalf("longest ban is %d bytes with separator, MaxEntryBytes %d", len(ban)+1, MaxEntryBytes)
	}
	public, private, _ := ed25519.GenerateKey(nil)
	list := limitList(MaxEntries)
	payload, err := SigningPayload(list)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Seal(list, ed25519.Sign(private, payload))
	if err != nil {
		t.Fatalf("exactly MaxEntries longest bans: %v", err)
	}
	if len(encoded) > MaxListBytes {
		t.Fatalf("list %d bytes over MaxListBytes", len(encoded))
	}
	if _, err := Open(encoded, list.NodeID, func(string) (ed25519.PublicKey, bool) { return public, true }); err != nil {
		t.Fatalf("open the largest list: %v", err)
	}
	if _, err := SigningPayload(limitList(MaxEntries + 1)); err == nil {
		t.Fatal("MaxEntries+1 entries accepted")
	}
	if _, err := Decode(make([]byte, MaxListBytes+1)); err == nil {
		t.Fatal("MaxListBytes+1 accepted")
	}
	if MaxCarrierBytes > 1<<20 {
		t.Fatalf("carrier bound %d over the 1 MiB gRPC message limit", MaxCarrierBytes)
	}
}
