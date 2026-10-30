package sched302

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"net/netip"
	"os"
	"strings"
	"testing"
)

const (
	nodeA = "00000000-0000-4000-8000-00000000000a"
	nodeB = "00000000-0000-4000-8000-00000000000b"
	nodeC = "00000000-0000-4000-8000-00000000000c"
	nodeD = "00000000-0000-4000-8000-00000000000d"
	site1 = "11111111-1111-4111-8111-111111111111"
)

func testKey() []byte {
	key := make([]byte, KeyBytes)
	for index := range key {
		key[index] = byte(index)
	}
	return key
}

func TestNormalizeSite(t *testing.T) {
	site := Site{Target: TargetAddress, KeepPath: true, SignatureTTLSeconds: 60,
		Extensions: []string{".MP4", "zip", "mp4"}, PathPrefixes: []string{"/v/", "/d/", "/v/"}, MinSizeBytes: 1 << 20}
	if err := NormalizeSite(&site); err != nil {
		t.Fatal(err)
	}
	if strings.Join(site.Extensions, ",") != "mp4,zip" || strings.Join(site.PathPrefixes, ",") != "/d/,/v/" {
		t.Fatalf("normalized %+v", site)
	}
	if !ValidSite(site) {
		t.Fatal("normalized site is not valid")
	}
	for name, mutate := range map[string]func(*Site){
		"target":         func(s *Site) { s.Target = "ip" },
		"ttl low":        func(s *Site) { s.SignatureTTLSeconds = 9 },
		"ttl high":       func(s *Site) { s.SignatureTTLSeconds = 3601 },
		"extension":      func(s *Site) { s.Extensions = []string{"tar.gz"} },
		"prefix":         func(s *Site) { s.PathPrefixes = []string{"v/"} },
		"prefix percent": func(s *Site) { s.PathPrefixes = []string{"/a%20b"} },
		"prefix landing": func(s *Site) { s.PathPrefixes = []string{"/_cdnca302/x"} },
		"size":           func(s *Site) { s.MinSizeBytes = -1 },
	} {
		value := Site{Target: TargetAddress, SignatureTTLSeconds: 60}
		mutate(&value)
		if err := NormalizeSite(&value); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if ValidSite(Site{Target: TargetAddress, SignatureTTLSeconds: 60, Extensions: []string{"zip", "mp4"}, PathPrefixes: []string{}}) {
		t.Fatal("unsorted extensions accepted as canonical")
	}
}

func sampleTable() Table {
	return Table{Schema: TableSchema, NodeID: nodeA, Revision: 3, GeneratedAt: 1_800_000_000, Sites: []TableSite{{
		SiteID: site1, Hosts: []string{"dl.example.test", "*.cdn.example.test"}, Key: base64.RawURLEncoding.EncodeToString(testKey()),
		Candidates: []Candidate{
			{NodeID: nodeA, Host: "198.51.100.1", HTTPPort: 80, Carrier: "telecom", Country: "CN", Province: 440000, Weight: 10, Available: true},
			{NodeID: nodeB, Host: "edge-b.cdnca.com", HTTPPort: 80, Carrier: "unicom", Country: "CN", Province: 110000, Weight: 10, Available: true, Load: 20},
		},
	}}}
}

func TestTableRoundTrip(t *testing.T) {
	encoded, err := Encode(sampleTable())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil || decoded.Sites[0].Candidates[1].Host != "edge-b.cdnca.com" {
		t.Fatalf("decode: %v %+v", err, decoded)
	}
	if _, err := Decode(append(encoded, '\n')); err == nil {
		t.Fatal("non-canonical table accepted")
	}
	for name, mutate := range map[string]func(*Table){
		"order":    func(table *Table) { c := table.Sites[0].Candidates; c[0], c[1] = c[1], c[0] },
		"key":      func(table *Table) { table.Sites[0].Key = "AAAA" },
		"host":     func(table *Table) { table.Sites[0].Candidates[0].Host = "[::1]" },
		"ports":    func(table *Table) { table.Sites[0].Candidates[0].HTTPPort = 0 },
		"hosts":    func(table *Table) { table.Sites[0].Hosts = nil },
		"carrier":  func(table *Table) { table.Sites[0].Candidates[0].Carrier = "cmcc" },
		"province": func(table *Table) { table.Sites[0].Candidates[0].Province = 440300 },
		"load":     func(table *Table) { table.Sites[0].Candidates[0].Load = 101 },
		"schema":   func(table *Table) { table.Schema = "x" },
	} {
		table := sampleTable()
		mutate(&table)
		if _, err := Encode(table); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestSignVector pins the landing signature (the node Lua has the same vector).
func TestSignVector(t *testing.T) {
	got := LandingPath(testKey(), site1, "dl.example.test", "/v/a.mp4?x=1", 1_800_000_060)
	const want = "/_cdnca302/1800000060.b31jbohLec6U7CFe-WwoRM/dl.example.test/v/a.mp4?x=1"
	if got != want {
		t.Fatalf("landing path\n got %s\nwant %s", got, want)
	}
	if Sign(testKey(), site1, "dl.example.test", "/v/a.mp4?x=2", 1_800_000_060) == Sign(testKey(), site1, "dl.example.test", "/v/a.mp4?x=1", 1_800_000_060) {
		t.Fatal("signature does not cover the query")
	}
}

func TestSelectTiers(t *testing.T) {
	candidates := []Candidate{
		{NodeID: nodeA, Host: "198.51.100.1", HTTPPort: 80, Carrier: "telecom", Country: "CN", Province: 440000, Weight: 10, Available: true},
		{NodeID: nodeB, Host: "198.51.100.2", HTTPPort: 80, Carrier: "unicom", Country: "CN", Province: 110000, Weight: 10, Available: true},
		{NodeID: nodeC, Host: "198.51.100.3", HTTPPort: 80, Carrier: "bgp", Country: "CN", Weight: 10, Available: true},
		{NodeID: nodeD, Host: "203.0.113.4", HTTPPort: 80, Carrier: "", Country: "US", Weight: 10, Available: true},
	}
	client := func(address, carrier, country string, province uint32) Client {
		return Client{Address: netip.MustParseAddr(address), Carrier: carrier, Country: country, Province: province}
	}
	for _, tc := range []struct {
		name   string
		client Client
		want   string
	}{
		{"telecom guangdong", client("1.0.0.1", "telecom", "CN", 440000), nodeA},
		{"unicom beijing", client("2.0.0.1", "unicom", "CN", 110000), nodeB},
		{"telecom other province", client("1.0.0.2", "telecom", "CN", 310000), nodeA},
		{"mobile -> bgp", client("3.0.0.1", "mobile", "CN", 440000), nodeC},
		{"us", client("8.8.8.8", "", "US", 0), nodeD},
	} {
		got, ok := Select(candidates, tc.client)
		if !ok || got.NodeID != tc.want {
			t.Errorf("%s: got %s %v want %s", tc.name, got.NodeID, ok, tc.want)
		}
	}
	// Unavailable and overloaded candidates are skipped.
	down := append([]Candidate(nil), candidates...)
	down[0].Available = false
	if got, _ := Select(down, client("1.0.0.1", "telecom", "CN", 440000)); got.NodeID != nodeC {
		t.Fatalf("telecom down: %s", got.NodeID)
	}
	loaded := append([]Candidate(nil), candidates...)
	loaded = append(loaded, Candidate{NodeID: "00000000-0000-4000-8000-0000000000aa", Host: "198.51.100.9", HTTPPort: 80,
		Carrier: "telecom", Country: "CN", Province: 440000, Weight: 100, Available: true})
	loaded[4].Load = 95
	for index := 0; index < 64; index++ {
		address := netip.AddrFrom4([4]byte{1, 0, 0, byte(index)})
		if got, _ := Select(loaded, Client{Address: address, Carrier: "telecom", Country: "CN", Province: 440000}); got.NodeID != nodeA {
			t.Fatalf("overloaded candidate chosen for %s: %s", address, got.NodeID)
		}
	}
	if _, ok := Select(nil, client("1.0.0.1", "telecom", "CN", 440000)); ok {
		t.Fatal("selected from no candidates")
	}
}

// TestWriteSched302LuaVectors writes Select's answers for random clients
// against a mixed candidate set, for edge/openresty/sched302/unit_test.lua
// (set SCHED302_LUA_VECTORS to the output file).
func TestWriteSched302LuaVectors(t *testing.T) {
	output := os.Getenv("SCHED302_LUA_VECTORS")
	if output == "" {
		t.Skip("SCHED302_LUA_VECTORS not set")
	}
	candidates := []Candidate{
		{NodeID: nodeA, Host: "198.51.100.1", HTTPPort: 80, Carrier: "telecom", Country: "CN", Province: 440000, Weight: 10, Available: true},
		{NodeID: nodeB, Host: "198.51.100.2", HTTPPort: 80, Carrier: "telecom", Country: "CN", Province: 440000, Weight: 30, Available: true, Load: 40},
		{NodeID: nodeC, Host: "198.51.100.3", HTTPPort: 8080, Carrier: "unicom", Country: "CN", Province: 110000, Weight: 10, Available: true},
		{NodeID: nodeD, Host: "198.51.100.4", HTTPPort: 80, Carrier: "bgp", Country: "CN", Weight: 20, Available: true, Load: 95},
		{NodeID: "00000000-0000-4000-8000-0000000000ee", Host: "2001:db8::5", HTTPPort: 80, Country: "US", Weight: 5, Available: true},
		{NodeID: "00000000-0000-4000-8000-0000000000ff", Host: "198.51.100.6", HTTPPort: 80, Carrier: "mobile", Country: "CN", Province: 310000, Weight: 10},
	}
	type vector struct {
		Address  string `json:"address"`
		Carrier  string `json:"carrier"`
		Country  string `json:"country"`
		Province uint32 `json:"province"`
		Want     string `json:"want"`
	}
	random := rand.New(rand.NewSource(20261018))
	carriersList := []string{"", "telecom", "unicom", "mobile"}
	countries := []string{"", "CN", "US", "JP"}
	provinces := []uint32{0, 440000, 110000, 310000}
	var cases []vector
	for index := 0; index < 5000; index++ {
		var address netip.Addr
		if index%5 == 0 {
			var raw [16]byte
			random.Read(raw[:])
			address = netip.AddrFrom16(raw)
		} else {
			var raw [4]byte
			random.Read(raw[:])
			address = netip.AddrFrom4(raw)
		}
		client := Client{Address: address, Carrier: carriersList[random.Intn(4)], Country: countries[random.Intn(4)],
			Province: provinces[random.Intn(4)]}
		chosen, _ := Select(candidates, client)
		cases = append(cases, vector{Address: hex.EncodeToString(address.AsSlice()), Carrier: client.Carrier,
			Country: client.Country, Province: client.Province, Want: chosen.NodeID})
	}
	encoded, err := json.Marshal(map[string]any{"candidates": candidates, "cases": cases})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRendezvousSpreadsByWeight(t *testing.T) {
	counts := map[string]int{}
	candidates := []Candidate{
		{NodeID: nodeA, Host: "198.51.100.1", HTTPPort: 80, Weight: 30, Available: true},
		{NodeID: nodeB, Host: "198.51.100.2", HTTPPort: 80, Weight: 10, Available: true},
	}
	for index := 0; index < 4000; index++ {
		address := netip.AddrFrom4([4]byte{10, byte(index >> 8), byte(index), 1})
		got, _ := Select(candidates, Client{Address: address})
		counts[got.NodeID]++
	}
	if ratio := float64(counts[nodeA]) / float64(counts[nodeB]); ratio < 2.4 || ratio > 3.7 {
		t.Fatalf("weight 30:10 spread %v", counts)
	}
}

func TestMatchHost(t *testing.T) {
	hosts := []string{"dl.example.test", "*.cdn.example.test"}
	for host, want := range map[string]bool{"dl.example.test": true, "a.cdn.example.test": true, "a.b.cdn.example.test": true,
		"cdn.example.test": false, "xdl.example.test": false, "evil.test": false, "acdn.example.test": false} {
		if MatchHost(hosts, host) != want {
			t.Errorf("%s: want %v", host, want)
		}
	}
}
