package ipintel

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestWriteLuaParityFixtures writes artifacts plus the Go reference answers
// ((*Table).Lookup) for the node Lua lookup (edge/openresty/iplib). Run by
// scripts/security/iplib-smoke.sh with IPINTEL_LUA_FIXTURE_DIR set:
//
//	boundary.ipi / boundary.cases   sampleFacts + lookupBoundaryCases
//	boundary-next.ipi               same ranges, revision 8, 1.0.0.0/24 retagged cn-unicom (reload test)
//	large.ipi / large.cases         ~400k IPv4 + ~100k IPv6 random ranges, 100k random addresses
//
// A .cases line is "<hex address> <found 0|1> <tags hex16> <asn> <country|-> <province> <city>".
func TestWriteLuaParityFixtures(t *testing.T) {
	dir := os.Getenv("IPINTEL_LUA_FIXTURE_DIR")
	if dir == "" {
		t.Skip("IPINTEL_LUA_FIXTURE_DIR not set")
	}
	boundary := buildSample(t, sampleFacts(), testSources())
	addresses := make([]netip.Addr, 0, len(lookupBoundaryCases))
	for _, tc := range lookupBoundaryCases {
		addresses = append(addresses, netip.MustParseAddr(tc.addr))
	}
	writeParity(t, dir, "boundary", boundary, addresses)

	next := sampleFacts()
	next[0] = fact("1.0.0.0/24", TagCNUnicom, 0, "CN", 0)
	nextArtifact, err := Build(sampleInput(8, "ipintel-20261017-0008", testGeneratedAt, next, testSources()))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "boundary-next.ipi"), nextArtifact.Bytes)

	random := rand.New(rand.NewSource(20261017))
	facts := largeFacts(random, 400_000, 100_000)
	started := time.Now()
	largeInput := sampleInput(9, "ipintel-20261017-0009", testGeneratedAt, facts, testSources())
	largeInput.Regions = parityRegions
	large, err := Build(largeInput)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("large artifact: %d bytes, %+v, built in %s", len(large.Bytes), large.Metadata.Counts, time.Since(started))
	addresses = append([]netip.Addr(nil), addresses...)
	for len(addresses) < 100_000+len(lookupBoundaryCases) {
		addresses = append(addresses, randomAddr(random, facts))
	}
	writeParity(t, dir, "large", large, addresses)
}

var parityCountries = []string{"CN", "US", "JP", "DE", "SG", "HK", "GB", "BR"}

var parityRegions = map[uint32]string{440000: "广东省", 440300: "深圳市", 110000: "北京市", 110100: "北京市",
	310000: "上海市", 310100: "上海市", 330000: "浙江省", 330100: "杭州市", 429004: "仙桃市", 420000: "湖北省"}

// largeFacts draws random prefixes (CIDR prefixes are always nested or
// disjoint, which Build requires) with random attributes.
func largeFacts(random *rand.Rand, v4, v6 int) []Fact {
	tagBits := []uint64{TagCNTelecom, TagCNUnicom, TagCNMobile, TagCNCERNET, TagCNCSTNET, TagCNDrPeng, TagCNCBN, TagIDCCN, TagIDCGlobal}
	regions := [][2]uint32{{440000, 440300}, {110000, 110100}, {310000, 310100}, {330000, 330100}, {420000, 429004}, {440000, 0}}
	facts := make([]Fact, 0, v4+v6)
	for index := 0; index < v4+v6; index++ {
		var prefix netip.Prefix
		if index < v4 {
			var raw [4]byte
			random.Read(raw[:])
			prefix = netip.PrefixFrom(netip.AddrFrom4(raw), 12+random.Intn(21)).Masked()
		} else {
			var raw [16]byte
			random.Read(raw[:])
			raw[0] = 0x20 + byte(random.Intn(2))
			prefix = netip.PrefixFrom(netip.AddrFrom16(raw), 20+random.Intn(45)).Masked()
		}
		item := Fact{Prefix: prefix, CountryRank: uint8(random.Intn(3))}
		if random.Intn(3) != 0 {
			item.Tags = tagBits[random.Intn(len(tagBits))]
			if random.Intn(8) == 0 {
				item.Tags |= tagBits[random.Intn(len(tagBits))]
			}
		}
		if random.Intn(2) == 0 {
			item.ASN = uint32(1 + random.Intn(400000))
			if random.Intn(50) == 0 {
				item.ASN = 4294967295 - uint32(random.Intn(10))
			}
		}
		if random.Intn(4) != 0 || item.Tags == 0 && item.ASN == 0 {
			item.Country = parityCountries[random.Intn(len(parityCountries))]
			if item.Country == "CN" && random.Intn(2) == 0 {
				region := regions[random.Intn(len(regions))]
				item.Province, item.City = region[0], region[1]
			}
		}
		facts = append(facts, item)
	}
	return facts
}

// randomAddr is a uniformly random address half of the time, otherwise one
// inside, at the edge of or just outside a random fact, sometimes in the
// IPv4-mapped form.
func randomAddr(random *rand.Rand, facts []Fact) netip.Addr {
	if random.Intn(2) == 0 {
		if random.Intn(2) == 0 {
			var raw [4]byte
			random.Read(raw[:])
			return netip.AddrFrom4(raw)
		}
		var raw [16]byte
		random.Read(raw[:])
		return netip.AddrFrom16(raw)
	}
	prefix := facts[random.Intn(len(facts))].Prefix
	addr := prefix.Addr()
	switch random.Intn(4) {
	case 0:
		if previous := addr.Prev(); previous.IsValid() {
			addr = previous
		}
	case 1:
		addr = lastAddr(prefix)
	case 2:
		if next := lastAddr(prefix).Next(); next.IsValid() {
			addr = next
		}
	}
	if addr.Is4() && random.Intn(4) == 0 {
		addr = netip.AddrFrom16(addr.As16())
	}
	return addr
}

func writeParity(t *testing.T, dir, name string, artifact Artifact, addresses []netip.Addr) {
	t.Helper()
	table, err := Open(artifact.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var cases strings.Builder
	for _, addr := range addresses {
		got, found := table.Lookup(addr)
		country := got.Country
		if country == "" {
			country = "-"
		}
		foundFlag := 0
		if found {
			foundFlag = 1
		}
		fmt.Fprintf(&cases, "%s %d %016x %d %s %d %d\n", hex.EncodeToString(addr.AsSlice()), foundFlag, got.Tags, got.ASN,
			country, got.Province, got.City)
	}
	writeFile(t, filepath.Join(dir, name+".ipi"), artifact.Bytes)
	writeFile(t, filepath.Join(dir, name+".cases"), []byte(cases.String()))
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
