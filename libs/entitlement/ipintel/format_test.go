package ipintel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"net/netip"
	"testing"
	"time"
)

var testGeneratedAt = time.Date(2026, 10, 17, 3, 0, 0, 0, time.UTC)

func fact(prefix string, tags uint64, asn uint32, country string, rank uint8) Fact {
	return Fact{Prefix: netip.MustParsePrefix(prefix), Tags: tags, ASN: asn, Country: country, CountryRank: rank}
}

func testSources() []Source {
	return []Source{
		{ID: "ipverse-as-ip-blocks", Name: "ipverse/as-ip-blocks", URL: "https://github.com/ipverse/as-ip-blocks",
			License: "CC0-1.0", Ref: "latest", Role: "asn,country,idc",
			Files: []SourceFile{{Path: "as-ip-blocks.tar.gz", SHA256: "bb", Bytes: 2}}},
		{ID: "china-operator-ip", Name: "gaoyifan/china-operator-ip", URL: "https://github.com/gaoyifan/china-operator-ip",
			License: "MIT", Attribution: "Copyright (c) Yifan Gao", Ref: "ip-lists", Role: "carrier,country",
			Files: []SourceFile{{Path: "unicom.txt", SHA256: "cc", Bytes: 3}, {Path: "chinanet.txt", SHA256: "aa", Bytes: 1}}},
	}
}

func sampleFacts() []Fact {
	return []Fact{
		fact("1.0.0.0/24", TagCNTelecom, 0, "CN", 0),
		fact("1.0.0.128/25", 0, 4134, "CN", 1),
		fact("1.0.1.0/24", TagCNUnicom, 0, "CN", 0),
		fact("8.8.8.0/24", TagIDCGlobal, 15169, "US", 1),
		fact("255.255.255.255/32", TagIDCGlobal, 64500, "", 1),
		fact("240e::/20", TagCNTelecom, 0, "CN", 0),
		fact("240e:100::/24", 0, 4134, "CN", 1),
		fact("2400:3200::/32", TagIDCCN, 37963, "CN", 1),
		fact("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff00/120", TagIDCGlobal, 64501, "", 1),
	}
}

func sampleInput(revision uint64, buildID string, generatedAt time.Time, facts []Fact, sources []Source) BuildInput {
	return BuildInput{Revision: revision, BuildID: buildID, GeneratedAt: generatedAt,
		DataUpdatedAt: generatedAt.Add(-time.Hour), StaleAfter: generatedAt.Add(30 * 24 * time.Hour), SourceRelease: "ipx-0123456789abcdef01234567",
		Sources: sources, Notice: "test notice", Facts: facts,
		Regions: map[uint32]string{440000: "广东省", 440300: "深圳市", 110000: "北京市", 110100: "北京市"}}
}

func buildSample(t *testing.T, facts []Fact, sources []Source) Artifact {
	t.Helper()
	artifact, err := Build(sampleInput(7, "ipintel-20261017-0007", testGeneratedAt, facts, sources))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return artifact
}

// lookupBoundaryCases are the edge addresses of sampleFacts (range ends,
// holes, 0.255.255.255 / 255.255.255.255 / ffff…ffff, IPv4-mapped); the
// node Lua lookup is checked against the same list (lua_parity_test.go).
var lookupBoundaryCases = []struct {
	addr    string
	found   bool
	tags    uint64
	asn     uint32
	country string
}{
	{"0.255.255.255", false, 0, 0, ""},
	{"1.0.0.0", true, TagCNTelecom, 0, "CN"},
	{"1.0.0.127", true, TagCNTelecom, 0, "CN"},
	{"1.0.0.128", true, TagCNTelecom, 4134, "CN"},
	{"1.0.0.255", true, TagCNTelecom, 4134, "CN"},
	{"1.0.1.0", true, TagCNUnicom, 0, "CN"},
	{"1.0.1.255", true, TagCNUnicom, 0, "CN"},
	{"1.0.2.0", false, 0, 0, ""},
	{"8.8.8.8", true, TagIDCGlobal, 15169, "US"},
	{"255.255.255.254", false, 0, 0, ""},
	{"255.255.255.255", true, TagIDCGlobal, 64500, ""},
	{"::ffff:1.0.0.1", true, TagCNTelecom, 0, "CN"},
	{"240d:ffff::1", false, 0, 0, ""},
	{"240e::1", true, TagCNTelecom, 0, "CN"},
	{"240e:ff:ffff::1", true, TagCNTelecom, 0, "CN"},
	{"240e:100::1", true, TagCNTelecom, 4134, "CN"},
	{"240e:1ff:ffff:ffff:ffff:ffff:ffff:ffff", true, TagCNTelecom, 4134, "CN"},
	{"240e:200::", true, TagCNTelecom, 0, "CN"},
	{"240e:fff:ffff:ffff:ffff:ffff:ffff:ffff", true, TagCNTelecom, 0, "CN"},
	{"240e:1000::", false, 0, 0, ""},
	{"2400:3200::8", true, TagIDCCN, 37963, "CN"},
	{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:feff", false, 0, 0, ""},
	{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true, TagIDCGlobal, 64501, ""},
}

func TestBuildLookupBoundaries(t *testing.T) {
	artifact := buildSample(t, sampleFacts(), testSources())
	table, err := Open(artifact.Bytes)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if table.Metadata.Counts.IPv4Ranges != 5 || table.Metadata.Counts.IPv6Ranges != 5 {
		t.Fatalf("counts = %+v", table.Metadata.Counts)
	}
	for _, tc := range lookupBoundaryCases {
		got, found := table.Lookup(netip.MustParseAddr(tc.addr))
		if found != tc.found || got.Tags != tc.tags || got.ASN != tc.asn || got.Country != tc.country {
			t.Errorf("Lookup(%s) = %+v,%v want tags=%b asn=%d country=%q found=%v",
				tc.addr, got, found, tc.tags, tc.asn, tc.country, tc.found)
		}
	}
}

func TestBuildIsDeterministicAcrossInputOrder(t *testing.T) {
	first := buildSample(t, sampleFacts(), testSources())
	random := rand.New(rand.NewSource(1))
	for round := 0; round < 20; round++ {
		facts := sampleFacts()
		random.Shuffle(len(facts), func(i, j int) { facts[i], facts[j] = facts[j], facts[i] })
		sources := testSources()
		random.Shuffle(len(sources), func(i, j int) { sources[i], sources[j] = sources[j], sources[i] })
		again := buildSample(t, facts, sources)
		if !bytes.Equal(first.Bytes, again.Bytes) || first.SHA256 != again.SHA256 {
			t.Fatalf("round %d: build differs", round)
		}
	}
	other, err := Build(sampleInput(8, "ipintel-20261018-0008", testGeneratedAt.Add(24*time.Hour), sampleFacts(), testSources()))
	if err != nil {
		t.Fatal(err)
	}
	if other.DataSHA256 != first.DataSHA256 || other.SHA256 == first.SHA256 {
		t.Fatalf("data digest must only depend on ranges: %s/%s %s/%s", other.DataSHA256, first.DataSHA256, other.SHA256, first.SHA256)
	}
}

func TestBuildMergesDuplicatesAndAdjacentRanges(t *testing.T) {
	artifact := buildSample(t, []Fact{
		fact("1.0.0.0/25", TagCNTelecom, 0, "CN", 0),
		fact("1.0.0.128/25", TagCNTelecom, 0, "CN", 0),
		// Same prefix announced by two origins and listed by two carriers.
		fact("2.0.0.0/24", TagCNTelecom, 0, "CN", 0),
		fact("2.0.0.0/24", TagCNUnicom, 0, "", 0),
		fact("2.0.0.0/24", 0, 4837, "CN", 1),
		fact("2.0.0.0/24", 0, 4134, "US", 1),
	}, testSources())
	table, err := Open(artifact.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if table.Metadata.Counts.IPv4Ranges != 2 {
		t.Fatalf("ipv4 ranges = %d, want adjacent equal ranges merged", table.Metadata.Counts.IPv4Ranges)
	}
	got, found := table.Lookup(netip.MustParseAddr("2.0.0.9"))
	if !found || got.Tags != TagCNTelecom|TagCNUnicom || got.ASN != 4134 || got.Country != "CN" {
		t.Fatalf("merged duplicate = %+v", got)
	}
}

func TestBuildCountryPriority(t *testing.T) {
	artifact := buildSample(t, []Fact{
		// Higher-priority outer country survives a lower-priority, more specific one.
		fact("3.0.0.0/16", 0, 0, "CN", 0),
		fact("3.0.1.0/24", 0, 16509, "US", 1),
		// A more specific prefix of equal priority wins.
		fact("4.0.0.0/16", 0, 3356, "US", 1),
		fact("4.0.1.0/24", 0, 2914, "JP", 1),
		// A more specific prefix of higher priority wins.
		fact("5.0.0.0/16", 0, 3356, "US", 1),
		fact("5.0.1.0/24", 0, 0, "CN", 0),
	}, testSources())
	table, err := Open(artifact.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]Attrs{
		"3.0.1.1": {ASN: 16509, Country: "CN"}, "3.0.2.1": {Country: "CN"},
		"4.0.1.1": {ASN: 2914, Country: "JP"}, "4.0.2.1": {ASN: 3356, Country: "US"},
		"5.0.1.1": {ASN: 3356, Country: "CN"}, "5.0.2.1": {ASN: 3356, Country: "US"},
	} {
		if got, found := table.Lookup(netip.MustParseAddr(addr)); !found || got != want {
			t.Errorf("Lookup(%s) = %+v, want %+v", addr, got, want)
		}
	}
}

func TestBuildRejectsInvalidInput(t *testing.T) {
	valid := sampleInput(1, "b1", testGeneratedAt, []Fact{fact("1.0.0.0/24", TagCNTelecom, 0, "CN", 0)}, testSources())
	for name, mutate := range map[string]func(*BuildInput){
		"zero revision":    func(in *BuildInput) { in.Revision = 0 },
		"bad build id":     func(in *BuildInput) { in.BuildID = "bad id" },
		"sub-second time":  func(in *BuildInput) { in.GeneratedAt = testGeneratedAt.Add(time.Millisecond) },
		"no facts":         func(in *BuildInput) { in.Facts = nil },
		"no sources":       func(in *BuildInput) { in.Sources = nil },
		"duplicate source": func(in *BuildInput) { in.Sources = append(in.Sources, in.Sources[0]) },
		"host bits": func(in *BuildInput) {
			in.Facts = []Fact{{Prefix: netip.MustParsePrefix("1.0.0.1/24"), Tags: TagCNTelecom}}
		},
		"4in6 prefix":        func(in *BuildInput) { in.Facts = []Fact{fact("::ffff:1.0.0.0/120", TagCNTelecom, 0, "", 0)} },
		"bad country":        func(in *BuildInput) { in.Facts = []Fact{fact("1.0.0.0/24", 0, 0, "cn", 0)} },
		"unknown tag":        func(in *BuildInput) { in.Facts = []Fact{fact("1.0.0.0/24", 1<<40, 0, "", 0)} },
		"empty fact":         func(in *BuildInput) { in.Facts = []Fact{fact("1.0.0.0/24", 0, 0, "", 0)} },
		"no data time":       func(in *BuildInput) { in.DataUpdatedAt = time.Time{} },
		"data after build":   func(in *BuildInput) { in.DataUpdatedAt = in.GeneratedAt.Add(time.Second) },
		"stale at build":     func(in *BuildInput) { in.StaleAfter = in.GeneratedAt },
		"bad source release": func(in *BuildInput) { in.SourceRelease = "bad release" },
		"province without country": func(in *BuildInput) {
			in.Facts = []Fact{{Prefix: netip.MustParsePrefix("1.0.0.0/24"), ASN: 1, Province: 440000}}
		},
		"city outside province": func(in *BuildInput) {
			in.Facts = []Fact{{Prefix: netip.MustParsePrefix("1.0.0.0/24"), Country: "CN", Province: 440000, City: 110100}}
		},
		"city without province": func(in *BuildInput) {
			in.Facts = []Fact{{Prefix: netip.MustParsePrefix("1.0.0.0/24"), Country: "CN", City: 440300}}
		},
		"unnamed region": func(in *BuildInput) {
			in.Facts = []Fact{{Prefix: netip.MustParsePrefix("1.0.0.0/24"), Country: "CN", Province: 330000}}
		},
	} {
		input := valid
		input.Sources = testSources()
		mutate(&input)
		if _, err := Build(input); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if _, err := Build(valid); err != nil {
		t.Fatalf("valid input: %v", err)
	}
}

func TestOpenRejectsCorruption(t *testing.T) {
	artifact := buildSample(t, sampleFacts(), testSources())
	header := artifact.Bytes[:HeaderSize]
	attrOff := binary.LittleEndian.Uint32(header[32:36])
	v4Off := binary.LittleEndian.Uint32(header[36:40])
	mutations := map[string]func([]byte) []byte{
		"magic":           func(b []byte) []byte { b[0] = 'X'; return b },
		"version":         func(b []byte) []byte { binary.LittleEndian.PutUint16(b[8:10], 1); return b },
		"truncated":       func(b []byte) []byte { return b[:len(b)-1] },
		"trailing":        func(b []byte) []byte { return append(b, 0) },
		"range data":      func(b []byte) []byte { b[v4Off+3] ^= 1; return b },
		"attr reserved":   func(b []byte) []byte { b[attrOff+14] = 1; return b },
		"revision header": func(b []byte) []byte { binary.LittleEndian.PutUint64(b[24:32], 99); return b },
		"metadata":        func(b []byte) []byte { b[len(b)-2] = ' '; return b },
	}
	for name, mutate := range mutations {
		if _, err := Open(mutate(bytes.Clone(artifact.Bytes))); !errors.Is(err, ErrInvalidArtifact) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// Unsorted ranges are rejected even when the data digest is recomputed.
	corrupt := bytes.Clone(artifact.Bytes)
	first := corrupt[v4Off : v4Off+IPv4RecordSize]
	second := corrupt[v4Off+IPv4RecordSize : v4Off+2*IPv4RecordSize]
	swapped := append(bytes.Clone(second), first...)
	copy(corrupt[v4Off:], swapped)
	if _, err := openUnchecked(corrupt); !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("unsorted ranges: err = %v", err)
	}
}

func TestTagNames(t *testing.T) {
	seen := map[uint8]bool{}
	for _, definition := range TagDefinitions() {
		if seen[definition.Bit] || TagMask&(1<<definition.Bit) == 0 {
			t.Fatalf("bad tag definition %+v", definition)
		}
		seen[definition.Bit] = true
		if bit, ok := TagByName(definition.Name); !ok || bit != 1<<definition.Bit {
			t.Fatalf("TagByName(%s) = %d,%v", definition.Name, bit, ok)
		}
	}
	if len(seen) != 9 {
		t.Fatalf("tag count = %d", len(seen))
	}
	if names := TagNames(TagCNTelecom | TagIDCCN); len(names) != 2 || names[0] != "carrier:cn-telecom" || names[1] != "idc:cn" {
		t.Fatalf("TagNames = %v", names)
	}
}

func TestBuildRegionsAndIDCByCountry(t *testing.T) {
	artifact := buildSample(t, []Fact{
		{Prefix: netip.MustParsePrefix("36.96.0.0/12"), Country: "CN", Province: 440000, City: 440300, CountryRank: 0},
		{Prefix: netip.MustParsePrefix("36.96.0.0/12"), Tags: TagCNTelecom, ASN: 4134},
		{Prefix: netip.MustParsePrefix("36.100.0.0/16"), Country: "CN", Province: 440000, CountryRank: 0}, // less specific geo, same rank: wins as inner
		{Prefix: netip.MustParsePrefix("47.96.0.0/16"), Country: "CN", Province: 110000, City: 110100},
		{Prefix: netip.MustParsePrefix("47.96.0.0/16"), Tags: TagIDCByCountry, ASN: 37963},
		{Prefix: netip.MustParsePrefix("3.0.0.0/8"), Country: "US"},
		{Prefix: netip.MustParsePrefix("3.0.0.0/9"), Tags: TagIDCByCountry, ASN: 16509},
		{Prefix: netip.MustParsePrefix("45.76.0.0/16"), Tags: TagIDCByCountry}, // no country: global
		// Same prefix, two geo claims at the same rank: the more specific (city) one wins deterministically.
		{Prefix: netip.MustParsePrefix("58.16.0.0/16"), Country: "CN", Province: 110000},
		{Prefix: netip.MustParsePrefix("58.16.0.0/16"), Country: "CN", Province: 110000, City: 110100},
	}, testSources())
	table, err := Open(artifact.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]Attrs{
		"36.96.0.1":  {Tags: TagCNTelecom, ASN: 4134, Country: "CN", Province: 440000, City: 440300},
		"36.100.0.1": {Tags: TagCNTelecom, ASN: 4134, Country: "CN", Province: 440000},
		"47.96.0.1":  {Tags: TagIDCCN, ASN: 37963, Country: "CN", Province: 110000, City: 110100},
		"3.1.0.1":    {Tags: TagIDCGlobal, ASN: 16509, Country: "US"},
		"3.200.0.1":  {Country: "US"},
		"45.76.0.1":  {Tags: TagIDCGlobal},
		"58.16.0.1":  {Country: "CN", Province: 110000, City: 110100},
	} {
		if got, found := table.Lookup(netip.MustParseAddr(addr)); !found || got != want {
			t.Errorf("Lookup(%s) = %+v, want %+v", addr, got, want)
		}
	}
	metadata := table.Metadata
	if len(metadata.Regions) != 4 || metadata.Regions["440300"] != "深圳市" || metadata.Regions["110100"] != "北京市" ||
		metadata.FormatVersion != 2 || metadata.CapabilityVersion != 2 || metadata.SourceRelease != "ipx-0123456789abcdef01234567" ||
		metadata.DataUpdatedAt != "2026-10-17T02:00:00Z" || metadata.StaleAfter != "2026-11-16T03:00:00Z" {
		t.Fatalf("metadata = %+v", metadata)
	}
	for _, attrs := range table.attrs {
		if attrs.Tags&TagIDCByCountry != 0 {
			t.Fatal("build-only bit stored")
		}
	}
}
