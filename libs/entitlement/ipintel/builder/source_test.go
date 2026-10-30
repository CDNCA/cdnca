package builder

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	format "github.com/cdnca/cdnca/libs/entitlement/ipintel"
)

var fixtureNow = time.Date(2026, 10, 17, 4, 0, 0, 0, time.UTC)

func loadFixture(t *testing.T) *FixtureSource {
	t.Helper()
	source, err := LoadFixtureSource(filepath.Join("testdata", "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func compileFixture(t *testing.T, collection Collection) format.Artifact {
	t.Helper()
	artifact, err := Compile(collection, CompileRequest{Revision: 3, BuildID: "ipintel-20261017-000003", GeneratedAt: fixtureNow})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return artifact
}

func TestFixtureSourceLookups(t *testing.T) {
	var source Source = loadFixture(t)
	collection, err := source.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	table, err := format.Open(compileFixture(t, collection).Bytes)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		addr    string
		tags    uint64
		asn     uint32
		country string
	}{
		{"1.0.1.1", format.TagCNTelecom, 0, "CN"},
		{"36.100.0.1", format.TagCNTelecom, 4134, "CN"},
		{"240e:1::1", format.TagCNTelecom, 4134, "CN"},
		{"240e:100::1", format.TagCNTelecom, 0, "CN"},
		{"1.25.0.1", format.TagCNUnicom, 4837, "CN"},
		{"2408:8000::1", format.TagCNUnicom, 4837, "CN"},
		{"39.130.0.1", format.TagCNMobile, 9808, "CN"},
		{"202.112.0.1", format.TagCNCERNET, 4538, "CN"},
		{"47.93.0.1", format.TagIDCCN, 37963, "CN"},
		{"2401:b180::1", format.TagIDCCN, 37963, "CN"},
		{"3.1.255.255", format.TagIDCGlobal, 16509, "US"},
		{"2600:1f00::1", format.TagIDCGlobal, 16509, "US"},
		{"8.8.8.8", 0, 15169, "US"},
		{"1.161.0.1", 0, 3462, "TW"},
	}
	for _, tc := range cases {
		got, found := table.Lookup(netip.MustParseAddr(tc.addr))
		if !found || got.Tags != tc.tags || got.ASN != tc.asn || got.Country != tc.country {
			t.Errorf("Lookup(%s) = %+v found=%v, want %v asn=%d %s", tc.addr, got, found, format.TagNames(tc.tags), tc.asn, tc.country)
		}
	}
	for _, addr := range []string{"3.2.0.0", "9.9.9.9", "2a00::1"} {
		if got, found := table.Lookup(netip.MustParseAddr(addr)); found {
			t.Errorf("Lookup(%s) = %+v, want not found", addr, got)
		}
	}
	if len(table.Metadata.Sources) != 2 || table.Metadata.Notice == "" {
		t.Fatalf("metadata = %+v", table.Metadata)
	}
}

func TestCompileAndFingerprintAreDeterministic(t *testing.T) {
	collection, err := loadFixture(t).Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first := compileFixture(t, collection)
	fingerprint := Fingerprint(collection)
	random := rand.New(rand.NewSource(3))
	for round := 0; round < 10; round++ {
		shuffled := collection
		shuffled.Facts = append([]format.Fact(nil), collection.Facts...)
		random.Shuffle(len(shuffled.Facts), func(i, j int) { shuffled.Facts[i], shuffled.Facts[j] = shuffled.Facts[j], shuffled.Facts[i] })
		if !bytes.Equal(compileFixture(t, shuffled).Bytes, first.Bytes) || Fingerprint(shuffled) != fingerprint {
			t.Fatalf("round %d: output depends on fact order", round)
		}
	}
	changed := collection
	changed.Facts = append(append([]format.Fact(nil), collection.Facts...),
		format.Fact{Prefix: netip.MustParsePrefix("1.56.0.0/13"), Tags: format.TagCNUnicom})
	if Fingerprint(changed) == fingerprint || compileFixture(t, changed).DataSHA256 == first.DataSHA256 {
		t.Fatal("changed facts kept the fingerprint or data digest")
	}
	relicensed := collection
	relicensed.Sources = append([]format.Source(nil), collection.Sources...)
	relicensed.Sources[0].Ref = "fixture-2"
	if Fingerprint(relicensed) == fingerprint {
		t.Fatal("source version change kept the fingerprint")
	}
}

func TestFixtureSourceRejectsBadFiles(t *testing.T) {
	valid, err := os.ReadFile(filepath.Join("testdata", "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(string) string{
		"schema":        func(s string) string { return strings.Replace(s, "fixture/v1", "fixture/v2", 1) },
		"unknown field": func(s string) string { return strings.Replace(s, `"notice"`, `"extra": 1, "notice"`, 1) },
		"unknown tag":   func(s string) string { return strings.Replace(s, "carrier:cn-mobile", "carrier:cn-tietong", 1) },
		"bad prefix":    func(s string) string { return strings.Replace(s, `"39.128.0.0/10"`, `"39.128.0.1/10"`, 1) },
	} {
		if _, err := NewFixtureSource("fixture", []byte(mutate(string(valid)))); !errors.Is(err, ErrSource) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// No sources listed: the fixture records itself as the source.
	minimal := `{"schema": "cdnca.ip-intel.fixture/v1", "entries": [{"prefix": "1.0.1.0/24", "tags": ["carrier:cn-telecom"]}]}`
	source, err := NewFixtureSource("fixture", []byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	collection, _ := source.Collect(context.Background())
	if len(collection.Sources) != 1 || collection.Sources[0].Files[0].SHA256 == "" {
		t.Fatalf("default source = %+v", collection.Sources)
	}
	compileFixture(t, collection)
}

// RIPE RIS, PeeringDB and the Tor exit list are redistributable (owner
// 2026-10-17) only under their exact LicenseRef and with an attribution.
func TestCheckRedistributableAcceptsRoutingAndTorSources(t *testing.T) {
	for id, license := range map[string]string{
		"ripe-ris": "LicenseRef-ripe-ncc-ris", "peeringdb": "LicenseRef-peeringdb-aup",
		"tor-exitlist": "LicenseRef-tor-project-exitlist",
	} {
		ok := format.Source{ID: id, License: license, Attribution: id + " attribution"}
		if err := CheckRedistributable([]format.Source{ok}); err != nil {
			t.Errorf("%s: %v", id, err)
		}
		for name, bad := range map[string]format.Source{
			"wrong license":  {ID: id, License: "LicenseRef-dnspup", Attribution: "x"},
			"no attribution": {ID: id, License: license},
		} {
			if err := CheckRedistributable([]format.Source{bad}); !errors.Is(err, ErrLicense) {
				t.Errorf("%s %s: want ErrLicense, got %v", id, name, err)
			}
		}
	}
}
