package analyticsgeo

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func catalogDocument(version, publishedAt, entries string) []byte {
	return []byte(fmt.Sprintf(`{"version":%q,"published_at":%q,"entries":[%s]}`, version, publishedAt, entries))
}

func catalogInput(data []byte) CatalogInput {
	digest := sha256.Sum256(data)
	return CatalogInput{Data: data, ExpectedSHA256: fmt.Sprintf("%x", digest)}
}

func TestCatalogResolvesIPv4IPv6UnknownAndHistoricalVersions(t *testing.T) {
	oldData := catalogDocument("geo-2026.07", "2026-07-01T00:00:00Z",
		`{"prefix":"203.0.113.0/24","country_code":"CN","region":"CN-SH","carrier":"carrier-old","asn":64510},`+
			`{"prefix":"2001:db8::/32","country_code":"CN","region":"CN-BJ","carrier":"ipv6-old","asn":64511}`)
	currentData := catalogDocument("geo-2026.08", "2026-08-01T00:00:00Z",
		`{"prefix":"203.0.113.0/24","country_code":"CN","region":"CN-SH","carrier":"carrier-current","asn":64510},`+
			`{"prefix":"203.0.113.128/25","country_code":"JP","region":"JP-13","carrier":"specific","asn":64512},`+
			`{"prefix":"2001:db8::/32","country_code":"CN","region":"CN-BJ","carrier":"ipv6-current","asn":64511}`)
	catalog, err := NewCatalog([]CatalogInput{catalogInput(oldData), catalogInput(currentData)}, "geo-2026.08")
	if err != nil {
		t.Fatal(err)
	}

	for _, check := range []struct {
		version, address, country, carrier, resolution string
		bits                                           int
	}{
		{address: "203.0.113.129", country: "JP", carrier: "specific", resolution: "matched", bits: 25},
		{address: "2001:db8::7", country: "CN", carrier: "ipv6-current", resolution: "matched", bits: 32},
		{version: "geo-2026.07", address: "203.0.113.129", country: "CN", carrier: "carrier-old", resolution: "matched", bits: 24},
		{address: "198.51.100.1", country: "__unknown__", carrier: "__unknown__", resolution: "unknown"},
	} {
		attribution, provenance, err := catalog.Resolve(check.version, netip.MustParseAddr(check.address))
		if err != nil {
			t.Fatalf("Resolve(%q, %q): %v", check.version, check.address, err)
		}
		if attribution.CountryCode != check.country || attribution.Carrier != check.carrier ||
			attribution.Resolution != check.resolution || attribution.PrefixLength != check.bits ||
			provenance.Version == "" || len(provenance.SHA256) != 64 {
			t.Fatalf("Resolve(%q, %q) = %#v %#v", check.version, check.address, attribution, provenance)
		}
	}
}

func TestCatalogProjectsTraceableDatasetAndAddressFamily(t *testing.T) {
	data := []byte(`{"version":"geo-2026.08","provider":"example-geo","published_at":"2026-08-01T00:00:00Z","effective_at":"2026-08-02T00:00:00Z","entries":[{"prefix":"203.0.113.0/24","country_code":"CN","region":"CN-SH","city":"Shanghai","carrier":"carrier-v4","asn":64510},{"prefix":"2001:db8::/32","country_code":"CN","region":"CN-BJ","city":"Beijing","carrier":"carrier-v6","asn":64511}]}`)
	catalog, err := NewCatalog([]CatalogInput{catalogInput(data)}, "geo-2026.08")
	if err != nil {
		t.Fatal(err)
	}

	for _, check := range []struct {
		address, family, city, carrier string
	}{
		{address: "203.0.113.7", family: "ipv4", city: "Shanghai", carrier: "carrier-v4"},
		{address: "2001:db8::7", family: "ipv6", city: "Beijing", carrier: "carrier-v6"},
	} {
		attribution, provenance, err := catalog.Resolve("", netip.MustParseAddr(check.address))
		if err != nil {
			t.Fatal(err)
		}
		if attribution.AddressFamily != check.family || attribution.City != check.city ||
			attribution.Carrier != check.carrier || attribution.LookupReason != LookupReasonPrefixMatch ||
			provenance.Provider != "example-geo" ||
			!provenance.EffectiveAt.Equal(time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)) {
			t.Fatalf("traceable lookup = %#v %#v", attribution, provenance)
		}
	}

	unknown, provenance, err := catalog.Resolve("", netip.MustParseAddr("2001:db9::7"))
	if err != nil {
		t.Fatal(err)
	}
	if unknown.AddressFamily != "ipv6" || unknown.City != "__unknown__" ||
		unknown.LookupReason != LookupReasonNoPrefixMatch || provenance.Provider != "example-geo" {
		t.Fatalf("unknown lookup = %#v %#v", unknown, provenance)
	}
}

func TestCatalogRejectsUnverifiedOrAmbiguousDocuments(t *testing.T) {
	base := catalogDocument("geo-2026.08", "2026-08-01T00:00:00Z",
		`{"prefix":"203.0.113.0/24","country_code":"CN","region":"CN-SH","carrier":"carrier","asn":64510}`)
	badHash := catalogInput(base)
	badHash.ExpectedSHA256 = fmt.Sprintf("%064d", 0)
	if _, err := NewCatalog([]CatalogInput{badHash}, "geo-2026.08"); err == nil {
		t.Fatal("NewCatalog accepted a digest mismatch")
	}
	duplicate := catalogDocument("geo-2026.08", "2026-08-01T00:00:00Z",
		`{"prefix":"203.0.113.0/24","country_code":"CN","region":"CN-SH","carrier":"a","asn":1},`+
			`{"prefix":"203.0.113.0/24","country_code":"CN","region":"CN-SH","carrier":"b","asn":2}`)
	if _, err := NewCatalog([]CatalogInput{catalogInput(duplicate)}, "geo-2026.08"); err == nil {
		t.Fatal("NewCatalog accepted a duplicate prefix")
	}
}
