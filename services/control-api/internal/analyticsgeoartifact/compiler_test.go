package analyticsgeoartifact

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeo"
)

func TestCompilerProducesCanonicalLoaderCompatibleIPv4IPv6Artifact(t *testing.T) {
	compiler, privateKey := newCompilerFixture(t, 16, 100, 1<<20, 1<<20)
	issuedAt := time.Date(2026, 8, 8, 7, 0, 0, 0, time.UTC)
	request := validCompileRequest(issuedAt)

	first, err := compiler.Compile(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := compiler.Compile(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes, replay.Bytes) || first.SHA256 != replay.SHA256 || first.Revision != 7 ||
		!first.IssuedAt.Equal(issuedAt) || !first.ExpiresAt.Equal(request.ExpiresAt) {
		t.Fatalf("exact replay changed artifact: first=%#v replay=%#v", first, replay)
	}
	digest := sha256.Sum256(first.Bytes)
	if first.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("artifact digest = %q", first.SHA256)
	}

	keyring, err := analyticsgeo.NewTrustedEd25519Keyring(map[string]ed25519.PublicKey{
		"geo-publisher-1": privateKey.Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	loader, err := analyticsgeo.NewSignedFileLoader(analyticsgeo.SignedFileLoaderConfig{
		Keyring: keyring, Now: func() time.Time { return issuedAt },
		MaxArtifactBytes: 1 << 20, MaxAggregateCatalogBytes: 1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "geo-authority.json")
	if err := os.WriteFile(path, first.Bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := loader.Poll(t.Context(), analyticsgeo.FileTrigger{Path: path, ExpectedSHA256: first.SHA256}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		address, carrier, region, version string
		asn, bits                         int
	}{
		{address: "203.0.113.129", carrier: "specific", region: "JP-13", version: "geo-2026.08", asn: 64512, bits: 25},
		{address: "203.0.113.7", carrier: "current", region: "CN-SH", version: "geo-2026.08", asn: 64510, bits: 24},
		{address: "2001:db8::7", carrier: "ipv6-current", region: "CN-BJ", version: "geo-2026.08", asn: 64511, bits: 32},
		{address: "203.0.113.129", carrier: "old", region: "CN-SH", version: "geo-2026.07", asn: 64509, bits: 24},
	} {
		result, err := loader.Lookup(t.Context(), test.version, netip.MustParseAddr(test.address))
		if err != nil {
			t.Fatal(err)
		}
		if result.Attribution.Carrier != test.carrier || result.Attribution.Region != test.region ||
			result.Attribution.ASN != uint32(test.asn) || result.Attribution.PrefixLength != test.bits ||
			result.Provenance.Version != test.version || !result.Provenance.PublishedAt.Equal(issuedAt) ||
			len(result.Provenance.SHA256) != sha256.Size*2 || result.Revision != request.Revision {
			t.Fatalf("Lookup(%s,%s) = %#v", test.version, test.address, result)
		}
	}
}

func TestCompilerRejectsSameRevisionContentConflictAndRollback(t *testing.T) {
	compiler, _ := newCompilerFixture(t, 16, 100, 1<<20, 1<<20)
	request := validCompileRequest(time.Date(2026, 8, 8, 7, 0, 0, 0, time.UTC))
	first, err := compiler.Compile(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.Catalogs = cloneCatalogs(request.Catalogs)
	changed.Catalogs[1].Entries[0].Carrier = "changed"
	if _, err := compiler.Compile(t.Context(), changed); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("same revision changed content error = %v", err)
	}
	rollback := request
	rollback.Revision--
	if _, err := compiler.Compile(t.Context(), rollback); !errors.Is(err, ErrRevision) {
		t.Fatalf("rollback error = %v", err)
	}
	newer := changed
	newer.Revision++
	second, err := compiler.Compile(t.Context(), newer)
	if err != nil {
		t.Fatal(err)
	}
	if second.Revision != 8 || bytes.Equal(first.Bytes, second.Bytes) {
		t.Fatalf("new revision = %#v", second)
	}
}

func TestCompilerValidatesCIDRConflictsFactsTimesAndCurrentVersion(t *testing.T) {
	issuedAt := time.Date(2026, 8, 8, 7, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*CompileRequest)
		want   error
	}{
		{name: "host bits in CIDR", want: ErrInvalidFact, mutate: func(request *CompileRequest) {
			request.Catalogs[1].Entries[0].Prefix = "203.0.113.1/24"
		}},
		{name: "conflicting exact prefix", want: ErrFactConflict, mutate: func(request *CompileRequest) {
			conflict := request.Catalogs[1].Entries[0]
			conflict.Carrier = "other"
			request.Catalogs[1].Entries = append(request.Catalogs[1].Entries, conflict)
		}},
		{name: "invalid country", want: ErrInvalidFact, mutate: func(request *CompileRequest) {
			request.Catalogs[1].Entries[0].CountryCode = "cn"
		}},
		{name: "invalid region", want: ErrInvalidFact, mutate: func(request *CompileRequest) {
			request.Catalogs[1].Entries[0].Region = " CN-SH"
		}},
		{name: "invalid carrier", want: ErrInvalidFact, mutate: func(request *CompileRequest) {
			request.Catalogs[1].Entries[0].Carrier = "secret\nvalue"
		}},
		{name: "missing ASN", want: ErrInvalidFact, mutate: func(request *CompileRequest) {
			request.Catalogs[1].Entries[0].ASN = 0
		}},
		{name: "missing current version", want: ErrInvalidRequest, mutate: func(request *CompileRequest) {
			request.CurrentCatalogVersion = "geo-missing"
		}},
		{name: "non canonical catalog version", want: ErrInvalidRequest, mutate: func(request *CompileRequest) {
			request.Catalogs[1].Version = "geo 2026.08"
		}},
		{name: "non UTC issued time", want: ErrInvalidRequest, mutate: func(request *CompileRequest) {
			request.IssuedAt = request.IssuedAt.In(time.FixedZone("UTC+8", 8*60*60))
		}},
		{name: "non canonical expiry", want: ErrInvalidRequest, mutate: func(request *CompileRequest) {
			request.ExpiresAt = request.ExpiresAt.Add(time.Nanosecond)
		}},
		{name: "expiry before issued", want: ErrInvalidRequest, mutate: func(request *CompileRequest) {
			request.ExpiresAt = request.IssuedAt
		}},
		{name: "implicit address policy", want: ErrAddressPolicy, mutate: func(request *CompileRequest) {
			request.AddressPolicy = ""
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			compiler, _ := newCompilerFixture(t, 16, 100, 1<<20, 1<<20)
			request := validCompileRequest(issuedAt)
			request.Catalogs = cloneCatalogs(request.Catalogs)
			test.mutate(&request)
			if _, err := compiler.Compile(t.Context(), request); !errors.Is(err, test.want) {
				t.Fatalf("Compile() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCompilerRequiresExplicitPrivateReservedAddressPolicy(t *testing.T) {
	compiler, _ := newCompilerFixture(t, 16, 100, 1<<20, 1<<20)
	request := validCompileRequest(time.Date(2026, 8, 8, 7, 0, 0, 0, time.UTC))
	request.AddressPolicy = AddressPolicyPublicOnly
	if _, err := compiler.Compile(t.Context(), request); !errors.Is(err, ErrAddressPolicy) {
		t.Fatalf("reserved documentation prefixes error = %v", err)
	}
	request.AddressPolicy = AddressPolicyAllowNonPublic
	request.Catalogs[1].Entries = append(request.Catalogs[1].Entries, Fact{
		Prefix: "10.0.0.0/8", CountryCode: "ZZ", Region: "PRIVATE", Carrier: "internal", ASN: 64513,
	})
	if _, err := compiler.Compile(t.Context(), request); err != nil {
		t.Fatalf("explicit non-public policy error = %v", err)
	}
}

func TestCompilerEnforcesConfiguredCatalogEntryAndArtifactCapacity(t *testing.T) {
	issuedAt := time.Date(2026, 8, 8, 7, 0, 0, 0, time.UTC)
	request := validCompileRequest(issuedAt)
	for _, test := range []struct {
		name                                       string
		maxCatalogs, maxEntries, catalog, artifact int
	}{
		{name: "catalog count", maxCatalogs: 1, maxEntries: 100, catalog: 1 << 20, artifact: 1 << 20},
		{name: "entry count", maxCatalogs: 16, maxEntries: 2, catalog: 1 << 20, artifact: 1 << 20},
		{name: "catalog bytes", maxCatalogs: 16, maxEntries: 100, catalog: 64, artifact: 1 << 20},
		{name: "artifact bytes", maxCatalogs: 16, maxEntries: 100, catalog: 1 << 20, artifact: 128},
	} {
		t.Run(test.name, func(t *testing.T) {
			compiler, _ := newCompilerFixture(t, test.maxCatalogs, test.maxEntries, test.catalog, test.artifact)
			if _, err := compiler.Compile(t.Context(), request); !errors.Is(err, ErrCapacity) {
				t.Fatalf("Compile() error = %v", err)
			}
		})
	}
}

func newCompilerFixture(t *testing.T, maxCatalogs, maxEntries, maxCatalogBytes, maxArtifactBytes int) (*Compiler, ed25519.PrivateKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x57}, ed25519.SeedSize))
	compiler, err := NewCompiler(CompilerConfig{
		KeyID: "geo-publisher-1", PrivateKey: privateKey,
		MaxCatalogs: maxCatalogs, MaxEntriesPerCatalog: maxEntries,
		MaxCatalogBytes: maxCatalogBytes, MaxArtifactBytes: maxArtifactBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return compiler, privateKey
}

func validCompileRequest(issuedAt time.Time) CompileRequest {
	return CompileRequest{
		Revision: 7, IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour),
		CurrentCatalogVersion: "geo-2026.08", AddressPolicy: AddressPolicyAllowNonPublic,
		Catalogs: []CatalogFacts{
			{Version: "geo-2026.07", Entries: []Fact{
				{Prefix: "203.0.113.0/24", CountryCode: "CN", Region: "CN-SH", Carrier: "old", ASN: 64509},
			}},
			{Version: "geo-2026.08", Entries: []Fact{
				{Prefix: "203.0.113.0/24", CountryCode: "CN", Region: "CN-SH", Carrier: "current", ASN: 64510},
				{Prefix: "203.0.113.128/25", CountryCode: "JP", Region: "JP-13", Carrier: "specific", ASN: 64512},
				{Prefix: "2001:db8::/32", CountryCode: "CN", Region: "CN-BJ", Carrier: "ipv6-current", ASN: 64511},
			}},
		},
	}
}

func cloneCatalogs(source []CatalogFacts) []CatalogFacts {
	cloned := make([]CatalogFacts, len(source))
	for index, catalog := range source {
		cloned[index] = catalog
		cloned[index].Entries = append([]Fact(nil), catalog.Entries...)
	}
	return cloned
}
