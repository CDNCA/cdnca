package analyticsgeo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type CatalogInput struct {
	Data           []byte
	ExpectedSHA256 string
}

type catalogFile struct {
	Version     string         `json:"version"`
	Provider    string         `json:"provider"`
	PublishedAt time.Time      `json:"published_at"`
	EffectiveAt time.Time      `json:"effective_at"`
	Entries     []catalogEntry `json:"entries"`
}

type catalogEntry struct {
	Prefix      string `json:"prefix"`
	CountryCode string `json:"country_code"`
	Region      string `json:"region"`
	City        string `json:"city"`
	Carrier     string `json:"carrier"`
	ASN         uint32 `json:"asn"`
}

type catalogVersion struct {
	provenance Provenance
	entries    []resolvedEntry
}

type resolvedEntry struct {
	prefix      netip.Prefix
	attribution Attribution
}

type Catalog struct {
	current  string
	versions map[string]catalogVersion
}

func NewCatalog(inputs []CatalogInput, current string) (*Catalog, error) {
	if len(inputs) == 0 || len(inputs) > maximumCatalogDocuments || !validVersion(current) {
		return nil, ErrInvalidConfiguration
	}
	catalog := &Catalog{current: current, versions: make(map[string]catalogVersion, len(inputs))}
	for _, input := range inputs {
		version, err := parseCatalog(input)
		if err != nil {
			return nil, err
		}
		if _, duplicate := catalog.versions[version.provenance.Version]; duplicate {
			return nil, ErrInvalidConfiguration
		}
		catalog.versions[version.provenance.Version] = version
	}
	if _, ok := catalog.versions[current]; !ok {
		return nil, ErrInvalidConfiguration
	}
	return catalog, nil
}

func parseCatalog(input CatalogInput) (catalogVersion, error) {
	if len(input.Data) == 0 || len(input.Data) > maximumCatalogBytes || len(input.ExpectedSHA256) != sha256.Size*2 {
		return catalogVersion{}, ErrInvalidConfiguration
	}
	expected, err := hex.DecodeString(input.ExpectedSHA256)
	actual := sha256.Sum256(input.Data)
	if err != nil || !bytes.Equal(expected, actual[:]) || input.ExpectedSHA256 != strings.ToLower(input.ExpectedSHA256) {
		return catalogVersion{}, ErrInvalidConfiguration
	}
	decoder := json.NewDecoder(bytes.NewReader(input.Data))
	decoder.DisallowUnknownFields()
	var document catalogFile
	if decoder.Decode(&document) != nil || decoder.Decode(&struct{}{}) != io.EOF || !validVersion(document.Version) ||
		document.PublishedAt.IsZero() || document.PublishedAt.Location() != time.UTC || len(document.Entries) == 0 ||
		len(document.Entries) > maximumCatalogEntries {
		return catalogVersion{}, ErrInvalidConfiguration
	}
	if document.Provider == "" {
		document.Provider = "__legacy__"
	} else if !validCatalogText(document.Provider, 128) {
		return catalogVersion{}, ErrInvalidConfiguration
	}
	if document.EffectiveAt.IsZero() {
		document.EffectiveAt = document.PublishedAt
	} else if document.EffectiveAt.Location() != time.UTC {
		return catalogVersion{}, ErrInvalidConfiguration
	}
	entries := make([]resolvedEntry, 0, len(document.Entries))
	seen := make(map[netip.Prefix]struct{}, len(document.Entries))
	for _, entry := range document.Entries {
		if entry.City == "" {
			entry.City = "__unknown__"
		}
		prefix, err := netip.ParsePrefix(entry.Prefix)
		if err != nil || prefix.String() != entry.Prefix || prefix.Masked() != prefix || !validCode(entry.CountryCode, 8) ||
			!validCatalogText(entry.Region, 64) || !validCatalogText(entry.City, 128) ||
			!validCatalogText(entry.Carrier, 128) || entry.ASN == 0 {
			return catalogVersion{}, ErrInvalidConfiguration
		}
		if _, duplicate := seen[prefix]; duplicate {
			return catalogVersion{}, ErrInvalidConfiguration
		}
		seen[prefix] = struct{}{}
		entries = append(entries, resolvedEntry{prefix: prefix, attribution: Attribution{
			CountryCode: entry.CountryCode, Region: entry.Region, City: entry.City, Carrier: entry.Carrier, ASN: entry.ASN,
			Resolution: ResolutionMatched, PrefixLength: prefix.Bits(),
		}})
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].prefix.Bits() > entries[right].prefix.Bits() })
	return catalogVersion{provenance: Provenance{
		Version: document.Version, Provider: document.Provider, SHA256: fmt.Sprintf("%x", actual),
		PublishedAt: document.PublishedAt, EffectiveAt: document.EffectiveAt,
	}, entries: entries}, nil
}

func (catalog *Catalog) Resolve(version string, address netip.Addr) (Attribution, Provenance, error) {
	if catalog == nil || !address.IsValid() || address.Zone() != "" {
		return Attribution{}, Provenance{}, ErrInvalidInput
	}
	if version == "" {
		version = catalog.current
	}
	database, ok := catalog.versions[version]
	if !ok {
		return Attribution{}, Provenance{}, ErrVersionNotFound
	}
	for _, entry := range database.entries {
		if entry.prefix.Contains(address) {
			attribution := entry.attribution
			attribution.AddressFamily = addressFamily(address)
			attribution.LookupReason = LookupReasonPrefixMatch
			return attribution, database.provenance, nil
		}
	}
	return Attribution{CountryCode: "__unknown__", Region: "__unknown__", City: "__unknown__", Carrier: "__unknown__",
		AddressFamily: addressFamily(address), LookupReason: LookupReasonNoPrefixMatch,
		Resolution: ResolutionUnknown}, database.provenance, nil
}

func addressFamily(address netip.Addr) string {
	if address.Is4() {
		return "ipv4"
	}
	return "ipv6"
}

func validVersion(value string) bool {
	if !validIdentity(value, 64) {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._-", character)) {
			return false
		}
	}
	return true
}

func validCode(value string, limit int) bool {
	if !validIdentity(value, limit) {
		return false
	}
	for _, character := range value {
		if !((character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func validCatalogText(value string, limit int) bool { return validIdentity(value, limit) }
