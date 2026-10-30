package analyticsgeoartifact

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsgeo"
)

const (
	maximumCatalogs       = 16
	maximumEntries        = 100_000
	maximumCatalogBytes   = 16 * (8 << 20)
	maximumArtifactBytes  = 180 << 20
	artifactSchemaVersion = analyticsgeo.AuthoritySchemaV1
	maximumIdentityBytes  = 64
	maximumCountryBytes   = 8
	maximumRegionBytes    = 64
	maximumCarrierBytes   = 128
)

var (
	ErrConfiguration    = errors.New("analytics geo artifact configuration invalid")
	ErrInvalidRequest   = errors.New("analytics geo artifact request invalid")
	ErrInvalidFact      = errors.New("analytics geo artifact fact invalid")
	ErrFactConflict     = errors.New("analytics geo artifact fact conflict")
	ErrAddressPolicy    = errors.New("analytics geo artifact address policy rejected")
	ErrCapacity         = errors.New("analytics geo artifact capacity exceeded")
	ErrRevision         = errors.New("analytics geo artifact revision invalid")
	ErrRevisionConflict = errors.New("analytics geo artifact revision conflict")
)

type AddressPolicy string

const (
	AddressPolicyPublicOnly     AddressPolicy = "public_only"
	AddressPolicyAllowNonPublic AddressPolicy = "allow_non_public"
)

type Fact struct {
	Prefix      string
	CountryCode string
	Region      string
	Carrier     string
	ASN         uint32
}

type CatalogFacts struct {
	Version string
	Entries []Fact
}

type CompileRequest struct {
	Revision              uint64
	IssuedAt              time.Time
	ExpiresAt             time.Time
	CurrentCatalogVersion string
	AddressPolicy         AddressPolicy
	Catalogs              []CatalogFacts
}

type CompilerConfig struct {
	KeyID                string
	PrivateKey           ed25519.PrivateKey
	MaxCatalogs          int
	MaxEntriesPerCatalog int
	MaxCatalogBytes      int
	MaxArtifactBytes     int
}

type CompiledArtifact struct {
	Bytes     []byte
	SHA256    string
	Revision  uint64
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type Compiler struct {
	mu                   sync.Mutex
	keyID                string
	privateKey           ed25519.PrivateKey
	maxCatalogs          int
	maxEntriesPerCatalog int
	maxCatalogBytes      int
	maxArtifactBytes     int
	last                 CompiledArtifact
}

type catalogDocument struct {
	Version     string         `json:"version"`
	PublishedAt time.Time      `json:"published_at"`
	Entries     []catalogEntry `json:"entries"`
}

type catalogEntry struct {
	Prefix      string `json:"prefix"`
	CountryCode string `json:"country_code"`
	Region      string `json:"region"`
	Carrier     string `json:"carrier"`
	ASN         uint32 `json:"asn"`
}

type signedCatalogArtifact struct {
	DataBase64     string `json:"data_base64"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

type signedAuthorityArtifact struct {
	SchemaVersion         string                  `json:"schema_version"`
	Revision              uint64                  `json:"revision"`
	KeyID                 string                  `json:"key_id"`
	CurrentCatalogVersion string                  `json:"current_catalog_version"`
	ExpiresAt             string                  `json:"expires_at"`
	Catalogs              []signedCatalogArtifact `json:"catalogs"`
	SignatureBase64       string                  `json:"signature_base64"`
}

func NewCompiler(config CompilerConfig) (*Compiler, error) {
	if !validVersion(config.KeyID) || len(config.PrivateKey) != ed25519.PrivateKeySize ||
		config.MaxCatalogs <= 0 || config.MaxCatalogs > maximumCatalogs ||
		config.MaxEntriesPerCatalog <= 0 || config.MaxEntriesPerCatalog > maximumEntries ||
		config.MaxCatalogBytes <= 0 || config.MaxCatalogBytes > maximumCatalogBytes ||
		config.MaxArtifactBytes <= 0 || config.MaxArtifactBytes > maximumArtifactBytes {
		return nil, ErrConfiguration
	}
	derived := ed25519.NewKeyFromSeed(config.PrivateKey[:ed25519.SeedSize])
	if !bytes.Equal(derived, config.PrivateKey) {
		return nil, ErrConfiguration
	}
	return &Compiler{
		keyID: config.KeyID, privateKey: bytes.Clone(config.PrivateKey), maxCatalogs: config.MaxCatalogs,
		maxEntriesPerCatalog: config.MaxEntriesPerCatalog, maxCatalogBytes: config.MaxCatalogBytes,
		maxArtifactBytes: config.MaxArtifactBytes,
	}, nil
}

func (compiler *Compiler) Compile(ctx context.Context, request CompileRequest) (CompiledArtifact, error) {
	if compiler == nil || ctx == nil {
		return CompiledArtifact{}, ErrConfiguration
	}
	compiler.mu.Lock()
	defer compiler.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return CompiledArtifact{}, err
	}
	if request.Revision == 0 || !canonicalTime(request.IssuedAt) || !canonicalTime(request.ExpiresAt) ||
		!request.ExpiresAt.After(request.IssuedAt) || !validVersion(request.CurrentCatalogVersion) ||
		len(request.Catalogs) == 0 {
		return CompiledArtifact{}, ErrInvalidRequest
	}
	if request.AddressPolicy != AddressPolicyPublicOnly && request.AddressPolicy != AddressPolicyAllowNonPublic {
		return CompiledArtifact{}, ErrAddressPolicy
	}
	if len(request.Catalogs) > compiler.maxCatalogs {
		return CompiledArtifact{}, ErrCapacity
	}

	catalogs := append([]CatalogFacts(nil), request.Catalogs...)
	sort.Slice(catalogs, func(left, right int) bool { return catalogs[left].Version < catalogs[right].Version })
	wireCatalogs := make([]signedCatalogArtifact, 0, len(catalogs))
	digests := make([]string, 0, len(catalogs))
	seenVersions := make(map[string]struct{}, len(catalogs))
	currentFound := false
	totalCatalogBytes := 0
	for _, catalog := range catalogs {
		if err := ctx.Err(); err != nil {
			return CompiledArtifact{}, err
		}
		if !validVersion(catalog.Version) {
			return CompiledArtifact{}, ErrInvalidRequest
		}
		if _, duplicate := seenVersions[catalog.Version]; duplicate {
			return CompiledArtifact{}, ErrInvalidRequest
		}
		seenVersions[catalog.Version] = struct{}{}
		currentFound = currentFound || catalog.Version == request.CurrentCatalogVersion
		data, err := compiler.compileCatalog(ctx, request.IssuedAt, request.AddressPolicy, catalog)
		if err != nil {
			return CompiledArtifact{}, err
		}
		if len(data) > compiler.maxCatalogBytes-totalCatalogBytes {
			return CompiledArtifact{}, ErrCapacity
		}
		totalCatalogBytes += len(data)
		digest := sha256.Sum256(data)
		digestHex := hex.EncodeToString(digest[:])
		digests = append(digests, digestHex)
		wireCatalogs = append(wireCatalogs, signedCatalogArtifact{
			DataBase64: base64.StdEncoding.EncodeToString(data), ExpectedSHA256: digestHex,
		})
	}
	if !currentFound {
		return CompiledArtifact{}, ErrInvalidRequest
	}
	manifest, err := json.Marshal(analyticsgeo.AuthorityManifest{
		SchemaVersion: artifactSchemaVersion, Revision: request.Revision, KeyID: compiler.keyID,
		CurrentCatalogVersion: request.CurrentCatalogVersion,
		ExpiresAt:             request.ExpiresAt.Format(time.RFC3339Nano), CatalogSHA256: digests,
	})
	if err != nil {
		return CompiledArtifact{}, ErrInvalidRequest
	}
	signature := ed25519.Sign(compiler.privateKey, manifest)
	wire, err := json.Marshal(signedAuthorityArtifact{
		SchemaVersion: artifactSchemaVersion, Revision: request.Revision, KeyID: compiler.keyID,
		CurrentCatalogVersion: request.CurrentCatalogVersion,
		ExpiresAt:             request.ExpiresAt.Format(time.RFC3339Nano), Catalogs: wireCatalogs,
		SignatureBase64: base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		return CompiledArtifact{}, ErrInvalidRequest
	}
	if len(wire) > compiler.maxArtifactBytes {
		return CompiledArtifact{}, ErrCapacity
	}
	digest := sha256.Sum256(wire)
	compiled := CompiledArtifact{
		Bytes: bytes.Clone(wire), SHA256: hex.EncodeToString(digest[:]), Revision: request.Revision,
		IssuedAt: request.IssuedAt, ExpiresAt: request.ExpiresAt,
	}
	if compiler.last.Revision != 0 {
		switch {
		case request.Revision < compiler.last.Revision:
			return CompiledArtifact{}, ErrRevision
		case request.Revision == compiler.last.Revision:
			if !bytes.Equal(compiled.Bytes, compiler.last.Bytes) {
				return CompiledArtifact{}, ErrRevisionConflict
			}
			return cloneArtifact(compiler.last), nil
		}
	}
	if err := ctx.Err(); err != nil {
		return CompiledArtifact{}, err
	}
	compiler.last = cloneArtifact(compiled)
	return cloneArtifact(compiled), nil
}

func (compiler *Compiler) compileCatalog(
	ctx context.Context,
	issuedAt time.Time,
	policy AddressPolicy,
	catalog CatalogFacts,
) ([]byte, error) {
	if len(catalog.Entries) == 0 {
		return nil, ErrInvalidRequest
	}
	if len(catalog.Entries) > compiler.maxEntriesPerCatalog {
		return nil, ErrCapacity
	}
	unique := make(map[netip.Prefix]Fact, len(catalog.Entries))
	for index, fact := range catalog.Entries {
		if index%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		prefix, err := netip.ParsePrefix(fact.Prefix)
		if err != nil || prefix.String() != fact.Prefix || prefix != prefix.Masked() || prefix.Addr().Is4In6() ||
			!validCode(fact.CountryCode, maximumCountryBytes) || !validText(fact.Region, maximumRegionBytes) ||
			!validText(fact.Carrier, maximumCarrierBytes) || fact.ASN == 0 {
			return nil, ErrInvalidFact
		}
		if policy == AddressPolicyPublicOnly && nonPublicPrefix(prefix) {
			return nil, ErrAddressPolicy
		}
		if previous, duplicate := unique[prefix]; duplicate {
			if previous != fact {
				return nil, ErrFactConflict
			}
			continue
		}
		unique[prefix] = fact
	}
	entries := make([]catalogEntry, 0, len(unique))
	for _, fact := range unique {
		entries = append(entries, catalogEntry{
			Prefix: fact.Prefix, CountryCode: fact.CountryCode, Region: fact.Region,
			Carrier: fact.Carrier, ASN: fact.ASN,
		})
	}
	sort.Slice(entries, func(left, right int) bool {
		leftPrefix := netip.MustParsePrefix(entries[left].Prefix)
		rightPrefix := netip.MustParsePrefix(entries[right].Prefix)
		if leftPrefix.Addr().BitLen() != rightPrefix.Addr().BitLen() {
			return leftPrefix.Addr().BitLen() < rightPrefix.Addr().BitLen()
		}
		if compared := leftPrefix.Addr().Compare(rightPrefix.Addr()); compared != 0 {
			return compared < 0
		}
		return leftPrefix.Bits() < rightPrefix.Bits()
	})
	return json.Marshal(catalogDocument{Version: catalog.Version, PublishedAt: issuedAt, Entries: entries})
}

func cloneArtifact(value CompiledArtifact) CompiledArtifact {
	value.Bytes = bytes.Clone(value.Bytes)
	return value
}

func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Equal(value.Truncate(time.Millisecond))
}

func validIdentity(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
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

func validVersion(value string) bool {
	if !validIdentity(value, maximumIdentityBytes) {
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

func validText(value string, limit int) bool { return validIdentity(value, limit) }

var nonPublicNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func nonPublicPrefix(prefix netip.Prefix) bool {
	if !prefix.Addr().IsGlobalUnicast() || prefix.Addr().IsPrivate() {
		return true
	}
	for _, reserved := range nonPublicNetworks {
		if prefix.Addr().BitLen() == reserved.Addr().BitLen() && prefix.Overlaps(reserved) {
			return true
		}
	}
	return false
}
