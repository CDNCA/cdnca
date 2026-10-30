// Package artifactcatalog defines the signed per-installation artifact
// catalog (cdnca.artifact-catalog/v1) the license service serves to control
// installations (ADR 0007 §4.1): one list of signed entries — system rules
// (ruleset), the CRS rule text (crs_profile), the IP intelligence base
// library (ipintel) and later kinds — each naming its bytes by sha256. The
// bytes are fetched separately and checked against the signed entry.
//
// The license service and control-api both import this package so canonical
// encoding, digests, proof messages and verification cannot drift.
package artifactcatalog

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/cdnca/cdnca/libs/entitlement/enginemodule"
)

const (
	CatalogSchema = "cdnca.artifact-catalog/v1"

	KindRuleset        = "ruleset"
	KindCRSProfile     = "crs_profile"
	KindIPIntel        = "ipintel"
	KindDataset        = "dataset"
	KindEngineModule   = "engine_module"
	KindNodeCapability = "node_capability"
	KindRulePack       = "rule_pack"
	// KindMarketRulePack / KindMarketTheme are data packages bought on the
	// plugin market (PA-18): market_rule_pack/<plugin id> (a developer-layer
	// rule pack) and market_theme/<plugin id> (a theme market.<plugin id>),
	// served only to installations whose plugin installation authorization
	// is authorized or enabled.
	KindMarketRulePack = "market_rule_pack"
	KindMarketTheme    = "market_theme"
	// KindPluginUI is the page declaration of a ui_page plugin (PA-19,
	// libs/entitlement/pluginui): plugin_ui/<plugin id>, served like the
	// market data packages only while the installation's authorization is
	// authorized or enabled. It carries no code, only where the pages are.
	KindPluginUI = "plugin_ui"
	// KindPluginProvider is the declaration of a third-party provider plugin
	// (PA-22, libs/entitlement/pluginprovider): plugin_provider/<plugin id>,
	// served while the installation's authorization is authorized or enabled.
	KindPluginProvider = "plugin_provider"

	MediaTypeRuleset = "application/vnd.cdnca.ruleset-item+json;version=1"
	// MediaTypeCRSProfile is the CRS rule text package (crs_profile/crs_rules,
	// a rulecatalog item with a bundle body); MediaTypeCRSProfilePack is a
	// CRS profile pack (crs_profile/crs-<level>, a cdnca.rule-pack/v1
	// document in canonical form, libs/rulepack).
	MediaTypeCRSProfile     = "application/vnd.cdnca.crs-profile+json;version=1"
	MediaTypeCRSProfilePack = "application/vnd.cdnca.rule-pack+json;version=1"
	MediaTypeIPIntel        = "application/vnd.cdnca.ip-intel-artifact;version=2"
	// MediaTypeEngineModule is an engine module bundle (enginemodule.Bundle).
	MediaTypeEngineModule = enginemodule.MediaType
	// MediaTypeRulePack: a cdnca.rule-pack/v1 document (encryption none) or
	// its sealed form cdnca.rule-pack-sealed/v1 (install_wrapped, PA-14).
	MediaTypeRulePack = "application/vnd.cdnca.rule-pack+json;version=1"
	// MediaTypeTheme: a cdnca.theme/v1 package (market themes).
	MediaTypeTheme = "application/vnd.cdnca.theme+json;version=1"
	// MediaTypePluginUI: a cdnca.plugin-ui/v1 declaration.
	MediaTypePluginUI = "application/vnd.cdnca.plugin-ui+json;version=1"
	// MediaTypePluginProvider: a cdnca.plugin-provider/v1 declaration.
	MediaTypePluginProvider = "application/vnd.cdnca.plugin-provider+json;version=1"
	// MediaTypeTrustedCrawlers: the official crawler IP ranges dataset
	// (dataset/trusted-crawlers, libs/edgeconfig/crawlerdefaults).
	MediaTypeTrustedCrawlers = "application/vnd.cdnca.trusted-crawlers+json;version=1"

	EncryptionNone           = "none"
	EncryptionInstallWrapped = "install_wrapped"

	MaxEntries      = 4096
	MaxCatalogBytes = 2 << 20
	// MaxContentBytes bounds one entry's bytes (the IP library is the largest).
	MaxContentBytes = 256 << 20
	maxRevision     = 1<<53 - 1
)

var (
	ErrInvalidCatalog  = errors.New("invalid artifact catalog")
	ErrContentMismatch = errors.New("artifact bytes do not match the catalog entry")

	artifactIDPattern = regexp.MustCompile(`^([a-z][a-z0-9_]{0,31})/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	versionPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)
	mediaTypePattern  = regexp.MustCompile(`^application/vnd\.(cdnca|cdnca)\.[a-z0-9.+-]{1,96}(;version=[0-9]{1,4})?$`)
	featurePattern    = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	capabilityPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	spdxPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$`)
	sha256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	wrappedKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,684}$`)
)

// knownMediaTypes pins the media types of every kind this release can use.
var knownMediaTypes = map[string][]string{
	KindRuleset: {MediaTypeRuleset}, KindCRSProfile: {MediaTypeCRSProfile, MediaTypeCRSProfilePack},
	KindIPIntel:        {MediaTypeIPIntel},
	KindEngineModule:   {MediaTypeEngineModule},
	KindRulePack:       {MediaTypeRulePack},
	KindMarketRulePack: {MediaTypeRulePack},
	KindMarketTheme:    {MediaTypeTheme},
	KindPluginUI:       {MediaTypePluginUI},
	KindPluginProvider: {MediaTypePluginProvider},
	KindDataset:        {MediaTypeTrustedCrawlers},
}

// Catalog is the installation's set of entries, sorted by artifact_id.
type Catalog struct {
	Schema  string  `json:"schema"`
	Entries []Entry `json:"entries"`
}

// Entry describes one artifact. Field order is alphabetical so the canonical
// JSON is plain json.Marshal.
//   - ArtifactID is "<kind>/<name>"; Revision only moves forward per id.
//   - RequiresFeature is the lease feature code that unlocks it ("" = free).
//   - Resident entries are downloaded by default (ADR 0007 §5.4); others only
//     when an administrator asks for them.
//   - WrappedKey is the installation-wrapped content key of an
//     install_wrapped entry (empty for none).
type Entry struct {
	ArtifactID         string      `json:"artifact_id"`
	Encryption         string      `json:"encryption"`
	Kind               string      `json:"kind"`
	LicenseSPDX        string      `json:"license_spdx"`
	MediaType          string      `json:"media_type"`
	RequiresCapability *Capability `json:"requires_capability"`
	RequiresFeature    string      `json:"requires_feature"`
	Resident           bool        `json:"resident"`
	Revision           uint64      `json:"revision"`
	SHA256             string      `json:"sha256"`
	Size               int64       `json:"size"`
	Supersedes         string      `json:"supersedes"`
	Version            string      `json:"version"`
	WrappedKey         string      `json:"wrapped_key"`
}

// Capability is the node capability an entry needs to be used.
type Capability struct {
	MinVersion int    `json:"min_version"`
	Name       string `json:"name"`
}

// CanonicalCatalog validates catalog and returns its canonical bytes and
// SHA-256 digest.
func CanonicalCatalog(catalog Catalog) ([]byte, [32]byte, error) {
	if err := ValidateCatalog(catalog); err != nil {
		return nil, [32]byte{}, err
	}
	encoded, err := json.Marshal(catalog)
	if err != nil || len(encoded) > MaxCatalogBytes {
		return nil, [32]byte{}, ErrInvalidCatalog
	}
	return encoded, sha256.Sum256(encoded), nil
}

// DigestString is the envelope encoding of a catalog digest.
func DigestString(digest [32]byte) string { return base64.RawURLEncoding.EncodeToString(digest[:]) }

// SortEntries orders entries by artifact_id, the canonical order.
func SortEntries(entries []Entry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].ArtifactID < entries[j].ArtifactID })
}

func ValidateCatalog(catalog Catalog) error {
	if catalog.Schema != CatalogSchema || catalog.Entries == nil || len(catalog.Entries) > MaxEntries {
		return ErrInvalidCatalog
	}
	for index, entry := range catalog.Entries {
		if index > 0 && catalog.Entries[index-1].ArtifactID >= entry.ArtifactID {
			return ErrInvalidCatalog
		}
		if err := ValidateEntry(entry); err != nil {
			return err
		}
	}
	return nil
}

// ValidateEntry checks one entry in isolation. Kinds this release does not
// know are valid (a newer license service may list them); use Supported.
func ValidateEntry(entry Entry) error {
	match := artifactIDPattern.FindStringSubmatch(entry.ArtifactID)
	if match == nil || match[1] != entry.Kind || !versionPattern.MatchString(entry.Version) ||
		entry.Revision < 1 || entry.Revision > maxRevision || !sha256Pattern.MatchString(entry.SHA256) ||
		entry.Size < 1 || entry.Size > MaxContentBytes || !mediaTypePattern.MatchString(entry.MediaType) ||
		entry.RequiresFeature != "" && !featurePattern.MatchString(entry.RequiresFeature) ||
		entry.LicenseSPDX != "" && !spdxPattern.MatchString(entry.LicenseSPDX) ||
		entry.Supersedes != "" && (!artifactIDPattern.MatchString(entry.Supersedes) || entry.Supersedes == entry.ArtifactID) {
		return ErrInvalidCatalog
	}
	if want, known := knownMediaTypes[entry.Kind]; known && !slices.Contains(want, entry.MediaType) {
		return ErrInvalidCatalog
	}
	if capability := entry.RequiresCapability; capability != nil &&
		(!capabilityPattern.MatchString(capability.Name) || capability.MinVersion < 1 || capability.MinVersion > 1000) {
		return ErrInvalidCatalog
	}
	switch entry.Encryption {
	case EncryptionNone:
		if entry.WrappedKey != "" {
			return ErrInvalidCatalog
		}
	case EncryptionInstallWrapped:
		if !wrappedKeyPattern.MatchString(entry.WrappedKey) {
			return ErrInvalidCatalog
		}
	default:
		return ErrInvalidCatalog
	}
	return nil
}

// Supported reports whether this release can download and use entry: a
// known kind; only rule packs may be encrypted (install_wrapped, PA-14).
func Supported(entry Entry) bool {
	_, known := knownMediaTypes[entry.Kind]
	return known && (entry.Encryption == EncryptionNone || entry.Kind == KindRulePack)
}

// RulePackArtifactID is the entry id of a rule pack: rule_pack/<pack_id>
// with '/' spelled ':' (system/sqli-basic -> rule_pack/system:sqli-basic).
func RulePackArtifactID(packID string) string {
	return KindRulePack + "/" + strings.ReplaceAll(packID, "/", ":")
}

// ValidSHA256 reports a lowercase hex SHA-256 digest (entry sha256 form).
func ValidSHA256(value string) bool { return sha256Pattern.MatchString(value) }

// ValidArtifactID reports a well-formed artifact id.
func ValidArtifactID(value string) bool { return artifactIDPattern.MatchString(value) }

// ValidFeature reports a well-formed lease feature code.
func ValidFeature(value string) bool { return featurePattern.MatchString(value) }
