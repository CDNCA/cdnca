package artifactcatalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/libs/entitlement/enginemodule"
	"github.com/cdnca/cdnca/libs/entitlement/ipintel"
	"github.com/cdnca/cdnca/libs/entitlement/rulecatalog"
)

const (
	// IPIntelBaseID is the license-built IP intelligence base library.
	IPIntelBaseID = "ipintel/base"
	// CRSRulesID is the OWASP CRS rule text (system rule waf_set:crs_rules).
	CRSRulesID = "crs_profile/crs_rules"

	crsLicense       = "Apache-2.0"
	systemRulePrefix = "waf_set:"
)

// crsProfilePackPrefix maps a CRS profile pack (pack_id system/crs-<level>)
// to its entry (crs_profile/crs-<level>); crsAppPackPrefix an application
// exclusion pack (system/app-<key>, the OWASP CRS official rule exclusion
// plugins, waf-apptype) to crs_profile/app-<key>. Both are Apache-2.0 rule
// packs of the same media type and table (crs_profile_pack_versions).
const (
	crsProfilePackPrefix = "crs-"
	crsAppPackPrefix     = "app-"
)

func crsPackName(name string) bool {
	return strings.HasPrefix(name, crsProfilePackPrefix) || strings.HasPrefix(name, crsAppPackPrefix)
}

// IsCRSAppPackEntry reports whether entry is an application exclusion pack.
func IsCRSAppPackEntry(entry Entry) bool {
	packID, ok := CRSProfilePackID(entry)
	return ok && strings.HasPrefix(packID, "system/"+crsAppPackPrefix)
}

// CRSProfilePackEntry describes a CRS profile pack (the canonical rule pack
// bytes, libs/rulepack; packID system/crs-<level>, version its semver). CRS
// profiles are Apache-2.0 CRS selections, free unless requiresFeature, and
// resident: system-layer security packs are downloaded and enabled by
// default (ADR 0007 §5.4).
func CRSProfilePackEntry(packID, version string, revision uint64, content []byte, requiresFeature string) (Entry, error) {
	name, ok := strings.CutPrefix(packID, "system/")
	if !ok || !crsPackName(name) || requiresFeature != "" && !featurePattern.MatchString(requiresFeature) {
		return Entry{}, ErrInvalidCatalog
	}
	digest := sha256.Sum256(content)
	entry := Entry{ArtifactID: KindCRSProfile + "/" + name, Encryption: EncryptionNone, Kind: KindCRSProfile,
		LicenseSPDX: crsLicense, MediaType: MediaTypeCRSProfilePack, RequiresFeature: requiresFeature, Resident: true,
		Revision: revision, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content)), Version: version}
	if err := ValidateEntry(entry); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// CRSProfilePackID is the pack ID a CRS profile or application exclusion
// pack entry carries (crs_profile/crs-<level> -> system/crs-<level>,
// crs_profile/app-<key> -> system/app-<key>).
func CRSProfilePackID(entry Entry) (string, bool) {
	name, ok := strings.CutPrefix(entry.ArtifactID, KindCRSProfile+"/")
	if !ok || entry.Kind != KindCRSProfile || entry.MediaType != MediaTypeCRSProfilePack || !crsPackName(name) {
		return "", false
	}
	return "system/" + name, true
}

// VerifyContent checks that data is exactly the bytes entry names.
func VerifyContent(entry Entry, data []byte) error {
	if int64(len(data)) != entry.Size {
		return ErrContentMismatch
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != entry.SHA256 {
		return ErrContentMismatch
	}
	return nil
}

// RulesetArtifactID maps a system rule to its entry id: the CRS rule text
// (a waf_rule_set with a bundle body) is crs_profile/<name>, every other
// system rule is ruleset/<system_key>.
func RulesetArtifactID(item rulecatalog.Item) string {
	if isCRSProfile(item) {
		return KindCRSProfile + "/" + strings.TrimPrefix(item.SystemKey, systemRulePrefix)
	}
	return KindRuleset + "/" + item.SystemKey
}

func isCRSProfile(item rulecatalog.Item) bool {
	return item.Body.WAFRuleSet != nil && item.Body.WAFRuleSet.Bundle != nil
}

// RulesetEntry describes one system rule as a catalog entry and returns its
// bytes (the canonical rulecatalog.Item JSON).
func RulesetEntry(item rulecatalog.Item, requiresFeature string, resident bool) (Entry, []byte, error) {
	if rulecatalog.ValidateItem(item) != nil || requiresFeature != "" && !featurePattern.MatchString(requiresFeature) {
		return Entry{}, nil, ErrInvalidCatalog
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		return Entry{}, nil, ErrInvalidCatalog
	}
	digest := sha256.Sum256(encoded)
	entry := Entry{ArtifactID: RulesetArtifactID(item), Encryption: EncryptionNone, Kind: KindRuleset,
		MediaType: MediaTypeRuleset, RequiresFeature: requiresFeature, Resident: resident, Revision: item.Revision,
		SHA256: hex.EncodeToString(digest[:]), Size: int64(len(encoded)), Version: strconv.FormatUint(item.Revision, 10)}
	if isCRSProfile(item) {
		entry.Kind, entry.MediaType, entry.LicenseSPDX = KindCRSProfile, MediaTypeCRSProfile, crsLicense
		entry.Version = item.Body.WAFRuleSet.Bundle.Version + "-r" + entry.Version
	}
	if err := ValidateEntry(entry); err != nil {
		return Entry{}, nil, err
	}
	return entry, encoded, nil
}

// DecodeRulesetItem checks data against a ruleset / crs_profile entry and
// returns the system rule it carries.
func DecodeRulesetItem(entry Entry, data []byte) (rulecatalog.Item, error) {
	if entry.Kind != KindRuleset && entry.Kind != KindCRSProfile || entry.MediaType == MediaTypeCRSProfilePack {
		return rulecatalog.Item{}, ErrContentMismatch
	}
	if err := VerifyContent(entry, data); err != nil {
		return rulecatalog.Item{}, err
	}
	if rulecatalog.RejectDuplicateKeys(data) != nil {
		return rulecatalog.Item{}, ErrContentMismatch
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var item rulecatalog.Item
	if err := decoder.Decode(&item); err != nil {
		return rulecatalog.Item{}, ErrContentMismatch
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return rulecatalog.Item{}, ErrContentMismatch
	}
	canonical, err := json.Marshal(item)
	if err != nil || rulecatalog.ValidateItem(item) != nil || !bytes.Equal(canonical, data) ||
		RulesetArtifactID(item) != entry.ArtifactID || item.Revision != entry.Revision ||
		isCRSProfile(item) != (entry.Kind == KindCRSProfile) {
		return rulecatalog.Item{}, ErrContentMismatch
	}
	return item, nil
}

// IPIntelEntry describes the license-built base library release.
func IPIntelEntry(release ipintel.Release) (Entry, error) {
	entry := Entry{ArtifactID: IPIntelBaseID, Encryption: EncryptionNone, Kind: KindIPIntel, MediaType: MediaTypeIPIntel,
		RequiresCapability: &Capability{Name: ipintel.Capability, MinVersion: release.CapabilityVersion},
		Resident:           true, Revision: release.Revision, SHA256: release.ArtifactSHA256, Size: release.ArtifactBytes,
		Version: release.BuildID}
	if err := ValidateEntry(entry); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// EngineModuleCapability is the node capability an engine module needs
// (agentv1 CAPABILITY_NAME_WAF_CRS_MODULE: the agent gates the module into
// its releases).
const EngineModuleCapability = "WAF_CRS_MODULE"

// EngineModuleEntry describes an engine module build at revision. The id
// and version come from the build's manifest; the bytes are the canonical
// bundle. Engine modules are resident (a node needs one as soon as a site
// enables OWASP CRS) and carry the libmodsecurity license.
func EngineModuleEntry(encoded []byte, revision uint64, requiresFeature string) (Entry, error) {
	checked, err := enginemodule.Decode(encoded)
	if err != nil {
		return Entry{}, errors.Join(ErrInvalidCatalog, err)
	}
	digest := sha256.Sum256(encoded)
	entry := Entry{ArtifactID: checked.ArtifactID(), Encryption: EncryptionNone, Kind: KindEngineModule,
		LicenseSPDX: crsLicense, MediaType: MediaTypeEngineModule,
		RequiresCapability: &Capability{Name: EngineModuleCapability, MinVersion: 1}, RequiresFeature: requiresFeature,
		Resident: true, Revision: revision, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(encoded)),
		Version: checked.Manifest.Version}
	if err := ValidateEntry(entry); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// VerifyEngineModule checks data against an engine_module entry: exact
// bytes, a well-formed bundle whose manifest names the entry's id and
// version. It does not judge the platform signatures (the node does).
func VerifyEngineModule(entry Entry, data []byte) (enginemodule.Checked, error) {
	if entry.Kind != KindEngineModule || entry.MediaType != MediaTypeEngineModule || entry.RequiresCapability == nil ||
		entry.RequiresCapability.Name != EngineModuleCapability {
		return enginemodule.Checked{}, ErrContentMismatch
	}
	if err := VerifyContent(entry, data); err != nil {
		return enginemodule.Checked{}, err
	}
	checked, err := enginemodule.Decode(data)
	if err != nil {
		return enginemodule.Checked{}, errors.Join(ErrContentMismatch, err)
	}
	if checked.ArtifactID() != entry.ArtifactID || checked.Manifest.Version != entry.Version {
		return enginemodule.Checked{}, ErrContentMismatch
	}
	return checked, nil
}

// VerifyIPIntel checks data against an ipintel entry and opens it.
func VerifyIPIntel(entry Entry, data []byte) (*ipintel.Table, error) {
	if entry.Kind != KindIPIntel || entry.RequiresCapability == nil {
		return nil, ErrContentMismatch
	}
	if err := VerifyContent(entry, data); err != nil {
		return nil, err
	}
	table, err := ipintel.Open(data)
	if err != nil {
		return nil, errors.Join(ErrContentMismatch, err)
	}
	metadata := table.Metadata
	if metadata.Revision != entry.Revision || metadata.BuildID != entry.Version ||
		metadata.Capability != entry.RequiresCapability.Name || metadata.CapabilityVersion != entry.RequiresCapability.MinVersion {
		return nil, ErrContentMismatch
	}
	return table, nil
}

// DataPackEntry describes a market data package (market_rule_pack /
// market_theme) or a ui_page declaration (plugin_ui) whose bytes are content: artifact_id <kind>/<plugin id>, version = the plugin
// version, revision = the store revision of that version (only moves
// forward per plugin). Free of lease features: the plugin installation
// authorization is the gate.
func DataPackEntry(kind, pluginID, version string, revision uint64, content []byte, licenseSPDX string) (Entry, error) {
	mediaTypes, ok := knownMediaTypes[kind]
	if !ok || kind != KindMarketRulePack && kind != KindMarketTheme && kind != KindPluginUI &&
		kind != KindPluginProvider {
		return Entry{}, ErrInvalidCatalog
	}
	mediaType := mediaTypes[0]
	digest := sha256.Sum256(content)
	entry := Entry{ArtifactID: kind + "/" + pluginID, Encryption: EncryptionNone, Kind: kind, LicenseSPDX: licenseSPDX,
		MediaType: mediaType, Resident: true, Revision: revision, SHA256: hex.EncodeToString(digest[:]),
		Size: int64(len(content)), Version: version}
	if err := ValidateEntry(entry); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

// TrustedCrawlersID is the official crawler IP ranges dataset the license
// service builds every day (libs/edgeconfig/crawlerdefaults).
const TrustedCrawlersID = KindDataset + "/trusted-crawlers"

// TrustedCrawlersEntry describes revision of the trusted crawler dataset:
// free and resident (every control plane merges it into its sites' trusted
// crawlers); version is the dataset's build day (YYYYMMDD).
func TrustedCrawlersEntry(version string, revision uint64, content []byte) (Entry, error) {
	digest := sha256.Sum256(content)
	entry := Entry{ArtifactID: TrustedCrawlersID, Encryption: EncryptionNone, Kind: KindDataset,
		LicenseSPDX: "MIT", MediaType: MediaTypeTrustedCrawlers, Resident: true, Revision: revision,
		SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content)), Version: version}
	if err := ValidateEntry(entry); err != nil {
		return Entry{}, err
	}
	return entry, nil
}
