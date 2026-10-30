package entitlement

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	SchemaV1        = "cdnca.entitlement.lease/v1"
	ControlAudience = "cdnca-control-plane"
	Algorithm       = "Ed25519"

	FeatureErrorPagesManage   = "error_pages.manage"
	FeatureExtensionsWebhooks = "extensions.webhooks"
	// Node marketplace (docs/marketplace/08-admin-policy.md §2).
	FeatureMarketParticipate = "market.participate"
	FeatureMarketSell        = "market.sell"
	FeatureMarketResell      = "market.resell"

	QuotaDomainsCount              = "domains.count"
	QuotaErrorPageAssetBytes       = "error_pages.asset_bytes"
	QuotaErrorPageAssetsCount      = "error_pages.assets_count"
	QuotaErrorPagePublicationBytes = "error_pages.publication_bytes"
	QuotaErrorPagePublicationSites = "error_pages.publication_sites"
	QuotaErrorPageRulesPerScope    = "error_pages.rules_per_scope"
	QuotaErrorPageTotalBytes       = "error_pages.total_bytes"
	QuotaExtensionsWebhooksCount   = "extensions.webhooks.count"
	QuotaMarketOffersCount         = "market.offers.count"
	QuotaMonthlyTrafficBytes       = "monthly_traffic_bytes"
	QuotaNodesCount                = "nodes.count"
	QuotaPackagesCount             = "packages.count"
	QuotaReleaseChannelsCount      = "release_channels.count"
	QuotaSitesCount                = "sites.count"
	MaxQuotaLimit                  = int64(9_007_199_254_740_991)

	maxIDLength           = 128
	maxCodeLength         = 96
	maxEntitlements       = 256
	maxLeaseWindowSeconds = int64((366 * 24 * time.Hour) / time.Second)
	maxGraceWindowSeconds = int64((30 * 24 * time.Hour) / time.Second)
	maxUnixTimestamp      = int64(253402300799)
)

var supportedQuotaCodes = map[string]struct{}{
	QuotaDomainsCount:              {},
	QuotaErrorPageAssetBytes:       {},
	QuotaErrorPageAssetsCount:      {},
	QuotaErrorPagePublicationBytes: {},
	QuotaErrorPagePublicationSites: {},
	QuotaErrorPageRulesPerScope:    {},
	QuotaErrorPageTotalBytes:       {},
	QuotaExtensionsWebhooksCount:   {},
	QuotaMarketOffersCount:         {},
	QuotaMonthlyTrafficBytes:       {},
	QuotaNodesCount:                {},
	QuotaPackagesCount:             {},
	QuotaReleaseChannelsCount:      {},
	QuotaSitesCount:                {},
}

var (
	ErrInvalidLease         = errors.New("invalid entitlement lease")
	ErrInvalidEnvelope      = errors.New("invalid signed lease envelope")
	ErrUnknownKey           = errors.New("unknown signing key")
	ErrInvalidSignature     = errors.New("invalid entitlement signature")
	ErrAudienceMismatch     = errors.New("entitlement audience mismatch")
	ErrInstallationMismatch = errors.New("entitlement installation mismatch")
	ErrNotYetValid          = errors.New("entitlement lease is not yet valid")
)

var (
	idPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	codePattern    = regexp.MustCompile(`^[a-z][a-z0-9._-]*$`)
	channelPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]*$`)
	versionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)
)

// Lease is the only signed entitlement payload. Slices must be strictly sorted
// by code, making the representation deterministic and rejecting duplicates.
type Lease struct {
	Schema         string       `json:"schema"`
	Audience       string       `json:"audience"`
	CustomerID     string       `json:"customer_id"`
	InstallationID string       `json:"installation_id"`
	LicenseID      string       `json:"license_id"`
	Serial         uint64       `json:"serial"`
	NotBefore      int64        `json:"not_before"`
	ExpiresAt      int64        `json:"expires_at"`
	GraceUntil     int64        `json:"grace_until"`
	Version        VersionRange `json:"version"`
	Features       []Feature    `json:"features"`
	Quotas         []Quota      `json:"quotas"`
}

type VersionRange struct {
	Channel string `json:"channel"`
	Min     string `json:"min"`
	Max     string `json:"max"`
}

type Feature struct {
	Code string `json:"code"`
}

type Quota struct {
	Code  string `json:"code"`
	Limit int64  `json:"limit"`
}

func (lease Lease) Validate() error {
	if lease.Schema != SchemaV1 || !validText(lease.Audience, maxIDLength) ||
		!validID(lease.CustomerID) || !validID(lease.InstallationID) ||
		!validID(lease.LicenseID) || lease.Serial == 0 {
		return ErrInvalidLease
	}
	if lease.NotBefore <= 0 || lease.GraceUntil > maxUnixTimestamp ||
		lease.ExpiresAt <= lease.NotBefore || lease.GraceUntil < lease.ExpiresAt {
		return ErrInvalidLease
	}
	activeWindow := lease.ExpiresAt - lease.NotBefore
	graceWindow := lease.GraceUntil - lease.ExpiresAt
	if activeWindow > maxLeaseWindowSeconds || graceWindow > maxGraceWindowSeconds {
		return ErrInvalidLease
	}
	return ValidatePolicy(lease.Version, lease.Features, lease.Quotas)
}

// ValidatePolicy allows the issuer to reject invalid grants before persisting
// them, using the exact constraints later applied to signed leases.
func ValidatePolicy(version VersionRange, features []Feature, quotas []Quota) error {
	if err := version.validate(); err != nil {
		return err
	}
	if len(features) > maxEntitlements || len(quotas) > maxEntitlements {
		return ErrInvalidLease
	}
	previous := ""
	for _, feature := range features {
		if !validCode(feature.Code) || feature.Code <= previous {
			return ErrInvalidLease
		}
		if _, _, ok := ParseModuleFeatureCode(feature.Code); hasModulePrefix(feature.Code) && !ok {
			return ErrInvalidLease
		}
		previous = feature.Code
	}
	previous = ""
	for _, quota := range quotas {
		if !validCode(quota.Code) || !IsSupportedQuotaCode(quota.Code) || quota.Code <= previous ||
			quota.Limit < 0 || quota.Limit > MaxQuotaLimit {
			return ErrInvalidLease
		}
		previous = quota.Code
	}
	return nil
}

func IsSupportedQuotaCode(code string) bool {
	_, ok := supportedQuotaCodes[code]
	return ok
}

func ValidateKeyID(keyID string) error {
	if !validID(keyID) {
		return ErrInvalidEnvelope
	}
	return nil
}

func (version VersionRange) validate() error {
	if !channelPattern.MatchString(version.Channel) || len(version.Channel) > maxCodeLength ||
		!versionPattern.MatchString(version.Min) || !versionPattern.MatchString(version.Max) {
		return ErrInvalidLease
	}
	comparison, err := compareVersions(version.Min, version.Max)
	if err != nil || comparison > 0 {
		return ErrInvalidLease
	}
	return nil
}

func (lease Lease) AllowsVersion(channel, version string) bool {
	if lease.Version.validate() != nil || channel != lease.Version.Channel || !versionPattern.MatchString(version) {
		return false
	}
	fromMin, err := compareVersions(version, lease.Version.Min)
	if err != nil || fromMin < 0 {
		return false
	}
	fromMax, err := compareVersions(version, lease.Version.Max)
	return err == nil && fromMax <= 0
}

func (lease Lease) HasFeature(code string) bool {
	for _, feature := range lease.Features {
		if feature.Code == code {
			return true
		}
	}
	return false
}

func (lease Lease) Quota(code string) (int64, bool) {
	for _, quota := range lease.Quotas {
		if quota.Code == code {
			return quota.Limit, true
		}
	}
	return 0, false
}

func validID(value string) bool {
	return validText(value, maxIDLength) && idPattern.MatchString(value)
}

func validCode(value string) bool {
	return validText(value, maxCodeLength) && codePattern.MatchString(value)
}

func validText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value
}

func compareVersions(left, right string) (int, error) {
	l, err := numericVersion(left)
	if err != nil {
		return 0, err
	}
	r, err := numericVersion(right)
	if err != nil {
		return 0, err
	}
	for index := range l {
		if l[index] < r[index] {
			return -1, nil
		}
		if l[index] > r[index] {
			return 1, nil
		}
	}
	return 0, nil
}

func numericVersion(value string) ([3]uint64, error) {
	var result [3]uint64
	value = strings.TrimPrefix(value, "v")
	value, _, _ = strings.Cut(value, "-")
	parts := strings.Split(value, ".")
	if len(parts) != len(result) {
		return result, fmt.Errorf("invalid version")
	}
	for index, part := range parts {
		if len(part) > 1 && part[0] == '0' {
			return result, fmt.Errorf("invalid version")
		}
		parsed, err := strconv.ParseUint(part, 10, 63)
		if err != nil {
			return result, fmt.Errorf("invalid version")
		}
		result[index] = parsed
	}
	return result, nil
}
