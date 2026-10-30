package errorpagecontrol

import (
	"context"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type VerifiedLeaseLimitProvider struct {
	pool  *pgxpool.Pool
	trust *entitlementguard.TrustStore
	now   Clock
}

var _ LimitProvider = (*VerifiedLeaseLimitProvider)(nil)

func NewVerifiedLeaseLimitProvider(
	pool *pgxpool.Pool,
	trust *entitlementguard.TrustStore,
	now Clock,
) (*VerifiedLeaseLimitProvider, error) {
	if pool == nil || trust == nil || now == nil {
		return nil, ErrInvalidStore
	}
	return &VerifiedLeaseLimitProvider{pool: pool, trust: trust, now: now}, nil
}

func (provider *VerifiedLeaseLimitProvider) Limits(
	ctx context.Context,
	tx pgx.Tx,
	check EntitlementCheck,
) (EntitlementLimits, error) {
	if provider == nil || provider.pool == nil || provider.now == nil || ctx == nil || tx == nil {
		return EntitlementLimits{}, ErrUnavailable
	}
	// cdncaCE: no license service; the community edition uses the default
	// plan's error page quotas (license-service portal_license_plans).
	return EntitlementLimits{
		FeatureEnabled:      true,
		AssetQuota:          AssetQuota{MaxAssetBytes: min(int64(1073741824), MaxEdgeResourceBytes), MaxAssets: 100000, MaxTotalBytes: 10737418240},
		MaxRulesPerScope:    min(10000, MaxEdgeRulesPerScope),
		MaxPublicationSites: min(1000000, MaxPublicationSites),
		MaxPublicationBytes: min(int64(1073741824), MaxEdgePolicyBytes),
	}, nil
}

func (provider *VerifiedLeaseLimitProvider) leaseLimits(
	ctx context.Context,
	tx pgx.Tx,
	check EntitlementCheck,
) (EntitlementLimits, error) {
	if provider == nil || provider.pool == nil || provider.trust == nil || provider.now == nil ||
		ctx == nil || tx == nil {
		return EntitlementLimits{}, ErrUnavailable
	}

	var installationID string
	var serial *int64
	var encodedLease []byte
	err := tx.QueryRow(ctx, `
		SELECT installation.installation_id, installation.current_serial, lease.signed_lease
		FROM control_installation_entitlement installation
		LEFT JOIN entitlement_cached_leases lease ON lease.serial = installation.current_serial
		WHERE installation.singleton = true
		FOR UPDATE OF installation`,
	).Scan(&installationID, &serial, &encodedLease)
	if err != nil || serial == nil || *serial < 1 || len(encodedLease) == 0 {
		return EntitlementLimits{}, ErrUnavailable
	}

	signed, err := entitlement.Decode(encodedLease)
	if err != nil {
		return EntitlementLimits{}, ErrUnavailable
	}
	verified, err := provider.trust.Verify(signed, entitlement.VerifyOptions{
		Now:                    provider.now(),
		ExpectedAudience:       entitlement.ControlAudience,
		ExpectedInstallationID: installationID,
	})
	if err != nil || verified.Lease.Serial != uint64(*serial) {
		return EntitlementLimits{}, ErrUnavailable
	}
	return limitsFromVerifiedLease(verified)
}

func limitsFromVerifiedLease(verified entitlement.Result) (EntitlementLimits, error) {
	if err := verified.Lease.Validate(); err != nil {
		return EntitlementLimits{}, ErrUnavailable
	}
	switch verified.Status {
	// Grace keeps error pages manageable while the license service is
	// unreachable.
	case entitlement.StatusValid, entitlement.StatusGrace:
	case entitlement.StatusExpired, entitlement.StatusRevoked:
		return EntitlementLimits{}, ErrEntitlementDenied
	default:
		return EntitlementLimits{}, ErrUnavailable
	}
	if !verified.Lease.HasFeature(entitlement.FeatureErrorPagesManage) {
		return EntitlementLimits{}, ErrEntitlementDenied
	}

	assetBytes, err := requiredPositiveQuota(verified.Lease, entitlement.QuotaErrorPageAssetBytes)
	if err != nil {
		return EntitlementLimits{}, err
	}
	assetCount, err := requiredPositiveQuota(verified.Lease, entitlement.QuotaErrorPageAssetsCount)
	if err != nil {
		return EntitlementLimits{}, err
	}
	totalBytes, err := requiredPositiveQuota(verified.Lease, entitlement.QuotaErrorPageTotalBytes)
	if err != nil {
		return EntitlementLimits{}, err
	}
	rules, err := requiredPositiveQuota(verified.Lease, entitlement.QuotaErrorPageRulesPerScope)
	if err != nil {
		return EntitlementLimits{}, err
	}
	publicationSites, err := requiredPositiveQuota(verified.Lease, entitlement.QuotaErrorPagePublicationSites)
	if err != nil {
		return EntitlementLimits{}, err
	}
	publicationBytes, err := requiredPositiveQuota(verified.Lease, entitlement.QuotaErrorPagePublicationBytes)
	if err != nil {
		return EntitlementLimits{}, err
	}

	maxInt := uint64(^uint(0) >> 1)
	if uint64(rules) > maxInt || uint64(publicationSites) > maxInt {
		return EntitlementLimits{}, ErrUnavailable
	}
	if assetBytes > MaxEdgeResourceBytes {
		assetBytes = MaxEdgeResourceBytes
	}
	if rules > int64(MaxEdgeRulesPerScope) {
		rules = int64(MaxEdgeRulesPerScope)
	}
	if publicationSites > int64(MaxPublicationSites) {
		publicationSites = int64(MaxPublicationSites)
	}
	if publicationBytes > MaxEdgePolicyBytes {
		publicationBytes = MaxEdgePolicyBytes
	}

	return EntitlementLimits{
		FeatureEnabled: true,
		AssetQuota: AssetQuota{
			MaxAssetBytes: assetBytes,
			MaxAssets:     assetCount,
			MaxTotalBytes: totalBytes,
		},
		MaxRulesPerScope:    int(rules),
		MaxPublicationSites: int(publicationSites),
		MaxPublicationBytes: publicationBytes,
	}, nil
}

func requiredPositiveQuota(lease entitlement.Lease, code string) (int64, error) {
	value, found := lease.Quota(code)
	if !found || value < 1 {
		return 0, ErrEntitlementDenied
	}
	return value, nil
}
