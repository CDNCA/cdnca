package systemconfig

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrPlatformResourcesUnavailable = errors.New("effective platform resource configuration unavailable")
	ErrPlatformResourcesInvalid     = errors.New("effective platform resource configuration invalid")
)

type EffectiveResourceTarget struct {
	RegionID string
	NodeID   string
}

type EffectivePlatformResources struct {
	PlatformScopeID uuid.UUID
	Revision        int64
	SnapshotSHA256  string
	Resources       ResourceLimits
}

// LoadEffectivePlatformResources reads the resource limits used by a tenant
// write from that write's transaction. Only the active platform revision is
// authoritative; a fresh installation without one uses the project bootstrap.
func LoadEffectivePlatformResources(
	ctx context.Context,
	tx pgx.Tx,
	target EffectiveResourceTarget,
) (EffectivePlatformResources, error) {
	if tx == nil {
		return EffectivePlatformResources{}, ErrPlatformResourcesUnavailable
	}
	if target.RegionID != "" && !validSafeLabel(target.RegionID) ||
		target.NodeID != "" && !validSafeLabel(target.NodeID) {
		return EffectivePlatformResources{}, ErrPlatformResourcesInvalid
	}

	platformScopeID, revision, err := loadActivePlatformRevision(ctx, tx)
	if err != nil {
		return EffectivePlatformResources{}, err
	}
	effective, err := ResolveScopedConfiguration(revision.Configuration, target.RegionID, target.NodeID)
	if err != nil {
		return EffectivePlatformResources{}, fmt.Errorf("%w: resolve target: %v",
			ErrPlatformResourcesInvalid, err)
	}
	return EffectivePlatformResources{
		PlatformScopeID: platformScopeID,
		Revision:        revision.Revision,
		SnapshotSHA256:  revision.SnapshotSHA256,
		Resources:       effective.Resources,
	}, nil
}

// loadActivePlatformRevision is the active platform revision, or the project
// bootstrap on a fresh installation without one.
func loadActivePlatformRevision(ctx context.Context, tx pgx.Tx) (uuid.UUID, Revision, error) {
	var platformScopeID uuid.UUID
	var activeRevision *int64
	if err := tx.QueryRow(ctx, `SELECT platform.id,(
			SELECT stream.active_revision FROM system_configuration_streams stream
			WHERE stream.platform_scope_id=platform.id FOR SHARE
		)
		FROM access_scopes platform
		WHERE platform.kind='platform' AND platform.tenant_id IS NULL
		FOR SHARE OF platform`).
		Scan(&platformScopeID, &activeRevision); err != nil {
		return uuid.Nil, Revision{}, fmt.Errorf("%w: read platform scope: %v",
			ErrPlatformResourcesUnavailable, err)
	}

	var revision Revision
	if activeRevision == nil {
		configuration, _, snapshotHash, err := CanonicalSnapshot(ProjectBootstrapConfiguration())
		if err != nil {
			return uuid.Nil, Revision{}, fmt.Errorf("%w: bootstrap snapshot: %v",
				ErrPlatformResourcesInvalid, err)
		}
		revision = Revision{Configuration: configuration, SnapshotSHA256: snapshotHash}
	} else {
		if *activeRevision < 1 {
			return uuid.Nil, Revision{}, ErrPlatformResourcesInvalid
		}
		var err error
		revision, err = loadRevision(ctx, tx, platformScopeID, *activeRevision)
		if errors.Is(err, ErrInvalidInput) {
			return uuid.Nil, Revision{}, fmt.Errorf("%w: decode active revision",
				ErrPlatformResourcesInvalid)
		}
		if err != nil {
			return uuid.Nil, Revision{}, fmt.Errorf("%w: read active revision: %v",
				ErrPlatformResourcesUnavailable, err)
		}
		if revision.Status != StatusActive {
			return uuid.Nil, Revision{}, ErrPlatformResourcesInvalid
		}
	}

	return platformScopeID, revision, nil
}

// LoadDefaultForceHTTPS is the platform default for forced HTTPS (系统设置 >
// 网站默认 > HTTPS), which new sites inherit; tenants read it, never write it.
func LoadDefaultForceHTTPS(ctx context.Context, tx pgx.Tx) (bool, error) {
	if tx == nil {
		return false, ErrPlatformResourcesUnavailable
	}
	_, revision, err := loadActivePlatformRevision(ctx, tx)
	if err != nil {
		return false, err
	}
	return revision.Configuration.Defaults.Website.HTTPS.ForceHTTPS, nil
}

// LoadDefaultWAFSecurity is the platform default WAF security of new WAF
// policies (系统设置 > 网站默认 > 安全设置): the master switch, the built-in
// module modes and the auto block; tenants read it, never write it.
func LoadDefaultWAFSecurity(ctx context.Context, tx pgx.Tx) (DefaultSecuritySettings, error) {
	if tx == nil {
		return DefaultSecuritySettings{}, ErrPlatformResourcesUnavailable
	}
	_, revision, err := loadActivePlatformRevision(ctx, tx)
	if err != nil {
		return DefaultSecuritySettings{}, err
	}
	return revision.Configuration.Defaults.Website.Security, nil
}

// WebsiteCreationDefaults are the platform defaults a new site inherits when
// its request does not say (系统设置 > 网站默认): the origin
// pool's load balancing, and HSTS for a site created with HTTPS.
type WebsiteCreationDefaults struct {
	LoadBalancing string
	HSTSEnabled   bool
	// GzipTypes: the types a site whose owner's 默认设置 > Gzip is on compresses.
	GzipTypes []string
}

// DefaultHSTSMaxAgeSeconds is the max-age a site inheriting the HSTS default
// gets (one year, without includeSubDomains or preload: both are the site
// owner's decision).
const DefaultHSTSMaxAgeSeconds = 31536000

// LoadWebsiteCreationDefaults reads them from the active platform revision
// (the project bootstrap on a fresh installation).
func LoadWebsiteCreationDefaults(ctx context.Context, tx pgx.Tx) (WebsiteCreationDefaults, error) {
	if tx == nil {
		return WebsiteCreationDefaults{}, ErrPlatformResourcesUnavailable
	}
	_, revision, err := loadActivePlatformRevision(ctx, tx)
	if err != nil {
		return WebsiteCreationDefaults{}, err
	}
	website := revision.Configuration.Defaults.Website
	return WebsiteCreationDefaults{LoadBalancing: website.Other.LoadBalancing, HSTSEnabled: website.HTTPS.HSTSEnabled,
		GzipTypes: slices.Clone(website.Other.GzipTypes)}, nil
}

// DefaultSiteTLS is the platform default TLS profile a new site inherits
// (系统设置 > 网站默认 > HTTPS > SSL 与 OCSP stapling).
type DefaultSiteTLS struct {
	Protocols    []string
	CipherPreset string
	OCSPStapling bool
}

// LoadDefaultSiteTLS reads DefaultSiteTLS from the active platform revision.
func LoadDefaultSiteTLS(ctx context.Context, tx pgx.Tx) (DefaultSiteTLS, error) {
	if tx == nil {
		return DefaultSiteTLS{}, ErrPlatformResourcesUnavailable
	}
	_, revision, err := loadActivePlatformRevision(ctx, tx)
	if err != nil {
		return DefaultSiteTLS{}, err
	}
	https := revision.Configuration.Defaults.Website.HTTPS
	return DefaultSiteTLS{Protocols: slices.Clone(https.SSL.Protocols),
		CipherPreset: SiteCipherPreset(https.SSL.Mode), OCSPStapling: https.OCSPStaplingEnabled}, nil
}

// SiteCipherPreset maps a system SSL mode to the site cipher preset
// (edgeconfig.TLSCipher*).
func SiteCipherPreset(mode string) string {
	switch mode {
	case "legacy_tls12":
		return "compatible"
	case "legacy_full":
		return "legacy"
	default:
		return "modern"
	}
}

// LoadDefaultCertificateIssuer is the CA new ACME orders use (系统设置 >
// 网站默认 > 证书 > 签发机构).
func LoadDefaultCertificateIssuer(ctx context.Context, tx pgx.Tx) (string, error) {
	if tx == nil {
		return "", ErrPlatformResourcesUnavailable
	}
	_, revision, err := loadActivePlatformRevision(ctx, tx)
	if err != nil {
		return "", err
	}
	return revision.Configuration.Defaults.Certificate.Issuer, nil
}
