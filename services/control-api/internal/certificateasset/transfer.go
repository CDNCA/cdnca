package certificateasset

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 网站更换所属用户（fix-transfer S2）：证书随站过户。私钥信封的 AAD 含
// tenant_scope_id，版本/信封表不可变，所以在原租户解封、作为目标用户名下的
// 上传证书在目标租户重新封装成新资产，激活并绑定到新站。ACME 私钥是 opaque
// wrapped（需要 ACME 包装密钥解析），不随站复制，由新租户重新申请。

// SiteTransferCertificate is the old site's certificate loaded for a site
// transfer (private key in memory until Close). Skipped names why it is not
// carried ("none", "acme", "unavailable"); the new site then has HTTPS off.
type SiteTransferCertificate struct {
	Skipped   string
	material  PublicationMaterial
	name      string
	isDefault bool
}

// Close zeroes the loaded private key.
func (c *SiteTransferCertificate) Close() {
	if c != nil {
		zeroBytes(c.material.PrivateKeyPEM)
		c.material.PrivateKeyPEM = nil
	}
}

// LoadForSiteTransferTx reads and unseals the certificate bound to siteID in
// scopeID. One that cannot be carried (ACME's opaque key, expired, revoked,
// not covering domains, sealed under a retired key) is Skipped, not an error.
func (s *Store) LoadForSiteTransferTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID,
	domains []string) (*SiteTransferCertificate, error) {
	if s == nil || s.enveloper == nil {
		return &SiteTransferCertificate{Skipped: "unavailable"}, nil
	}
	if tx == nil || scopeID == uuid.Nil || siteID == uuid.Nil || len(domains) == 0 {
		return nil, ErrInvalidInput
	}
	binding, found, err := loadLatestBinding(ctx, tx, scopeID, siteID)
	if err != nil {
		return nil, err
	}
	if !found || !binding.Bound {
		return &SiteTransferCertificate{Skipped: "none"}, nil
	}
	var source, name string
	if err := tx.QueryRow(ctx, `SELECT source,name FROM certificate_assets
		WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL`,
		scopeID, binding.AssetID).Scan(&source, &name); errors.Is(err, pgx.ErrNoRows) {
		return &SiteTransferCertificate{Skipped: "unavailable"}, nil
	} else if err != nil {
		return nil, err
	}
	if source != SourceUploaded {
		return &SiteTransferCertificate{Skipped: "acme"}, nil
	}
	material, err := s.loadPublicationMaterial(ctx, tx, storeTime(s.now()), scopeID,
		struct {
			tenantID uuid.UUID
			domains  []string
		}{domains: domains}, binding, nil)
	if errors.Is(err, ErrEnvelopeUnavailable) || errors.Is(err, ErrInvalidTransition) ||
		errors.Is(err, ErrCertificateExpired) || errors.Is(err, ErrCertificateNotYetValid) ||
		errors.Is(err, ErrDomainNotCovered) {
		return &SiteTransferCertificate{Skipped: "unavailable"}, nil
	}
	if err != nil {
		return nil, err
	}
	return &SiteTransferCertificate{material: material, name: name, isDefault: binding.Default}, nil
}

// SiteTransferCopyRequest: the new site and its owner. The caller's
// transaction already holds the IAM scope locks of the target tenant and the
// actor's scope. KeyPrefix (at most 100 characters) prefixes the
// idempotency keys of the import / activate / bind writes.
type SiteTransferCopyRequest struct {
	ToScopeID uuid.UUID
	ToSiteID  uuid.UUID
	ToOwnerID uuid.UUID
	KeyPrefix string
	RequestID string
}

// CopyForSiteTransferTx imports the loaded certificate as an uploaded
// certificate of the new owner in the target tenant (sealed again under its
// AAD), activates it and binds it to the new site; the new asset's ID.
func (s *Store) CopyForSiteTransferTx(ctx context.Context, tx pgx.Tx, actor Actor, certificate *SiteTransferCertificate,
	request SiteTransferCopyRequest) (uuid.UUID, error) {
	if s == nil || tx == nil || certificate == nil || certificate.Skipped != "" || certificate.material.PrivateKeyPEM == nil ||
		request.ToScopeID == uuid.Nil || request.ToSiteID == uuid.Nil || request.ToOwnerID == uuid.Nil ||
		len(request.KeyPrefix) > 100 || actor.ScopeKind != ScopePlatform {
		return uuid.Nil, ErrInvalidInput
	}
	owner := request.ToOwnerID
	importRequest := ImportRequest{TenantScopeID: request.ToScopeID, OwnerUserID: &owner, Name: certificate.name,
		Source: SourceUploaded, CertificatePEM: certificate.material.CertificatePEM,
		PrivateKeyPEM: certificate.material.PrivateKeyPEM, IdempotencyKey: request.KeyPrefix + ".cert",
		RequestID: request.RequestID}
	prepared, digest, err := s.prepareImport(actor, &importRequest, false)
	if err != nil {
		return uuid.Nil, err
	}
	defer zeroBytes(prepared.CanonicalPrivateKey)
	imported, err := s.importPreparedInTx(ctx, tx, actor, importRequest, prepared, digest, false, false)
	if err != nil {
		return uuid.Nil, err
	}
	// A new asset starts as default; Bind needs it active. A deduplicated one
	// (the target already had this certificate) may already be.
	version := imported.Version
	if version.Status != StatusActive {
		activate := ActivateRequest{TenantScopeID: request.ToScopeID, AssetID: imported.Asset.ID,
			VersionID: version.ID, ExpectedRevision: imported.Asset.Revision,
			IdempotencyKey: request.KeyPrefix + ".activate", RequestID: request.RequestID}
		activateDigest, _ := digestRequest(struct {
			TenantScopeID    uuid.UUID `json:"tenant_scope_id"`
			AssetID          uuid.UUID `json:"asset_id"`
			VersionID        uuid.UUID `json:"version_id"`
			ExpectedRevision int64     `json:"expected_revision"`
		}{activate.TenantScopeID, activate.AssetID, activate.VersionID, activate.ExpectedRevision})
		if err := s.activateTx(ctx, tx, actor, activate, activateDigest, false, &version); err != nil {
			return uuid.Nil, err
		}
	}
	bind := BindRequest{TenantScopeID: request.ToScopeID, SiteID: request.ToSiteID, AssetID: imported.Asset.ID,
		VersionID: version.ID, Default: certificate.isDefault,
		IdempotencyKey: request.KeyPrefix + ".bind", RequestID: request.RequestID}
	bindDigest, _ := digestRequest(struct {
		TenantScopeID    uuid.UUID `json:"tenant_scope_id"`
		SiteID           uuid.UUID `json:"site_id"`
		AssetID          uuid.UUID `json:"asset_id"`
		VersionID        uuid.UUID `json:"version_id"`
		ExpectedRevision int64     `json:"expected_revision"`
		Default          bool      `json:"default"`
	}{bind.TenantScopeID, bind.SiteID, bind.AssetID, bind.VersionID, bind.ExpectedRevision, bind.Default})
	var bound Binding
	if err := s.bindTx(ctx, tx, actor, bind, bindDigest, false, &bound); err != nil {
		return uuid.Nil, err
	}
	return imported.Asset.ID, nil
}
