package certificateasset

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool      *pgxpool.Pool
	auditor   AuditAppender
	enveloper PrivateKeyEnveloper
	now       Clock
	// cancelRenewal cancels an in-flight renewal delivery a user's binding
	// change supersedes (fix-dnscert4).
	cancelRenewal RenewalDeliveryCanceller
}

func NewStore(pool *pgxpool.Pool, enveloper PrivateKeyEnveloper) (*Store, error) {
	return NewStoreWithDependencies(pool, enveloper, audit.New(pool), time.Now)
}

func NewStoreWithDependencies(
	pool *pgxpool.Pool,
	enveloper PrivateKeyEnveloper,
	auditor AuditAppender,
	now Clock,
) (*Store, error) {
	if pool == nil || enveloper == nil || auditor == nil || now == nil {
		return nil, ErrInvalidStore
	}
	return &Store{pool: pool, enveloper: enveloper, auditor: auditor, now: now}, nil
}

func (s *Store) Import(ctx context.Context, actor Actor, request ImportRequest) (result ImportResult, err error) {
	defer func() {
		assetID := uuid.Nil
		if request.AssetID != nil {
			assetID = *request.AssetID
		}
		s.auditFailure(ctx, actor, request.TenantScopeID, request.RequestID, operationImport, "certificate_asset", assetID, err)
	}()
	prepared, digest, err := s.prepareImport(actor, &request, false)
	if err != nil {
		return ImportResult{}, err
	}
	defer zeroBytes(prepared.CanonicalPrivateKey)
	if prepared.OpaquePrivateKey != nil {
		defer zeroBytes(prepared.OpaquePrivateKey.WrappedKeyMaterial)
	}
	return s.importPrepared(ctx, actor, request, prepared, digest)
}

func (s *Store) ImportACMEInTx(
	ctx context.Context,
	tx pgx.Tx,
	request ACMEImportRequest,
) (ImportResult, error) {
	if tx == nil {
		return ImportResult{}, ErrInvalidInput
	}
	prepared, digest, err := s.prepareImport(request.Actor, &request.Import, true)
	if err != nil {
		return ImportResult{}, err
	}
	defer zeroBytes(prepared.CanonicalPrivateKey)
	if prepared.OpaquePrivateKey != nil {
		defer zeroBytes(prepared.OpaquePrivateKey.WrappedKeyMaterial)
	}
	return s.importPreparedInTx(ctx, tx, request.Actor, request.Import, prepared, digest, true, false)
}

func (s *Store) prepareImport(
	actor Actor,
	request *ImportRequest,
	transactionalACME bool,
) (preparedCertificate, [32]byte, error) {
	request.Name = strings.TrimSpace(request.Name)
	request.Remark = strings.TrimSpace(request.Remark)
	request.Source = strings.ToLower(strings.TrimSpace(request.Source))
	if err := validateActor(actor, request.TenantScopeID); err != nil {
		return preparedCertificate{}, [32]byte{}, err
	}
	if request.OwnerUserID != nil && actor.ScopeKind == ScopeTenant && *request.OwnerUserID != actor.UserID {
		return preparedCertificate{}, [32]byte{}, ErrPermissionDenied
	}
	if !validOpaqueName(request.Name, 128) || !validRemark(request.Remark) ||
		(request.Remark != "" && request.AssetID != nil) ||
		(request.OwnerUserID != nil && (*request.OwnerUserID == uuid.Nil || request.Source != SourceUploaded)) ||
		!validRequestMetadata(request.IdempotencyKey, request.RequestID) ||
		(request.AssetID == nil && request.ExpectedRevision != 0) ||
		(request.AssetID != nil && (*request.AssetID == uuid.Nil || request.ExpectedRevision < 1)) ||
		(request.Source != SourceUploaded && request.Source != SourceACME) ||
		((len(request.PrivateKeyPEM) == 0) == (request.OpaquePrivateKey == nil)) ||
		(request.Source == SourceUploaded && request.OpaquePrivateKey != nil) ||
		(request.Source == SourceUploaded && request.ACMEOrderID != nil) ||
		(request.Source == SourceACME && (request.ACMEOrderID == nil || *request.ACMEOrderID == uuid.Nil)) ||
		(transactionalACME && (request.Source != SourceACME || len(request.PrivateKeyPEM) != 0 || request.OpaquePrivateKey == nil)) {
		return preparedCertificate{}, [32]byte{}, ErrInvalidInput
	}
	prepared, err := prepareCertificate(request.CertificatePEM, request.PrivateKeyPEM,
		request.OpaquePrivateKey, storeTime(s.now()))
	if err != nil {
		return preparedCertificate{}, [32]byte{}, err
	}
	keyMaterialKind := "plaintext_pkcs8"
	var wrappedMaterialSHA256 string
	var opaqueMetadataSHA256 string
	if prepared.OpaquePrivateKey != nil {
		keyMaterialKind = "opaque_wrapped"
		wrappedDigest := sha256.Sum256(prepared.OpaquePrivateKey.WrappedKeyMaterial)
		wrappedMaterialSHA256 = fingerprintHex(wrappedDigest)
		metadataDigest := sha256.Sum256(prepared.OpaquePrivateKey.Metadata)
		opaqueMetadataSHA256 = fingerprintHex(metadataDigest)
	}
	digest, err := digestRequest(struct {
		TenantScopeID         uuid.UUID  `json:"tenant_scope_id"`
		AssetID               *uuid.UUID `json:"asset_id,omitempty"`
		ExpectedRevision      int64      `json:"expected_revision"`
		Name                  string     `json:"name"`
		Source                string     `json:"source"`
		ACMEOrderID           *uuid.UUID `json:"acme_order_id,omitempty"`
		Fingerprint           string     `json:"fingerprint_sha256"`
		PrivateKeyReference   string     `json:"private_key_reference"`
		KeyMaterialKind       string     `json:"key_material_kind"`
		WrappedMaterialSHA256 string     `json:"wrapped_material_sha256,omitempty"`
		OpaqueMetadataSHA256  string     `json:"opaque_metadata_sha256,omitempty"`
		OwnerUserID           *uuid.UUID `json:"owner_user_id,omitempty"`
		Remark                string     `json:"remark,omitempty"`
	}{request.TenantScopeID, request.AssetID, request.ExpectedRevision, request.Name,
		request.Source, request.ACMEOrderID, fingerprintHex(prepared.Fingerprint),
		prepared.PrivateKeyReference, keyMaterialKind, wrappedMaterialSHA256, opaqueMetadataSHA256, request.OwnerUserID,
		request.Remark})
	if err != nil {
		zeroBytes(prepared.CanonicalPrivateKey)
		if prepared.OpaquePrivateKey != nil {
			zeroBytes(prepared.OpaquePrivateKey.WrappedKeyMaterial)
		}
		return preparedCertificate{}, [32]byte{}, ErrInvalidInput
	}
	return prepared, digest, nil
}

func (s *Store) Rewrap(ctx context.Context, actor Actor, request RewrapRequest) (result EnvelopeRevision, err error) {
	defer func() {
		s.auditFailure(ctx, actor, request.TenantScopeID, request.RequestID, operationRewrap, "certificate_asset_version", request.VersionID, err)
	}()
	if err := validateActor(actor, request.TenantScopeID); err != nil {
		return EnvelopeRevision{}, err
	}
	if request.AssetID == uuid.Nil || request.VersionID == uuid.Nil ||
		request.ExpectedEnvelopeSequence < 1 || !validOpaqueName(request.TargetKeyID, 128) ||
		!validRequestMetadata(request.IdempotencyKey, request.RequestID) {
		return EnvelopeRevision{}, ErrInvalidInput
	}
	digest, _ := digestRequest(struct {
		TenantScopeID            uuid.UUID `json:"tenant_scope_id"`
		AssetID                  uuid.UUID `json:"asset_id"`
		VersionID                uuid.UUID `json:"version_id"`
		ExpectedEnvelopeSequence int64     `json:"expected_envelope_sequence"`
		TargetKeyID              string    `json:"target_key_id"`
	}{request.TenantScopeID, request.AssetID, request.VersionID,
		request.ExpectedEnvelopeSequence, request.TargetKeyID})
	return s.rewrap(ctx, actor, request, digest)
}

func (s *Store) Activate(ctx context.Context, actor Actor, request ActivateRequest) (result Version, err error) {
	defer func() {
		s.auditFailure(ctx, actor, request.TenantScopeID, request.RequestID, operationActivate, "certificate_asset_version", request.VersionID, err)
	}()
	if err := validateActor(actor, request.TenantScopeID); err != nil {
		return Version{}, err
	}
	if request.AssetID == uuid.Nil || request.VersionID == uuid.Nil ||
		request.ExpectedRevision < 1 || !validRequestMetadata(request.IdempotencyKey, request.RequestID) {
		return Version{}, ErrInvalidInput
	}
	digest, _ := digestRequest(struct {
		TenantScopeID    uuid.UUID `json:"tenant_scope_id"`
		AssetID          uuid.UUID `json:"asset_id"`
		VersionID        uuid.UUID `json:"version_id"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{request.TenantScopeID, request.AssetID, request.VersionID, request.ExpectedRevision})
	return s.activate(ctx, actor, request, digest)
}

func (s *Store) Bind(ctx context.Context, actor Actor, request BindRequest) (result Binding, err error) {
	defer func() {
		s.auditFailure(ctx, actor, request.TenantScopeID, request.RequestID, operationBind, "site", request.SiteID, err)
	}()
	if err := validateActor(actor, request.TenantScopeID); err != nil {
		return Binding{}, err
	}
	if request.SiteID == uuid.Nil || request.AssetID == uuid.Nil ||
		request.VersionID == uuid.Nil || request.ExpectedRevision < 0 ||
		!validRequestMetadata(request.IdempotencyKey, request.RequestID) {
		return Binding{}, ErrInvalidInput
	}
	digest, _ := digestRequest(struct {
		TenantScopeID    uuid.UUID `json:"tenant_scope_id"`
		SiteID           uuid.UUID `json:"site_id"`
		AssetID          uuid.UUID `json:"asset_id"`
		VersionID        uuid.UUID `json:"version_id"`
		ExpectedRevision int64     `json:"expected_revision"`
		Default          bool      `json:"default"`
	}{request.TenantScopeID, request.SiteID, request.AssetID, request.VersionID,
		request.ExpectedRevision, request.Default})
	return s.bind(ctx, actor, request, digest)
}

func (s *Store) Unbind(ctx context.Context, actor Actor, request UnbindRequest) (result Binding, err error) {
	defer func() {
		s.auditFailure(ctx, actor, request.TenantScopeID, request.RequestID, operationUnbind, "site", request.SiteID, err)
	}()
	if err := validateActor(actor, request.TenantScopeID); err != nil {
		return Binding{}, err
	}
	if request.SiteID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validRequestMetadata(request.IdempotencyKey, request.RequestID) {
		return Binding{}, ErrInvalidInput
	}
	digest, _ := digestRequest(struct {
		TenantScopeID    uuid.UUID `json:"tenant_scope_id"`
		SiteID           uuid.UUID `json:"site_id"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{request.TenantScopeID, request.SiteID, request.ExpectedRevision})
	return s.unbind(ctx, actor, request, digest)
}

func (s *Store) Delete(ctx context.Context, actor Actor, request DeleteRequest) (result Asset, err error) {
	defer func() {
		s.auditFailure(ctx, actor, request.TenantScopeID, request.RequestID, operationDelete, "certificate_asset", request.AssetID, err)
	}()
	if err := validateActor(actor, request.TenantScopeID); err != nil {
		return Asset{}, err
	}
	if request.AssetID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validRequestMetadata(request.IdempotencyKey, request.RequestID) {
		return Asset{}, ErrInvalidInput
	}
	digest, _ := digestRequest(struct {
		TenantScopeID    uuid.UUID `json:"tenant_scope_id"`
		AssetID          uuid.UUID `json:"asset_id"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{request.TenantScopeID, request.AssetID, request.ExpectedRevision})
	return s.delete(ctx, actor, request, digest)
}

// SetAutoRenew turns an ACME certificate's automatic renewal on or off
// (fix-autorenew, migration 537). Uploaded certificates cannot auto-renew.
func (s *Store) SetAutoRenew(ctx context.Context, actor Actor, request SetAutoRenewRequest) (result Asset, err error) {
	defer func() {
		s.auditFailure(ctx, actor, request.TenantScopeID, request.RequestID, operationAutoRenew, "certificate_asset", request.AssetID, err)
	}()
	if err := validateActor(actor, request.TenantScopeID); err != nil {
		return Asset{}, err
	}
	if request.AssetID == uuid.Nil || request.ExpectedRevision < 1 ||
		!validRequestMetadata(request.IdempotencyKey, request.RequestID) {
		return Asset{}, ErrInvalidInput
	}
	digest, _ := digestRequest(struct {
		TenantScopeID    uuid.UUID `json:"tenant_scope_id"`
		AssetID          uuid.UUID `json:"asset_id"`
		Enabled          bool      `json:"enabled"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{request.TenantScopeID, request.AssetID, request.Enabled, request.ExpectedRevision})
	return s.setAutoRenew(ctx, actor, request, digest)
}

func validateActor(actor Actor, tenantScopeID uuid.UUID) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || tenantScopeID == uuid.Nil || actor.ScopeKind == "" {
		return ErrInvalidInput
	}
	if (actor.ScopeKind == ScopeTenant && actor.ScopeID != tenantScopeID) ||
		(actor.ScopeKind != ScopeTenant && actor.ScopeKind != ScopePlatform) {
		return ErrPermissionDenied
	}
	return nil
}

func validRequestMetadata(idempotencyKey, requestID string) bool {
	return validOpaqueName(idempotencyKey, 128) && validOpaqueName(requestID, 128)
}

func digestRequest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func storeTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}
