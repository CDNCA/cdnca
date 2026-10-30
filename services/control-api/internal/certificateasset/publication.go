package certificateasset

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type PublicationRequest struct {
	TenantScopeID   uuid.UUID
	SiteIDs         []uuid.UUID
	AssetID         uuid.UUID
	VersionID       uuid.UUID
	BindingRevision int64
	OpaqueResolver  OpaquePublicationResolver
}

type OpaquePublicationResolveRequest struct {
	TenantScopeID           uuid.UUID
	PrivateKeyReference     string
	ExpectedPublicKeySHA256 [32]byte
	OuterEnvelopeMetadata   json.RawMessage
	WrappedKeyMaterial      []byte
}

type OpaquePublicationResolver func(context.Context, OpaquePublicationResolveRequest) ([]byte, error)

type PublicationMaterial struct {
	TenantID             uuid.UUID
	TenantScopeID        uuid.UUID
	SiteID               uuid.UUID
	SiteDomain           string
	SiteDomains          []string
	AssetID              uuid.UUID
	AssetRevision        int64
	CertificateVersionID uuid.UUID
	CertificateVersion   int64
	BindingRevision      int64
	CertificatePEM       []byte
	SANs                 []string
	FingerprintSHA256    [32]byte
	PublicKeySHA256      [32]byte
	NotBefore            time.Time
	NotAfter             time.Time
	PrivateKeyPEM        []byte
}

type PublicationConsumer func([]PublicationMaterial) error

// UsePublicationMaterialsInTx exposes validated certificate material only for
// the lifetime of consumer. The caller owns the surrounding transaction.
func (s *Store) UsePublicationMaterialsInTx(
	ctx context.Context,
	tx pgx.Tx,
	request PublicationRequest,
	consumer PublicationConsumer,
) error {
	if s == nil || s.enveloper == nil || s.now == nil || tx == nil || consumer == nil ||
		request.TenantScopeID == uuid.Nil || request.AssetID == uuid.Nil ||
		request.VersionID == uuid.Nil || request.BindingRevision < 1 || len(request.SiteIDs) == 0 {
		return ErrInvalidInput
	}

	siteIDs := append([]uuid.UUID(nil), request.SiteIDs...)
	sort.Slice(siteIDs, func(left, right int) bool {
		return bytes.Compare(siteIDs[left][:], siteIDs[right][:]) < 0
	})
	for index, siteID := range siteIDs {
		if siteID == uuid.Nil || (index > 0 && siteID == siteIDs[index-1]) {
			return ErrInvalidInput
		}
	}

	var lockedID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM certificate_assets
		WHERE tenant_scope_id=$1 AND id=$2 AND deleted_at IS NULL FOR SHARE`,
		request.TenantScopeID, request.AssetID).Scan(&lockedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}

	type lockedSite struct {
		tenantID uuid.UUID
		domains  []string
	}
	lockedSites := make(map[uuid.UUID]lockedSite, len(siteIDs))
	for _, siteID := range siteIDs {
		var site lockedSite
		err := tx.QueryRow(ctx, `SELECT scope.tenant_id,COALESCE((
				SELECT array_agg(current_domain.canonical_domain ORDER BY current_domain.canonical_domain)
				FROM (
					SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain,fact.action
					FROM site_domain_facts fact
					WHERE fact.scope_id=site.scope_id AND fact.site_id=site.id
					ORDER BY fact.canonical_domain,fact.global_sequence DESC
				) current_domain WHERE current_domain.action='activate'
			),ARRAY[site.domain]::text[])
			FROM sites site
			JOIN access_scopes scope ON scope.id=site.scope_id AND scope.kind='tenant'
			WHERE site.scope_id=$1 AND site.id=$2 AND site.deleted_at IS NULL
			FOR SHARE OF site`, request.TenantScopeID, siteID).Scan(&site.tenantID, &site.domains)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		lockedSites[siteID] = site
	}

	now := storeTime(s.now())
	materials := make([]PublicationMaterial, 0, len(siteIDs))
	privateKeys := make([][]byte, 0, len(siteIDs))
	defer func() {
		for _, privateKey := range privateKeys {
			zeroBytes(privateKey)
		}
		for index := range materials {
			materials[index].PrivateKeyPEM = nil
			materials[index].CertificatePEM = nil
			materials[index].SANs = nil
		}
	}()

	for _, siteID := range siteIDs {
		var binding Binding
		var action string
		err := tx.QueryRow(ctx, `SELECT sequence,action,asset_id,version_id,is_default,
			changed_by_user_id,changed_at
			FROM certificate_site_binding_facts
			WHERE tenant_scope_id=$1 AND site_id=$2 AND sequence=$3
			FOR SHARE`, request.TenantScopeID, siteID, request.BindingRevision).Scan(
			&binding.Revision, &action, &binding.AssetID, &binding.VersionID, &binding.Default,
			&binding.ChangedBy, &binding.ChangedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		binding.TenantScopeID = request.TenantScopeID
		binding.SiteID = siteID
		binding.Bound = action == "bind"
		if !binding.Bound || binding.AssetID != request.AssetID || binding.VersionID != request.VersionID {
			return ErrRevisionConflict
		}

		var activeVersionID uuid.UUID
		err = tx.QueryRow(ctx, `SELECT version_id FROM certificate_asset_activation_facts
			WHERE tenant_scope_id=$1 AND asset_id=$2 ORDER BY sequence DESC LIMIT 1`,
			request.TenantScopeID, binding.AssetID).Scan(&activeVersionID)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidTransition
		}
		if err != nil {
			return err
		}
		if activeVersionID != binding.VersionID {
			return ErrInvalidTransition
		}

		material, err := s.loadPublicationMaterial(ctx, tx, now, request.TenantScopeID,
			lockedSites[siteID], binding, request.OpaqueResolver)
		if err != nil {
			return err
		}
		privateKeys = append(privateKeys, material.PrivateKeyPEM)
		materials = append(materials, material)
	}

	return consumer(materials)
}

func (s *Store) loadPublicationMaterial(
	ctx context.Context,
	tx pgx.Tx,
	now time.Time,
	tenantScopeID uuid.UUID,
	site struct {
		tenantID uuid.UUID
		domains  []string
	},
	binding Binding,
	resolver OpaquePublicationResolver,
) (PublicationMaterial, error) {
	var (
		assetRevision                          int64
		assetSource                            string
		certificateVersion                     int64
		certificatePEM                         []byte
		sans                                   []string
		fingerprint, publicKey, versionAAD     []byte
		privateKeyReference                    string
		notBefore, notAfter                    time.Time
		revoked                                bool
		envelopeFingerprint, envelopePublicKey []byte
		envelopePrivateKeyReference            string
		envelopeAAD                            []byte
		envelope                               PrivateKeyEnvelope
	)
	err := tx.QueryRow(ctx, `SELECT asset.revision,asset.source,version.version,version.certificate_pem,
		version.sans,version.fingerprint_sha256,version.public_key_sha256,
		version.private_key_reference,version.private_key_aad_sha256,
		version.not_before,version.not_after,
		EXISTS(SELECT 1 FROM certificate_asset_revocation_facts revoked
			WHERE revoked.tenant_scope_id=version.tenant_scope_id
			  AND revoked.asset_id=version.asset_id AND revoked.version_id=version.id),
		envelope.certificate_fingerprint_sha256,envelope.certificate_public_key_sha256,
		envelope.private_key_reference,envelope.aad_sha256,envelope.private_key_ciphertext,
		envelope.private_key_key_id,envelope.private_key_nonce,envelope.private_key_metadata
		FROM certificate_assets asset
		JOIN certificate_asset_versions version
		  ON version.tenant_scope_id=asset.tenant_scope_id AND version.asset_id=asset.id
		 AND version.id=$3
		JOIN LATERAL (
			SELECT certificate_fingerprint_sha256,certificate_public_key_sha256,
				private_key_reference,aad_sha256,private_key_ciphertext,private_key_key_id,
				private_key_nonce,private_key_metadata
			FROM certificate_asset_private_key_envelope_facts
			WHERE tenant_scope_id=asset.tenant_scope_id AND asset_id=asset.id AND version_id=version.id
			ORDER BY sequence DESC LIMIT 1
		) envelope ON true
		WHERE asset.tenant_scope_id=$1 AND asset.id=$2 AND asset.deleted_at IS NULL`,
		tenantScopeID, binding.AssetID, binding.VersionID).Scan(
		&assetRevision, &assetSource, &certificateVersion, &certificatePEM, &sans, &fingerprint, &publicKey,
		&privateKeyReference, &versionAAD, &notBefore, &notAfter, &revoked,
		&envelopeFingerprint, &envelopePublicKey, &envelopePrivateKeyReference, &envelopeAAD,
		&envelope.Ciphertext, &envelope.KeyID, &envelope.Nonce, &envelope.Metadata)
	if errors.Is(err, pgx.ErrNoRows) {
		return PublicationMaterial{}, ErrEnvelopeUnavailable
	}
	if err != nil {
		return PublicationMaterial{}, err
	}
	if revoked {
		return PublicationMaterial{}, ErrInvalidTransition
	}
	if now.Before(notBefore) {
		return PublicationMaterial{}, ErrCertificateNotYetValid
	}
	if !now.Before(notAfter) {
		return PublicationMaterial{}, ErrCertificateExpired
	}
	if err := RequireCoverage(sans, site.domains); err != nil {
		return PublicationMaterial{}, ErrDomainNotCovered
	}
	if len(fingerprint) != 32 || len(publicKey) != 32 || len(versionAAD) != 32 ||
		!bytes.Equal(fingerprint, envelopeFingerprint) ||
		!bytes.Equal(publicKey, envelopePublicKey) ||
		privateKeyReference != envelopePrivateKeyReference ||
		!bytes.Equal(versionAAD, envelopeAAD) || !validEnvelope(envelope) {
		return PublicationMaterial{}, ErrEnvelopeUnavailable
	}

	var fingerprintArray, publicKeyArray [32]byte
	copy(fingerprintArray[:], fingerprint)
	copy(publicKeyArray[:], publicKey)
	envelopeContext := PrivateKeyEnvelopeContext{
		TenantScopeID: tenantScopeID, AssetID: binding.AssetID, VersionID: binding.VersionID,
		Version: certificateVersion, CertificateFingerprintSHA256: fingerprintArray,
		CertificatePublicKeySHA256: publicKeyArray, PrivateKeyReference: privateKeyReference,
	}
	computedAAD, err := envelopeContext.AADDigest()
	if err != nil || !bytes.Equal(computedAAD[:], versionAAD) {
		return PublicationMaterial{}, ErrEnvelopeUnavailable
	}
	plaintext, err := s.enveloper.Unseal(ctx, PrivateKeyUnsealRequest{
		Context: envelopeContext, Envelope: cloneEnvelope(envelope),
	})
	if err != nil || len(plaintext) == 0 {
		zeroBytes(plaintext)
		return PublicationMaterial{}, ErrEnvelopeUnavailable
	}
	defer zeroBytes(plaintext)
	prepared, err := prepareCertificate(certificatePEM, plaintext, nil, now)
	if err != nil && assetSource == SourceACME {
		resolved, resolveErr := resolveOpaquePublicationPrivateKey(ctx, resolver,
			OpaquePublicationResolveRequest{
				TenantScopeID: tenantScopeID, PrivateKeyReference: privateKeyReference,
				ExpectedPublicKeySHA256: publicKeyArray,
				OuterEnvelopeMetadata:   append(json.RawMessage(nil), envelope.Metadata...),
				WrappedKeyMaterial:      plaintext,
			})
		if resolveErr != nil {
			return PublicationMaterial{}, ErrEnvelopeUnavailable
		}
		defer zeroBytes(resolved)
		resolvedPEM := acmeResolvedPrivateKeyPEM(resolved)
		defer zeroBytes(resolvedPEM)
		prepared, err = prepareCertificate(certificatePEM, resolvedPEM, nil, now)
	}
	if err != nil {
		return PublicationMaterial{}, ErrEnvelopeUnavailable
	}
	if !bytes.Equal(prepared.CanonicalPEM, certificatePEM) ||
		prepared.Fingerprint != fingerprintArray || prepared.PublicKeySHA256 != publicKeyArray ||
		!equalPublicationStrings(prepared.SANs, sans) ||
		!prepared.NotBefore.Equal(notBefore) || !prepared.NotAfter.Equal(notAfter) {
		zeroBytes(prepared.CanonicalPrivateKey)
		return PublicationMaterial{}, ErrEnvelopeUnavailable
	}

	return PublicationMaterial{
		TenantID: site.tenantID, TenantScopeID: tenantScopeID, SiteID: binding.SiteID,
		SiteDomain: site.domains[0], SiteDomains: append([]string(nil), site.domains...),
		AssetID: binding.AssetID, AssetRevision: assetRevision,
		CertificateVersionID: binding.VersionID, CertificateVersion: certificateVersion,
		BindingRevision: binding.Revision, CertificatePEM: append([]byte(nil), certificatePEM...),
		SANs: append([]string(nil), sans...), FingerprintSHA256: fingerprintArray,
		PublicKeySHA256: publicKeyArray, NotBefore: notBefore.UTC(), NotAfter: notAfter.UTC(),
		PrivateKeyPEM: prepared.CanonicalPrivateKey,
	}, nil
}

// acmeResolvedPrivateKeyPEM is the resolved ACME key as PEM: the production
// resolver (certificatepublish.acmePublicationResolver) returns the PKCS#8
// DER acmeruntime wrapped, which prepareCertificate (PEM only) would refuse,
// so an issued ACME certificate could never be published. A PEM key passes
// through unchanged; the caller zeroes the returned copy.
func acmeResolvedPrivateKeyPEM(key []byte) []byte {
	if bytes.HasPrefix(bytes.TrimSpace(key), []byte("-----BEGIN ")) {
		return append([]byte(nil), key...)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
}

func resolveOpaquePublicationPrivateKey(
	ctx context.Context,
	resolver OpaquePublicationResolver,
	request OpaquePublicationResolveRequest,
) (resolved []byte, err error) {
	if resolver == nil {
		return nil, ErrEnvelopeUnavailable
	}
	defer func() {
		if recover() != nil {
			zeroBytes(resolved)
			resolved = nil
			err = ErrEnvelopeUnavailable
		}
	}()
	resolved, err = resolver(ctx, request)
	if err != nil || len(resolved) == 0 {
		zeroBytes(resolved)
		return nil, ErrEnvelopeUnavailable
	}
	return resolved, nil
}

func equalPublicationStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
