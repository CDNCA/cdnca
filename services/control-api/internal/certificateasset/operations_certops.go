package certificateasset

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fix-certops（证书管理 > 更多）：禁用/启用与下载证书。

const (
	operationEnable   = "certificate.asset.enable"
	operationDisable  = "certificate.asset.disable"
	operationDownload = "certificate.asset.download"
)

// SetDisabled disables or re-enables a certificate (migration 552). Disabled
// certificates cannot be bound and are not auto-renewed; a certificate still
// bound to a site is refused with ErrReferenced.
func (s *Store) SetDisabled(ctx context.Context, actor Actor, request SetDisabledRequest) (result Asset, err error) {
	operation := operationEnable
	if request.Disabled {
		operation = operationDisable
	}
	defer func() {
		s.auditFailure(ctx, actor, request.TenantScopeID, request.RequestID, operation, "certificate_asset", request.AssetID, err)
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
		Disabled         bool      `json:"disabled"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{request.TenantScopeID, request.AssetID, request.Disabled, request.ExpectedRevision})
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := storeTime(s.now())
		if err := authorizeActor(ctx, tx, actor, request.TenantScopeID, true); err != nil {
			return err
		}
		write, err := replayOrClaim(ctx, tx, actor, request.TenantScopeID, operation, request.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if write.found {
			return decodeReplay(write.response, &result)
		}
		asset, err := loadAsset(ctx, tx, request.TenantScopeID, request.AssetID, true)
		if err != nil {
			return err
		}
		if asset.DeletedAt != nil {
			return ErrDeleted
		}
		if asset.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if request.Disabled {
			var bound bool
			if err := tx.QueryRow(ctx, `SELECT certificate_asset_bound_551($1,$2)`,
				request.TenantScopeID, request.AssetID).Scan(&bound); err != nil {
				return err
			}
			if bound {
				return ErrReferenced
			}
		}
		command, err := tx.Exec(ctx, `UPDATE certificate_assets
				SET disabled=$3,revision=revision+1,updated_by_scope_id=$4,updated_by_user_id=$5,updated_at=$6
				WHERE tenant_scope_id=$1 AND id=$2 AND revision=$7 AND deleted_at IS NULL`,
			request.TenantScopeID, request.AssetID, request.Disabled, actor.ScopeID, actor.UserID, now, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		result, err = loadAsset(ctx, tx, request.TenantScopeID, request.AssetID, false)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, request.TenantScopeID, request.RequestID, operation,
			"certificate_asset", request.AssetID, map[string]any{
				"asset_revision": result.Revision,
				"changes":        map[string]any{"disabled": map[string]any{"before": asset.Disabled, "after": result.Disabled}},
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, request.TenantScopeID, operation, request.IdempotencyKey, request.AssetID, result, now)
	})
	if err != nil {
		return Asset{}, fmt.Errorf("set certificate asset disabled: %w", err)
	}
	return result, nil
}

// Download returns the current version's certificate chain and private key
// (PKCS#8 PEM). The audit event is written in the same transaction before
// the key leaves the store; a failure to audit fails the download.
func (s *Store) Download(ctx context.Context, actor Actor, request DownloadRequest) (result Download, err error) {
	defer func() {
		s.auditFailure(ctx, actor, request.TenantScopeID, request.RequestID, operationDownload, "certificate_asset", request.AssetID, err)
		if err != nil {
			zeroBytes(result.PrivateKeyPEM)
			result = Download{}
		}
	}()
	if err := validateActor(actor, request.TenantScopeID); err != nil {
		return Download{}, err
	}
	if request.AssetID == uuid.Nil || !validOpaqueName(request.RequestID, 128) {
		return Download{}, ErrInvalidInput
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeActor(ctx, tx, actor, request.TenantScopeID, true); err != nil {
			return err
		}
		asset, err := loadAsset(ctx, tx, request.TenantScopeID, request.AssetID, false)
		if err != nil {
			return err
		}
		if asset.DeletedAt != nil {
			return ErrDeleted
		}
		material, err := s.loadDownloadMaterial(ctx, tx, request)
		if err != nil {
			return err
		}
		result = Download{AssetID: asset.ID, Name: asset.Name, SANs: material.sans,
			CertificatePEM: material.certificatePEM, PrivateKeyPEM: material.privateKeyPEM}
		return s.appendAudit(ctx, tx, actor, request.TenantScopeID, request.RequestID, operationDownload,
			"certificate_asset", request.AssetID, map[string]any{
				"asset_revision": asset.Revision, "version_id": material.versionID.String(),
				"version": material.version, "fingerprint_sha256": material.fingerprintHex,
			})
	})
	if err != nil {
		return result, fmt.Errorf("download certificate asset: %w", err)
	}
	return result, nil
}

type downloadMaterial struct {
	versionID      uuid.UUID
	version        int64
	sans           []string
	fingerprintHex string
	certificatePEM []byte
	privateKeyPEM  []byte
}

// loadDownloadMaterial opens the latest activated version's envelope with the
// same AAD checks as publication. Revoked versions are not exported.
func (s *Store) loadDownloadMaterial(ctx context.Context, tx pgx.Tx, request DownloadRequest) (downloadMaterial, error) {
	var (
		material                               downloadMaterial
		assetSource                            string
		fingerprint, publicKey, versionAAD     []byte
		privateKeyReference                    string
		revoked                                bool
		envelopeFingerprint, envelopePublicKey []byte
		envelopePrivateKeyReference            string
		envelopeAAD                            []byte
		envelope                               PrivateKeyEnvelope
	)
	err := tx.QueryRow(ctx, `SELECT asset.source,version.id,version.version,version.certificate_pem,version.sans,
		version.fingerprint_sha256,version.public_key_sha256,version.private_key_reference,version.private_key_aad_sha256,
		EXISTS(SELECT 1 FROM certificate_asset_revocation_facts revoked
			WHERE revoked.tenant_scope_id=version.tenant_scope_id
			  AND revoked.asset_id=version.asset_id AND revoked.version_id=version.id),
		envelope.certificate_fingerprint_sha256,envelope.certificate_public_key_sha256,
		envelope.private_key_reference,envelope.aad_sha256,envelope.private_key_ciphertext,
		envelope.private_key_key_id,envelope.private_key_nonce,envelope.private_key_metadata
		FROM certificate_assets asset
		-- The activated version, else (uploaded but never activated/bound) the newest version.
		JOIN LATERAL (
			SELECT candidate.id FROM certificate_asset_versions candidate
			LEFT JOIN LATERAL (
				SELECT version_id FROM certificate_asset_activation_facts
				WHERE tenant_scope_id=asset.tenant_scope_id AND asset_id=asset.id
				ORDER BY sequence DESC LIMIT 1
			) activation ON true
			WHERE candidate.tenant_scope_id=asset.tenant_scope_id AND candidate.asset_id=asset.id
			  AND (activation.version_id IS NULL OR candidate.id=activation.version_id)
			ORDER BY candidate.version DESC LIMIT 1
		) chosen ON true
		JOIN certificate_asset_versions version
		  ON version.tenant_scope_id=asset.tenant_scope_id AND version.asset_id=asset.id AND version.id=chosen.id
		JOIN LATERAL (
			SELECT certificate_fingerprint_sha256,certificate_public_key_sha256,
				private_key_reference,aad_sha256,private_key_ciphertext,private_key_key_id,
				private_key_nonce,private_key_metadata
			FROM certificate_asset_private_key_envelope_facts
			WHERE tenant_scope_id=asset.tenant_scope_id AND asset_id=asset.id AND version_id=version.id
			ORDER BY sequence DESC LIMIT 1
		) envelope ON true
		WHERE asset.tenant_scope_id=$1 AND asset.id=$2 AND asset.deleted_at IS NULL`,
		request.TenantScopeID, request.AssetID).Scan(
		&assetSource, &material.versionID, &material.version, &material.certificatePEM, &material.sans,
		&fingerprint, &publicKey, &privateKeyReference, &versionAAD, &revoked,
		&envelopeFingerprint, &envelopePublicKey, &envelopePrivateKeyReference, &envelopeAAD,
		&envelope.Ciphertext, &envelope.KeyID, &envelope.Nonce, &envelope.Metadata)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && revoked {
		return downloadMaterial{}, ErrDownloadUnavailable
	}
	if err != nil {
		return downloadMaterial{}, err
	}
	if len(fingerprint) != 32 || len(publicKey) != 32 || len(versionAAD) != 32 ||
		!bytes.Equal(fingerprint, envelopeFingerprint) || !bytes.Equal(publicKey, envelopePublicKey) ||
		privateKeyReference != envelopePrivateKeyReference || !bytes.Equal(versionAAD, envelopeAAD) || !validEnvelope(envelope) {
		return downloadMaterial{}, ErrEnvelopeUnavailable
	}
	var fingerprintArray, publicKeyArray [32]byte
	copy(fingerprintArray[:], fingerprint)
	copy(publicKeyArray[:], publicKey)
	envelopeContext := PrivateKeyEnvelopeContext{
		TenantScopeID: request.TenantScopeID, AssetID: request.AssetID, VersionID: material.versionID,
		Version: material.version, CertificateFingerprintSHA256: fingerprintArray,
		CertificatePublicKeySHA256: publicKeyArray, PrivateKeyReference: privateKeyReference,
	}
	computedAAD, err := envelopeContext.AADDigest()
	if err != nil || !bytes.Equal(computedAAD[:], versionAAD) {
		return downloadMaterial{}, ErrEnvelopeUnavailable
	}
	plaintext, err := s.enveloper.Unseal(ctx, PrivateKeyUnsealRequest{Context: envelopeContext, Envelope: cloneEnvelope(envelope)})
	if err != nil || len(plaintext) == 0 {
		zeroBytes(plaintext)
		return downloadMaterial{}, ErrEnvelopeUnavailable
	}
	defer zeroBytes(plaintext)
	keyPEM, err := downloadPrivateKeyPEM(plaintext, publicKeyArray)
	if err != nil && assetSource == SourceACME {
		resolved, resolveErr := resolveOpaquePublicationPrivateKey(ctx, request.OpaqueResolver, OpaquePublicationResolveRequest{
			TenantScopeID: request.TenantScopeID, PrivateKeyReference: privateKeyReference,
			ExpectedPublicKeySHA256: publicKeyArray,
			OuterEnvelopeMetadata:   append(json.RawMessage(nil), envelope.Metadata...),
			WrappedKeyMaterial:      plaintext,
		})
		if resolveErr != nil {
			return downloadMaterial{}, ErrEnvelopeUnavailable
		}
		defer zeroBytes(resolved)
		keyPEM, err = downloadPrivateKeyPEM(resolved, publicKeyArray)
	}
	if err != nil {
		return downloadMaterial{}, ErrEnvelopeUnavailable
	}
	material.privateKeyPEM = keyPEM
	material.fingerprintHex = fmt.Sprintf("%x", fingerprint)
	return material, nil
}

// downloadPrivateKeyPEM accepts the uploaded canonical PEM or an ACME
// PKCS#8 DER key, checks it against the certificate's public key and returns
// PKCS#8 PEM.
func downloadPrivateKeyPEM(key []byte, publicKeySHA256 [32]byte) ([]byte, error) {
	if bytes.HasPrefix(bytes.TrimSpace(key), []byte("-----BEGIN ")) {
		signer, canonical, err := parsePrivateKey(key)
		if err != nil {
			return nil, err
		}
		if err := matchPublicKey(signer.Public(), publicKeySHA256); err != nil {
			zeroBytes(canonical)
			return nil, err
		}
		return canonical, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, ErrInvalidPrivateKeyPEM
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, ErrInvalidPrivateKeyPEM
	}
	if err := matchPublicKey(signer.Public(), publicKeySHA256); err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), nil
}

func matchPublicKey(public crypto.PublicKey, want [32]byte) error {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil || sha256.Sum256(der) != want {
		return ErrKeyMismatch
	}
	return nil
}
