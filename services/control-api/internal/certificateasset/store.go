package certificateasset

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/tenantaccess"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	operationImport    = "certificate.asset.import"
	operationActivate  = "certificate.asset.activate"
	operationDelete    = "certificate.asset.delete"
	operationAutoRenew = "certificate.auto_renew.update"
	operationBind      = "certificate.asset.bind"
	operationUnbind    = "certificate.asset.unbind"
	operationRewrap    = "certificate.asset.rewrap"
)

type rowScanner interface {
	Scan(...any) error
}

type querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type storedWrite struct {
	response []byte
	found    bool
}

func (s *Store) importPrepared(
	ctx context.Context,
	actor Actor,
	request ImportRequest,
	prepared preparedCertificate,
	digest [32]byte,
) (ImportResult, error) {
	var result ImportResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		result, err = s.importPreparedInTx(ctx, tx, actor, request, prepared, digest, false, true)
		return err
	})
	if err != nil {
		return ImportResult{}, fmt.Errorf("import certificate asset: %w", err)
	}
	return result, nil
}

func (s *Store) importPreparedInTx(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	request ImportRequest,
	prepared preparedCertificate,
	digest [32]byte,
	requireIssuingOrder bool,
	lockIAM bool,
) (ImportResult, error) {
	var result ImportResult
	err := func() error {
		now := storeTime(s.now())
		var authorizationErr error
		if requireIssuingOrder {
			authorizationErr = authorizeActorInTx(ctx, tx, actor, request.TenantScopeID,
				"certificates.manage", false)
		} else {
			authorizationErr = authorizeActorInTx(ctx, tx, actor, request.TenantScopeID, "certificates.manage", lockIAM)
		}
		if authorizationErr != nil {
			return authorizationErr
		}
		if request.Source == SourceACME {
			var err error
			if requireIssuingOrder {
				err = validateIssuingACMEOrder(ctx, tx, request.TenantScopeID, *request.ACMEOrderID, prepared)
			} else {
				err = validateACMEOrder(ctx, tx, request.TenantScopeID, *request.ACMEOrderID, prepared)
			}
			if err != nil {
				return err
			}
		}
		write, err := replayOrClaim(ctx, tx, actor, request.TenantScopeID, operationImport, request.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if write.found {
			if err := decodeReplay(write.response, &result); err != nil {
				return err
			}
			if result.Asset.Tenant == nil {
				result.Asset.Tenant, err = loadAssetTenant(ctx, tx, request.TenantScopeID)
			}
			return err
		}
		ownerUserID := request.OwnerUserID
		if ownerUserID == nil && request.Source == SourceUploaded && request.AssetID == nil && actor.ScopeKind == ScopeTenant {
			ownerUserID = &actor.UserID
		}
		// A new ACME asset belongs to the order's user (migration 535: renewal
		// parent's owner, tenant-member orderer, else the tenant's single
		// owner); NULL only when none can be determined.
		if ownerUserID == nil && request.Source == SourceACME && request.AssetID == nil {
			if err := tx.QueryRow(ctx, `SELECT resolve_certificate_order_owner_535($1,$2)`,
				request.TenantScopeID, *request.ACMEOrderID).Scan(&ownerUserID); err != nil {
				return fmt.Errorf("resolve ACME certificate owner: %w", err)
			}
		}
		if err := validateImportOwner(ctx, tx, request.TenantScopeID, ownerUserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
			request.TenantScopeID.String()+":"+fingerprintHex(prepared.Fingerprint)); err != nil {
			return err
		}

		existing, found, err := loadByFingerprint(ctx, tx, request.TenantScopeID, prepared.Fingerprint, now)
		if err != nil {
			return err
		}
		if found {
			if existing.Asset.DeletedAt != nil {
				return ErrDeleted
			}
			if existing.Asset.Source != request.Source ||
				!sameOptionalUUID(existing.Version.ACMEOrderID, request.ACMEOrderID) ||
				(request.AssetID != nil && existing.Asset.ID != *request.AssetID) {
				return ErrIdempotencyConflict
			}
			if ownerUserID != nil && (existing.Asset.Owner == nil && request.OwnerUserID != nil ||
				existing.Asset.Owner != nil && existing.Asset.Owner.ID != *ownerUserID) {
				return ErrIdempotencyConflict
			}
			existing.Replayed = true
			result = existing
			var recordedOwnerID *uuid.UUID
			if result.Asset.Owner != nil {
				recordedOwnerID = &result.Asset.Owner.ID
			}
			if err := s.appendAudit(ctx, tx, actor, request.TenantScopeID, request.RequestID, operationImport,
				"certificate_asset", result.Asset.ID, map[string]any{
					"fingerprint_sha256": result.Version.FingerprintSHA256,
					"version":            result.Version.Version, "deduplicated": true,
					"owner_user_id": recordedOwnerID, "owner_status": result.Asset.OwnerStatus,
				}); err != nil {
				return err
			}
			return completeWrite(ctx, tx, actor, request.TenantScopeID, operationImport, request.IdempotencyKey, result.Asset.ID, result, now)
		}

		var asset Asset
		versionNumber := int64(1)
		initialStatus := StatusDefault
		if request.AssetID == nil {
			assetID, err := uuid.NewV7()
			if err != nil {
				return err
			}
			// An ACME certificate starts with its order's auto-renew choice
			// (migration 537); uploaded certificates never auto-renew.
			_, err = tx.Exec(ctx, `INSERT INTO certificate_assets (
					tenant_scope_id,id,name,source,created_by_scope_id,created_by_user_id,
					updated_by_scope_id,updated_by_user_id,created_at,updated_at,owner_user_id,remark,auto_renew
				) VALUES($1,$2,$3,$4,$5,$6,$5,$6,$7,$7,$8,$9,$4='acme' AND COALESCE((SELECT auto_renew
					FROM certificate_orders WHERE scope_id=$1 AND id=$10),false))`, request.TenantScopeID, assetID, request.Name,
				request.Source, actor.ScopeID, actor.UserID, now, ownerUserID, request.Remark, request.ACMEOrderID)
			if err != nil {
				return err
			}
			asset, err = loadAsset(ctx, tx, request.TenantScopeID, assetID, false)
			if err != nil {
				return err
			}
		} else {
			asset, err = loadAsset(ctx, tx, request.TenantScopeID, *request.AssetID, true)
			if err != nil {
				return err
			}
			if asset.DeletedAt != nil {
				return ErrDeleted
			}
			if asset.Revision != request.ExpectedRevision {
				return ErrRevisionConflict
			}
			if asset.Source != request.Source {
				return ErrInvalidTransition
			}
			if ownerUserID != nil && (asset.Owner == nil || asset.Owner.ID != *ownerUserID) {
				return ErrInvalidTransition
			}
			if err := tx.QueryRow(ctx, `SELECT COALESCE(max(version),0)+1
				FROM certificate_asset_versions WHERE tenant_scope_id=$1 AND asset_id=$2`,
				request.TenantScopeID, asset.ID).Scan(&versionNumber); err != nil {
				return err
			}
			initialStatus = StatusPendingActivation
			command, err := tx.Exec(ctx, `UPDATE certificate_assets
					SET revision=revision+1,updated_by_scope_id=$3,updated_by_user_id=$4,updated_at=$5
					WHERE tenant_scope_id=$1 AND id=$2 AND revision=$6 AND deleted_at IS NULL`,
				request.TenantScopeID, asset.ID, actor.ScopeID, actor.UserID, now, request.ExpectedRevision)
			if err != nil {
				return err
			}
			if command.RowsAffected() != 1 {
				return ErrRevisionConflict
			}
		}

		versionID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		var renewalDueAt *time.Time
		if request.Source == SourceACME {
			value := prepared.NotAfter.Add(-DefaultRenewBefore)
			if value.Before(prepared.NotBefore) {
				value = prepared.NotBefore
			}
			value = storeTime(value)
			renewalDueAt = &value
		}
		envelopeContext := PrivateKeyEnvelopeContext{
			TenantScopeID: request.TenantScopeID, AssetID: asset.ID, VersionID: versionID,
			Version: versionNumber, CertificateFingerprintSHA256: prepared.Fingerprint,
			CertificatePublicKeySHA256: prepared.PublicKeySHA256,
			PrivateKeyReference:        prepared.PrivateKeyReference,
		}
		aadDigest, err := envelopeContext.AADDigest()
		if err != nil {
			return ErrEnvelopeUnavailable
		}
		envelope, err := s.sealPrivateKey(ctx, envelopeContext, prepared)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO certificate_asset_versions (
					tenant_scope_id,id,asset_id,version,initial_status,fingerprint_sha256,certificate_pem,
					public_key_sha256,private_key_reference,private_key_aad_sha256,
					sans,leaf_subject,serial_number,public_key_algorithm,public_key_bits,signature_algorithm,
					not_before,not_after,acme_order_id,renewal_due_at,actor_scope_id,imported_by_user_id,imported_at
				) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
			request.TenantScopeID, versionID, asset.ID, versionNumber, initialStatus,
			prepared.Fingerprint[:], prepared.CanonicalPEM, prepared.PublicKeySHA256[:],
			prepared.PrivateKeyReference, aadDigest[:], prepared.SANs, prepared.Subject, prepared.SerialNumber,
			prepared.PublicKeyAlgorithm, prepared.PublicKeyBits, prepared.SignatureAlgorithm,
			prepared.NotBefore, prepared.NotAfter, request.ACMEOrderID, renewalDueAt, actor.ScopeID, actor.UserID, now)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO certificate_asset_private_key_envelope_facts (
					tenant_scope_id,asset_id,version_id,sequence,certificate_fingerprint_sha256,
					certificate_public_key_sha256,private_key_reference,aad_sha256,private_key_ciphertext,
					private_key_key_id,private_key_nonce,private_key_metadata,change_kind,request_id,
					actor_scope_id,changed_by_user_id,changed_at
				) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,'initial',$12,$13,$14,$15)`,
			request.TenantScopeID, asset.ID, versionID, prepared.Fingerprint[:], prepared.PublicKeySHA256[:],
			prepared.PrivateKeyReference, aadDigest[:], envelope.Ciphertext, envelope.KeyID,
			envelope.Nonce, envelope.Metadata, request.RequestID, actor.ScopeID, actor.UserID, now)
		if err != nil {
			return err
		}
		asset, err = loadAsset(ctx, tx, request.TenantScopeID, asset.ID, false)
		if err != nil {
			return err
		}
		version, err := loadVersion(ctx, tx, request.TenantScopeID, asset.ID, versionID, now)
		if err != nil {
			return err
		}
		result = ImportResult{Asset: asset, Version: version}
		var recordedOwnerID *uuid.UUID
		if asset.Owner != nil {
			recordedOwnerID = &asset.Owner.ID
		}
		if err := s.appendAudit(ctx, tx, actor, request.TenantScopeID, request.RequestID, operationImport,
			"certificate_asset", asset.ID, map[string]any{
				"fingerprint_sha256": version.FingerprintSHA256, "version": version.Version,
				"source": asset.Source, "san_count": len(version.SANs), "deduplicated": false,
				"owner_user_id": recordedOwnerID, "owner_status": asset.OwnerStatus,
				"changes": map[string]any{"version_id": map[string]any{"before": nil, "after": version.ID.String()}},
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, request.TenantScopeID, operationImport, request.IdempotencyKey, asset.ID, result, now)
	}()
	return result, err
}

func (s *Store) sealPrivateKey(
	ctx context.Context,
	envelopeContext PrivateKeyEnvelopeContext,
	prepared preparedCertificate,
) (PrivateKeyEnvelope, error) {
	var envelope PrivateKeyEnvelope
	var err error
	if prepared.OpaquePrivateKey == nil {
		envelope, err = s.enveloper.Seal(ctx, PrivateKeySealRequest{
			Context: envelopeContext, PlaintextPKCS8: prepared.CanonicalPrivateKey,
		})
	} else {
		envelope, err = s.enveloper.SealOpaque(ctx, OpaquePrivateKeySealRequest{
			Context:            envelopeContext,
			WrappedKeyMaterial: prepared.OpaquePrivateKey.WrappedKeyMaterial,
			Metadata:           prepared.OpaquePrivateKey.Metadata,
		})
	}
	if err != nil || !validEnvelope(envelope) ||
		(len(prepared.CanonicalPrivateKey) != 0 && envelopeContainsPlaintext(envelope, prepared.CanonicalPrivateKey)) ||
		(prepared.OpaquePrivateKey != nil &&
			envelopeContainsPlaintext(envelope, prepared.OpaquePrivateKey.WrappedKeyMaterial)) {
		return PrivateKeyEnvelope{}, ErrEnvelopeUnavailable
	}
	return cloneEnvelope(envelope), nil
}

func (s *Store) activate(ctx context.Context, actor Actor, request ActivateRequest, digest [32]byte) (Version, error) {
	var result Version
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return s.activateTx(ctx, tx, actor, request, digest, true, &result)
	})
	if err != nil {
		return Version{}, fmt.Errorf("activate certificate asset version: %w", err)
	}
	return result, nil
}

// activateTx is activate inside tx; lockIAM false when the caller already holds
// the IAM scope locks of a superset (site transfer).
func (s *Store) activateTx(ctx context.Context, tx pgx.Tx, actor Actor, request ActivateRequest, digest [32]byte,
	lockIAM bool, result *Version) error {
	now := storeTime(s.now())
	if err := authorizeActorInTx(ctx, tx, actor, request.TenantScopeID, "certificates.manage", lockIAM); err != nil {
		return err
	}
	write, err := replayOrClaim(ctx, tx, actor, request.TenantScopeID, operationActivate, request.IdempotencyKey, digest, now)
	if err != nil {
		return err
	}
	if write.found {
		return decodeReplay(write.response, result)
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
	target, err := loadVersion(ctx, tx, request.TenantScopeID, request.AssetID, request.VersionID, now)
	if err != nil {
		return err
	}
	if target.Status == StatusActive || target.Status == StatusRevoked || target.Status == StatusExpired {
		return ErrInvalidTransition
	}
	bindings, err := loadCurrentBindingsForAssetAndLockSites(ctx, tx,
		request.TenantScopeID, request.AssetID)
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		var domains []string
		if err := tx.QueryRow(ctx, `SELECT COALESCE((
				SELECT array_agg(current_domain.canonical_domain ORDER BY current_domain.canonical_domain)
				FROM (
					SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain,fact.action
					FROM site_domain_facts fact
					WHERE fact.scope_id=site.scope_id AND fact.site_id=site.id
					ORDER BY fact.canonical_domain,fact.global_sequence DESC
				) current_domain WHERE current_domain.action='activate'
			),ARRAY[site.domain]::text[]) FROM sites site
				WHERE site.scope_id=$1 AND site.id=$2 AND site.deleted_at IS NULL`,
			request.TenantScopeID, binding.SiteID).Scan(&domains); err != nil {
			return err
		}
		if err := RequireCoverage(target.SANs, domains); err != nil {
			return ErrDomainNotCovered
		}
	}
	var sequence int64
	var previousVersionID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(sequence),0)+1
		FROM certificate_asset_activation_facts WHERE tenant_scope_id=$1 AND asset_id=$2`,
		request.TenantScopeID, request.AssetID).Scan(&sequence); err != nil {
		return err
	}
	if sequence > 1 {
		var value uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT version_id FROM certificate_asset_activation_facts
			WHERE tenant_scope_id=$1 AND asset_id=$2 ORDER BY sequence DESC LIMIT 1`,
			request.TenantScopeID, request.AssetID).Scan(&value); err != nil {
			return err
		}
		previousVersionID = &value
	}
	resultingRevision := request.ExpectedRevision + 1
	command, err := tx.Exec(ctx, `UPDATE certificate_assets
			SET revision=$3,updated_by_scope_id=$4,updated_by_user_id=$5,updated_at=$6
			WHERE tenant_scope_id=$1 AND id=$2 AND revision=$7 AND deleted_at IS NULL`,
		request.TenantScopeID, request.AssetID, resultingRevision, actor.ScopeID, actor.UserID, now, request.ExpectedRevision)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrRevisionConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO certificate_asset_activation_facts (
			tenant_scope_id,asset_id,sequence,version_id,previous_version_id,
			expected_asset_revision,resulting_asset_revision,request_id,actor_scope_id,activated_by_user_id,activated_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, request.TenantScopeID, request.AssetID,
		sequence, request.VersionID, previousVersionID, request.ExpectedRevision, resultingRevision,
		request.RequestID, actor.ScopeID, actor.UserID, now)
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		if err := s.supersedeRenewalDeliveriesTx(ctx, tx, actor, request.TenantScopeID, binding.SiteID,
			request.RequestID); err != nil {
			return err
		}
		resultingBindingRevision, err := nextBindingRevisionTx(ctx, tx, request.TenantScopeID, binding.SiteID,
			binding.Revision)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO certificate_site_binding_facts (
					tenant_scope_id,site_id,sequence,action,asset_id,version_id,is_default,
					expected_revision,resulting_revision,request_id,actor_scope_id,changed_by_user_id,changed_at
				) VALUES($1,$2,$3,'bind',$4,$5,$6,$7,$3,$8,$9,$10,$11)`,
			request.TenantScopeID, binding.SiteID, resultingBindingRevision, request.AssetID,
			request.VersionID, binding.Default, resultingBindingRevision-1, request.RequestID, actor.ScopeID, actor.UserID, now)
		if err != nil {
			return err
		}
		publicationBinding := binding
		publicationBinding.VersionID = request.VersionID
		publicationBinding.Revision = resultingBindingRevision
		if err := appendCertificatePublicationIntent(ctx, tx, "publish", publicationBinding,
			request.RequestID, actor); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, request.TenantScopeID, request.RequestID, operationBind,
			"site", binding.SiteID, map[string]any{
				"asset_id": request.AssetID, "version_id": request.VersionID,
				"previous_version_id": binding.VersionID,
				"binding_revision":    resultingBindingRevision, "default": binding.Default,
				"cause":   "certificate_version_activation",
				"changes": map[string]any{"version_id": map[string]any{"before": binding.VersionID.String(), "after": request.VersionID.String()}},
			}); err != nil {
			return err
		}
	}
	if target.ACMEOrderID != nil {
		if err := s.advanceActivatedACMEOrder(ctx, tx, actor, request, *target.ACMEOrderID, len(bindings) == 0); err != nil {
			return err
		}
	}
	*result, err = loadVersion(ctx, tx, request.TenantScopeID, request.AssetID, request.VersionID, now)
	if err != nil {
		return err
	}
	if err := s.appendAudit(ctx, tx, actor, request.TenantScopeID, request.RequestID, operationActivate,
		"certificate_asset_version", request.VersionID, map[string]any{
			"asset_id": request.AssetID, "version": result.Version,
			"previous_version_id": previousVersionID, "asset_revision": resultingRevision,
			"migrated_binding_count": len(bindings),
			"changes":                map[string]any{"active_version_id": map[string]any{"before": previousVersionID, "after": request.VersionID.String()}},
		}); err != nil {
		return err
	}
	return completeWrite(ctx, tx, actor, request.TenantScopeID, operationActivate, request.IdempotencyKey, request.AssetID, *result, now)
}

// advanceActivatedACMEOrder (CERT-RENEW-LIFECYCLE-01 A): activating the
// version an ACME order issued moves the order issued -> deploying; with no
// site bound there is nothing to deploy, so on to active. A bound version
// becomes active when its publication succeeds (PublicationIntentStore).
// Renewal scheduling takes active / renewal_due orders.
func (s *Store) advanceActivatedACMEOrder(ctx context.Context, tx pgx.Tx, actor Actor, request ActivateRequest,
	orderID uuid.UUID, unbound bool) error {
	steps := [][2]string{{"issued", "deploying"}}
	if unbound {
		steps = append(steps, [2]string{"deploying", "active"})
	}
	for _, step := range steps {
		command, err := tx.Exec(ctx, `UPDATE certificate_orders SET status=$6,revision=revision+1,
			updated_at=GREATEST(updated_at,statement_timestamp())
			WHERE scope_id=$1 AND id=$2 AND issued_asset_id=$3 AND issued_asset_version_id=$4 AND status=$5`,
			request.TenantScopeID, orderID, request.AssetID, request.VersionID, step[0], step[1])
		if err != nil {
			return fmt.Errorf("advance activated ACME order: %w", err)
		}
		if command.RowsAffected() == 0 {
			return nil // already past this step (a reactivation)
		}
		if err := s.appendAudit(ctx, tx, actor, request.TenantScopeID, request.RequestID, "certificate.order.transition",
			"certificate_order", orderID, map[string]any{
				"from_status": step[0], "to_status": step[1], "reason": "certificate_version_activated",
				"state":   step[1],
				"changes": map[string]any{"status": map[string]any{"before": step[0], "after": step[1]}},
			}); err != nil {
			return err
		}
	}
	return nil
}

func appendCertificatePublicationIntent(
	ctx context.Context,
	tx pgx.Tx,
	operation string,
	binding Binding,
	requestID string,
	actor Actor,
) error {
	if (operation != "publish" && operation != "unpublish") || actor.SessionID == uuid.Nil {
		return ErrInvalidInput
	}
	result, err := tx.Exec(ctx, `INSERT INTO certificate_publication_intents (
		tenant_scope_id,site_id,binding_revision,operation,asset_id,version_id,is_default,
		request_id,actor_scope_id,actor_user_id,actor_session_id,actor_scope_kind,
		actor_user_revision,target_tenant_id,target_tenant_revision,deadline_at
	) SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,session_row.id,actor_scope.kind,
		account.revision,target_scope.tenant_id,target_tenant.revision,
		transaction_timestamp()+interval '1 hour'
	FROM auth_sessions session_row
	JOIN users account ON account.id=session_row.user_id AND account.status='active'
	JOIN memberships membership ON membership.scope_id=session_row.scope_id
		AND membership.user_id=session_row.user_id AND membership.status='active'
	JOIN access_scopes actor_scope ON actor_scope.id=session_row.scope_id
	JOIN access_scopes target_scope ON target_scope.id=$1 AND target_scope.kind='tenant'
	JOIN tenants target_tenant ON target_tenant.id=target_scope.tenant_id AND target_tenant.status='active'
	WHERE session_row.id=$11 AND session_row.scope_id=$9 AND session_row.user_id=$10
	  AND session_row.revoked_at IS NULL AND session_row.replaced_by_id IS NULL
	  AND session_row.expires_at>transaction_timestamp() AND actor_scope.kind=$12`,
		binding.TenantScopeID, binding.SiteID, binding.Revision, operation,
		binding.AssetID, binding.VersionID, binding.Default, requestID, actor.ScopeID, actor.UserID,
		actor.SessionID, actor.ScopeKind)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrPermissionDenied
	}
	return nil
}

func loadCurrentBindingsForAssetAndLockSites(
	ctx context.Context,
	tx pgx.Tx,
	tenantScopeID, assetID uuid.UUID,
) ([]Binding, error) {
	rows, err := tx.Query(ctx, `SELECT site_id FROM (
		SELECT DISTINCT ON (site_id) site_id,action,asset_id
		FROM certificate_site_binding_facts
		WHERE tenant_scope_id=$1 ORDER BY site_id,sequence DESC
	) current_binding
	WHERE action='bind' AND asset_id=$2 ORDER BY site_id`, tenantScopeID, assetID)
	if err != nil {
		return nil, err
	}
	var siteIDs []uuid.UUID
	for rows.Next() {
		var siteID uuid.UUID
		if err := rows.Scan(&siteID); err != nil {
			rows.Close()
			return nil, err
		}
		siteIDs = append(siteIDs, siteID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	bindings := make([]Binding, 0, len(siteIDs))
	for _, siteID := range siteIDs {
		var lockedID uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM sites
			WHERE scope_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`,
			tenantScopeID, siteID).Scan(&lockedID); err != nil {
			return nil, err
		}
		binding, found, err := loadLatestBinding(ctx, tx, tenantScopeID, siteID)
		if err != nil {
			return nil, err
		}
		if found && binding.Bound && binding.AssetID == assetID {
			bindings = append(bindings, binding)
		}
	}
	return bindings, nil
}

func (s *Store) rewrap(
	ctx context.Context,
	actor Actor,
	request RewrapRequest,
	digest [32]byte,
) (EnvelopeRevision, error) {
	var result EnvelopeRevision
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := storeTime(s.now())
		if err := authorizeActor(ctx, tx, actor, request.TenantScopeID, true); err != nil {
			return err
		}
		write, err := replayOrClaim(ctx, tx, actor, request.TenantScopeID, operationRewrap, request.IdempotencyKey, digest, now)
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
		var versionNumber, envelopeSequence int64
		var fingerprint, publicKeyDigest, versionAADDigest, envelopeAADDigest []byte
		var keyReference string
		var envelope PrivateKeyEnvelope
		err = tx.QueryRow(ctx, `SELECT v.version,v.fingerprint_sha256,v.public_key_sha256,
			v.private_key_reference,v.private_key_aad_sha256,e.sequence,e.aad_sha256,
			e.private_key_ciphertext,e.private_key_key_id,e.private_key_nonce,e.private_key_metadata
			FROM certificate_asset_versions v
			JOIN certificate_asset_private_key_envelope_facts e
			  ON e.tenant_scope_id=v.tenant_scope_id AND e.asset_id=v.asset_id AND e.version_id=v.id
			WHERE v.tenant_scope_id=$1 AND v.asset_id=$2 AND v.id=$3
			ORDER BY e.sequence DESC LIMIT 1 FOR UPDATE OF e`, request.TenantScopeID,
			request.AssetID, request.VersionID).Scan(&versionNumber, &fingerprint, &publicKeyDigest,
			&keyReference, &versionAADDigest, &envelopeSequence, &envelopeAADDigest,
			&envelope.Ciphertext, &envelope.KeyID, &envelope.Nonce, &envelope.Metadata)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if envelopeSequence != request.ExpectedEnvelopeSequence || len(fingerprint) != 32 ||
			len(publicKeyDigest) != 32 || !bytes.Equal(versionAADDigest, envelopeAADDigest) {
			return ErrRevisionConflict
		}
		var fingerprintArray, publicKeyArray [32]byte
		copy(fingerprintArray[:], fingerprint)
		copy(publicKeyArray[:], publicKeyDigest)
		envelopeContext := PrivateKeyEnvelopeContext{
			TenantScopeID: request.TenantScopeID, AssetID: request.AssetID, VersionID: request.VersionID,
			Version: versionNumber, CertificateFingerprintSHA256: fingerprintArray,
			CertificatePublicKeySHA256: publicKeyArray, PrivateKeyReference: keyReference,
		}
		computedAADDigest, err := envelopeContext.AADDigest()
		if err != nil || !bytes.Equal(computedAADDigest[:], versionAADDigest) {
			return ErrEnvelopeUnavailable
		}
		newEnvelope, err := s.enveloper.Rewrap(ctx, PrivateKeyRewrapRequest{
			Context: envelopeContext, Envelope: cloneEnvelope(envelope), TargetKeyID: request.TargetKeyID,
		})
		if err != nil || newEnvelope.KeyID != request.TargetKeyID || !validEnvelope(newEnvelope) {
			return ErrEnvelopeUnavailable
		}
		result = EnvelopeRevision{
			TenantScopeID: request.TenantScopeID, AssetID: request.AssetID,
			VersionID: request.VersionID, Sequence: envelopeSequence + 1,
			AADDigest: hex.EncodeToString(computedAADDigest[:]), ChangedAt: now,
		}
		_, err = tx.Exec(ctx, `INSERT INTO certificate_asset_private_key_envelope_facts (
				tenant_scope_id,asset_id,version_id,sequence,certificate_fingerprint_sha256,
				certificate_public_key_sha256,private_key_reference,aad_sha256,private_key_ciphertext,
				private_key_key_id,private_key_nonce,private_key_metadata,change_kind,request_id,
				actor_scope_id,changed_by_user_id,changed_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'rewrap',$13,$14,$15,$16)`,
			request.TenantScopeID, request.AssetID, request.VersionID, result.Sequence,
			fingerprint, publicKeyDigest, keyReference, computedAADDigest[:], newEnvelope.Ciphertext,
			newEnvelope.KeyID, newEnvelope.Nonce, newEnvelope.Metadata, request.RequestID, actor.ScopeID, actor.UserID, now)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, request.TenantScopeID, request.RequestID, operationRewrap,
			"certificate_asset_version", request.VersionID, map[string]any{
				"asset_id": request.AssetID, "envelope_sequence": result.Sequence,
				"aad_sha256": result.AADDigest,
				"changes":    map[string]any{"envelope_sequence": map[string]any{"before": request.ExpectedEnvelopeSequence, "after": result.Sequence}},
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, request.TenantScopeID, operationRewrap, request.IdempotencyKey,
			request.VersionID, result, now)
	})
	if err != nil {
		return EnvelopeRevision{}, fmt.Errorf("rewrap certificate private key envelope: %w", err)
	}
	return result, nil
}

func (s *Store) bind(ctx context.Context, actor Actor, request BindRequest, digest [32]byte) (Binding, error) {
	var result Binding
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return s.bindTx(ctx, tx, actor, request, digest, true, &result)
	})
	if err != nil {
		return Binding{}, fmt.Errorf("bind certificate asset: %w", err)
	}
	return result, nil
}

// bindTx is bind inside tx; lockIAM false when the caller already holds
// the IAM scope locks of a superset (site transfer).
func (s *Store) bindTx(ctx context.Context, tx pgx.Tx, actor Actor, request BindRequest, digest [32]byte,
	lockIAM bool, result *Binding) error {
	now := storeTime(s.now())
	if err := authorizeActorInTx(ctx, tx, actor, request.TenantScopeID, "certificates.manage", lockIAM); err != nil {
		return err
	}
	write, err := replayOrClaim(ctx, tx, actor, request.TenantScopeID, operationBind, request.IdempotencyKey, digest, now)
	if err != nil {
		return err
	}
	if write.found {
		return decodeReplay(write.response, result)
	}
	asset, err := loadAsset(ctx, tx, request.TenantScopeID, request.AssetID, true)
	if err != nil {
		return err
	}
	if asset.DeletedAt != nil {
		return ErrDeleted
	}
	if asset.Disabled {
		return ErrAssetDisabled
	}
	var domains []string
	err = tx.QueryRow(ctx, `SELECT COALESCE((
			SELECT array_agg(current_domain.canonical_domain ORDER BY current_domain.canonical_domain)
			FROM (
				SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain,fact.action
				FROM site_domain_facts fact
				WHERE fact.scope_id=site.scope_id AND fact.site_id=site.id
				ORDER BY fact.canonical_domain,fact.global_sequence DESC
			) current_domain WHERE current_domain.action='activate'
		),ARRAY[site.domain]::text[]) FROM sites site
		WHERE site.scope_id=$1 AND site.id=$2 AND site.deleted_at IS NULL FOR UPDATE OF site`,
		request.TenantScopeID, request.SiteID).Scan(&domains)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	version, err := loadVersion(ctx, tx, request.TenantScopeID, request.AssetID, request.VersionID, now)
	if err != nil {
		return err
	}
	if version.Status != StatusActive {
		return ErrInvalidTransition
	}
	if err := RequireCoverage(version.SANs, domains); err != nil {
		return ErrDomainNotCovered
	}
	latest, found, err := loadLatestBinding(ctx, tx, request.TenantScopeID, request.SiteID)
	if err != nil {
		return err
	}
	currentRevision := int64(0)
	if found {
		currentRevision = latest.Revision
	}
	if currentRevision != request.ExpectedRevision {
		return ErrRevisionConflict
	}
	if err := s.supersedeRenewalDeliveriesTx(ctx, tx, actor, request.TenantScopeID, request.SiteID,
		request.RequestID); err != nil {
		return err
	}
	nextRevision, err := nextBindingRevisionTx(ctx, tx, request.TenantScopeID, request.SiteID, currentRevision)
	if err != nil {
		return err
	}
	*result = Binding{
		TenantScopeID: request.TenantScopeID, SiteID: request.SiteID, AssetID: request.AssetID,
		VersionID: request.VersionID, Revision: nextRevision, Default: request.Default,
		Bound: true, ChangedBy: actor.UserID, ChangedAt: now,
	}
	_, err = tx.Exec(ctx, `INSERT INTO certificate_site_binding_facts (
			tenant_scope_id,site_id,sequence,action,asset_id,version_id,is_default,
			expected_revision,resulting_revision,request_id,actor_scope_id,changed_by_user_id,changed_at
		) VALUES($1,$2,$3,'bind',$4,$5,$6,$7,$3,$8,$9,$10,$11)`, request.TenantScopeID,
		request.SiteID, result.Revision, request.AssetID, request.VersionID, request.Default,
		result.Revision-1, request.RequestID, actor.ScopeID, actor.UserID, now)
	if err != nil {
		return err
	}
	if err := appendCertificatePublicationIntent(ctx, tx, "publish", *result,
		request.RequestID, actor); err != nil {
		return err
	}
	var boundBefore any
	if found && latest.Bound {
		boundBefore = latest.VersionID.String()
	}
	if err := s.appendAudit(ctx, tx, actor, request.TenantScopeID, request.RequestID, operationBind,
		"site", request.SiteID, map[string]any{
			"asset_id": request.AssetID, "version_id": request.VersionID,
			"binding_revision": result.Revision, "default": request.Default,
			"changes": map[string]any{"certificate_version_id": map[string]any{"before": boundBefore, "after": request.VersionID.String()}},
		}); err != nil {
		return err
	}
	return completeWrite(ctx, tx, actor, request.TenantScopeID, operationBind, request.IdempotencyKey, request.SiteID, *result, now)
}

func (s *Store) unbind(ctx context.Context, actor Actor, request UnbindRequest, digest [32]byte) (Binding, error) {
	var result Binding
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := storeTime(s.now())
		if err := authorizeActor(ctx, tx, actor, request.TenantScopeID, true); err != nil {
			return err
		}
		write, err := replayOrClaim(ctx, tx, actor, request.TenantScopeID, operationUnbind, request.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if write.found {
			return decodeReplay(write.response, &result)
		}
		var ignored uuid.UUID
		err = tx.QueryRow(ctx, `SELECT id FROM sites
			WHERE scope_id=$1 AND id=$2 AND deleted_at IS NULL FOR UPDATE`,
			request.TenantScopeID, request.SiteID).Scan(&ignored)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		latest, found, err := loadLatestBinding(ctx, tx, request.TenantScopeID, request.SiteID)
		if err != nil {
			return err
		}
		if !found || !latest.Bound {
			return ErrInvalidTransition
		}
		if latest.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if err := s.supersedeRenewalDeliveriesTx(ctx, tx, actor, request.TenantScopeID, request.SiteID,
			request.RequestID); err != nil {
			return err
		}
		nextRevision, err := nextBindingRevisionTx(ctx, tx, request.TenantScopeID, request.SiteID, latest.Revision)
		if err != nil {
			return err
		}
		result = latest
		result.Revision = nextRevision
		result.Bound = false
		result.ChangedBy = actor.UserID
		result.ChangedAt = now
		_, err = tx.Exec(ctx, `INSERT INTO certificate_site_binding_facts (
				tenant_scope_id,site_id,sequence,action,asset_id,version_id,is_default,
				expected_revision,resulting_revision,request_id,actor_scope_id,changed_by_user_id,changed_at
			) VALUES($1,$2,$3,'unbind',$4,$5,$6,$7,$3,$8,$9,$10,$11)`, request.TenantScopeID,
			request.SiteID, result.Revision, result.AssetID, result.VersionID, result.Default,
			result.Revision-1, request.RequestID, actor.ScopeID, actor.UserID, now)
		if err != nil {
			return err
		}
		if err := appendCertificatePublicationIntent(ctx, tx, "unpublish", result,
			request.RequestID, actor); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, request.TenantScopeID, request.RequestID, operationUnbind,
			"site", request.SiteID, map[string]any{
				"asset_id": result.AssetID, "version_id": result.VersionID,
				"binding_revision": result.Revision,
				"changes":          map[string]any{"certificate_version_id": map[string]any{"before": result.VersionID.String(), "after": nil}},
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, request.TenantScopeID, operationUnbind, request.IdempotencyKey, request.SiteID, result, now)
	})
	if err != nil {
		return Binding{}, fmt.Errorf("unbind certificate asset: %w", err)
	}
	return result, nil
}

func (s *Store) delete(ctx context.Context, actor Actor, request DeleteRequest, digest [32]byte) (Asset, error) {
	var result Asset
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := storeTime(s.now())
		if err := authorizeActor(ctx, tx, actor, request.TenantScopeID, true); err != nil {
			return err
		}
		write, err := replayOrClaim(ctx, tx, actor, request.TenantScopeID, operationDelete, request.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if write.found {
			if err := decodeReplay(write.response, &result); err != nil {
				return err
			}
			if result.Tenant == nil {
				result.Tenant, err = loadAssetTenant(ctx, tx, request.TenantScopeID)
			}
			return err
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
		var referenced bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM (
				SELECT DISTINCT ON (site_id) site_id,action,asset_id
				FROM certificate_site_binding_facts
				WHERE tenant_scope_id=$1 ORDER BY site_id,sequence DESC
			) binding WHERE binding.action='bind' AND binding.asset_id=$2
		) OR EXISTS (
			SELECT 1
			FROM certificate_asset_versions AS version
			JOIN certificate_orders AS certificate_order
			  ON certificate_order.scope_id=version.tenant_scope_id
			 AND certificate_order.id=version.acme_order_id
			WHERE version.tenant_scope_id=$1 AND version.asset_id=$2
			  AND certificate_order.status IN ('issued','deploying','active','renewal_due')
		)`, request.TenantScopeID, request.AssetID).Scan(&referenced); err != nil {
			return err
		}
		if referenced {
			return ErrReferenced
		}
		command, err := tx.Exec(ctx, `UPDATE certificate_assets
				SET revision=revision+1,updated_by_scope_id=$3,updated_by_user_id=$4,updated_at=$5,
					deleted_at=$5,deleted_by_scope_id=$3,deleted_by_user_id=$4
				WHERE tenant_scope_id=$1 AND id=$2 AND revision=$6 AND deleted_at IS NULL`,
			request.TenantScopeID, request.AssetID, actor.ScopeID, actor.UserID, now, request.ExpectedRevision)
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
		if err := s.appendAudit(ctx, tx, actor, request.TenantScopeID, request.RequestID, operationDelete,
			"certificate_asset", request.AssetID, map[string]any{
				"asset_revision": result.Revision, "tombstone": true,
				"changes": map[string]any{"deleted": map[string]any{"before": false, "after": true}},
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, request.TenantScopeID, operationDelete, request.IdempotencyKey, request.AssetID, result, now)
	})
	if err != nil {
		return Asset{}, fmt.Errorf("delete certificate asset: %w", err)
	}
	return result, nil
}

func (s *Store) setAutoRenew(ctx context.Context, actor Actor, request SetAutoRenewRequest, digest [32]byte) (Asset, error) {
	var result Asset
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := storeTime(s.now())
		if err := authorizeActor(ctx, tx, actor, request.TenantScopeID, true); err != nil {
			return err
		}
		write, err := replayOrClaim(ctx, tx, actor, request.TenantScopeID, operationAutoRenew, request.IdempotencyKey, digest, now)
		if err != nil {
			return err
		}
		if write.found {
			if err := decodeReplay(write.response, &result); err != nil {
				return err
			}
			if result.Tenant == nil {
				result.Tenant, err = loadAssetTenant(ctx, tx, request.TenantScopeID)
			}
			return err
		}
		asset, err := loadAsset(ctx, tx, request.TenantScopeID, request.AssetID, true)
		if err != nil {
			return err
		}
		if asset.DeletedAt != nil {
			return ErrDeleted
		}
		if asset.Source != SourceACME {
			return ErrAutoRenewUnsupported
		}
		if asset.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		command, err := tx.Exec(ctx, `UPDATE certificate_assets
				SET auto_renew=$3,revision=revision+1,updated_by_scope_id=$4,updated_by_user_id=$5,updated_at=$6
				WHERE tenant_scope_id=$1 AND id=$2 AND revision=$7 AND deleted_at IS NULL`,
			request.TenantScopeID, request.AssetID, request.Enabled, actor.ScopeID, actor.UserID, now, request.ExpectedRevision)
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
		if err := s.appendAudit(ctx, tx, actor, request.TenantScopeID, request.RequestID, operationAutoRenew,
			"certificate_asset", request.AssetID, map[string]any{
				"asset_revision": result.Revision,
				"changes":        map[string]any{"auto_renew": map[string]any{"before": asset.AutoRenew, "after": result.AutoRenew}},
			}); err != nil {
			return err
		}
		return completeWrite(ctx, tx, actor, request.TenantScopeID, operationAutoRenew, request.IdempotencyKey, request.AssetID, result, now)
	})
	if err != nil {
		return Asset{}, fmt.Errorf("set certificate asset auto-renew: %w", err)
	}
	return result, nil
}

func (s *Store) Get(ctx context.Context, actor Actor, tenantScopeID, assetID uuid.UUID) (Asset, []Version, error) {
	if err := validateActor(actor, tenantScopeID); err != nil {
		return Asset{}, nil, err
	}
	if assetID == uuid.Nil {
		return Asset{}, nil, ErrInvalidInput
	}
	if err := authorizeActor(ctx, s.pool, actor, tenantScopeID, false); err != nil {
		return Asset{}, nil, err
	}
	asset, err := loadAsset(ctx, s.pool, tenantScopeID, assetID, false)
	if err != nil {
		return Asset{}, nil, err
	}
	if asset.DeletedAt != nil {
		return Asset{}, nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT id FROM certificate_asset_versions
		WHERE tenant_scope_id=$1 AND asset_id=$2 ORDER BY version`, tenantScopeID, assetID)
	if err != nil {
		return Asset{}, nil, fmt.Errorf("list certificate asset versions: %w", err)
	}
	defer rows.Close()
	ids := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return Asset{}, nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return Asset{}, nil, err
	}
	rows.Close()
	versions := make([]Version, 0, len(ids))
	now := storeTime(s.now())
	for _, id := range ids {
		version, err := loadVersion(ctx, s.pool, tenantScopeID, assetID, id, now)
		if err != nil {
			return Asset{}, nil, err
		}
		versions = append(versions, version)
	}
	return asset, versions, nil
}

func (s *Store) ListPage(ctx context.Context, actor Actor, request ListRequest) (ListResult, error) {
	allTenants := request.TenantScopeID == uuid.Nil && actor.ScopeKind == ScopePlatform
	if !allTenants {
		if err := validateActor(actor, request.TenantScopeID); err != nil {
			return ListResult{}, err
		}
	}
	search := strings.TrimSpace(request.Search)
	if request.Page < 1 || request.Limit < 1 || request.Limit > 100 ||
		int64(request.Page) > math.MaxInt64/int64(request.Limit) || search != request.Search ||
		!utf8.ValidString(search) || len(search) > 128 || strings.ContainsFunc(search, unicode.IsControl) ||
		request.Status != "" && !slices.Contains(ListStatuses, request.Status) || !validListFilters(request.Filters) {
		return ListResult{}, ErrInvalidInput
	}
	if allTenants {
		if err := authorizePlatformAssetList(ctx, s.pool, actor); err != nil {
			return ListResult{}, err
		}
	} else if err := authorizeActor(ctx, s.pool, actor, request.TenantScopeID, false); err != nil {
		return ListResult{}, err
	}
	where := "asset.tenant_scope_id=$1"
	arguments := []any{request.TenantScopeID}
	if allTenants {
		where = `EXISTS (SELECT 1 FROM access_scopes target_scope
			JOIN tenants target_tenant ON target_tenant.id=target_scope.tenant_id
			WHERE target_scope.id=asset.tenant_scope_id AND target_scope.kind='tenant'
			AND target_tenant.status='active')`
		arguments = nil
	}
	if !request.IncludeDeleted {
		where += " AND asset.deleted_at IS NULL"
	}
	if search != "" {
		arguments = append(arguments, search)
		where += fmt.Sprintf(` AND (
			strpos(lower(asset.name),lower($%[1]d))>0 OR strpos(asset.display_id::text,$%[1]d)>0 OR
			EXISTS (SELECT 1 FROM users owner WHERE owner.id=asset.owner_user_id AND
				(strpos(owner.display_id::text,$%[1]d)>0 OR strpos(lower(owner.username),lower($%[1]d))>0)) OR
			EXISTS (SELECT 1 FROM certificate_asset_versions version
				CROSS JOIN LATERAL unnest(version.sans) domain
				WHERE version.tenant_scope_id=asset.tenant_scope_id
				  AND version.asset_id=asset.id
				  AND strpos(lower(domain),lower($%[1]d))>0)
		)`, len(arguments))
	}
	// fact: the latest version's expiry class (as the list shows it: a
	// passed not_after is expired even when revoked; otherwise only an
	// active/default version is normal or expiring) and whether an
	// auto-renewing order issued the asset. Per asset these are index
	// lookups (versions by asset/version, latest activation, revocation and
	// order by issued asset), bounded by the scope's assets.
	arguments = append(arguments, storeTime(s.now()))
	nowPosition := len(arguments)
	where += listFilterSQL(request.Filters, &arguments, nowPosition)
	facts := fmt.Sprintf(` LEFT JOIN LATERAL (
		SELECT version.sans AS latest_sans, version.not_after AS latest_not_after, CASE
			WHEN version.not_after <= $%[1]d THEN 'expired'
			WHEN EXISTS (SELECT 1 FROM certificate_asset_revocation_facts revoked
				WHERE revoked.tenant_scope_id=version.tenant_scope_id AND revoked.asset_id=version.asset_id
				  AND revoked.version_id=version.id) THEN 'other'
			WHEN NOT (active.version_id IS NOT DISTINCT FROM version.id OR version.initial_status='default' AND
				NOT EXISTS (SELECT 1 FROM certificate_asset_activation_facts historical
					WHERE historical.tenant_scope_id=version.tenant_scope_id AND historical.asset_id=version.asset_id
					  AND historical.version_id=version.id)) THEN 'other'
			WHEN version.not_after - $%[1]d <= interval '30 days' THEN 'expiring'
			ELSE 'normal' END AS expiry
		FROM (SELECT * FROM certificate_asset_versions latest
			WHERE latest.tenant_scope_id=asset.tenant_scope_id AND latest.asset_id=asset.id
			ORDER BY latest.version DESC LIMIT 1) version
		LEFT JOIN LATERAL (SELECT activation.version_id FROM certificate_asset_activation_facts activation
			WHERE activation.tenant_scope_id=version.tenant_scope_id AND activation.asset_id=version.asset_id
			ORDER BY activation.sequence DESC LIMIT 1) active ON true
	) fact ON true
	CROSS JOIN LATERAL (SELECT asset.auto_renew) renew `, nowPosition)
	statusFilter := map[string]string{
		"": "true", "normal": "fact.expiry='normal'", "expiring": "fact.expiry='expiring'",
		"expired": "fact.expiry='expired'", "auto_renew": "renew.auto_renew", "manual_renew": "NOT renew.auto_renew",
	}[request.Status]
	var total int64
	var counts ListCounts
	if err := s.pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER (WHERE fact.expiry='normal'),
		count(*) FILTER (WHERE fact.expiry='expiring'),count(*) FILTER (WHERE fact.expiry='expired'),
		count(*) FILTER (WHERE renew.auto_renew),count(*) FILTER (WHERE NOT renew.auto_renew),
		count(*) FILTER (WHERE `+statusFilter+`)
		FROM certificate_assets asset`+facts+`WHERE `+where, arguments...).Scan(
		&counts.All, &counts.Normal, &counts.Expiring, &counts.Expired, &counts.AutoRenew, &counts.ManualRenew, &total,
	); err != nil {
		return ListResult{}, fmt.Errorf("count certificate assets: %w", err)
	}
	where += " AND " + statusFilter
	offset := (int64(request.Page) - 1) * int64(request.Limit)
	arguments = append(arguments, request.Limit, offset)
	query := `SELECT asset.id,asset.display_id::text,asset.tenant_scope_id,asset.name,asset.remark,asset.source,asset.auto_renew,asset.disabled,asset.revision,
		asset.created_by_user_id,creator.display_id::text,asset.updated_by_user_id,updater.display_id::text,
		asset.created_at,asset.updated_at,asset.deleted_at,
		CASE WHEN owner.id IS NULL THEN NULL ELSE jsonb_build_object('id',owner.id,
			'display_id',owner.display_id::text,'username',owner.username,'display_name',owner.display_name) END,
		CASE WHEN asset.owner_user_id IS NULL THEN 'legacy_unknown' ELSE 'recorded' END,
		jsonb_build_object('id',tenant.id,'display_id',tenant.display_id::text,'name',tenant.display_name)
		FROM certificate_assets asset` + facts + `
		JOIN access_scopes scope ON scope.id=asset.tenant_scope_id
		JOIN tenants tenant ON tenant.id=scope.tenant_id
		JOIN users creator ON creator.id=asset.created_by_user_id
		JOIN users updater ON updater.id=asset.updated_by_user_id
		LEFT JOIN users owner ON owner.id=asset.owner_user_id
		WHERE ` + where +
		fmt.Sprintf(" ORDER BY asset.created_at DESC,asset.id DESC LIMIT $%d OFFSET $%d", len(arguments)-1, len(arguments))
	rows, err := s.pool.Query(ctx, query, arguments...)
	if err != nil {
		return ListResult{}, fmt.Errorf("list certificate assets: %w", err)
	}
	defer rows.Close()
	result := make([]Asset, 0)
	for rows.Next() {
		var asset Asset
		if err := rows.Scan(&asset.ID, &asset.DisplayID, &asset.TenantScopeID, &asset.Name, &asset.Remark, &asset.Source,
			&asset.AutoRenew, &asset.Disabled, &asset.Revision, &asset.CreatedBy, &asset.CreatedByDisplayID, &asset.UpdatedBy,
			&asset.UpdatedByDisplayID, &asset.CreatedAt,
			&asset.UpdatedAt, &asset.DeletedAt, &asset.Owner, &asset.OwnerStatus, &asset.Tenant); err != nil {
			return ListResult{}, err
		}
		result = append(result, asset)
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, err
	}
	return ListResult{Items: result, Total: total, Counts: counts}, nil
}

func (s *Store) List(ctx context.Context, actor Actor, tenantScopeID uuid.UUID, includeDeleted bool) ([]Asset, error) {
	items := make([]Asset, 0)
	for page := 1; ; page++ {
		result, err := s.ListPage(ctx, actor, ListRequest{
			TenantScopeID: tenantScopeID, IncludeDeleted: includeDeleted, Page: page, Limit: 100,
		})
		if err != nil {
			return nil, err
		}
		items = append(items, result.Items...)
		if int64(len(items)) >= result.Total || len(result.Items) == 0 {
			return items, nil
		}
	}
}

func (s *Store) GetSiteBinding(
	ctx context.Context,
	actor Actor,
	tenantScopeID, siteID uuid.UUID,
) (Binding, Version, error) {
	if err := validateActor(actor, tenantScopeID); err != nil {
		return Binding{}, Version{}, err
	}
	if siteID == uuid.Nil {
		return Binding{}, Version{}, ErrInvalidInput
	}
	if err := authorizeActor(ctx, s.pool, actor, tenantScopeID, false); err != nil {
		return Binding{}, Version{}, err
	}
	binding, found, err := loadLatestBinding(ctx, s.pool, tenantScopeID, siteID)
	if err != nil {
		return Binding{}, Version{}, err
	}
	if !found || !binding.Bound {
		return Binding{}, Version{}, ErrNotFound
	}
	version, err := loadVersion(ctx, s.pool, tenantScopeID, binding.AssetID, binding.VersionID, storeTime(s.now()))
	if err != nil {
		return Binding{}, Version{}, err
	}
	return binding, version, nil
}

func (s *Store) ListBindings(ctx context.Context, actor Actor, tenantScopeID, assetID uuid.UUID) ([]Binding, error) {
	if err := validateActor(actor, tenantScopeID); err != nil {
		return nil, err
	}
	if assetID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	if err := authorizeActor(ctx, s.pool, actor, tenantScopeID, false); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT site_id,sequence,action,asset_id,version_id,is_default,
		changed_by_user_id,changed_at FROM (
			SELECT DISTINCT ON (site_id) site_id,sequence,action,asset_id,version_id,is_default,
				changed_by_user_id,changed_at
			FROM certificate_site_binding_facts WHERE tenant_scope_id=$1
			ORDER BY site_id,sequence DESC
		) current_binding WHERE asset_id=$2 ORDER BY site_id`, tenantScopeID, assetID)
	if err != nil {
		return nil, fmt.Errorf("list certificate asset bindings: %w", err)
	}
	defer rows.Close()
	result := make([]Binding, 0)
	for rows.Next() {
		var action string
		binding := Binding{TenantScopeID: tenantScopeID}
		if err := rows.Scan(&binding.SiteID, &binding.Revision, &action, &binding.AssetID,
			&binding.VersionID, &binding.Default, &binding.ChangedBy, &binding.ChangedAt); err != nil {
			return nil, err
		}
		binding.Bound = action == "bind"
		result = append(result, binding)
	}
	return result, rows.Err()
}

func (s *Store) ListRenewalDue(ctx context.Context, actor Actor, tenantScopeID uuid.UUID, asOf time.Time) ([]Version, error) {
	if err := validateActor(actor, tenantScopeID); err != nil {
		return nil, err
	}
	if asOf.IsZero() {
		return nil, ErrInvalidInput
	}
	if err := authorizeActor(ctx, s.pool, actor, tenantScopeID, false); err != nil {
		return nil, err
	}
	asOf = storeTime(asOf)
	rows, err := s.pool.Query(ctx, `SELECT v.asset_id,v.id
		FROM certificate_asset_versions v
		JOIN certificate_assets a ON a.tenant_scope_id=v.tenant_scope_id AND a.id=v.asset_id
		JOIN certificate_orders o ON o.scope_id=v.tenant_scope_id AND o.id=v.acme_order_id
		WHERE v.tenant_scope_id=$1 AND v.renewal_due_at <= $2 AND v.not_after > $2
		  AND a.deleted_at IS NULL AND a.auto_renew
		  AND o.status IN ('issued','deploying','active','renewal_due')
		ORDER BY v.renewal_due_at,v.asset_id,v.id`, tenantScopeID, asOf)
	if err != nil {
		return nil, fmt.Errorf("list renewal due certificate assets: %w", err)
	}
	defer rows.Close()
	type key struct{ assetID, versionID uuid.UUID }
	keys := make([]key, 0)
	for rows.Next() {
		var item key
		if err := rows.Scan(&item.assetID, &item.versionID); err != nil {
			return nil, err
		}
		keys = append(keys, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	result := make([]Version, 0, len(keys))
	for _, item := range keys {
		version, err := loadVersion(ctx, s.pool, tenantScopeID, item.assetID, item.versionID, asOf)
		if err != nil {
			return nil, err
		}
		if version.Status == StatusDefault || version.Status == StatusActive {
			result = append(result, version)
		}
	}
	return result, nil
}

func validateImportOwner(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, ownerUserID *uuid.UUID) error {
	if ownerUserID == nil {
		return nil
	}
	var active bool
	err := tx.QueryRow(ctx, `SELECT membership.status='active' AND account.status='active'
		FROM memberships membership JOIN users account ON account.id=membership.user_id
		WHERE membership.scope_id=$1 AND membership.user_id=$2 FOR SHARE OF membership,account`,
		scopeID, *ownerUserID).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !active {
		return ErrPermissionDenied
	}
	return err
}

func authorizePlatformAssetList(ctx context.Context, query querier, actor Actor) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != ScopePlatform {
		return ErrPermissionDenied
	}
	var allowed bool
	err := query.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM access_scopes actor_scope
		JOIN memberships membership ON membership.scope_id=actor_scope.id AND membership.user_id=$2
		JOIN users account ON account.id=membership.user_id
		JOIN role_assignments assignment ON assignment.scope_id=actor_scope.id AND assignment.user_id=account.id
		JOIN roles role ON role.scope_id=assignment.scope_id AND role.id=assignment.role_id
		JOIN role_permissions permission ON permission.role_id=role.id
		WHERE actor_scope.id=$1 AND actor_scope.kind='platform' AND actor_scope.tenant_id IS NULL
		AND membership.status='active' AND account.status='active' AND permission.permission_name IN ('certificates.read','platform.admin')
	)`, actor.ScopeID, actor.UserID).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

func authorizeActor(ctx context.Context, query querier, actor Actor, tenantScopeID uuid.UUID, manage bool) error {
	permission := "certificates.read"
	if manage {
		permission = "certificates.manage"
	}
	if tx, ok := query.(pgx.Tx); ok {
		return authorizeActorInTx(ctx, tx, actor, tenantScopeID, permission, true)
	}
	return authorizeActorRead(ctx, query, actor, tenantScopeID, permission)
}

func authorizeActorRead(
	ctx context.Context,
	query querier,
	actor Actor,
	tenantScopeID uuid.UUID,
	permission string,
) error {
	var allowed bool
	err := query.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1
		FROM access_scopes target_scope
		JOIN tenants target_tenant ON target_tenant.id=target_scope.tenant_id
		JOIN access_scopes actor_scope ON actor_scope.id=$2
		JOIN memberships membership ON membership.scope_id=actor_scope.id AND membership.user_id=$3
		JOIN users account ON account.id=membership.user_id
		JOIN role_assignments assignment ON assignment.scope_id=actor_scope.id AND assignment.user_id=membership.user_id
		JOIN roles role ON role.scope_id=assignment.scope_id AND role.id=assignment.role_id
		JOIN role_permissions permission ON permission.role_id=role.id
		WHERE target_scope.id=$1 AND target_scope.kind='tenant' AND target_tenant.status='active'
		  AND actor_scope.kind=$4 AND actor_scope.kind IN ('tenant','platform')
		  AND (actor_scope.kind='platform' OR actor_scope.id=target_scope.id)
		  AND membership.status='active' AND account.status='active'
		  AND (permission.permission_name=$5 OR
		       actor_scope.kind='platform' AND permission.permission_name='platform.admin')
	)`, tenantScopeID, actor.ScopeID, actor.UserID, actor.ScopeKind, permission).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

func authorizeActorInTx(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	tenantScopeID uuid.UUID,
	permission string,
	acquireIAMProtocol bool,
) error {
	lockedScopes := []uuid.UUID{actor.ScopeID}
	if tenantScopeID != actor.ScopeID {
		lockedScopes = append(lockedScopes, tenantScopeID)
		if bytes.Compare(lockedScopes[0][:], lockedScopes[1][:]) > 0 {
			lockedScopes[0], lockedScopes[1] = lockedScopes[1], lockedScopes[0]
		}
	}
	if acquireIAMProtocol {
		if err := iamlock.AcquireShared(ctx, tx); err != nil {
			return err
		}
		var err error
		lockedScopes, err = iamlock.AcquireScopes(ctx, tx, lockedScopes)
		if err != nil {
			return err
		}
	}

	type scopeFact struct {
		kind     string
		tenantID *uuid.UUID
	}
	scopes := make(map[uuid.UUID]scopeFact, len(lockedScopes))
	rows, err := tx.Query(ctx, `SELECT id,kind,tenant_id FROM access_scopes
		WHERE id=ANY($1::uuid[]) ORDER BY id FOR KEY SHARE`, lockedScopes)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id uuid.UUID
		var fact scopeFact
		if err := rows.Scan(&id, &fact.kind, &fact.tenantID); err != nil {
			rows.Close()
			return err
		}
		scopes[id] = fact
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return rowErr
	}
	if len(scopes) != len(lockedScopes) {
		return ErrPermissionDenied
	}
	target, targetExists := scopes[tenantScopeID]
	authentication, actorExists := scopes[actor.ScopeID]
	if !targetExists || target.kind != ScopeTenant || target.tenantID == nil ||
		!actorExists || authentication.kind != actor.ScopeKind ||
		actor.ScopeKind != ScopeTenant && actor.ScopeKind != ScopePlatform ||
		actor.ScopeKind == ScopeTenant && actor.ScopeID != tenantScopeID ||
		actor.ScopeKind == ScopePlatform && authentication.tenantID != nil {
		return ErrPermissionDenied
	}

	var tenantStatus string
	err = tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1 FOR SHARE`, *target.tenantID).Scan(&tenantStatus)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && tenantStatus != "active" {
		return ErrPermissionDenied
	}
	if err != nil {
		return err
	}

	var membershipStatus string
	err = tx.QueryRow(ctx, `SELECT status FROM memberships
		WHERE scope_id=$1 AND user_id=$2 FOR SHARE`, actor.ScopeID, actor.UserID).Scan(&membershipStatus)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && membershipStatus != "active" {
		return ErrPermissionDenied
	}
	if err != nil {
		return err
	}
	var accountStatus string
	err = tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR SHARE`, actor.UserID).Scan(&accountStatus)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && accountStatus != "active" {
		return ErrPermissionDenied
	}
	if err != nil {
		return err
	}

	assignmentRows, err := tx.Query(ctx, `SELECT role_id FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 ORDER BY role_id FOR SHARE`, actor.ScopeID, actor.UserID)
	if err != nil {
		return err
	}
	roleIDs := make([]uuid.UUID, 0, 4)
	for assignmentRows.Next() {
		var roleID uuid.UUID
		if err := assignmentRows.Scan(&roleID); err != nil {
			assignmentRows.Close()
			return err
		}
		roleIDs = append(roleIDs, roleID)
	}
	rowErr = assignmentRows.Err()
	assignmentRows.Close()
	if rowErr != nil {
		return rowErr
	}
	if len(roleIDs) == 0 {
		return ErrPermissionDenied
	}

	roleRows, err := tx.Query(ctx, `SELECT id FROM roles
		WHERE scope_id=$1 AND id=ANY($2::uuid[]) ORDER BY id FOR SHARE`, actor.ScopeID, roleIDs)
	if err != nil {
		return err
	}
	roleCount := 0
	for roleRows.Next() {
		roleCount++
	}
	rowErr = roleRows.Err()
	roleRows.Close()
	if rowErr != nil {
		return rowErr
	}
	if roleCount != len(roleIDs) {
		return ErrPermissionDenied
	}

	var lockedPermission string
	err = tx.QueryRow(ctx, `SELECT name FROM permissions WHERE name=$1 FOR SHARE`, permission).Scan(&lockedPermission)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPermissionDenied
	}
	if err != nil {
		return err
	}

	// A platform administrator may act on any tenant's certificates.
	granted := []string{lockedPermission}
	if actor.ScopeKind == ScopePlatform {
		granted = append(granted, tenantaccess.PlatformAdminPermission)
	}
	permissionRows, err := tx.Query(ctx, `SELECT role_id,permission_name FROM role_permissions
		WHERE role_id=ANY($1::uuid[]) AND permission_name=ANY($2::text[])
		ORDER BY role_id,permission_name FOR SHARE`, roleIDs, granted)
	if err != nil {
		return err
	}
	allowed := false
	for permissionRows.Next() {
		var roleID uuid.UUID
		var grantedName string
		if err := permissionRows.Scan(&roleID, &grantedName); err != nil {
			permissionRows.Close()
			return err
		}
		if grantedName == permission || grantedName == tenantaccess.PlatformAdminPermission {
			allowed = true
		}
	}
	rowErr = permissionRows.Err()
	permissionRows.Close()
	if rowErr != nil {
		return rowErr
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

func loadAsset(ctx context.Context, query querier, scopeID, assetID uuid.UUID, lock bool) (Asset, error) {
	sql := `SELECT asset.id,asset.display_id::text,asset.tenant_scope_id,asset.name,asset.remark,asset.source,asset.auto_renew,asset.disabled,asset.revision,
		asset.created_by_user_id,creator.display_id::text,asset.updated_by_user_id,updater.display_id::text,
		asset.created_at,asset.updated_at,asset.deleted_at,
		CASE WHEN owner.id IS NULL THEN NULL ELSE jsonb_build_object('id',owner.id,
			'display_id',owner.display_id::text,'username',owner.username,'display_name',owner.display_name) END,
		CASE WHEN asset.owner_user_id IS NULL THEN 'legacy_unknown' ELSE 'recorded' END,
		jsonb_build_object('id',tenant.id,'display_id',tenant.display_id::text,'name',tenant.display_name)
		FROM certificate_assets asset
		JOIN access_scopes scope ON scope.id=asset.tenant_scope_id
		JOIN tenants tenant ON tenant.id=scope.tenant_id
		JOIN users creator ON creator.id=asset.created_by_user_id
		JOIN users updater ON updater.id=asset.updated_by_user_id
		LEFT JOIN users owner ON owner.id=asset.owner_user_id
		WHERE asset.tenant_scope_id=$1 AND asset.id=$2`
	if lock {
		sql += " FOR UPDATE OF asset"
	}
	var asset Asset
	err := query.QueryRow(ctx, sql, scopeID, assetID).Scan(&asset.ID, &asset.DisplayID, &asset.TenantScopeID, &asset.Name,
		&asset.Remark, &asset.Source, &asset.AutoRenew, &asset.Disabled, &asset.Revision, &asset.CreatedBy, &asset.CreatedByDisplayID, &asset.UpdatedBy,
		&asset.UpdatedByDisplayID, &asset.CreatedAt,
		&asset.UpdatedAt, &asset.DeletedAt, &asset.Owner, &asset.OwnerStatus, &asset.Tenant)
	if errors.Is(err, pgx.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	if err != nil {
		return Asset{}, err
	}
	return asset, nil
}

func loadAssetTenant(ctx context.Context, query querier, scopeID uuid.UUID) (*AssetTenant, error) {
	var tenant AssetTenant
	err := query.QueryRow(ctx, `SELECT tenant.id,tenant.display_id::text,tenant.display_name
		FROM access_scopes scope JOIN tenants tenant ON tenant.id=scope.tenant_id
		WHERE scope.id=$1 AND scope.kind='tenant'`, scopeID).Scan(&tenant.ID, &tenant.DisplayID, &tenant.Name)
	if err != nil {
		return nil, err
	}
	return &tenant, nil
}

func loadVersion(ctx context.Context, query querier, scopeID, assetID, versionID uuid.UUID, asOf time.Time) (Version, error) {
	var version Version
	var fingerprint []byte
	err := query.QueryRow(ctx, `WITH latest_activation AS (
		SELECT version_id FROM certificate_asset_activation_facts
		WHERE tenant_scope_id=$1 AND asset_id=$2 ORDER BY sequence DESC LIMIT 1
	)
	SELECT v.id,v.asset_id,v.tenant_scope_id,v.version,
		CASE
			WHEN revoked.version_id IS NOT NULL THEN 'revoked'
			WHEN v.not_after <= $4 THEN 'expired'
			WHEN active.version_id=v.id THEN 'active'
			WHEN EXISTS (SELECT 1 FROM certificate_asset_activation_facts historical
				WHERE historical.tenant_scope_id=v.tenant_scope_id
				  AND historical.asset_id=v.asset_id AND historical.version_id=v.id) THEN 'superseded'
			ELSE v.initial_status
		END,
		v.fingerprint_sha256,v.certificate_pem,v.sans,v.leaf_subject,v.serial_number,
		v.public_key_algorithm,v.public_key_bits,v.signature_algorithm,v.not_before,v.not_after,
		v.acme_order_id,v.renewal_due_at,
		(certificate_asset_auto_renew_537(v.tenant_scope_id,v.asset_id) AND v.renewal_due_at <= $4
			AND v.not_after > $4 AND revoked.version_id IS NULL),
		v.imported_by_user_id,v.imported_at
	FROM certificate_asset_versions v
	LEFT JOIN latest_activation active ON true
	LEFT JOIN certificate_asset_revocation_facts revoked
		ON revoked.tenant_scope_id=v.tenant_scope_id AND revoked.asset_id=v.asset_id AND revoked.version_id=v.id
	WHERE v.tenant_scope_id=$1 AND v.asset_id=$2 AND v.id=$3`, scopeID, assetID, versionID, asOf).Scan(
		&version.ID, &version.AssetID, &version.TenantScopeID, &version.Version, &version.Status,
		&fingerprint, &version.CertificatePEM, &version.SANs, &version.Subject, &version.SerialNumber,
		&version.PublicKeyAlgorithm, &version.PublicKeyBits, &version.SignatureAlgorithm,
		&version.NotBefore, &version.NotAfter, &version.ACMEOrderID, &version.RenewalDueAt,
		&version.RenewalDue, &version.ImportedBy, &version.ImportedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, ErrNotFound
	}
	if err != nil {
		return Version{}, err
	}
	version.FingerprintSHA256 = hex.EncodeToString(fingerprint)
	if version.Status != StatusDefault && version.Status != StatusActive {
		version.RenewalDue = false
	}
	return version, nil
}

func loadByFingerprint(ctx context.Context, query querier, scopeID uuid.UUID, fingerprint [32]byte, asOf time.Time) (ImportResult, bool, error) {
	var assetID, versionID uuid.UUID
	err := query.QueryRow(ctx, `SELECT asset_id,id FROM certificate_asset_versions
		WHERE tenant_scope_id=$1 AND fingerprint_sha256=$2`, scopeID, fingerprint[:]).Scan(&assetID, &versionID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ImportResult{}, false, nil
	}
	if err != nil {
		return ImportResult{}, false, err
	}
	asset, err := loadAsset(ctx, query, scopeID, assetID, false)
	if err != nil {
		return ImportResult{}, false, err
	}
	version, err := loadVersion(ctx, query, scopeID, assetID, versionID, asOf)
	if err != nil {
		return ImportResult{}, false, err
	}
	return ImportResult{Asset: asset, Version: version}, true, nil
}

func loadLatestBinding(ctx context.Context, query querier, scopeID, siteID uuid.UUID) (Binding, bool, error) {
	var action string
	binding := Binding{TenantScopeID: scopeID, SiteID: siteID}
	err := query.QueryRow(ctx, `SELECT sequence,action,asset_id,version_id,is_default,changed_by_user_id,changed_at
		FROM certificate_site_binding_facts WHERE tenant_scope_id=$1 AND site_id=$2
		ORDER BY sequence DESC LIMIT 1`, scopeID, siteID).Scan(&binding.Revision, &action,
		&binding.AssetID, &binding.VersionID, &binding.Default, &binding.ChangedBy, &binding.ChangedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, false, nil
	}
	if err != nil {
		return Binding{}, false, err
	}
	binding.Bound = action == "bind"
	return binding, true, nil
}

func validateACMEOrder(ctx context.Context, query querier, scopeID, orderID uuid.UUID, prepared preparedCertificate) error {
	var domains []string
	var status string
	var notAfter *time.Time
	err := query.QueryRow(ctx, `SELECT domains,status,not_after FROM certificate_orders
		WHERE scope_id=$1 AND id=$2 FOR SHARE`, scopeID, orderID).Scan(&domains, &status, &notAfter)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrACMEOrderMismatch
	}
	if err != nil {
		return err
	}
	if status != "issued" && status != "deploying" && status != "active" && status != "renewal_due" {
		return ErrACMEOrderMismatch
	}
	if err := RequireCoverage(prepared.SANs, domains); err != nil || notAfter == nil ||
		!notAfter.UTC().Truncate(time.Second).Equal(prepared.NotAfter.UTC().Truncate(time.Second)) {
		return ErrACMEOrderMismatch
	}
	return nil
}

func validateIssuingACMEOrder(
	ctx context.Context,
	query querier,
	scopeID, orderID uuid.UUID,
	prepared preparedCertificate,
) error {
	var domains []string
	var status string
	err := query.QueryRow(ctx, `SELECT domains,status FROM certificate_orders
		WHERE scope_id=$1 AND id=$2 FOR UPDATE`, scopeID, orderID).Scan(&domains, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrACMEOrderMismatch
	}
	if err != nil {
		return err
	}
	if status != "issuing" {
		return ErrACMEOrderMismatch
	}
	if err := RequireCoverage(prepared.SANs, domains); err != nil {
		return ErrACMEOrderMismatch
	}
	return nil
}

func replayOrClaim(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	tenantScopeID uuid.UUID,
	operation, key string,
	digest [32]byte,
	now time.Time,
) (storedWrite, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return storedWrite{}, err
	}
	command, err := tx.Exec(ctx, `INSERT INTO certificate_asset_write_requests (
		id,tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key,request_digest,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8)
	ON CONFLICT (tenant_scope_id,actor_scope_id,actor_user_id,operation,idempotency_key) DO NOTHING`,
		id, tenantScopeID, actor.ScopeID, actor.UserID, operation, key, digest[:], now)
	if err != nil {
		return storedWrite{}, err
	}
	if command.RowsAffected() == 1 {
		return storedWrite{}, nil
	}
	var storedDigest []byte
	var response string
	err = tx.QueryRow(ctx, `SELECT request_digest,COALESCE(response_body::text,'')
		FROM certificate_asset_write_requests
		WHERE tenant_scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND operation=$4 AND idempotency_key=$5
		FOR UPDATE`, tenantScopeID, actor.ScopeID, actor.UserID, operation, key).Scan(&storedDigest, &response)
	if err != nil {
		return storedWrite{}, err
	}
	if !bytes.Equal(storedDigest, digest[:]) {
		return storedWrite{}, ErrIdempotencyConflict
	}
	if len(response) == 0 {
		return storedWrite{}, ErrRevisionConflict
	}
	return storedWrite{response: []byte(response), found: true}, nil
}

func completeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	tenantScopeID uuid.UUID,
	operation, key string,
	resourceID uuid.UUID,
	response any,
	now time.Time,
) error {
	encoded, err := json.Marshal(response)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE certificate_asset_write_requests
		SET resource_id=$6,response_body=$7,completed_at=$8
		WHERE tenant_scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND operation=$4 AND idempotency_key=$5
		  AND completed_at IS NULL`, tenantScopeID, actor.ScopeID, actor.UserID, operation, key, resourceID, encoded, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrRevisionConflict
	}
	return nil
}

func decodeReplay(raw []byte, target any) error {
	if err := json.Unmarshal(raw, target); err != nil {
		return err
	}
	switch value := target.(type) {
	case *ImportResult:
		value.Replayed = true
		if value.Asset.OwnerStatus == "" && value.Asset.Owner == nil {
			value.Asset.OwnerStatus = "legacy_unknown"
		}
	case *Asset:
		if value.OwnerStatus == "" && value.Owner == nil {
			value.OwnerStatus = "legacy_unknown"
		}
	}
	return nil
}

func sameOptionalUUID(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (s *Store) appendAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	tenantScopeID uuid.UUID,
	requestID, action, resourceType string,
	resourceID uuid.UUID,
	payload map[string]any,
) error {
	actorID := actor.UserID
	payload["actor_scope_id"] = actor.ScopeID.String()
	payload["target_scope_id"] = tenantScopeID.String()
	payload["operation"] = action
	if reason, ok := payload["reason"].(string); !ok || strings.TrimSpace(reason) == "" {
		payload["reason"] = "requested"
	}
	if ip := audit.SourceIPFrom(ctx); ip != "" {
		payload["ip"] = ip
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: tenantScopeID, ActorUserID: &actorID, Action: action,
		ResourceType: resourceType, ResourceID: resourceID.String(), RequestID: requestID,
		Result: "success", Payload: payload,
	})
}
