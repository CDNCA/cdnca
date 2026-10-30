package originauthcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const maximumPublicationRules = 10_000

func (service *Service) CreatePublication(
	ctx context.Context,
	actor Actor,
	request CreatePublicationRequest,
) (PublicationWriteResult, error) {
	if err := validateTarget(actor, request.TargetScopeID); err != nil {
		return PublicationWriteResult{}, err
	}
	if request.ExpectedRevision < 0 || request.ExpectedRevision > maxSafeRevision ||
		!validWriteMetadata(request.WriteMetadata) {
		return PublicationWriteResult{}, ErrInvalidInput
	}
	digest, err := digestRequest(struct {
		TargetScopeID    uuid.UUID `json:"target_scope_id"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{request.TargetScopeID, request.ExpectedRevision})
	if err != nil {
		return PublicationWriteResult{}, ErrUnavailable
	}
	publicationID := uuid.Must(uuid.NewV7())
	var result PublicationWriteResult
	err = pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		tenantID, err := service.authorizeTarget(ctx, tx, actor, request.TargetScopeID, PermissionManage)
		if err != nil {
			return err
		}
		write, err := service.claimWrite(ctx, tx, actor, request.TargetScopeID,
			"origin_auth.publication.create", request.WriteMetadata, digest)
		if err != nil {
			return err
		}
		if write.found {
			if err := json.Unmarshal(write.responseBody, &result.Publication); err != nil {
				return ErrUnavailable
			}
			result.Replayed = true
			return nil
		}
		if err := service.checkEntitlement(ctx, tx, actor, request.TargetScopeID, publicationID,
			request.WriteMetadata, "origin_auth.publication.create"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(
			hashtextextended('origin-auth-publication:' || $1::text,0))`, request.TargetScopeID); err != nil {
			return err
		}
		var previousRevision int64
		var previousHash []byte
		err = tx.QueryRow(ctx, `SELECT revision,snapshot_sha256 FROM origin_auth_publications
			WHERE tenant_scope_id=$1 ORDER BY revision DESC LIMIT 1`, request.TargetScopeID).Scan(
			&previousRevision, &previousHash)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if request.ExpectedRevision != previousRevision {
			return ErrRevisionConflict
		}
		nextRevision := previousRevision + 1
		snapshot, canonical, err := buildPublicationSnapshot(ctx, tx, request.TargetScopeID, nextRevision)
		if err != nil {
			return err
		}
		hash := sha256.Sum256(canonical)
		now := storeTime(service.now())
		result.Publication = Publication{
			ID: publicationID, TenantScopeID: request.TargetScopeID, Revision: nextRevision,
			SnapshotHash: hex.EncodeToString(hash[:]), PreviousHash: hex.EncodeToString(previousHash),
			Snapshot: snapshot, CreatedAt: now,
		}
		if err := service.appendAudit(ctx, tx, actor, request.TargetScopeID, publicationID,
			request.WriteMetadata, "origin_auth.publication.create", "origin_auth_publication", map[string]any{
				"revision": nextRevision, "rule_count": len(snapshot.Rules),
			}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO origin_auth_publications(
			id,tenant_scope_id,tenant_id,revision,schema_version,canonical_snapshot,snapshot_sha256,
			previous_sha256,created_by_scope_id,created_by_user_id,request_id,trace_id,created_at)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, publicationID,
			request.TargetScopeID, tenantID, nextRevision, publicationSchema, canonical, hash[:],
			nullableDigest(previousHash), actor.ScopeID, actor.UserID, request.RequestID,
			request.TraceID, now); err != nil {
			return err
		}
		if service.published != nil {
			if err := service.published(ctx, tx, request.TargetScopeID); err != nil {
				return err
			}
		}
		return service.completeWrite(ctx, tx, actor, "origin_auth.publication.create",
			request.IdempotencyKey, publicationID, 201, result.Publication)
	})
	if err != nil {
		return PublicationWriteResult{}, normalizeServiceError(err)
	}
	return result, nil
}

func (service *Service) GetLatestPublication(
	ctx context.Context,
	actor Actor,
	targetScopeID uuid.UUID,
) (Publication, error) {
	if err := validateTarget(actor, targetScopeID); err != nil {
		return Publication{}, ErrInvalidInput
	}
	var publication Publication
	var canonical, hash, previousHash []byte
	err := service.authorizedRead(ctx, actor, targetScopeID, PermissionRead, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT id,tenant_scope_id,revision,canonical_snapshot,
			snapshot_sha256,previous_sha256,created_at FROM origin_auth_publications
			WHERE tenant_scope_id=$1 ORDER BY revision DESC LIMIT 1`, targetScopeID).Scan(
			&publication.ID, &publication.TenantScopeID, &publication.Revision, &canonical,
			&hash, &previousHash, &publication.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	if err != nil {
		return Publication{}, normalizeServiceError(err)
	}
	actual := sha256.Sum256(canonical)
	if len(hash) != sha256.Size || !equalBytes(hash, actual[:]) ||
		json.Unmarshal(canonical, &publication.Snapshot) != nil {
		return Publication{}, ErrUnavailable
	}
	publication.SnapshotHash = hex.EncodeToString(hash)
	publication.PreviousHash = hex.EncodeToString(previousHash)
	return publication, nil
}

func buildPublicationSnapshot(
	ctx context.Context,
	tx pgx.Tx,
	targetScopeID uuid.UUID,
	revision int64,
) (PublicationSnapshot, []byte, error) {
	rows, err := tx.Query(ctx, `SELECT identity.id,identity.site_id,identity.source_position,
		current.provider,current.algorithm,current.endpoint,current.bucket,current.path_prefix,
		current.region,current.service,current.signature_ttl_seconds,
		current.current_credential_revision_ref,current.previous_credential_revision_ref,
		current.activate_current_at
		FROM origin_auth_rules identity
		JOIN LATERAL (SELECT * FROM origin_auth_rule_revisions rule_revision
			WHERE rule_revision.rule_id=identity.id ORDER BY rule_revision.revision DESC LIMIT 1) current ON true
		WHERE identity.tenant_scope_id=$1 AND current.enabled AND NOT current.deleted
		ORDER BY identity.site_id,identity.source_position,identity.id
		LIMIT $2`, targetScopeID, maximumPublicationRules+1)
	if err != nil {
		return PublicationSnapshot{}, nil, err
	}
	defer rows.Close()
	rules := make([]PublicationRule, 0)
	for rows.Next() {
		if len(rules) == maximumPublicationRules {
			return PublicationSnapshot{}, nil, ErrValidation
		}
		var rule PublicationRule
		var activateAt *time.Time
		if err := rows.Scan(&rule.RuleID, &rule.SiteID, &rule.SourcePosition, &rule.Provider,
			&rule.Algorithm, &rule.Endpoint, &rule.Bucket, &rule.PathPrefix, &rule.Region,
			&rule.Service, &rule.SignatureTTLSeconds, &rule.CurrentCredentialRevisionRef,
			&rule.PreviousCredentialRevisionRef, &activateAt); err != nil {
			return PublicationSnapshot{}, nil, err
		}
		if activateAt != nil {
			rule.ActivateCurrentAtUnix = activateAt.UTC().Unix()
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return PublicationSnapshot{}, nil, err
	}
	snapshot := PublicationSnapshot{
		SchemaVersion: publicationSchema, TenantScopeID: targetScopeID,
		PublicationRevision: revision, Rules: rules,
	}
	canonical, err := encodeJSON(snapshot)
	if err != nil {
		return PublicationSnapshot{}, nil, err
	}
	if len(canonical) > maximumJSONBytes {
		return PublicationSnapshot{}, nil, ErrValidation
	}
	return snapshot, canonical, nil
}

func nullableDigest(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
