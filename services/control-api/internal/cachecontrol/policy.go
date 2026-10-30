package cachecontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/sitelock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (store *Store) PublishPolicy(
	ctx context.Context,
	actor Actor,
	request PublishPolicyRequest,
) (PolicyWriteResult, error) {
	if ctx == nil || !validActor(actor) || request.SiteID == uuid.Nil || request.ExpectedRevision < 0 ||
		!validWriteMetadata(request.IdempotencyKey, request.RequestID) {
		return PolicyWriteResult{}, ErrInvalidInput
	}
	bindingMode := request.BindingMode
	if bindingMode == "" {
		bindingMode = BindingOverride
	}
	definitionID := request.DefinitionID
	var document PolicyDocument
	switch bindingMode {
	case BindingInherit:
		if definitionID == uuid.Nil || request.DefinitionRevision < 1 ||
			request.ExpectedDefinitionRevision != nil || !emptyPolicyDocument(request.Document) {
			return PolicyWriteResult{}, ErrInvalidInput
		}
	case BindingOverride:
		if request.DefinitionRevision != 0 ||
			(request.ExpectedDefinitionRevision != nil && *request.ExpectedDefinitionRevision < 0) {
			return PolicyWriteResult{}, ErrInvalidInput
		}
		if definitionID == uuid.Nil {
			definitionID = request.SiteID
		} else if definitionID != request.SiteID && request.ExpectedDefinitionRevision == nil {
			return PolicyWriteResult{}, ErrInvalidInput
		}
		var err error
		document, err = normalizePolicy(request.Document)
		if err != nil {
			return PolicyWriteResult{}, err
		}
	default:
		return PolicyWriteResult{}, ErrInvalidInput
	}
	digest, err := digestJSON(struct {
		SiteID                     uuid.UUID      `json:"site_id"`
		ExpectedRevision           int64          `json:"expected_revision"`
		BindingMode                BindingMode    `json:"binding_mode"`
		DefinitionID               uuid.UUID      `json:"definition_id"`
		DefinitionRevision         int64          `json:"definition_revision"`
		ExpectedDefinitionRevision *int64         `json:"expected_definition_revision,omitempty"`
		Document                   PolicyDocument `json:"document"`
	}{request.SiteID, request.ExpectedRevision, bindingMode, definitionID, request.DefinitionRevision,
		request.ExpectedDefinitionRevision, document})
	if err != nil {
		return PolicyWriteResult{}, err
	}
	now := store.timestamp()
	var result PolicyWriteResult
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		tenantID, err := store.authorizeActor(ctx, tx, actor, "sites.manage")
		if err != nil {
			return err
		}
		site, err := loadSiteDescriptor(ctx, tx, actor.ScopeID, request.SiteID, true)
		if err != nil {
			return err
		}
		if site.TenantID != tenantID {
			return ErrPermissionDenied
		}
		if err := sitelock.RequireUnlocked(ctx, tx, actor.ActorScopeID, request.SiteID); errors.Is(err, sitelock.ErrLocked) {
			return ErrSiteLocked
		} else if err != nil {
			return err
		}
		if err := store.checkSiteEntitlement(
			ctx, tx, actor, request.SiteID, request.RequestID, "cache.policy.publish",
		); err != nil {
			return err
		}

		write, found, err := lockPolicyWrite(ctx, tx, actor, request.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if write.actorUserID != actor.UserID || !bytes.Equal(write.digest, digest[:]) {
				return ErrIdempotencyConflict
			}
			if write.revision == nil {
				return fmt.Errorf("incomplete cache policy write request")
			}
			result.Policy, err = loadPolicyRevision(ctx, tx, actor.ScopeID, request.SiteID, *write.revision)
			result.Replayed = err == nil
			return err
		}
		command, err := tx.Exec(ctx, `
			INSERT INTO cache_policy_write_requests (
				id,scope_id,actor_scope_id,actor_user_id,site_id,idempotency_key,request_digest,created_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (scope_id,actor_scope_id,actor_user_id,idempotency_key) DO NOTHING`,
			uuid.New(), actor.ScopeID, actor.ActorScopeID, actor.UserID, request.SiteID,
			request.IdempotencyKey, digest[:], now)
		if err != nil {
			return fmt.Errorf("claim cache policy write: %w", err)
		}
		if command.RowsAffected() == 0 {
			write, found, err = lockPolicyWrite(ctx, tx, actor, request.IdempotencyKey)
			if err != nil || !found {
				return err
			}
			if write.actorUserID != actor.UserID || !bytes.Equal(write.digest, digest[:]) {
				return ErrIdempotencyConflict
			}
			if write.revision == nil {
				return fmt.Errorf("incomplete cache policy write request")
			}
			result.Policy, err = loadPolicyRevision(ctx, tx, actor.ScopeID, request.SiteID, *write.revision)
			result.Replayed = err == nil
			return err
		}

		result.Policy, err = writePolicyRevisionTx(ctx, tx, store.auditor, store.siteSettings, actor, tenantID,
			request, bindingMode, definitionID, document, digest[:], now)
		if err != nil {
			return err
		}
		revision := result.Policy.Revision
		if _, err := tx.Exec(ctx, `
			UPDATE cache_policy_write_requests SET response_revision=$5,completed_at=$6
			WHERE scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND idempotency_key=$4`,
			actor.ScopeID, actor.ActorScopeID, actor.UserID, request.IdempotencyKey, revision, now); err != nil {
			return fmt.Errorf("complete cache policy write: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrEntitlementDenied) {
			if auditErr := store.persistSiteEntitlementDenial(
				ctx, actor, request.SiteID, request.RequestID, "cache.policy.publish",
			); auditErr != nil {
				err = errors.Join(err, auditErr)
			}
		}
		return PolicyWriteResult{}, fmt.Errorf("publish cache policy: %w", err)
	}
	return result, nil
}

func (store *Store) GetPolicy(ctx context.Context, actor Actor, siteID uuid.UUID, revision int64) (PolicyRevision, error) {
	if ctx == nil || !validActor(actor) || siteID == uuid.Nil || revision < 0 {
		return PolicyRevision{}, ErrInvalidInput
	}
	var result PolicyRevision
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead,
	}, func(tx pgx.Tx) error {
		if _, err := store.authorizeActor(ctx, tx, actor, "sites.read"); err != nil {
			return err
		}
		if revision == 0 {
			if err := tx.QueryRow(ctx, `
				SELECT current_revision FROM cache_policy_heads
				WHERE scope_id=$1 AND site_id=$2`, actor.ScopeID, siteID).Scan(&revision); err == pgx.ErrNoRows {
				return ErrNotFound
			} else if err != nil {
				return err
			}
		}
		var err error
		result, err = loadPolicyRevision(ctx, tx, actor.ScopeID, siteID, revision)
		return err
	})
	return result, err
}

type policyWrite struct {
	actorUserID uuid.UUID
	digest      []byte
	revision    *int64
}

func lockPolicyWrite(ctx context.Context, tx pgx.Tx, actor Actor, key string) (policyWrite, bool, error) {
	var result policyWrite
	err := tx.QueryRow(ctx, `
		SELECT actor_user_id,request_digest,response_revision FROM cache_policy_write_requests
		WHERE scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND idempotency_key=$4 FOR UPDATE`,
		actor.ScopeID, actor.ActorScopeID, actor.UserID, key).Scan(
		&result.actorUserID, &result.digest, &result.revision)
	if err == pgx.ErrNoRows {
		return policyWrite{}, false, nil
	}
	if err != nil {
		return policyWrite{}, false, fmt.Errorf("read cache policy write: %w", err)
	}
	return result, true, nil
}

func loadPolicyRevision(
	ctx context.Context,
	row interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	scopeID, siteID uuid.UUID,
	revision int64,
) (PolicyRevision, error) {
	var result PolicyRevision
	var rules, extensions []byte
	err := row.QueryRow(ctx, `
		SELECT binding.site_id,binding.scope_id,binding.tenant_id,binding.revision,
		       binding.binding_mode,binding.definition_id,binding.definition_revision,
		       definition.schema_version,definition.mode,definition.rules,definition.query_mode,
		       definition.query_names,definition.vary_headers,definition.disk_quota_bytes,
		       binding.created_by_user_id,binding.request_id,binding.created_at,definition.extensions
		FROM cache_policy_revisions binding
		JOIN cache_policy_definition_revisions definition
		  ON definition.scope_id=binding.scope_id AND definition.definition_id=binding.definition_id
		 AND definition.revision=binding.definition_revision
		WHERE binding.scope_id=$1 AND binding.site_id=$2 AND binding.revision=$3`, scopeID, siteID, revision).Scan(
		&result.SiteID, &result.ScopeID, &result.TenantID, &result.Revision,
		&result.BindingMode, &result.DefinitionID, &result.DefinitionRevision,
		&result.Document.SchemaVersion, &result.Document.Mode, &rules, &result.Document.QueryMode, &result.Document.QueryNames,
		&result.Document.VaryHeaders, &result.Document.DiskQuotaBytes,
		&result.CreatedByUserID, &result.RequestID, &result.CreatedAt, &extensions)
	if err == pgx.ErrNoRows {
		return PolicyRevision{}, ErrNotFound
	}
	if err != nil {
		return PolicyRevision{}, fmt.Errorf("load cache policy revision: %w", err)
	}
	result.Document, err = DecodeStoredPolicyDocument(
		result.Document.SchemaVersion, result.Document.Mode, rules, result.Document.QueryMode,
		result.Document.QueryNames, result.Document.VaryHeaders, result.Document.DiskQuotaBytes, extensions,
	)
	if err != nil {
		return PolicyRevision{}, fmt.Errorf("decode cache policy document: %w", err)
	}
	return result, nil
}

type policyDefinitionRevision struct {
	ScopeID, TenantID, DefinitionID uuid.UUID
	Revision                        int64
	Document                        PolicyDocument
}

func loadPolicyDefinitionRevision(
	ctx context.Context,
	row interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	scopeID, definitionID uuid.UUID,
	revision int64,
) (policyDefinitionRevision, error) {
	var result policyDefinitionRevision
	var rules, extensions []byte
	err := row.QueryRow(ctx, `
		SELECT scope_id,tenant_id,definition_id,revision,schema_version,mode,rules,query_mode,
		       query_names,vary_headers,disk_quota_bytes,extensions
		FROM cache_policy_definition_revisions
		WHERE scope_id=$1 AND definition_id=$2 AND revision=$3`, scopeID, definitionID, revision).Scan(
		&result.ScopeID, &result.TenantID, &result.DefinitionID, &result.Revision,
		&result.Document.SchemaVersion, &result.Document.Mode, &rules, &result.Document.QueryMode,
		&result.Document.QueryNames, &result.Document.VaryHeaders, &result.Document.DiskQuotaBytes, &extensions)
	if errors.Is(err, pgx.ErrNoRows) {
		return policyDefinitionRevision{}, ErrNotFound
	}
	if err != nil {
		return policyDefinitionRevision{}, fmt.Errorf("load cache policy definition revision: %w", err)
	}
	result.Document, err = DecodeStoredPolicyDocument(
		result.Document.SchemaVersion, result.Document.Mode, rules, result.Document.QueryMode,
		result.Document.QueryNames, result.Document.VaryHeaders, result.Document.DiskQuotaBytes, extensions,
	)
	if err != nil {
		return policyDefinitionRevision{}, fmt.Errorf("decode cache policy definition document: %w", err)
	}
	return result, nil
}

func emptyPolicyDocument(document PolicyDocument) bool {
	return document.SchemaVersion == 0 && document.Mode == "" && len(document.Rules) == 0 &&
		document.QueryMode == "" && len(document.QueryNames) == 0 && len(document.VaryHeaders) == 0 &&
		document.DiskQuotaBytes == 0 && document.Extensions == (PolicyExtensions{})
}

// writePolicyRevisionTx appends the site's next cache policy revision (and
// for an override its definition revision), advances the edge scope's source
// revision and audits cache_policy.publish, in the caller's tx after it
// authorized the actor and claimed the write request. A nil siteSettings
// leaves the publication to the caller (a site create publishes itself).
func writePolicyRevisionTx(ctx context.Context, tx pgx.Tx, auditor auditAppender, siteSettings SiteSettingEnqueuer,
	actor Actor, tenantID uuid.UUID, request PublishPolicyRequest, bindingMode BindingMode, definitionID uuid.UUID,
	document PolicyDocument, digest []byte, now time.Time) (PolicyRevision, error) {
	var edgeSourceRevision int64
	if err := tx.QueryRow(ctx, `SELECT source_revision FROM edge_configuration_scopes
		WHERE scope_id=$1 FOR UPDATE`, actor.ScopeID).Scan(&edgeSourceRevision); err == pgx.ErrNoRows {
		return PolicyRevision{}, ErrNotFound
	} else if err != nil {
		return PolicyRevision{}, fmt.Errorf("lock cache policy edge scope: %w", err)
	}
	var current int64
	err := tx.QueryRow(ctx, `
		SELECT current_revision FROM cache_policy_heads
		WHERE scope_id=$1 AND site_id=$2 FOR UPDATE`, actor.ScopeID, request.SiteID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) {
		current = 0
	} else if err != nil {
		return PolicyRevision{}, fmt.Errorf("lock cache policy head: %w", err)
	}
	if current != request.ExpectedRevision {
		return PolicyRevision{}, ErrRevisionConflict
	}
	revision := current + 1
	nextEdgeSourceRevision := edgeSourceRevision + 1
	definitionRevision := request.DefinitionRevision
	if bindingMode == BindingInherit {
		definition, err := loadPolicyDefinitionRevision(ctx, tx, actor.ScopeID, definitionID, definitionRevision)
		if err != nil {
			return PolicyRevision{}, err
		}
		if definition.TenantID != tenantID {
			return PolicyRevision{}, ErrPermissionDenied
		}
		document = definition.Document
	} else {
		var definitionTenantID uuid.UUID
		var currentDefinitionRevision int64
		err = tx.QueryRow(ctx, `
			SELECT tenant_id,current_revision FROM cache_policy_definition_heads
			WHERE scope_id=$1 AND definition_id=$2 FOR UPDATE`, actor.ScopeID, definitionID).Scan(
			&definitionTenantID, &currentDefinitionRevision)
		if errors.Is(err, pgx.ErrNoRows) {
			currentDefinitionRevision = 0
		} else if err != nil {
			return PolicyRevision{}, fmt.Errorf("lock cache policy definition head: %w", err)
		} else if definitionTenantID != tenantID {
			return PolicyRevision{}, ErrPermissionDenied
		}
		expectedDefinitionRevision := currentDefinitionRevision
		if request.ExpectedDefinitionRevision != nil {
			expectedDefinitionRevision = *request.ExpectedDefinitionRevision
		}
		if expectedDefinitionRevision != currentDefinitionRevision {
			return PolicyRevision{}, ErrRevisionConflict
		}
		definitionRevision = currentDefinitionRevision + 1
		if currentDefinitionRevision == 0 {
			if _, err := tx.Exec(ctx, `
				INSERT INTO cache_policy_definition_heads (
					scope_id,tenant_id,definition_id,current_revision,created_at,updated_at
				) VALUES ($1,$2,$3,$4,$5,$5)`, actor.ScopeID, tenantID, definitionID,
				definitionRevision, now); err != nil {
				return PolicyRevision{}, fmt.Errorf("create cache policy definition head: %w", err)
			}
		} else {
			command, err := tx.Exec(ctx, `
				UPDATE cache_policy_definition_heads SET current_revision=$3,updated_at=$4
				WHERE scope_id=$1 AND definition_id=$2 AND current_revision=$5`, actor.ScopeID,
				definitionID, definitionRevision, now, currentDefinitionRevision)
			if err != nil {
				return PolicyRevision{}, fmt.Errorf("advance cache policy definition head: %w", err)
			}
			if command.RowsAffected() != 1 {
				return PolicyRevision{}, ErrRevisionConflict
			}
		}
		rules, err := json.Marshal(document.Rules)
		if err != nil {
			return PolicyRevision{}, ErrInvalidInput
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO cache_policy_definition_revisions (
				scope_id,tenant_id,definition_id,revision,source_site_id,schema_version,mode,rules,
				query_mode,query_names,vary_headers,disk_quota_bytes,request_digest,actor_scope_id,
				created_by_user_id,request_id,created_at,extensions
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
			actor.ScopeID, tenantID, definitionID, definitionRevision, request.SiteID,
			document.SchemaVersion, document.Mode, rules, document.QueryMode, document.QueryNames,
			document.VaryHeaders, document.DiskQuotaBytes, digest, actor.ActorScopeID,
			actor.UserID, request.RequestID, now, document.StoredExtensions()); err != nil {
			return PolicyRevision{}, fmt.Errorf("append cache policy definition revision: %w", err)
		}
	}
	if current == 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO cache_policy_heads (
				site_id,scope_id,tenant_id,current_revision,created_at,updated_at
			) VALUES ($1,$2,$3,$4,$5,$5)`,
			request.SiteID, actor.ScopeID, tenantID, revision, now); err != nil {
			return PolicyRevision{}, fmt.Errorf("create cache policy head: %w", err)
		}
	} else {
		command, err := tx.Exec(ctx, `
			UPDATE cache_policy_heads SET current_revision=$3,updated_at=$4
			WHERE scope_id=$1 AND site_id=$2 AND current_revision=$5`,
			actor.ScopeID, request.SiteID, revision, now, current)
		if err != nil {
			return PolicyRevision{}, fmt.Errorf("advance cache policy head: %w", err)
		}
		if command.RowsAffected() != 1 {
			return PolicyRevision{}, ErrRevisionConflict
		}
	}
	command, err := tx.Exec(ctx, `UPDATE edge_configuration_scopes
		SET source_revision=$2,updated_at=$3 WHERE scope_id=$1 AND source_revision=$4`,
		actor.ScopeID, nextEdgeSourceRevision, now, edgeSourceRevision)
	if err != nil {
		return PolicyRevision{}, fmt.Errorf("advance cache policy edge scope: %w", err)
	}
	if command.RowsAffected() != 1 {
		return PolicyRevision{}, ErrRevisionConflict
	}
	// A saved cache policy goes out like every other site
	// setting (sitecrs, siteaccess): an automatic scope publishes it as
	// its policy actor's site.update; a manual scope keeps it pending
	// (the source revision advanced above).
	if siteSettings != nil {
		if _, err := siteSettings.EnqueueSiteSettingTx(ctx, tx, actor.ScopeID, request.SiteID,
			request.RequestID); err != nil {
			return PolicyRevision{}, fmt.Errorf("enqueue cache policy publication: %w", err)
		}
	}
	rules, err := json.Marshal(document.Rules)
	if err != nil {
		return PolicyRevision{}, ErrInvalidInput
	}
	if _, err := tx.Exec(ctx, `
			INSERT INTO cache_policy_revisions (
				site_id,scope_id,tenant_id,revision,schema_version,mode,rules,query_mode,query_names,
				vary_headers,disk_quota_bytes,request_digest,actor_scope_id,created_by_user_id,
				edge_source_revision,request_id,created_at,binding_mode,definition_id,definition_revision,extensions
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
		request.SiteID, actor.ScopeID, tenantID, revision, document.SchemaVersion, document.Mode, rules,
		document.QueryMode, document.QueryNames, document.VaryHeaders, document.DiskQuotaBytes,
		digest, actor.ActorScopeID, actor.UserID, nextEdgeSourceRevision, request.RequestID, now,
		bindingMode, definitionID, definitionRevision, document.StoredExtensions()); err != nil {
		return PolicyRevision{}, fmt.Errorf("append cache policy revision: %w", err)
	}
	policy := PolicyRevision{
		SiteID: request.SiteID, ScopeID: actor.ScopeID, TenantID: tenantID,
		Revision: revision, BindingMode: bindingMode, DefinitionID: definitionID,
		DefinitionRevision: definitionRevision, Document: document, CreatedByUserID: actor.UserID,
		RequestID: request.RequestID, CreatedAt: now,
	}
	if err := auditor.Append(ctx, tx, audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "cache_policy.publish",
		ResourceType: "cache_policy", ResourceID: request.SiteID.String(),
		RequestID: request.RequestID, Result: "success",
		Payload: map[string]any{
			"revision": revision, "schema_version": document.SchemaVersion,
			"mode": document.Mode, "binding_mode": bindingMode,
			"definition_id": definitionID, "definition_revision": definitionRevision,
			"actor_scope_id": actor.ActorScopeID, "extensions": document.Extensions,
		},
	}); err != nil {
		return PolicyRevision{}, err
	}
	return policy, nil
}
