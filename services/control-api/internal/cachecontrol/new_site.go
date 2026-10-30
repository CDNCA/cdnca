package cachecontrol

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CreateForNewSiteTx writes a new site's first cache policy revision (an
// override of document) in the site create's tx (网站默认设置 > 网站缓存):
// the same revision, write request and cache_policy.publish
// audit PublishPolicy writes, without its authorization (the create checked
// sites.manage and the entitlement) and without enqueueing a publication
// (the site create publishes the site). actor.ScopeID is the site's scope,
// actor.ActorScopeID the creator's.
func CreateForNewSiteTx(ctx context.Context, tx pgx.Tx, auditor auditAppender, actor Actor, tenantID, siteID uuid.UUID,
	document PolicyDocument, requestID string, now time.Time) (PolicyRevision, error) {
	if !validActor(actor) || tenantID == uuid.Nil || siteID == uuid.Nil || auditor == nil {
		return PolicyRevision{}, ErrInvalidInput
	}
	document, err := normalizePolicy(document)
	if err != nil {
		return PolicyRevision{}, err
	}
	request := PublishPolicyRequest{SiteID: siteID, BindingMode: BindingOverride, DefinitionID: siteID,
		Document: document, IdempotencyKey: "site-create-" + siteID.String(), RequestID: requestID}
	digest, err := digestJSON(struct {
		SiteID   uuid.UUID      `json:"site_id"`
		Source   string         `json:"source"`
		Document PolicyDocument `json:"document"`
	}{siteID, "site_default", document})
	if err != nil {
		return PolicyRevision{}, err
	}
	now = now.UTC().Truncate(time.Microsecond)
	if _, err := tx.Exec(ctx, `
		INSERT INTO cache_policy_write_requests (
			id,scope_id,actor_scope_id,actor_user_id,site_id,idempotency_key,request_digest,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		uuid.New(), actor.ScopeID, actor.ActorScopeID, actor.UserID, siteID, request.IdempotencyKey, digest[:], now); err != nil {
		return PolicyRevision{}, fmt.Errorf("claim new site cache policy write: %w", err)
	}
	policy, err := writePolicyRevisionTx(ctx, tx, auditor, nil, actor, tenantID, request, BindingOverride, siteID,
		document, digest[:], now)
	if err != nil {
		return PolicyRevision{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE cache_policy_write_requests SET response_revision=$5,completed_at=$6
		WHERE scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND idempotency_key=$4`,
		actor.ScopeID, actor.ActorScopeID, actor.UserID, request.IdempotencyKey, policy.Revision, now); err != nil {
		return PolicyRevision{}, fmt.Errorf("complete new site cache policy write: %w", err)
	}
	return policy, nil
}

// SiteDocumentTx is the site's current cache policy document when the site
// overrides the definition (site transfer copies it); found false for none
// or an inherited one (the new site inherits its own tenant's default).
func SiteDocumentTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) (PolicyDocument, bool, error) {
	var revision int64
	err := tx.QueryRow(ctx, `SELECT current_revision FROM cache_policy_heads WHERE scope_id=$1 AND site_id=$2`,
		scopeID, siteID).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return PolicyDocument{}, false, nil
	}
	if err != nil {
		return PolicyDocument{}, false, err
	}
	policy, err := loadPolicyRevision(ctx, tx, scopeID, siteID, revision)
	if err != nil {
		return PolicyDocument{}, false, err
	}
	if policy.BindingMode != BindingOverride {
		return PolicyDocument{}, false, nil
	}
	return policy.Document, true, nil
}

// SiteEffectiveDocument is the cache policy document the site's nodes run
// (its own override or the inherited definition); found false for a site
// that never had a policy. The market subscriber compiles it into the
// site's market revision (fix-mktsiteconf).
func SiteEffectiveDocument(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, siteID uuid.UUID) (PolicyDocument, bool, error) {
	var scopeID uuid.UUID
	var revision int64
	err := q.QueryRow(ctx, `SELECT scope_id,current_revision FROM cache_policy_heads WHERE site_id=$1`, siteID).
		Scan(&scopeID, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return PolicyDocument{}, false, nil
	}
	if err != nil {
		return PolicyDocument{}, false, err
	}
	policy, err := loadPolicyRevision(ctx, q, scopeID, siteID, revision)
	if err != nil {
		return PolicyDocument{}, false, err
	}
	return policy.Document, true, nil
}
