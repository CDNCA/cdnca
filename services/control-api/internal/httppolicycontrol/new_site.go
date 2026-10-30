package httppolicycontrol

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// NewSitePolicyConfig is 网站列表 > 默认设置 #18 源站请求头 / #25 上传文件大小
// 限制 as an HTTP policy of a new site: the upload limit
// (0: maxUpload, the system client_max_body_size) and the request headers
// sent to the origin; nothing else.
func NewSitePolicyConfig(maxUploadBytes int64, requestHeaders []HeaderAction) (Config, error) {
	if requestHeaders == nil {
		requestHeaders = []HeaderAction{}
	}
	return normalizeConfig(Config{MaxUploadBytes: maxUploadBytes, RequestHeaders: requestHeaders, ResponseHeaders: []HeaderAction{},
		Rewrites: []RewriteRule{}, RedirectAllowedHosts: []string{}, Redirects: []RedirectRule{}})
}

// ValidRequestHeaders reports whether actions are request header actions an
// HTTP policy accepts (the default is checked when saved).
func ValidRequestHeaders(actions []HeaderAction) bool {
	_, err := normalizeHeaderActions(actions, true)
	return err == nil && len(actions) > 0
}

// CreateForNewSiteTx creates the new site's enabled HTTP policy inside the
// site create's tx, as Create does after its authorization: revision one
// (its trigger projects http_policies and advances the publication head),
// the success audit the revision requires. The site's create publishes it.
// actorScopeID / actorUserID must hold http_policies.manage (the revision
// trigger checks it); a tenant actor must own the site.
func CreateForNewSiteTx(ctx context.Context, tx pgx.Tx, actorScopeID, actorUserID, scopeID, tenantID, siteID, ownerID uuid.UUID,
	config Config, now time.Time) (uuid.UUID, error) {
	policyID, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	now = now.UTC().Truncate(time.Microsecond)
	item := storedPolicy{Policy: Policy{ID: policyID, TenantScopeID: scopeID, SiteID: siteID, SiteOwnerUserID: ownerID,
		Enabled: true, Revision: 1, CreatedAt: now, UpdatedAt: now}, TenantID: tenantID}
	applyConfig(&item.Policy, config)
	store := &Store{}
	if err := store.ensurePublicationCandidate(ctx, tx, item); err != nil {
		return uuid.Nil, err
	}
	metadata := WriteMetadata{RequestID: "site-default-" + siteID.String(), TraceID: "site-default-" + siteID.String()}
	actor := Actor{UserID: actorUserID, ScopeID: actorScopeID}
	if err := insertRevision(ctx, tx, actor, item, metadata, "create"); err != nil {
		return uuid.Nil, err
	}
	if item.PublicationRevision, err = publicationRevision(ctx, tx, scopeID); err != nil {
		return uuid.Nil, err
	}
	if err := (audit.New(nil)).Append(ctx, tx, audit.Event{
		ScopeID: scopeID, ActorUserID: &actorUserID, Action: "http_policy.create", ResourceType: "http_policy",
		ResourceID: policyID.String(), RequestID: metadata.RequestID, Result: "success",
		Payload: map[string]any{"trace_id": metadata.TraceID, "revision": item.Revision,
			"publication_revision": item.PublicationRevision, "site_id": siteID.String(), "enabled": true,
			"source": "site_default"},
	}); err != nil {
		return uuid.Nil, fmt.Errorf("audit new site HTTP policy: %w", err)
	}
	return policyID, nil
}

// SiteConfigTx is the live, enabled HTTP policy of a site as a Config (site
// transfer copies it to the new site); found false when the site has none.
func SiteConfigTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID) (Config, bool, error) {
	var id uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM http_policies WHERE tenant_scope_id=$1 AND site_id=$2
		AND deleted_at IS NULL AND current_enabled`, scopeID, siteID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return Config{}, false, nil
	}
	if err != nil {
		return Config{}, false, err
	}
	item, err := selectPolicy(ctx, tx, Actor{ScopeKind: "platform"}, scopeID, id, false)
	if err != nil {
		return Config{}, false, err
	}
	return configFromPolicy(item.Policy), true, nil
}
