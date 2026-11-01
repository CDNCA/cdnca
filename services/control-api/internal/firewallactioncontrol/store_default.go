package firewallactioncontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// inheritedDocumentBytes is the document of an inherited site revision (607:
// inherited revisions carry exactly {}).
var inheritedDocumentBytes = []byte("{}")

type tenantDefault struct {
	revision  int64
	document  []byte
	policy    PolicyInput
	updatedAt time.Time
}

// loadTenantDefault reads scopeID's saved default (found false: never saved).
func loadTenantDefault(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, lock bool) (tenantDefault, bool, error) {
	query := `SELECT revision,document_bytes,updated_at FROM firewall_action_tenant_defaults WHERE tenant_scope_id=$1`
	if lock {
		query += ` FOR UPDATE`
	}
	var result tenantDefault
	err := tx.QueryRow(ctx, query, scopeID).Scan(&result.revision, &result.document, &result.updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return tenantDefault{}, false, nil
	}
	if err != nil {
		return tenantDefault{}, false, err
	}
	if result.policy, err = decodeDefaultDocument(result.document); err != nil {
		return tenantDefault{}, false, ErrUnavailable
	}
	return result, true, nil
}

// inheritedView is the GET answer of a site without its own policy:
// siteRevision is its own revision counter (0: never configured).
func inheritedView(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, siteRevision int64, host string) (Policy, error) {
	saved, found, err := loadTenantDefault(ctx, tx, scopeID, false)
	if err != nil {
		return Policy{}, err
	}
	view := Policy{
		ID: InheritedPolicyID(scopeID, siteID), TenantScopeID: scopeID, SiteID: siteID,
		Revision: siteRevision, DeploymentState: StateInherited, HostEscalation: host, Inherited: true,
		// 608: the on/off switch is the own policy's; an inherited site follows the default.
		Enabled: true,
	}
	if !found {
		view.PolicyInput, view.Source = SystemDefaultPolicy(), SourceSystemDefault
		document, _ := json.Marshal(inheritedEdgePolicy(scopeID, siteID, 1, view.PolicyInput))
		digest := sha256.Sum256(document)
		view.DocumentSHA256 = hex.EncodeToString(digest[:])
		return view, nil
	}
	document, err := InheritedDocument(scopeID, siteID, saved.revision, saved.document)
	if err != nil {
		return Policy{}, ErrUnavailable
	}
	digest := sha256.Sum256(document)
	updatedAt := saved.updatedAt
	view.PolicyInput, view.Source, view.Delivered = saved.policy, SourceTenantDefault, true
	view.DocumentSHA256, view.CreatedAt, view.UpdatedAt = hex.EncodeToString(digest[:]), &updatedAt, &updatedAt
	return view, nil
}

// Inherit drops the site's own policy: it records an inherited revision
// (revision+1, document {}) so the site follows the tenant default again.
func (store *Store) Inherit(ctx context.Context, request InheritRequest) (WriteResult, error) {
	if !store.ready() {
		return WriteResult{}, ErrUnavailable
	}
	var result WriteResult
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionManage); err != nil {
			return err
		}
		if err := requireSite(ctx, tx, request.TargetScopeID, request.SiteID); err != nil {
			return err
		}
		if replay, found, err := loadReceipt(ctx, tx, request.TargetScopeID, request.SiteID, request.Actor, request.IdempotencyKey, request.RequestSHA256); err != nil {
			return err
		} else if found {
			result = replay
			result.Replayed = true
			return nil
		}
		current, found, err := lockPolicy(ctx, tx, request.TargetScopeID, request.SiteID)
		if err != nil {
			return err
		}
		if !found || current.Inherited {
			return ErrNotFound
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		now := store.now().UTC().Truncate(time.Microsecond)
		revision := current.Revision + 1
		digest := sha256.Sum256(inheritedDocumentBytes)
		if _, err := tx.Exec(ctx, `INSERT INTO firewall_action_policy_revisions(tenant_scope_id,site_id,revision,policy_id,document,document_bytes,document_sha256,
			expected_active_revision,actor_scope_id,actor_user_id,request_id,created_at,inherited) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,true)`,
			request.TargetScopeID, request.SiteID, revision, current.ID, inheritedDocumentBytes, inheritedDocumentBytes, digest[:], current.ActiveRevision,
			request.Actor.ScopeID, request.Actor.UserID, request.RequestID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE firewall_action_policy_heads SET document=$3,document_bytes=$4,document_sha256=$5,revision=$6,
			deployment_state='pending',inherited=true,updated_at=$7 WHERE tenant_scope_id=$1 AND site_id=$2`,
			request.TargetScopeID, request.SiteID, inheritedDocumentBytes, inheritedDocumentBytes, digest[:], revision, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, request.TargetScopeID); err != nil {
			return err
		}
		view, err := inheritedView(ctx, tx, request.TargetScopeID, request.SiteID, revision, current.HostEscalation)
		if err != nil {
			return err
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: request.TargetScopeID, ActorUserID: &request.Actor.UserID, Action: "firewall.action.inherit",
			ResourceType: "firewall_action_policy", ResourceID: current.ID.String(), RequestID: request.RequestID,
			Result: "success", Payload: map[string]any{"site_id": request.SiteID.String(), "revision": revision,
				"changes": map[string]any{"source": map[string]any{"before": SourceSite, "after": view.Source}}},
		}); err != nil {
			return err
		}
		if err := store.publishRevisionTx(ctx, tx, request.TargetScopeID, request.SiteID, request.RequestID); err != nil {
			return err
		}
		result = WriteResult{Policy: view}
		return saveReceipt(ctx, tx, request.TargetScopeID, request.SiteID, request.Actor, request.IdempotencyKey, request.RequestSHA256, result, now)
	})
	if err != nil {
		return WriteResult{}, normalizeStoreError(err)
	}
	return result, nil
}

func (store *Store) GetDefault(ctx context.Context, request DefaultReadRequest) (DefaultPolicy, error) {
	if !store.ready() {
		return DefaultPolicy{}, ErrUnavailable
	}
	var result DefaultPolicy
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionRead); err != nil {
			return err
		}
		if err := requireScope(ctx, tx, request.TargetScopeID); err != nil {
			return err
		}
		var err error
		result, err = defaultView(ctx, tx, request.TargetScopeID, false)
		return err
	})
	if err != nil {
		return DefaultPolicy{}, normalizeStoreError(err)
	}
	return result, nil
}

func (store *Store) PutDefault(ctx context.Context, request DefaultPutRequest) (DefaultWriteResult, error) {
	if !store.ready() {
		return DefaultWriteResult{}, ErrUnavailable
	}
	var result DefaultWriteResult
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionManage); err != nil {
			return err
		}
		if err := requireScope(ctx, tx, request.TargetScopeID); err != nil {
			return err
		}
		if replay, found, err := loadDefaultReceipt(ctx, tx, request); err != nil {
			return err
		} else if found {
			result = replay
			result.Replayed = true
			return nil
		}
		// Serializes the first save too (no row to lock yet): a racing writer
		// then sees the saved revision and gets a revision conflict.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
			"firewall-action-default-head/"+request.TargetScopeID.String()); err != nil {
			return err
		}
		before, found, err := loadTenantDefault(ctx, tx, request.TargetScopeID, true)
		if err != nil {
			return err
		}
		if !found && request.ExpectedRevision != 0 || found && before.revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		document, err := encodeDefaultDocument(request.Policy)
		if err != nil {
			return ErrInvalidInput
		}
		digest := sha256.Sum256(document)
		now := store.now().UTC().Truncate(time.Microsecond)
		revision := request.ExpectedRevision + 1
		if _, err := tx.Exec(ctx, `INSERT INTO firewall_action_tenant_default_revisions(tenant_scope_id,revision,document,document_bytes,document_sha256,
			actor_scope_id,actor_user_id,request_id,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			request.TargetScopeID, revision, document, document, digest[:], request.Actor.ScopeID, request.Actor.UserID, request.RequestID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO firewall_action_tenant_defaults(tenant_scope_id,document,document_bytes,document_sha256,revision,created_at,updated_at)
			VALUES($1,$2,$3,$4,$5,$6,$6) ON CONFLICT(tenant_scope_id) DO UPDATE SET document=EXCLUDED.document,
			document_bytes=EXCLUDED.document_bytes,document_sha256=EXCLUDED.document_sha256,revision=EXCLUDED.revision,
			deployment_state='pending',updated_at=EXCLUDED.updated_at`,
			request.TargetScopeID, document, document, digest[:], revision, now); err != nil {
			return err
		}
		view, err := defaultView(ctx, tx, request.TargetScopeID, true)
		if err != nil {
			return err
		}
		// Only inheriting sites change: without any the scope is left alone.
		if view.InheritingSiteCount > 0 {
			if _, err := tx.Exec(ctx, `SELECT advance_edge_configuration_scope_revision($1)`, request.TargetScopeID); err != nil {
				return err
			}
		}
		changes := map[string]any{"revision": map[string]any{"before": request.ExpectedRevision, "after": revision}}
		if found {
			for key, values := range defaultChanges(before.policy, request.Policy) {
				changes[key] = values
			}
		}
		if err := store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: request.TargetScopeID, ActorUserID: &request.Actor.UserID, Action: "firewall.action.default_put",
			ResourceType: "firewall_action_tenant_default", ResourceID: request.TargetScopeID.String(), RequestID: request.RequestID,
			Result: "success", Payload: map[string]any{"revision": revision, "inheriting_site_count": view.InheritingSiteCount, "changes": changes},
		}); err != nil {
			return err
		}
		if view.InheritingSiteCount > 0 && store.revisions != nil {
			var siteID uuid.UUID
			if err := tx.QueryRow(ctx, inheritingSitesSQL+` ORDER BY site.id LIMIT 1`, request.TargetScopeID).Scan(&siteID); err != nil {
				return err
			}
			if _, err := store.revisions.EnqueueUnrequestedSiteRevisionTx(ctx, tx, request.TargetScopeID, siteID, "firewall-action-default/"+request.RequestID); err != nil {
				return err
			}
		}
		result = DefaultWriteResult{Policy: view}
		return saveDefaultReceipt(ctx, tx, request, result, now)
	})
	if err != nil {
		return DefaultWriteResult{}, normalizeStoreError(err)
	}
	return result, nil
}

// inheritingSitesSQL selects the live sites of scope $1 without a policy of
// their own (never configured, or restored to inherit).
const inheritingSitesSQL = `SELECT site.id FROM sites site
	WHERE site.scope_id=$1 AND site.deleted_at IS NULL AND NOT EXISTS (
		SELECT 1 FROM firewall_action_policy_heads head
		WHERE head.tenant_scope_id=site.scope_id AND head.site_id=site.id AND NOT head.inherited)`

func defaultView(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, lock bool) (DefaultPolicy, error) {
	saved, found, err := loadTenantDefault(ctx, tx, scopeID, lock)
	if err != nil {
		return DefaultPolicy{}, err
	}
	view := DefaultPolicy{TenantScopeID: scopeID, Source: SourceSystemDefault, PolicyInput: SystemDefaultPolicy()}
	if found {
		updatedAt := saved.updatedAt
		view.Source, view.Revision, view.PolicyInput, view.UpdatedAt = SourceTenantDefault, saved.revision, saved.policy, &updatedAt
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM (`+inheritingSitesSQL+`) inheriting`, scopeID).Scan(&view.InheritingSiteCount); err != nil {
		return DefaultPolicy{}, err
	}
	return view, nil
}

// defaultChanges lists the changed scalar fields (before → after) and marks
// changed network/crawler lists without copying them into the audit row.
func defaultChanges(before, after PolicyInput) map[string]any {
	changes := map[string]any{}
	scalar := func(key string, left, right any) {
		if left != right {
			changes[key] = map[string]any{"before": left, "after": right}
		}
	}
	scalar("normal_action", before.NormalAction, after.NormalAction)
	scalar("engage_threshold", before.EngageThreshold, after.EngageThreshold)
	scalar("recover_threshold", before.RecoverThreshold, after.RecoverThreshold)
	scalar("recovery_windows", before.RecoveryWindows, after.RecoveryWindows)
	scalar("return_page_status", before.ReturnPage.Status, after.ReturnPage.Status)
	list := func(key string, left, right any) {
		leftJSON, _ := json.Marshal(left)
		rightJSON, _ := json.Marshal(right)
		if string(leftJSON) != string(rightJSON) {
			changes[key] = map[string]any{"changed": true}
		}
	}
	list("block_networks", before.BlockNetworks, after.BlockNetworks)
	list("trusted_proxies", before.TrustedProxies, after.TrustedProxies)
	list("trusted_crawlers", before.TrustedCrawlers, after.TrustedCrawlers)
	list("return_page_body", before.ReturnPage, after.ReturnPage)
	return changes
}

func requireScope(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM access_scopes WHERE id=$1)`, scopeID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func loadDefaultReceipt(ctx context.Context, tx pgx.Tx, request DefaultPutRequest) (DefaultWriteResult, bool, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
		"firewall-action-default/"+request.TargetScopeID.String()+"/"+request.IdempotencyKey); err != nil {
		return DefaultWriteResult{}, false, err
	}
	var storedDigest, response []byte
	var actorScopeID, actorUserID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT request_sha256,actor_scope_id,actor_user_id,response_body FROM firewall_action_tenant_default_receipts
		WHERE tenant_scope_id=$1 AND idempotency_key=$2`, request.TargetScopeID, request.IdempotencyKey).
		Scan(&storedDigest, &actorScopeID, &actorUserID, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultWriteResult{}, false, nil
	}
	if err != nil {
		return DefaultWriteResult{}, false, err
	}
	if string(storedDigest) != string(request.RequestSHA256[:]) || actorScopeID != request.Actor.ScopeID || actorUserID != request.Actor.UserID {
		return DefaultWriteResult{}, false, ErrIdempotencyConflict
	}
	var result DefaultWriteResult
	if err := json.Unmarshal(response, &result); err != nil {
		return DefaultWriteResult{}, false, ErrUnavailable
	}
	return result, true, nil
}

func saveDefaultReceipt(ctx context.Context, tx pgx.Tx, request DefaultPutRequest, result DefaultWriteResult, now time.Time) error {
	response, err := json.Marshal(result)
	if err != nil {
		return ErrUnavailable
	}
	_, err = tx.Exec(ctx, `INSERT INTO firewall_action_tenant_default_receipts(tenant_scope_id,idempotency_key,request_sha256,
		actor_scope_id,actor_user_id,response_body,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		request.TargetScopeID, request.IdempotencyKey, request.RequestSHA256[:], request.Actor.ScopeID, request.Actor.UserID, response, now)
	return err
}
