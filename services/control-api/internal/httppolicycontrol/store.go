package httppolicycontrol

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/sitelock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type auditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Store struct {
	pool       *pgxpool.Pool
	auditor    auditAppender
	gate       entitlementGate
	authorizer TxAuthorizer
	now        func() time.Time
	revisions  SiteRevisionPublisher
}

// SiteRevisionPublisher is edgeautopublish.EnqueueUnrequestedSiteRevisionTx
// (injected: edgeautopublish imports this package). A policy revision
// advances the scope's source revision (trigger
// zz_http_policy_edge_source_revision_167) outside any site request; an
// automatic scope publishes it unless a request already covers the revision.
type SiteRevisionPublisher interface {
	EnqueueUnrequestedSiteRevisionTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, requestID string) (bool, error)
}

// WithSiteRevisionPublisher wires automatic publication of policy writes;
// without it a write stays pending until the scope's next publication.
func (store *Store) WithSiteRevisionPublisher(publisher SiteRevisionPublisher) *Store {
	store.revisions = publisher
	return store
}

func (store *Store) publishRevisionTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, requestID string) error {
	if store.revisions == nil {
		return nil
	}
	_, err := store.revisions.EnqueueUnrequestedSiteRevisionTx(ctx, tx, scopeID, siteID, "http-policy/"+requestID)
	return err
}

type entitlementGuardAdapter struct {
	guard *entitlementguard.Guard
}

func (adapter entitlementGuardAdapter) Check(ctx context.Context, tx pgx.Tx, check entitlementCheck) error {
	return adapter.guard.CheckSiteChange(ctx, tx, entitlementguard.SiteCheck{
		AuditScopeID: check.AuditScopeID, ActorUserID: check.ActorUserID,
		ResourceID: check.ResourceID, RequestID: check.RequestID,
		Operation: check.Operation, Delta: 0,
	})
}

type storedWrite struct {
	Found        bool
	Outcome      string
	ResponseBody []byte
}

type pageCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        uuid.UUID `json:"id"`
}

type listPageAccumulator struct {
	result ListResult
	last   pageCursor
}

func NewStore(pool *pgxpool.Pool) *Store {
	return NewStoreWithClock(pool, time.Now, nil)
}

func NewStoreWithClock(pool *pgxpool.Pool, now func() time.Time, trust *entitlementguard.TrustStore) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		pool: pool, auditor: audit.New(pool),
		gate:       entitlementGuardAdapter{guard: entitlementguard.NewGuard(pool, now, trust)},
		authorizer: denyTxAuthorizer{}, now: now,
	}
}

func newStoreWithAuthorizer(
	pool *pgxpool.Pool,
	now func() time.Time,
	trust *entitlementguard.TrustStore,
	authorizer TxAuthorizer,
) (*Store, error) {
	if isNilDependency(pool) || isNilDependency(now) || isNilDependency(trust) || isNilDependency(authorizer) {
		return nil, ErrInvalidStoreConfig
	}
	return newStoreWithDependencies(pool, now, entitlementGuardAdapter{
		guard: entitlementguard.NewGuard(pool, now, trust),
	}, nil, authorizer)
}

func newStoreWithDependencies(
	pool *pgxpool.Pool,
	now func() time.Time,
	gate entitlementGate,
	auditor auditAppender,
	authorizer TxAuthorizer,
) (*Store, error) {
	if isNilDependency(pool) || isNilDependency(now) || isNilDependency(gate) || isNilDependency(authorizer) {
		return nil, ErrInvalidStoreConfig
	}
	if auditor == nil {
		auditor = audit.New(pool)
	} else if isNilDependency(auditor) {
		return nil, ErrInvalidStoreConfig
	}
	return &Store{pool: pool, auditor: auditor, gate: gate, authorizer: authorizer, now: now}, nil
}

func (store *Store) ready() bool {
	return store != nil && !isNilDependency(store.pool) && !isNilDependency(store.auditor) &&
		!isNilDependency(store.gate) && !isNilDependency(store.authorizer) && !isNilDependency(store.now)
}

func (store *Store) Create(ctx context.Context, actor Actor, request CreateRequest, digest [32]byte) (WriteResult, error) {
	if !store.ready() {
		return WriteResult{}, ErrUnavailable
	}
	policyID, err := uuid.NewV7()
	if err != nil {
		return WriteResult{}, ErrUnavailable
	}
	var result WriteResult
	var denial error
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		tenantID, err := store.authorizeWrite(ctx, tx, actor, request.TargetScopeID, PermissionManage)
		if err != nil {
			return err
		}
		ownerID, err := authorizeSite(ctx, tx, actor, request.TargetScopeID, request.SiteID)
		if err != nil {
			return err
		}
		write, err := store.claimWrite(ctx, tx, actor, request.TargetScopeID, "http_policy.create", request.WriteMetadata, digest)
		if err != nil {
			return err
		}
		if write.Found {
			return replayWrite(write, &result)
		}
		denial = store.checkEntitlement(ctx, tx, actor, request.TargetScopeID, policyID, request.WriteMetadata, "http_policy.create")
		if denial != nil {
			return store.completeDenial(ctx, tx, actor, request.TargetScopeID, policyID, "http_policy.create", request.WriteMetadata, denial)
		}
		now := store.now().UTC().Truncate(time.Microsecond)
		item := storedPolicy{
			Policy: Policy{
				ID: policyID, TenantScopeID: request.TargetScopeID, SiteID: request.SiteID,
				SiteOwnerUserID: ownerID, Enabled: request.Enabled, Revision: 1,
				CreatedAt: now, UpdatedAt: now,
			},
			TenantID: tenantID,
		}
		applyConfig(&item.Policy, request.Config)
		if err := store.ensurePublicationCandidate(ctx, tx, item); err != nil {
			return err
		}
		if err := insertRevision(ctx, tx, actor, item, request.WriteMetadata, "create"); err != nil {
			return err
		}
		item.PublicationRevision, err = publicationRevision(ctx, tx, item.TenantScopeID)
		if err != nil {
			return err
		}
		if err := store.appendAudit(ctx, tx, actor, item, request.WriteMetadata, "create", "success"); err != nil {
			return err
		}
		if err := store.publishRevisionTx(ctx, tx, item.TenantScopeID, item.SiteID, request.RequestID); err != nil {
			return err
		}
		result.Policy = clonePolicy(item.Policy)
		return store.completeWrite(ctx, tx, actor, "http_policy.create", request.IdempotencyKey, "success", item.ID, 201, result.Policy)
	})
	if err != nil {
		return WriteResult{}, normalizeStoreError(err)
	}
	if denial != nil {
		return WriteResult{}, denial
	}
	return result, nil
}

func (store *Store) Update(ctx context.Context, actor Actor, request UpdateRequest, digest [32]byte) (WriteResult, error) {
	return store.change(ctx, actor, request.TargetScopeID, request.ID, request.ExpectedRevision,
		request.WriteMetadata, digest, "update", true, func(item *storedPolicy) error {
			applyConfig(&item.Policy, request.Config)
			return nil
		})
}

func (store *Store) SetEnabled(ctx context.Context, actor Actor, request StateRequest, digest [32]byte) (WriteResult, error) {
	action := "disable"
	requireEntitlement := false
	if request.Enabled {
		action = "enable"
		requireEntitlement = true
	}
	return store.change(ctx, actor, request.TargetScopeID, request.ID, request.ExpectedRevision,
		request.WriteMetadata, digest, action, requireEntitlement, func(item *storedPolicy) error {
			if item.Enabled == request.Enabled {
				return ErrConflict
			}
			item.Enabled = request.Enabled
			return nil
		})
}

func (store *Store) Delete(ctx context.Context, actor Actor, request DeleteRequest, digest [32]byte) (WriteResult, error) {
	return store.change(ctx, actor, request.TargetScopeID, request.ID, request.ExpectedRevision,
		request.WriteMetadata, digest, "delete", false, func(item *storedPolicy) error {
			item.Enabled = false
			item.Deleted = true
			return nil
		})
}

func (store *Store) change(
	ctx context.Context,
	actor Actor,
	targetScopeID, policyID uuid.UUID,
	expectedRevision int64,
	metadata WriteMetadata,
	digest [32]byte,
	action string,
	requireEntitlement bool,
	mutate func(*storedPolicy) error,
) (WriteResult, error) {
	if !store.ready() {
		return WriteResult{}, ErrUnavailable
	}
	operation := "http_policy." + action
	var result WriteResult
	var denial error
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := store.authorizeWrite(ctx, tx, actor, targetScopeID, PermissionManage); err != nil {
			return err
		}
		item, err := lockPolicy(ctx, tx, actor, targetScopeID, policyID, true)
		if err != nil {
			return err
		}
		ownerID, err := authorizeSite(ctx, tx, actor, targetScopeID, item.SiteID)
		if err != nil {
			return err
		}
		if ownerID != item.SiteOwnerUserID {
			return ErrNotFound
		}
		write, err := store.claimWrite(ctx, tx, actor, targetScopeID, operation, metadata, digest)
		if err != nil {
			return err
		}
		if write.Found {
			return replayWrite(write, &result)
		}
		if item.Deleted {
			return ErrNotFound
		}
		if item.Revision != expectedRevision {
			return ErrRevisionConflict
		}
		if requireEntitlement {
			denial = store.checkEntitlement(ctx, tx, actor, targetScopeID, policyID, metadata, operation)
			if denial != nil {
				return store.completeDenial(ctx, tx, actor, targetScopeID, policyID, operation, metadata, denial)
			}
		}
		if err := mutate(&item); err != nil {
			return err
		}
		item.Revision++
		item.UpdatedAt = store.now().UTC().Truncate(time.Microsecond)
		if err := store.ensurePublicationCandidate(ctx, tx, item); err != nil {
			return err
		}
		if err := insertRevision(ctx, tx, actor, item, metadata, action); err != nil {
			return err
		}
		item.PublicationRevision, err = publicationRevision(ctx, tx, item.TenantScopeID)
		if err != nil {
			return err
		}
		if err := store.appendAudit(ctx, tx, actor, item, metadata, action, "success"); err != nil {
			return err
		}
		if err := store.publishRevisionTx(ctx, tx, item.TenantScopeID, item.SiteID, metadata.RequestID); err != nil {
			return err
		}
		result.Policy = clonePolicy(item.Policy)
		return store.completeWrite(ctx, tx, actor, operation, metadata.IdempotencyKey, "success", item.ID, 200, result.Policy)
	})
	if err != nil {
		return WriteResult{}, normalizeStoreError(err)
	}
	if denial != nil {
		return WriteResult{}, denial
	}
	return result, nil
}

func (store *Store) authorizeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	permission string,
) (uuid.UUID, error) {
	if !store.ready() || tx == nil || !validActor(actor) || targetScopeID == uuid.Nil ||
		(permission != PermissionRead && permission != PermissionManage) {
		return uuid.Nil, ErrPermissionDenied
	}
	if actor.ScopeKind == "tenant" && actor.ScopeID != targetScopeID {
		return uuid.Nil, ErrNotFound
	}
	// site-parity3b: a platform administrator writes a tenant's site HTTP
	// policy in that tenant's scope (the IAM check below requires the
	// platform role's http_policies.manage or platform.admin; the revision
	// records created_by_scope_id = the platform scope).
	tenantID, err := store.authorizer.AuthorizeWrite(ctx, tx, actor, targetScopeID, permission)
	if err != nil {
		return uuid.Nil, err
	}
	if tenantID == uuid.Nil {
		return uuid.Nil, ErrPermissionDenied
	}
	return tenantID, nil
}

func (store *Store) Get(ctx context.Context, actor Actor, targetScopeID, id uuid.UUID) (Policy, error) {
	if !store.ready() {
		return Policy{}, ErrUnavailable
	}
	var result Policy
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := store.authorizeWrite(ctx, tx, actor, targetScopeID, PermissionRead); err != nil {
			return err
		}
		item, err := selectPolicy(ctx, tx, actor, targetScopeID, id, false)
		if err != nil {
			return err
		}
		result = clonePolicy(item.Policy)
		return nil
	})
	if err != nil {
		return Policy{}, normalizeStoreError(err)
	}
	return result, nil
}

func (store *Store) List(ctx context.Context, actor Actor, filter ListFilter) (ListResult, error) {
	if !store.ready() {
		return ListResult{}, ErrUnavailable
	}
	var result ListResult
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := store.authorizeWrite(ctx, tx, actor, filter.TargetScopeID, PermissionRead); err != nil {
			return err
		}
		cursor, err := decodeCursor(filter.Cursor)
		if err != nil {
			return ErrInvalidInput
		}
		conditions := []string{"policy.tenant_scope_id = $1", "policy.deleted_at IS NULL"}
		args := []any{filter.TargetScopeID}
		if actor.ScopeKind == "tenant" {
			args = append(args, actor.UserID)
			conditions = append(conditions, fmt.Sprintf("policy.site_owner_user_id = $%d", len(args)))
		}
		if filter.SiteID != uuid.Nil {
			args = append(args, filter.SiteID)
			conditions = append(conditions, fmt.Sprintf("policy.site_id = $%d", len(args)))
		}
		if filter.Enabled != nil {
			args = append(args, *filter.Enabled)
			conditions = append(conditions, fmt.Sprintf("policy.current_enabled = $%d", len(args)))
		}
		if cursor != nil {
			args = append(args, cursor.CreatedAt, cursor.ID)
			conditions = append(conditions, fmt.Sprintf("(policy.created_at, policy.id) < ($%d, $%d)", len(args)-1, len(args)))
		}
		args = append(args, filter.Limit+1)
		rows, err := tx.Query(ctx, selectPolicySQL+`
			WHERE `+strings.Join(conditions, " AND ")+`
			ORDER BY policy.created_at DESC, policy.id DESC
			LIMIT $`+fmt.Sprint(len(args)), args...)
		if err != nil {
			return err
		}
		page := listPageAccumulator{result: ListResult{Items: make([]Policy, 0, filter.Limit)}}
		hasMore := false
		for rows.Next() {
			item, err := scanStoredPolicy(rows)
			if err != nil {
				rows.Close()
				return err
			}
			if len(page.result.Items) == filter.Limit {
				hasMore = true
				break
			}
			added, err := page.add(item)
			if err != nil {
				rows.Close()
				return err
			}
			if !added {
				hasMore = true
				break
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		result, err = page.finish(hasMore)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return ListResult{}, normalizeStoreError(err)
	}
	return result, nil
}

func (page *listPageAccumulator) add(item storedPolicy) (bool, error) {
	cursor := pageCursor{CreatedAt: item.CreatedAt, ID: item.ID}
	nextCursor, err := encodeCursor(cursor)
	if err != nil {
		return false, err
	}
	page.result.Items = append(page.result.Items, clonePolicy(item.Policy))
	page.result.NextCursor = nextCursor
	encoded, err := json.Marshal(page.result)
	page.result.NextCursor = ""
	if err != nil || len(encoded)+1 > maxResponseBytes {
		last := len(page.result.Items) - 1
		page.result.Items[last] = Policy{}
		page.result.Items = page.result.Items[:last]
		return false, err
	}
	page.last = cursor
	return true, nil
}

func (page *listPageAccumulator) finish(hasMore bool) (ListResult, error) {
	if !hasMore {
		return page.result, nil
	}
	if len(page.result.Items) == 0 {
		return ListResult{}, ErrUnavailable
	}
	nextCursor, err := encodeCursor(page.last)
	if err != nil {
		return ListResult{}, err
	}
	page.result.NextCursor = nextCursor
	encoded, err := json.Marshal(page.result)
	if err != nil || len(encoded)+1 > maxResponseBytes {
		return ListResult{}, ErrUnavailable
	}
	return page.result, nil
}

func (store *Store) PublicationPreview(ctx context.Context, actor Actor, targetScopeID uuid.UUID) (PublicationPreview, error) {
	if !store.ready() {
		return PublicationPreview{}, ErrUnavailable
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return PublicationPreview{}, ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.authorizeWrite(ctx, tx, actor, targetScopeID, PermissionRead); err != nil {
		return PublicationPreview{}, normalizeStoreError(err)
	}
	version, err := publicationRevision(ctx, tx, targetScopeID)
	if err != nil {
		return PublicationPreview{}, normalizeStoreError(err)
	}
	policies, err := selectEnabledPolicies(ctx, tx, actor, targetScopeID)
	if err != nil {
		return PublicationPreview{}, normalizeStoreError(err)
	}
	snapshot, _, digest, err := canonicalSnapshot(version, policies)
	if err != nil {
		return PublicationPreview{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PublicationPreview{}, ErrUnavailable
	}
	return PublicationPreview{State: "preview", SHA256: hex.EncodeToString(digest[:]), Snapshot: snapshot}, nil
}

func (store *Store) ensurePublicationCandidate(ctx context.Context, tx pgx.Tx, candidate storedPolicy) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('http-policy-publication:' || $1::text, 0))`, candidate.TenantScopeID); err != nil {
		return err
	}
	version, err := nextPublicationRevision(ctx, tx, candidate.TenantScopeID)
	if err != nil {
		return err
	}
	policies, err := selectEnabledPolicies(ctx, tx, Actor{ScopeKind: "platform"}, candidate.TenantScopeID)
	if err != nil {
		return err
	}
	replaced := false
	for index := range policies {
		if policies[index].ID != candidate.ID {
			continue
		}
		replaced = true
		if candidate.Enabled && !candidate.Deleted {
			policies[index] = clonePolicy(candidate.Policy)
		} else {
			policies = append(policies[:index], policies[index+1:]...)
		}
		break
	}
	if !replaced && candidate.Enabled && !candidate.Deleted {
		policies = append(policies, clonePolicy(candidate.Policy))
	}
	if len(policies) == 0 {
		return nil
	}
	_, _, _, err = canonicalSnapshot(version, policies)
	return err
}

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func authorizeActorTarget(ctx context.Context, database queryRower, actor Actor, targetScopeID uuid.UUID, permission string) (uuid.UUID, error) {
	if !validActor(actor) || targetScopeID == uuid.Nil || actor.ScopeKind == "tenant" && actor.ScopeID != targetScopeID {
		return uuid.Nil, ErrNotFound
	}
	var tenantID uuid.UUID
	var allowed bool
	err := database.QueryRow(ctx, `
		SELECT target.tenant_id,
		       CASE
		         WHEN actor_scope.kind = 'tenant' THEN actor_scope.id = target.id AND EXISTS (
		           SELECT 1 FROM custom_rbac_effective_permissions(actor_scope.id, $2)
		           WHERE permission_name = $4
		         )
		         WHEN actor_scope.kind = 'platform' THEN EXISTS (
		           SELECT 1 FROM role_assignments assignment
		           JOIN role_permissions grant_row ON grant_row.role_id = assignment.role_id
		           WHERE assignment.scope_id = actor_scope.id AND assignment.user_id = $2
		             AND grant_row.permission_name IN ($4, 'platform.admin')
		         )
		         ELSE false
		       END
		FROM access_scopes target
		JOIN tenants tenant ON tenant.id = target.tenant_id AND tenant.status = 'active'
		JOIN access_scopes actor_scope ON actor_scope.id = $1 AND actor_scope.kind = $3
		JOIN memberships membership
		  ON membership.scope_id = actor_scope.id AND membership.user_id = $2
		 AND membership.status = 'active'
		JOIN users account ON account.id = membership.user_id AND account.status = 'active'
		WHERE target.id = $5 AND target.kind = 'tenant'`,
		actor.ScopeID, actor.UserID, actor.ScopeKind, permission, targetScopeID).Scan(&tenantID, &allowed)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	if !allowed {
		return uuid.Nil, ErrPermissionDenied
	}
	return tenantID, nil
}

func authorizeSite(ctx context.Context, tx pgx.Tx, actor Actor, targetScopeID, siteID uuid.UUID) (uuid.UUID, error) {
	var ownerID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT owner_user_id FROM sites
		WHERE id = $1 AND scope_id = $2 AND deleted_at IS NULL
		FOR SHARE`, siteID, targetScopeID).Scan(&ownerID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrNotFound
	}
	if err != nil {
		return uuid.Nil, err
	}
	if actor.ScopeKind == "tenant" && actor.UserID != ownerID {
		return uuid.Nil, ErrNotFound
	}
	if err := sitelock.RequireUnlocked(ctx, tx, actor.ScopeID, siteID); errors.Is(err, sitelock.ErrLocked) {
		return uuid.Nil, ErrSiteLocked
	} else if err != nil {
		return uuid.Nil, err
	}
	return ownerID, nil
}

func (store *Store) checkEntitlement(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID, resourceID uuid.UUID,
	metadata WriteMetadata,
	operation string,
) error {
	if store.gate == nil {
		return ErrEntitlementUnavailable
	}
	err := store.gate.Check(ctx, tx, entitlementCheck{
		AuditScopeID: targetScopeID, ActorUserID: actor.UserID, ResourceID: resourceID,
		RequestID: metadata.RequestID, Operation: operation,
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, entitlementguard.ErrUnavailable), errors.Is(err, entitlementguard.ErrInvalid):
		return ErrEntitlementUnavailable
	case entitlementguard.IsDenial(err):
		return ErrEntitlementDenied
	default:
		return err
	}
}

func (store *Store) completeDenial(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID, resourceID uuid.UUID,
	operation string,
	metadata WriteMetadata,
	denial error,
) error {
	outcome := "entitlement_denied"
	status := 403
	if errors.Is(denial, ErrEntitlementUnavailable) {
		outcome = "entitlement_unavailable"
		status = 503
	} else if !errors.Is(denial, ErrEntitlementDenied) {
		return denial
	}
	if err := store.auditor.Append(ctx, tx, audit.Event{
		ScopeID: targetScopeID, ActorUserID: &actor.UserID, Action: operation,
		ResourceType: "http_policy", ResourceID: resourceID.String(), RequestID: metadata.RequestID,
		Result: "denied", Payload: map[string]any{"trace_id": metadata.TraceID, "reason": outcome},
	}); err != nil {
		return err
	}
	body := map[string]any{"error": map[string]string{"code": outcome}}
	return store.completeWrite(ctx, tx, actor, operation, metadata.IdempotencyKey, outcome, resourceID, status, body)
}

func (store *Store) appendAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	item storedPolicy,
	metadata WriteMetadata,
	action, result string,
) error {
	return store.auditor.Append(ctx, tx, audit.Event{
		ScopeID: item.TenantScopeID, ActorUserID: &actor.UserID,
		Action: "http_policy." + action, ResourceType: "http_policy", ResourceID: item.ID.String(),
		RequestID: metadata.RequestID, Result: result,
		Payload: map[string]any{
			"trace_id": metadata.TraceID, "revision": item.Revision,
			"publication_revision": item.PublicationRevision,
			"site_id":              item.SiteID.String(), "enabled": item.Enabled,
		},
	})
}

func insertRevision(ctx context.Context, tx pgx.Tx, actor Actor, item storedPolicy, metadata WriteMetadata, action string) error {
	document := revisionDocument{
		SchemaVersion: DocumentSchema, PolicyID: item.ID, TenantScopeID: item.TenantScopeID,
		SiteID: item.SiteID, SiteOwnerUserID: item.SiteOwnerUserID, Revision: item.Revision,
		MaxUploadBytes: item.MaxUploadBytes, RequestHeaders: item.RequestHeaders,
		ResponseHeaders: item.ResponseHeaders, Rewrites: item.Rewrites,
		RedirectAllowedHosts: item.RedirectAllowedHosts, Redirects: item.Redirects,
		CORS: item.CORS, RefererCheck: item.RefererCheck, Enabled: item.Enabled, Deleted: item.Deleted,
	}
	encodedDocument, err := json.Marshal(document)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO http_policy_revisions (
			policy_id, tenant_scope_id, tenant_id, site_id, site_owner_user_id,
			revision, action, enabled, deleted, document, created_by_scope_id,
			created_by_user_id, request_id, trace_id, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		item.ID, item.TenantScopeID, item.TenantID, item.SiteID, item.SiteOwnerUserID,
		item.Revision, action, item.Enabled, item.Deleted, encodedDocument,
		actor.ScopeID, actor.UserID, metadata.RequestID, metadata.TraceID, item.UpdatedAt)
	return err
}

const selectPolicySQL = `
	SELECT policy.id, policy.tenant_scope_id, policy.tenant_id, policy.site_id,
	       policy.site_owner_user_id, policy.current_revision, policy.current_enabled,
	       policy.current_deleted, policy.current_document, publication.revision,
	       policy.created_at, policy.updated_at
	FROM http_policies policy
	JOIN http_policy_publication_heads publication
	  ON publication.tenant_scope_id = policy.tenant_scope_id`

func selectPolicy(ctx context.Context, database queryRower, actor Actor, targetScopeID, id uuid.UUID, includeDeleted bool) (storedPolicy, error) {
	query := selectPolicySQL + " WHERE policy.tenant_scope_id = $1 AND policy.id = $2"
	args := []any{targetScopeID, id}
	if !includeDeleted {
		query += " AND policy.deleted_at IS NULL"
	}
	if actor.ScopeKind == "tenant" {
		query += " AND policy.site_owner_user_id = $3"
		args = append(args, actor.UserID)
	}
	item, err := scanStoredPolicy(database.QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return storedPolicy{}, ErrNotFound
	}
	return item, err
}

func lockPolicy(ctx context.Context, tx pgx.Tx, actor Actor, targetScopeID, id uuid.UUID, includeDeleted bool) (storedPolicy, error) {
	query := selectPolicySQL + `
			WHERE policy.tenant_scope_id = $1 AND policy.id = $2`
	args := []any{targetScopeID, id}
	if !includeDeleted {
		query += " AND policy.deleted_at IS NULL"
	}
	if actor.ScopeKind == "tenant" {
		query += " AND policy.site_owner_user_id = $3"
		args = append(args, actor.UserID)
	}
	query += " FOR UPDATE OF policy"
	item, err := scanStoredPolicy(tx.QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return storedPolicy{}, ErrNotFound
	}
	return item, err
}

type rowScanner interface {
	Scan(...any) error
}

func scanStoredPolicy(row rowScanner) (storedPolicy, error) {
	var item storedPolicy
	var documentBytes []byte
	err := row.Scan(
		&item.ID, &item.TenantScopeID, &item.TenantID, &item.SiteID,
		&item.SiteOwnerUserID, &item.Revision, &item.Enabled, &item.Deleted,
		&documentBytes, &item.PublicationRevision, &item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		return storedPolicy{}, err
	}
	var document revisionDocument
	if err := json.Unmarshal(documentBytes, &document); err != nil {
		return storedPolicy{}, err
	}
	if document.SchemaVersion != DocumentSchema || document.PolicyID != item.ID ||
		document.TenantScopeID != item.TenantScopeID || document.SiteID != item.SiteID ||
		document.SiteOwnerUserID != item.SiteOwnerUserID || document.Revision != item.Revision ||
		document.Enabled != item.Enabled || document.Deleted != item.Deleted {
		return storedPolicy{}, ErrUnavailable
	}
	applyConfig(&item.Policy, Config{
		MaxUploadBytes: document.MaxUploadBytes, RequestHeaders: document.RequestHeaders,
		ResponseHeaders: document.ResponseHeaders, Rewrites: document.Rewrites,
		RedirectAllowedHosts: document.RedirectAllowedHosts, Redirects: document.Redirects,
		CORS: document.CORS, RefererCheck: document.RefererCheck,
	})
	return item, nil
}

func selectEnabledPolicies(ctx context.Context, database interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, actor Actor, targetScopeID uuid.UUID) ([]Policy, error) {
	query := selectPolicySQL + `
		WHERE policy.tenant_scope_id = $1 AND policy.deleted_at IS NULL
		  AND policy.current_enabled = true`
	args := []any{targetScopeID}
	if actor.ScopeKind == "tenant" {
		query += " AND policy.site_owner_user_id = $2"
		args = append(args, actor.UserID)
	}
	query += " ORDER BY policy.site_id::text"
	rows, err := database.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	policies := make([]Policy, 0)
	for rows.Next() {
		item, err := scanStoredPolicy(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, clonePolicy(item.Policy))
	}
	return policies, rows.Err()
}

func publicationRevision(ctx context.Context, database queryRower, targetScopeID uuid.UUID) (uint64, error) {
	var revision int64
	if err := database.QueryRow(ctx, `
		SELECT revision FROM http_policy_publication_heads WHERE tenant_scope_id = $1`, targetScopeID).Scan(&revision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	if revision < 1 || revision > MaxPolicyVersion {
		return 0, ErrUnavailable
	}
	return uint64(revision), nil
}

func nextPublicationRevision(ctx context.Context, database queryRower, targetScopeID uuid.UUID) (uint64, error) {
	var current int64
	if err := database.QueryRow(ctx, `
		SELECT COALESCE((SELECT revision FROM http_policy_publication_heads WHERE tenant_scope_id = $1), 0)`, targetScopeID).Scan(&current); err != nil {
		return 0, err
	}
	if current < 0 || current >= MaxPolicyVersion {
		return 0, ErrConflict
	}
	return uint64(current + 1), nil
}

func replayWrite(write storedWrite, result *WriteResult) error {
	switch write.Outcome {
	case "success":
		if err := json.Unmarshal(write.ResponseBody, &result.Policy); err != nil {
			return err
		}
		result.Replayed = true
		return nil
	case "entitlement_denied":
		return ErrEntitlementDenied
	case "entitlement_unavailable":
		return ErrEntitlementUnavailable
	default:
		return ErrIdempotencyConflict
	}
}

func (store *Store) claimWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	targetScopeID uuid.UUID,
	operation string,
	metadata WriteMetadata,
	digest [32]byte,
) (storedWrite, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return storedWrite{}, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO http_policy_write_requests (
			id, actor_scope_id, actor_user_id, target_scope_id, operation,
			idempotency_key, request_digest, request_id, trace_id, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (actor_scope_id, actor_user_id, operation, idempotency_key) DO NOTHING`,
		id, actor.ScopeID, actor.UserID, targetScopeID, operation, metadata.IdempotencyKey,
		digest[:], metadata.RequestID, metadata.TraceID, store.now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return storedWrite{}, err
	}
	if command.RowsAffected() == 1 {
		return storedWrite{}, nil
	}
	var existingDigest []byte
	var existingTarget uuid.UUID
	var outcome *string
	var body []byte
	var completedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT target_scope_id, request_digest, outcome, response_body, completed_at
		FROM http_policy_write_requests
		WHERE actor_scope_id = $1 AND actor_user_id = $2 AND operation = $3 AND idempotency_key = $4
		FOR UPDATE`, actor.ScopeID, actor.UserID, operation, metadata.IdempotencyKey).Scan(
		&existingTarget, &existingDigest, &outcome, &body, &completedAt)
	if err != nil {
		return storedWrite{}, err
	}
	if existingTarget != targetScopeID || !bytes.Equal(existingDigest, digest[:]) || outcome == nil || completedAt == nil {
		return storedWrite{}, ErrIdempotencyConflict
	}
	return storedWrite{Found: true, Outcome: *outcome, ResponseBody: body}, nil
}

func (store *Store) completeWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation, key, outcome string,
	resourceID uuid.UUID,
	status int,
	body any,
) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE http_policy_write_requests
		SET outcome = $5, resource_id = $6, response_status = $7,
		    response_body = $8, completed_at = $9
		WHERE actor_scope_id = $1 AND actor_user_id = $2 AND operation = $3
		  AND idempotency_key = $4 AND completed_at IS NULL`,
		actor.ScopeID, actor.UserID, operation, key, outcome, resourceID, status,
		string(encoded), store.now().UTC().Truncate(time.Microsecond))
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func encodeCursor(cursor pageCursor) (string, error) {
	encoded, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(encoded), nil
}

func decodeCursor(encoded string) (*pageCursor, error) {
	if encoded == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) > maxCursorBytes {
		return nil, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cursor pageCursor
	if err := decoder.Decode(&cursor); err != nil || cursor.CreatedAt.IsZero() || cursor.ID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidInput
	}
	return &cursor, nil
}

func clonePolicy(input Policy) Policy {
	result := input
	config := configFromPolicy(input)
	applyConfig(&result, config)
	return result
}

func normalizeStoreError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{
		ErrUnauthenticated, ErrInvalidInput, ErrValidation, ErrPermissionDenied, ErrNotFound, ErrConflict, ErrSiteLocked,
		ErrRevisionConflict, ErrIdempotencyConflict, ErrEntitlementDenied,
		ErrEntitlementUnavailable, context.Canceled, context.DeadlineExceeded,
	} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrUnavailable
}

func sortedPolicies(policies []Policy) {
	sort.Slice(policies, func(left, right int) bool {
		return policies[left].SiteID.String() < policies[right].SiteID.String()
	})
}
