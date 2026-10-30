package cachecontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/entitlementguard"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type auditAppender interface {
	Append(context.Context, pgx.Tx, audit.Event) error
}

type Store struct {
	pool       *pgxpool.Pool
	now        func() time.Time
	auditor    auditAppender
	guard      EntitlementChecker
	authorizer *iamlock.Authorizer
	// siteSettings enqueues the automatic publication of a saved policy
	// (edgeautopublish.SiteSettingPublisher, injected: edgepublish's tests
	// import this package). Nil leaves the policy pending.
	siteSettings SiteSettingEnqueuer
}

// SiteSettingEnqueuer is edgeautopublish.EnqueueSiteSettingTx.
type SiteSettingEnqueuer interface {
	EnqueueSiteSettingTx(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, requestID string) (bool, error)
}

// WithSiteSettingEnqueuer makes PublishPolicy enqueue the automatic
// publication of the saved policy.
func (store *Store) WithSiteSettingEnqueuer(enqueuer SiteSettingEnqueuer) *Store {
	store.siteSettings = enqueuer
	return store
}

const redactedSessionAuthorization = "cachecontrol.sessionAuthorization{token:redacted}"

type sessionAuthorizationContextKey struct{}

type sessionAuthorization struct {
	rawToken string
}

func (sessionAuthorization) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedSessionAuthorization))
}

func (sessionAuthorization) String() string   { return redactedSessionAuthorization }
func (sessionAuthorization) GoString() string { return redactedSessionAuthorization }

func (sessionAuthorization) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedSessionAuthorization)
}

func WithSessionAuthorization(ctx context.Context, rawToken string) (context.Context, error) {
	if ctx == nil || rawToken == "" || len(rawToken) >= 8192 || strings.ContainsFunc(rawToken, unicode.IsSpace) {
		return nil, ErrInvalidInput
	}
	return context.WithValue(ctx, sessionAuthorizationContextKey{}, sessionAuthorization{rawToken: rawToken}), nil
}

const redactedAPIKeyAuthorization = "cachecontrol.apiKeyAuthorization{key:redacted}"

type apiKeyAuthorizationContextKey struct{}

// apiKeyAuthorization is the API key a task-center command was authenticated
// with (fix-cacheflow3 §1); the store re-authorizes it in its transaction.
type apiKeyAuthorization struct {
	keyID  uuid.UUID
	rawKey string
}

func (apiKeyAuthorization) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte(redactedAPIKeyAuthorization))
}

func (apiKeyAuthorization) String() string   { return redactedAPIKeyAuthorization }
func (apiKeyAuthorization) GoString() string { return redactedAPIKeyAuthorization }

func (apiKeyAuthorization) MarshalJSON() ([]byte, error) {
	return json.Marshal(redactedAPIKeyAuthorization)
}

// WithAPIKeyAuthorization makes the store authorize the actor with the API key
// (api_keys.id and raw credential): the key's scopes intersected with the
// holder's current permissions, checked in the command transaction.
func WithAPIKeyAuthorization(ctx context.Context, keyID uuid.UUID, rawKey string) (context.Context, error) {
	if ctx == nil || keyID == uuid.Nil || rawKey == "" || len(rawKey) >= 8192 ||
		strings.ContainsFunc(rawKey, unicode.IsSpace) {
		return nil, ErrInvalidInput
	}
	return context.WithValue(ctx, apiKeyAuthorizationContextKey{}, apiKeyAuthorization{keyID: keyID, rawKey: rawKey}), nil
}

// auditActorRef is the audit ActorRef of the credential in ctx: "api_key:<id>"
// for an API key, empty for a session.
func auditActorRef(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if key, ok := ctx.Value(apiKeyAuthorizationContextKey{}).(apiKeyAuthorization); ok && key.keyID != uuid.Nil {
		return "api_key:" + key.keyID.String()
	}
	return ""
}

type EntitlementChecker interface {
	CheckSiteChange(context.Context, pgx.Tx, entitlementguard.SiteCheck) error
}

func NewStore(pool *pgxpool.Pool, clock func() time.Time) (*Store, error) {
	return NewStoreWithEntitlement(pool, clock, nil)
}

func NewStoreWithEntitlement(
	pool *pgxpool.Pool,
	clock func() time.Time,
	guard EntitlementChecker,
) (*Store, error) {
	if pool == nil {
		return nil, ErrInvalidInput
	}
	if clock == nil {
		clock = time.Now
	}
	return &Store{pool: pool, now: clock, auditor: audit.New(pool), guard: guard}, nil
}

func NewStoreWithEntitlementAndIAM(
	pool *pgxpool.Pool,
	clock func() time.Time,
	guard EntitlementChecker,
	authorizer *iamlock.Authorizer,
) (*Store, error) {
	if authorizer == nil || !authorizer.Configured() {
		return nil, ErrInvalidInput
	}
	store, err := NewStoreWithEntitlement(pool, clock, guard)
	if err != nil {
		return nil, err
	}
	store.authorizer = authorizer
	return store, nil
}

func (store *Store) timestamp() time.Time {
	return store.now().UTC().Truncate(time.Microsecond)
}

func (store *Store) authorizeActor(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	requiredPermission string,
) (uuid.UUID, error) {
	if store.authorizer == nil {
		if actor.ActorScopeID != actor.ScopeID {
			return uuid.Nil, ErrPermissionDenied
		}
		return authorizeTenantActor(ctx, tx, actor, requiredPermission)
	}
	session, hasSession := ctx.Value(sessionAuthorizationContextKey{}).(sessionAuthorization)
	key, hasKey := ctx.Value(apiKeyAuthorizationContextKey{}).(apiKeyAuthorization)
	var sealed iamlock.Authorization
	var err error
	switch {
	case hasSession && !hasKey && session.rawToken != "":
		sealed, err = store.authorizer.AuthorizeSession(ctx, tx, session.rawToken, actor.ScopeID, requiredPermission)
	case hasKey && !hasSession && key.rawKey != "" && key.keyID != uuid.Nil:
		// API keys belong to one tenant scope and never act for the platform.
		if actor.ActorScopeID != actor.ScopeID {
			return uuid.Nil, ErrPermissionDenied
		}
		sealed, err = store.authorizer.AuthorizeAPIKey(ctx, tx, key.rawKey, actor.ScopeID, requiredPermission)
		if err == nil && (!sealed.Valid() || sealed.CredentialKind() != "api_key" || sealed.CredentialID() != key.keyID) {
			return uuid.Nil, ErrPermissionDenied
		}
	default:
		return uuid.Nil, ErrPermissionDenied
	}
	if err != nil {
		if errors.Is(err, iamlock.ErrPermissionDenied) {
			return uuid.Nil, fmt.Errorf("%w: formal session authorization", ErrPermissionDenied)
		}
		return uuid.Nil, fmt.Errorf("authorize cache control session: %w", err)
	}
	if sealed.UserID() != actor.UserID || sealed.AuthenticationScopeID() != actor.ActorScopeID ||
		sealed.TargetScopeID() != actor.ScopeID {
		return uuid.Nil, ErrPermissionDenied
	}
	tenantID, ok := sealed.TenantID()
	if !ok {
		return uuid.Nil, ErrPermissionDenied
	}
	return tenantID, nil
}

func (store *Store) checkSiteEntitlement(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	siteID uuid.UUID,
	requestID, operation string,
) error {
	if store.guard == nil {
		return nil
	}
	err := store.guard.CheckSiteChange(ctx, tx, entitlementguard.SiteCheck{
		AuditScopeID: actor.ScopeID,
		ActorUserID:  actor.UserID,
		ResourceID:   siteID,
		RequestID:    requestID,
		Operation:    operation,
		Delta:        0,
	})
	if entitlementguard.IsDenial(err) {
		return ErrEntitlementDenied
	}
	return err
}

func (store *Store) persistSiteEntitlementDenial(
	ctx context.Context,
	actor Actor,
	siteID uuid.UUID,
	requestID, operation string,
) error {
	if store.guard == nil {
		return fmt.Errorf("persist cache entitlement denial without guard")
	}
	check := entitlementguard.SiteCheck{
		AuditScopeID: actor.ScopeID,
		ActorUserID:  actor.UserID,
		ResourceID:   siteID,
		RequestID:    requestID,
		Operation:    operation,
		Delta:        0,
	}
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
			"custom-rbac-tenant:"+actor.ScopeID.String()); err != nil {
			return fmt.Errorf("lock cache entitlement denial scope: %w", err)
		}
		lockKey := "cache-entitlement-denial:" + actor.ScopeID.String() + ":" +
			actor.UserID.String() + ":" + siteID.String() + ":" + operation + ":" + requestID
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey); err != nil {
			return fmt.Errorf("lock cache entitlement denial audit: %w", err)
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM audit_events
			WHERE scope_id=$1 AND actor_user_id=$2 AND action='entitlement.guard.reject'
			  AND resource_type='site' AND resource_id=$3 AND request_id=$4 AND result='denied'
			  AND payload->>'operation'=$5
		)`, actor.ScopeID, actor.UserID, siteID.String(), requestID, operation).Scan(&exists); err != nil {
			return fmt.Errorf("read cache entitlement denial audit: %w", err)
		}
		if exists {
			return nil
		}
		err := store.guard.CheckSiteChange(ctx, tx, check)
		if entitlementguard.IsDenial(err) {
			return nil
		}
		if err == nil {
			return fmt.Errorf("cache entitlement denial changed before audit persistence")
		}
		return fmt.Errorf("persist cache entitlement denial audit: %w", err)
	})
}

func authorizeTenantActor(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	requiredPermission string,
) (uuid.UUID, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
		"custom-rbac-tenant:"+actor.ScopeID.String()); err != nil {
		return uuid.Nil, fmt.Errorf("lock cache control RBAC scope: %w", err)
	}
	var tenantID uuid.UUID
	var kind string
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes
		WHERE id=$1 FOR SHARE`, actor.ScopeID).Scan(&kind, &tenantID); err != nil || kind != "tenant" {
		if err == nil || err == pgx.ErrNoRows {
			return uuid.Nil, ErrPermissionDenied
		}
		return uuid.Nil, fmt.Errorf("lock cache control scope: %w", err)
	}
	var status string
	for _, query := range []struct {
		statement string
		arguments []any
	}{
		{`SELECT status FROM tenants WHERE id=$1 FOR UPDATE`, []any{tenantID}},
		{`SELECT status FROM users WHERE id=$1 FOR UPDATE`, []any{actor.UserID}},
		{`SELECT status FROM memberships WHERE scope_id=$1 AND user_id=$2 FOR UPDATE`,
			[]any{actor.ScopeID, actor.UserID}},
	} {
		if err := tx.QueryRow(ctx, query.statement, query.arguments...).Scan(&status); err != nil {
			if err == pgx.ErrNoRows {
				return uuid.Nil, ErrPermissionDenied
			}
			return uuid.Nil, fmt.Errorf("lock cache control principal: %w", err)
		}
		if status != "active" {
			return uuid.Nil, ErrPermissionDenied
		}
	}

	rows, err := tx.Query(ctx, `SELECT permission.permission_name
		FROM role_assignments assignment
		JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions permission ON permission.role_id=role.id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND permission.permission_name=$3
		ORDER BY role.id FOR SHARE OF assignment,role,permission`,
		actor.ScopeID, actor.UserID, requiredPermission)
	if err != nil {
		return uuid.Nil, fmt.Errorf("lock cache control permission: %w", err)
	}
	standardPermission := false
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			rows.Close()
			return uuid.Nil, fmt.Errorf("scan cache control permission: %w", err)
		}
		standardPermission = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return uuid.Nil, fmt.Errorf("lock cache control permission: %w", err)
	}
	rows.Close()

	var hasCustomRBAC bool
	if err := tx.QueryRow(ctx, `SELECT
		to_regprocedure('custom_rbac_effective_permissions(uuid,uuid)') IS NOT NULL`).Scan(&hasCustomRBAC); err != nil {
		return uuid.Nil, fmt.Errorf("inspect cache control RBAC schema: %w", err)
	}
	if !hasCustomRBAC {
		if !standardPermission {
			return uuid.Nil, ErrPermissionDenied
		}
		return tenantID, nil
	}
	var hasWatermark bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('custom_rbac_state_watermark') IS NOT NULL`).Scan(&hasWatermark); err != nil {
		return uuid.Nil, fmt.Errorf("inspect cache control RBAC watermark: %w", err)
	}
	if hasWatermark {
		var version int64
		if err := tx.QueryRow(ctx, `SELECT current_version FROM custom_rbac_state_watermark
			WHERE singleton FOR SHARE`).Scan(&version); err != nil {
			return uuid.Nil, fmt.Errorf("lock cache control RBAC watermark: %w", err)
		}
	}
	var allowed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM custom_rbac_effective_permissions($1,$2) WHERE permission_name=$3
	)`, actor.ScopeID, actor.UserID, requiredPermission).Scan(&allowed); err != nil {
		return uuid.Nil, fmt.Errorf("authorize cache control permission: %w", err)
	}
	if !allowed {
		return uuid.Nil, ErrPermissionDenied
	}
	return tenantID, nil
}

func authorizeWorkerScope(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	var kind, status string
	if err := tx.QueryRow(ctx, `SELECT scope.kind,tenant.status
		FROM access_scopes scope JOIN tenants tenant ON tenant.id=scope.tenant_id
		WHERE scope.id=$1 FOR SHARE OF scope,tenant`, scopeID).Scan(&kind, &status); err != nil {
		if err == pgx.ErrNoRows {
			return ErrPermissionDenied
		}
		return fmt.Errorf("authorize cache control worker scope: %w", err)
	}
	if kind != "tenant" || status != "active" {
		return ErrPermissionDenied
	}
	return nil
}

func (store *Store) appendAudit(
	ctx context.Context,
	tx pgx.Tx,
	scopeID uuid.UUID,
	actorUserID *uuid.UUID,
	action string,
	resourceID uuid.UUID,
	requestID string,
	payload map[string]any,
) (uuid.UUID, error) {
	if err := store.auditor.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, ActorUserID: actorUserID, Action: action, ActorRef: auditActorRef(ctx),
		ResourceType: "cache_operation", ResourceID: resourceID.String(),
		RequestID: requestID, Result: "success", Payload: payload,
	}); err != nil {
		return uuid.Nil, err
	}
	var eventID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM audit_events
		WHERE scope_id=$1 AND action=$2 AND resource_type='cache_operation'
		  AND resource_id=$3 AND request_id=$4 AND result='success'
		ORDER BY stream_position DESC LIMIT 1`,
		scopeID, action, resourceID.String(), requestID).Scan(&eventID); err != nil {
		return uuid.Nil, fmt.Errorf("load cache operation audit fact: %w", err)
	}
	return eventID, nil
}

func loadSiteDescriptor(ctx context.Context, tx pgx.Tx, scopeID, siteID uuid.UUID, lock bool) (siteDescriptor, error) {
	// Domains: the site's active names as edgepublish publishes them
	// (site_domain_facts, else the primary).
	query := `
		SELECT scope.tenant_id,site.domain,COALESCE((
		         SELECT array_agg(current_domain.canonical_domain ORDER BY current_domain.canonical_domain)
		         FROM (
		             SELECT DISTINCT ON (fact.canonical_domain) fact.canonical_domain,fact.action
		             FROM site_domain_facts fact
		             WHERE fact.scope_id=site.scope_id AND fact.site_id=site.id
		             ORDER BY fact.canonical_domain,fact.global_sequence DESC
		         ) current_domain WHERE current_domain.action='activate'
		       ),ARRAY[site.domain]::text[]),site.http_ports,site.https_ports
		FROM sites site
		JOIN access_scopes scope ON scope.id=site.scope_id
		WHERE site.scope_id=$1 AND site.id=$2 AND site.deleted_at IS NULL`
	if lock {
		query += " FOR UPDATE OF site"
	}
	var result siteDescriptor
	if err := tx.QueryRow(ctx, query, scopeID, siteID).Scan(
		&result.TenantID, &result.Domain, &result.Domains, &result.HTTPPorts, &result.HTTPSPorts,
	); err == pgx.ErrNoRows {
		return siteDescriptor{}, ErrNotFound
	} else if err != nil {
		return siteDescriptor{}, fmt.Errorf("load cache control site: %w", err)
	}
	return result, nil
}
