package impersonation

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type actorState struct {
	scopeID          uuid.UUID
	scopeKind        string
	activeReseller   bool
	userStatus       string
	membershipStatus string
	displayName      string
	permissions      []string
}

func (state actorState) canImpersonate() bool {
	if state.userStatus != "active" || state.membershipStatus != "active" {
		return false
	}
	required := ManagePermission
	switch {
	case state.scopeKind == "platform":
	case state.scopeKind == "tenant" && state.activeReseller:
		required = ResellerPermission
	default:
		return false
	}
	for _, permission := range state.permissions {
		if permission == required {
			return true
		}
	}
	return false
}

// mayTarget: a platform actor may switch to any tenant, a reseller only to
// its own customers (tenants.parent_scope_id).
func (state actorState) mayTarget(target targetState) bool {
	return state.scopeKind == "platform" || state.scopeKind == "tenant" && target.parentScopeID == state.scopeID
}

type targetState struct {
	scopeKind        string
	parentScopeID    uuid.UUID
	tenantStatus     string
	userStatus       string
	membershipStatus string
	username         string
	displayID        string
	displayName      string
	roles            []string
	permissions      []string
}

func (state targetState) active() bool {
	return state.scopeKind == "tenant" && state.tenantStatus == "active" &&
		state.userStatus == "active" && state.membershipStatus == "active"
}

type storedGrant struct {
	Grant
	primaryAuthSessionID     uuid.UUID
	codeDigest               []byte
	subjectPermissionsDigest []byte
	requestDigest            []byte
}

type storedSession struct {
	Session
	requestDigest []byte
}

type storedRevocation struct {
	Revocation
	requestDigest []byte
}

func loadActor(ctx context.Context, tx pgx.Tx, scopeID, userID uuid.UUID) (actorState, error) {
	var state actorState
	err := tx.QueryRow(ctx, `SELECT scope.id, scope.kind,
		scope.kind='tenant' AND reseller_scope_active_480(scope.id),
		users.status, membership.status, users.display_name,
		COALESCE(array_agg(DISTINCT permission.permission_name)
			FILTER (WHERE permission.permission_name IS NOT NULL), '{}'::text[])
		FROM access_scopes scope
		JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=$2
		JOIN users ON users.id=membership.user_id
		LEFT JOIN role_assignments assignment
			ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		LEFT JOIN role_permissions permission ON permission.role_id=assignment.role_id
		WHERE scope.id=$1
		GROUP BY scope.id,scope.kind,users.status,membership.status,users.display_name`, scopeID, userID).Scan(
		&state.scopeID, &state.scopeKind, &state.activeReseller, &state.userStatus, &state.membershipStatus,
		&state.displayName, &state.permissions)
	if err != nil {
		return actorState{}, err
	}
	return state, nil
}

func primaryAuthSessionActive(ctx context.Context, tx pgx.Tx, actor Actor, now time.Time) (bool, error) {
	var active bool
	err := tx.QueryRow(ctx, `SELECT true
		FROM auth_sessions
		WHERE id=$1 AND user_id=$2 AND scope_id=$3 AND created_at<=$4
		  AND expires_at>$4 AND revoked_at IS NULL
		FOR UPDATE`, actor.PrimaryAuthSessionID, actor.UserID, actor.ScopeID, now).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return active, err
}

func loadTarget(ctx context.Context, tx pgx.Tx, tenantID, scopeID, userID uuid.UUID) (targetState, error) {
	var state targetState
	err := tx.QueryRow(ctx, `SELECT scope.kind,COALESCE(tenant.parent_scope_id,'00000000-0000-0000-0000-000000000000'),
		tenant.status,users.status,membership.status,users.username,users.display_id::text,users.display_name,
		COALESCE(array_agg(DISTINCT role.name)
			FILTER (WHERE role.name IS NOT NULL), '{}'::text[]),
		COALESCE(array_agg(DISTINCT permission.permission_name)
			FILTER (WHERE permission.permission_name IS NOT NULL), '{}'::text[])
		FROM access_scopes scope
		JOIN tenants tenant ON tenant.id=scope.tenant_id
		JOIN memberships membership ON membership.scope_id=scope.id AND membership.user_id=$3
		JOIN users ON users.id=membership.user_id
		LEFT JOIN role_assignments assignment
			ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
		LEFT JOIN roles role ON role.id=assignment.role_id
		LEFT JOIN role_permissions permission ON permission.role_id=assignment.role_id
		WHERE scope.id=$2 AND scope.tenant_id=$1
		GROUP BY scope.kind,tenant.parent_scope_id,tenant.status,users.status,membership.status,users.username,users.display_id,users.display_name`,
		tenantID, scopeID, userID).Scan(&state.scopeKind, &state.parentScopeID, &state.tenantStatus, &state.userStatus,
		&state.membershipStatus, &state.username, &state.displayID, &state.displayName, &state.roles, &state.permissions)
	if err != nil {
		return targetState{}, err
	}
	return state, nil
}

func lockIdempotency(ctx context.Context, tx pgx.Tx, operation string, scopeID, actorID uuid.UUID, key string) error {
	lockKey := operation + ":" + scopeID.String() + ":" + actorID.String() + ":" + key
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, lockKey)
	return err
}

func loadGrantByIdempotency(ctx context.Context, tx pgx.Tx, actor Actor, key string) (storedGrant, bool, error) {
	var grant storedGrant
	err := scanGrant(tx.QueryRow(ctx, `SELECT id,tenant_id,tenant_scope_id,actor_user_id,actor_scope_id,
		primary_auth_session_id,subject_user_id,created_at,expires_at,code_digest,
		subject_permissions_digest,request_digest
		FROM admin_impersonation_grants
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND idempotency_key=$3
		FOR UPDATE`, actor.ScopeID, actor.UserID, key), &grant)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedGrant{}, false, nil
	}
	return grant, err == nil, err
}

func loadGrant(ctx context.Context, tx pgx.Tx, tenantID, scopeID, grantID uuid.UUID) (storedGrant, error) {
	var grant storedGrant
	err := scanGrant(tx.QueryRow(ctx, `SELECT id,tenant_id,tenant_scope_id,actor_user_id,actor_scope_id,
		primary_auth_session_id,subject_user_id,created_at,expires_at,code_digest,
		subject_permissions_digest,request_digest
		FROM admin_impersonation_grants
		WHERE id=$1 AND tenant_id=$2 AND tenant_scope_id=$3`, grantID, tenantID, scopeID), &grant)
	return grant, err
}

func lockGrant(ctx context.Context, tx pgx.Tx, tenantID, scopeID, grantID uuid.UUID) (storedGrant, error) {
	var grant storedGrant
	err := scanGrant(tx.QueryRow(ctx, `SELECT id,tenant_id,tenant_scope_id,actor_user_id,actor_scope_id,
		primary_auth_session_id,subject_user_id,created_at,expires_at,code_digest,
		subject_permissions_digest,request_digest
		FROM admin_impersonation_grants
		WHERE id=$1 AND tenant_id=$2 AND tenant_scope_id=$3
		FOR UPDATE`, grantID, tenantID, scopeID), &grant)
	return grant, err
}

type rowScanner interface{ Scan(...any) error }

func scanGrant(row rowScanner, grant *storedGrant) error {
	return row.Scan(&grant.ID, &grant.TenantID, &grant.TenantScopeID, &grant.ActorUserID,
		&grant.ActorScopeID, &grant.primaryAuthSessionID, &grant.SubjectUserID,
		&grant.CreatedAt, &grant.ExpiresAt, &grant.codeDigest, &grant.subjectPermissionsDigest,
		&grant.requestDigest)
}

func loadSessionByIdempotency(ctx context.Context, tx pgx.Tx, tenantScopeID uuid.UUID, key string) (storedSession, bool, error) {
	var session storedSession
	err := scanSession(tx.QueryRow(ctx, `SELECT id,grant_id,actor_user_id,actor_scope_id,subject_user_id,
		tenant_id,tenant_scope_id,created_at,expires_at,exchange_request_digest
		FROM admin_impersonation_sessions
		WHERE tenant_scope_id=$1 AND exchange_idempotency_key=$2`, tenantScopeID, key), &session)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedSession{}, false, nil
	}
	return session, err == nil, err
}

func lockSession(ctx context.Context, tx pgx.Tx, sessionID, grantID uuid.UUID) (Session, []byte, error) {
	var session Session
	var permissionsDigest []byte
	err := tx.QueryRow(ctx, `SELECT session.id,session.grant_id,session.actor_user_id,session.actor_scope_id,
		session.subject_user_id,session.tenant_id,session.tenant_scope_id,session.created_at,
		session.expires_at,session.subject_permissions_digest
		FROM admin_impersonation_sessions session
		JOIN admin_impersonation_grants grant_row ON grant_row.id=session.grant_id
		WHERE session.id=$1 AND session.grant_id=$2
		FOR UPDATE OF grant_row`, sessionID, grantID).Scan(&session.ID, &session.GrantID, &session.ActorUserID,
		&session.ActorScopeID, &session.SubjectUserID, &session.TenantID, &session.TenantScopeID,
		&session.CreatedAt, &session.ExpiresAt, &permissionsDigest)
	return session, permissionsDigest, err
}

func scanSession(row rowScanner, session *storedSession) error {
	return row.Scan(&session.ID, &session.GrantID, &session.ActorUserID, &session.ActorScopeID,
		&session.SubjectUserID, &session.TenantID, &session.TenantScopeID, &session.CreatedAt,
		&session.ExpiresAt, &session.requestDigest)
}

func grantRevoked(ctx context.Context, tx pgx.Tx, grantID uuid.UUID) (bool, error) {
	var revoked bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM admin_impersonation_revocations WHERE grant_id=$1)`, grantID).Scan(&revoked)
	return revoked, err
}

func grantConsumed(ctx context.Context, tx pgx.Tx, grantID uuid.UUID) (bool, error) {
	var consumed bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM admin_impersonation_sessions WHERE grant_id=$1)`, grantID).Scan(&consumed)
	return consumed, err
}

func loadRevocationByIdempotency(ctx context.Context, tx pgx.Tx, actor Actor, key string) (storedRevocation, bool, error) {
	var result storedRevocation
	err := tx.QueryRow(ctx, `SELECT id,grant_id,revoked_by_user_id,reason,revoked_at,request_digest
		FROM admin_impersonation_revocations
		WHERE revoked_by_scope_id=$1 AND revoked_by_user_id=$2 AND idempotency_key=$3`,
		actor.ScopeID, actor.UserID, key).Scan(&result.ID, &result.GrantID, &result.RevokedBy,
		&result.Reason, &result.RevokedAt, &result.requestDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedRevocation{}, false, nil
	}
	return result, err == nil, err
}

func loadRevocationByGrant(ctx context.Context, tx pgx.Tx, grantID uuid.UUID) (storedRevocation, bool, error) {
	var result storedRevocation
	err := tx.QueryRow(ctx, `SELECT id,grant_id,revoked_by_user_id,reason,revoked_at,request_digest
		FROM admin_impersonation_revocations WHERE grant_id=$1`, grantID).Scan(&result.ID,
		&result.GrantID, &result.RevokedBy, &result.Reason, &result.RevokedAt, &result.requestDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedRevocation{}, false, nil
	}
	return result, err == nil, err
}

func (s *Service) sessionWithBanner(ctx context.Context, tx pgx.Tx, session Session) (Session, error) {
	actor, err := loadActor(ctx, tx, session.ActorScopeID, session.ActorUserID)
	if err != nil {
		return Session{}, err
	}
	target, err := loadTarget(ctx, tx, session.TenantID, session.TenantScopeID, session.SubjectUserID)
	if err != nil {
		return Session{}, err
	}
	session.Banner = BannerClaims{
		GrantID: session.GrantID, ActorUserID: session.ActorUserID, ActorDisplayName: actor.displayName,
		SubjectUserID: session.SubjectUserID, SubjectDisplayName: target.displayName,
		TenantID: session.TenantID, ExpiresAt: session.ExpiresAt,
	}
	session.Principal = target.principal(session.SubjectUserID, session.TenantID, session.TenantScopeID)
	return session, nil
}

func (state targetState) principal(userID, tenantID, scopeID uuid.UUID) SubjectPrincipal {
	return SubjectPrincipal{
		UserID: userID, DisplayID: state.displayID, ScopeID: scopeID, TenantID: tenantID, ScopeKind: state.scopeKind,
		Username: state.username, DisplayName: state.displayName,
		Roles:       append([]string(nil), state.roles...),
		Permissions: append([]string(nil), state.permissions...),
	}
}

func sameSessionIdentity(stored, supplied Session) bool {
	return stored.ID == supplied.ID && stored.GrantID == supplied.GrantID &&
		stored.ActorUserID == supplied.ActorUserID && stored.ActorScopeID == supplied.ActorScopeID &&
		stored.SubjectUserID == supplied.SubjectUserID && stored.TenantID == supplied.TenantID &&
		stored.TenantScopeID == supplied.TenantScopeID && stored.CreatedAt.Equal(supplied.CreatedAt) &&
		stored.ExpiresAt.Equal(supplied.ExpiresAt) && !supplied.Refreshable
}

func (s *Service) appendAudit(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, actorID, subjectID, grantID uuid.UUID,
	request RequestContext,
	action, result, reasonCode, requestedAction string,
) error {
	payload := map[string]any{"trace_id": request.TraceID}
	resourceID := scopeID.String()
	if grantID != uuid.Nil {
		payload["grant_id"] = grantID.String()
		resourceID = grantID.String()
	}
	if actorID != uuid.Nil {
		payload["actor_user_id"] = actorID.String()
	}
	if subjectID != uuid.Nil {
		payload["subject_user_id"] = subjectID.String()
	}
	if reasonCode != "" {
		payload["reason_code"] = reasonCode
	}
	if requestedAction != "" {
		payload["requested_action"] = requestedAction
	}
	var auditActor *uuid.UUID
	if actorID != uuid.Nil {
		auditActor = &actorID
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, ActorUserID: auditActor, Action: action,
		ResourceType: "admin_impersonation_grant", ResourceID: resourceID,
		RequestID: request.RequestID, Result: result, Payload: payload,
	})
}
