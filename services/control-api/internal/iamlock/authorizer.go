package iamlock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"

	"github.com/cdnca/cdnca/services/control-api/internal/apikeycredential"
	"github.com/cdnca/cdnca/services/control-api/internal/sessioncredential"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

type Authorizer struct {
	sessions *sessioncredential.Verifier
	apiKeys  *apikeycredential.Verifier
}

// Authorization is a sealed result of same-transaction credential and RBAC checks.
type Authorization struct {
	userID                uuid.UUID
	authenticationScopeID uuid.UUID
	targetScopeID         uuid.UUID
	tenantID              uuid.UUID
	credentialID          uuid.UUID
	credentialKind        string
	credentialRevision    int64
}

type scopeFact struct {
	id       uuid.UUID
	kind     string
	tenantID uuid.UUID
}

func NewAuthorizer(
	sessions *sessioncredential.Verifier,
	apiKeys *apikeycredential.Verifier,
) (*Authorizer, error) {
	if sessions == nil || apiKeys == nil {
		return nil, ErrInvalidInput
	}
	return &Authorizer{sessions: sessions, apiKeys: apiKeys}, nil
}

// Configured reports whether NewAuthorizer initialized the authorizer's in-memory dependencies.
// It does not check dependency health.
func (authorizer *Authorizer) Configured() bool {
	return authorizer != nil && authorizer.sessions.Configured() && authorizer.apiKeys.Configured()
}

func (authorizer *Authorizer) AuthorizeSession(
	ctx context.Context,
	tx pgx.Tx,
	rawToken string,
	targetScopeID uuid.UUID,
	requiredPermission string,
) (Authorization, error) {
	return authorizer.AuthorizeSessionPermissions(ctx, tx, rawToken, targetScopeID, []string{requiredPermission})
}

// AuthorizeSessionPermissions verifies the session and locks the scopes once,
// then requires and locks every permission fact. Repeated AuthorizeSession calls
// for one platform session are rejected by the scope-lock identity guard.
func (authorizer *Authorizer) AuthorizeSessionPermissions(
	ctx context.Context,
	tx pgx.Tx,
	rawToken string,
	targetScopeID uuid.UUID,
	requiredPermissions []string,
) (Authorization, error) {
	if authorizer == nil || authorizer.sessions == nil || tx == nil || targetScopeID == uuid.Nil ||
		len(requiredPermissions) == 0 {
		return Authorization{}, ErrInvalidInput
	}
	for _, permission := range requiredPermissions {
		if !permissionPattern.MatchString(permission) {
			return Authorization{}, ErrInvalidInput
		}
	}
	if !authorizer.sessions.Configured() {
		return Authorization{}, unavailable("verify session credential")
	}
	authenticationScopeID, err := authorizer.sessions.CredentialScope(rawToken)
	if err != nil {
		return Authorization{}, ErrInvalidCredential
	}
	if err := authorizer.preflightSessionCredential(ctx, tx, rawToken, authenticationScopeID); err != nil {
		return Authorization{}, err
	}
	if err := AcquireShared(ctx, tx); err != nil {
		return Authorization{}, err
	}
	lockedScopes, err := AcquireScopes(ctx, tx, []uuid.UUID{authenticationScopeID, targetScopeID})
	if err != nil {
		return Authorization{}, err
	}
	scopes, err := lockAuthorityScopes(ctx, tx, lockedScopes)
	if err != nil {
		return Authorization{}, err
	}
	credential, err := authorizer.sessions.VerifyTx(ctx, tx, rawToken, lockedScopes)
	if err != nil {
		return Authorization{}, mapSessionCredentialError(err)
	}
	authenticationScope, exists := scopes[credential.ScopeID()]
	if !exists || authenticationScope.kind != credential.ScopeKind() {
		return Authorization{}, ErrPermissionDenied
	}
	targetScope, exists := scopes[targetScopeID]
	if !exists || credential.ScopeKind() == "tenant" && credential.ScopeID() != targetScopeID {
		return Authorization{}, ErrPermissionDenied
	}
	permissions := append([]string(nil), requiredPermissions...)
	sort.Strings(permissions)
	for index, permission := range permissions {
		if index > 0 && permission == permissions[index-1] {
			continue
		}
		if err := lockPermissionFacts(ctx, tx, credential.ScopeID(), credential.UserID(),
			permission, credential.ScopeKind() == "platform"); err != nil {
			return Authorization{}, err
		}
	}
	authorization := Authorization{
		userID: credential.UserID(), authenticationScopeID: credential.ScopeID(),
		targetScopeID: targetScopeID, tenantID: targetScope.tenantID,
		credentialID: credential.SessionID(), credentialKind: "session",
	}
	if !authorization.Valid() {
		return Authorization{}, ErrPermissionDenied
	}
	return authorization, nil
}

func (authorizer *Authorizer) preflightSessionCredential(
	ctx context.Context,
	tx pgx.Tx,
	rawToken string,
	authenticationScopeID uuid.UUID,
) error {
	preflight, err := tx.Begin(ctx)
	if err != nil {
		return unavailable("begin session credential preflight")
	}
	defer func() { _ = preflight.Rollback(context.Background()) }()
	if err := AcquireShared(ctx, preflight); err != nil {
		return err
	}
	lockedScopes, err := AcquireScopes(ctx, preflight, []uuid.UUID{authenticationScopeID})
	if err != nil {
		return err
	}
	if _, err := authorizer.sessions.VerifyTx(ctx, preflight, rawToken, lockedScopes); err != nil {
		return mapSessionCredentialError(err)
	}
	if err := preflight.Rollback(ctx); err != nil {
		return unavailable("rollback session credential preflight")
	}
	return nil
}

func (authorizer *Authorizer) AuthorizeAPIKey(
	ctx context.Context,
	tx pgx.Tx,
	rawCredential string,
	targetScopeID uuid.UUID,
	requiredPermission string,
) (Authorization, error) {
	if authorizer == nil || authorizer.apiKeys == nil || tx == nil || targetScopeID == uuid.Nil ||
		!permissionPattern.MatchString(requiredPermission) {
		return Authorization{}, ErrInvalidInput
	}
	if !authorizer.apiKeys.Configured() {
		return Authorization{}, unavailable("verify API key credential")
	}
	if err := AcquireShared(ctx, tx); err != nil {
		return Authorization{}, err
	}
	lockedScopes, err := AcquireScopes(ctx, tx, []uuid.UUID{targetScopeID})
	if err != nil {
		return Authorization{}, err
	}
	scopes, err := lockAuthorityScopes(ctx, tx, lockedScopes)
	if err != nil {
		return Authorization{}, err
	}
	targetScope, exists := scopes[targetScopeID]
	if !exists || targetScope.kind != "tenant" || targetScope.tenantID == uuid.Nil {
		return Authorization{}, ErrPermissionDenied
	}
	credential, err := authorizer.apiKeys.VerifyTx(ctx, tx, rawCredential, targetScopeID, lockedScopes)
	if err != nil {
		return Authorization{}, mapAPIKeyCredentialError(err)
	}
	if !credential.Allows(requiredPermission) {
		return Authorization{}, ErrPermissionDenied
	}
	if err := lockPermissionFacts(ctx, tx, credential.ScopeID(), credential.UserID(),
		requiredPermission, false); err != nil {
		return Authorization{}, err
	}
	authorization := Authorization{
		userID: credential.UserID(), authenticationScopeID: credential.ScopeID(),
		targetScopeID: targetScopeID, tenantID: targetScope.tenantID,
		credentialID: credential.ID(), credentialKind: "api_key",
		credentialRevision: credential.Revision(),
	}
	if !authorization.Valid() {
		return Authorization{}, ErrPermissionDenied
	}
	return authorization, nil
}

func (authorization Authorization) UserID() uuid.UUID { return authorization.userID }
func (authorization Authorization) AuthenticationScopeID() uuid.UUID {
	return authorization.authenticationScopeID
}
func (authorization Authorization) TargetScopeID() uuid.UUID { return authorization.targetScopeID }
func (authorization Authorization) CredentialID() uuid.UUID  { return authorization.credentialID }
func (authorization Authorization) CredentialKind() string   { return authorization.credentialKind }
func (authorization Authorization) CredentialRevision() int64 {
	return authorization.credentialRevision
}
func (authorization Authorization) TenantID() (uuid.UUID, bool) {
	return authorization.tenantID, authorization.tenantID != uuid.Nil
}

func (authorization Authorization) Valid() bool {
	if authorization.userID == uuid.Nil || authorization.authenticationScopeID == uuid.Nil ||
		authorization.targetScopeID == uuid.Nil || authorization.credentialID == uuid.Nil {
		return false
	}
	return authorization.credentialKind == "session" && authorization.credentialRevision == 0 ||
		authorization.credentialKind == "api_key" && authorization.credentialRevision >= 1
}

func (Authorization) String() string   { return "iamlock.Authorization{credential:redacted}" }
func (Authorization) GoString() string { return "iamlock.Authorization{credential:redacted}" }

func (Authorization) MarshalJSON() ([]byte, error) {
	return nil, errors.New("IAM authorization serialization forbidden")
}

func lockAuthorityScopes(
	ctx context.Context,
	tx pgx.Tx,
	lockedScopes []uuid.UUID,
) (map[uuid.UUID]scopeFact, error) {
	rows, err := tx.Query(ctx, `SELECT id,kind,tenant_id FROM access_scopes
		WHERE id=ANY($1::uuid[]) ORDER BY id FOR KEY SHARE`, lockedScopes)
	if err != nil {
		return nil, unavailable("lock authority scopes")
	}
	defer rows.Close()
	scopes := make(map[uuid.UUID]scopeFact, len(lockedScopes))
	tenantIDs := make([]uuid.UUID, 0, len(lockedScopes))
	for rows.Next() {
		var fact scopeFact
		var tenantID *uuid.UUID
		if err := rows.Scan(&fact.id, &fact.kind, &tenantID); err != nil {
			return nil, unavailable("scan authority scope")
		}
		if tenantID != nil {
			fact.tenantID = *tenantID
			tenantIDs = append(tenantIDs, *tenantID)
		}
		if fact.kind != "platform" && fact.kind != "tenant" ||
			fact.kind == "platform" && fact.tenantID != uuid.Nil ||
			fact.kind == "tenant" && fact.tenantID == uuid.Nil {
			return nil, ErrPermissionDenied
		}
		scopes[fact.id] = fact
	}
	if rows.Err() != nil {
		return nil, unavailable("read authority scopes")
	}
	if len(scopes) != len(lockedScopes) {
		return nil, ErrPermissionDenied
	}
	if len(tenantIDs) == 0 {
		return scopes, nil
	}
	sort.Slice(tenantIDs, func(i, j int) bool { return tenantIDs[i].String() < tenantIDs[j].String() })
	tenantRows, err := tx.Query(ctx, `SELECT id,status FROM tenants
		WHERE id=ANY($1::uuid[]) ORDER BY id FOR SHARE`, tenantIDs)
	if err != nil {
		return nil, unavailable("lock authority tenants")
	}
	defer tenantRows.Close()
	active := 0
	for tenantRows.Next() {
		var tenantID uuid.UUID
		var status string
		if err := tenantRows.Scan(&tenantID, &status); err != nil {
			return nil, unavailable("scan authority tenant")
		}
		if status != "active" {
			return nil, ErrPermissionDenied
		}
		active++
	}
	if tenantRows.Err() != nil {
		return nil, unavailable("read authority tenants")
	}
	if active != len(tenantIDs) {
		return nil, ErrPermissionDenied
	}
	return scopes, nil
}

func lockPermissionFacts(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, userID uuid.UUID,
	requiredPermission string,
	allowPlatformAdmin bool,
) error {
	rows, err := tx.Query(ctx, `SELECT role_id FROM role_assignments
		WHERE scope_id=$1 AND user_id=$2 ORDER BY role_id FOR SHARE`, scopeID, userID)
	if err != nil {
		return unavailable("lock role assignments")
	}
	roleIDs := make([]uuid.UUID, 0, 4)
	for rows.Next() {
		var roleID uuid.UUID
		if err := rows.Scan(&roleID); err != nil {
			rows.Close()
			return unavailable("scan role assignment")
		}
		roleIDs = append(roleIDs, roleID)
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return unavailable("read role assignments")
	}
	if len(roleIDs) == 0 {
		return ErrPermissionDenied
	}

	roleRows, err := tx.Query(ctx, `SELECT id FROM roles
		WHERE scope_id=$1 AND id=ANY($2::uuid[]) ORDER BY id FOR SHARE`, scopeID, roleIDs)
	if err != nil {
		return unavailable("lock roles")
	}
	roleCount := 0
	for roleRows.Next() {
		roleCount++
	}
	rowErr = roleRows.Err()
	roleRows.Close()
	if rowErr != nil {
		return unavailable("read roles")
	}
	if roleCount != len(roleIDs) {
		return ErrPermissionDenied
	}

	candidates := []string{requiredPermission}
	if allowPlatformAdmin && requiredPermission != "platform.admin" {
		candidates = append(candidates, "platform.admin")
		sort.Strings(candidates)
	}
	permissionRows, err := tx.Query(ctx, `SELECT name FROM permissions
		WHERE name=ANY($1::text[]) ORDER BY name FOR SHARE`, candidates)
	if err != nil {
		return unavailable("lock permission catalog")
	}
	permissionCount := 0
	for permissionRows.Next() {
		permissionCount++
	}
	rowErr = permissionRows.Err()
	permissionRows.Close()
	if rowErr != nil {
		return unavailable("read permission catalog")
	}
	if permissionCount < 1 {
		return ErrPermissionDenied
	}

	mappingRows, err := tx.Query(ctx, `SELECT role_id,permission_name FROM role_permissions
		WHERE role_id=ANY($1::uuid[]) AND permission_name=ANY($2::text[])
		ORDER BY role_id,permission_name FOR SHARE`, roleIDs, candidates)
	if err != nil {
		return unavailable("lock role permissions")
	}
	allowed := false
	for mappingRows.Next() {
		var roleID uuid.UUID
		var permission string
		if err := mappingRows.Scan(&roleID, &permission); err != nil {
			mappingRows.Close()
			return unavailable("scan role permission")
		}
		if permission == requiredPermission || allowPlatformAdmin && permission == "platform.admin" {
			allowed = true
		}
	}
	rowErr = mappingRows.Err()
	mappingRows.Close()
	if rowErr != nil {
		return unavailable("read role permissions")
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

func mapSessionCredentialError(err error) error {
	switch {
	case errors.Is(err, sessioncredential.ErrInvalidCredential):
		return ErrInvalidCredential
	case errors.Is(err, sessioncredential.ErrProtocolRequired):
		return ErrProtocolRequired
	default:
		return unavailable("verify session credential")
	}
}

func mapAPIKeyCredentialError(err error) error {
	switch {
	case errors.Is(err, apikeycredential.ErrInvalidCredential):
		return ErrInvalidCredential
	case errors.Is(err, apikeycredential.ErrProtocolRequired):
		return ErrProtocolRequired
	default:
		return unavailable("verify API key credential")
	}
}

func unavailable(operation string) error {
	return fmt.Errorf("%w: %s", ErrUnavailable, operation)
}

var _ json.Marshaler = Authorization{}
