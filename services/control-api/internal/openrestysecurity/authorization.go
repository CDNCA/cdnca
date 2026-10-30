package openrestysecurity

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Actor struct {
	UserID         uuid.UUID
	ScopeID        uuid.UUID
	ScopeKind      string
	Permissions    []string
	credentialKind string
	credentialID   uuid.UUID
	rawCredential  string
	tenantID       *uuid.UUID
}

func (Actor) String() string   { return "openrestysecurity.Actor{credential:redacted}" }
func (Actor) GoString() string { return "openrestysecurity.Actor{credential:redacted}" }
func (Actor) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("openrestysecurity.Actor{credential:redacted}"))
}

func (actor Actor) WithCredential(kind string, credentialID uuid.UUID, raw string, tenantID *uuid.UUID) Actor {
	actor.credentialKind, actor.credentialID, actor.rawCredential = kind, credentialID, raw
	if tenantID != nil {
		value := *tenantID
		actor.tenantID = &value
	}
	return actor
}

func validateActor(actor Actor, targetScopeID uuid.UUID, permission string) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || targetScopeID == uuid.Nil ||
		actor.ScopeKind != ScopeTenant && actor.ScopeKind != ScopePlatform {
		return ErrUnauthenticated
	}
	if actor.ScopeKind != ScopePlatform {
		return ErrPermissionDenied
	}
	if actor.ScopeID != targetScopeID {
		return ErrNotFound
	}
	if !slices.Contains(actor.Permissions, permission) && !slices.Contains(actor.Permissions, "platform.admin") {
		return ErrPermissionDenied
	}
	return nil
}

// TenantRuleGroupReadPermission is what a tenant needs to read the system rule
// catalog and rule groups. Migration 222 removed openresty_security.* from
// tenant_owner (global OpenResty config is platform-only); tenants read the
// catalog through their security policy permission (migration 230 projection).
const TenantRuleGroupReadPermission = "security_policies.read"

func ruleGroupReadPermission(scopeKind string) string {
	if scopeKind == ScopeTenant {
		return TenantRuleGroupReadPermission
	}
	return PermissionRead
}

func validateRuleGroupActor(actor Actor, targetScopeID uuid.UUID) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || targetScopeID == uuid.Nil ||
		(actor.ScopeKind != ScopeTenant && actor.ScopeKind != ScopePlatform) {
		return ErrUnauthenticated
	}
	if actor.ScopeID != targetScopeID {
		return ErrNotFound
	}
	if !slices.Contains(actor.Permissions, ruleGroupReadPermission(actor.ScopeKind)) && !slices.Contains(actor.Permissions, "platform.admin") {
		return ErrPermissionDenied
	}
	if actor.ScopeKind == ScopeTenant && actor.tenantID == nil {
		return ErrPermissionDenied
	}
	return nil
}

type TxAuthorizer interface {
	Authorize(context.Context, pgx.Tx, Actor, uuid.UUID, string) error
}

type ruleGroupAuthorizer interface {
	AuthorizeRuleGroups(context.Context, pgx.Tx, Actor, uuid.UUID) error
}

type iamTxAuthorizer struct{ iam *iamlock.Authorizer }

func NewIAMTxAuthorizer(iam *iamlock.Authorizer) (TxAuthorizer, error) {
	if iam == nil || !iam.Configured() {
		return nil, ErrUnavailable
	}
	return iamTxAuthorizer{iam: iam}, nil
}

func (authorizer iamTxAuthorizer) Authorize(ctx context.Context, tx pgx.Tx, actor Actor, targetScopeID uuid.UUID, permission string) error {
	if err := validateActor(actor, targetScopeID, permission); err != nil {
		return err
	}
	return authorizer.authorize(ctx, tx, actor, targetScopeID, permission, false)
}

func (authorizer iamTxAuthorizer) AuthorizeRuleGroups(ctx context.Context, tx pgx.Tx, actor Actor, targetScopeID uuid.UUID) error {
	if err := validateRuleGroupActor(actor, targetScopeID); err != nil {
		return err
	}
	return authorizer.authorize(ctx, tx, actor, targetScopeID, ruleGroupReadPermission(actor.ScopeKind), true)
}

func (authorizer iamTxAuthorizer) authorize(ctx context.Context, tx pgx.Tx, actor Actor, targetScopeID uuid.UUID, permission string, allowTenant bool) error {
	if tx == nil || actor.rawCredential == "" || targetScopeID == uuid.Nil ||
		(permission != PermissionRead && permission != PermissionManage &&
			(!allowTenant || permission != TenantRuleGroupReadPermission)) {
		return ErrPermissionDenied
	}
	var sealed iamlock.Authorization
	var err error
	switch actor.credentialKind {
	case CredentialSession:
		sealed, err = authorizer.iam.AuthorizeSession(ctx, tx, actor.rawCredential, targetScopeID, permission)
	case CredentialAPIKey:
		sealed, err = authorizer.iam.AuthorizeAPIKey(ctx, tx, actor.rawCredential, targetScopeID, permission)
	default:
		return ErrPermissionDenied
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		switch {
		case errors.Is(err, iamlock.ErrInvalidCredential):
			return ErrUnauthenticated
		case errors.Is(err, iamlock.ErrPermissionDenied), errors.Is(err, iamlock.ErrInvalidInput):
			return ErrPermissionDenied
		default:
			return ErrUnavailable
		}
	}
	if !sealed.Valid() || sealed.UserID() != actor.UserID || sealed.AuthenticationScopeID() != actor.ScopeID ||
		sealed.TargetScopeID() != targetScopeID || sealed.CredentialKind() != actor.credentialKind {
		return ErrUnauthenticated
	}
	if actor.credentialKind == CredentialSession && (actor.credentialID == uuid.Nil || sealed.CredentialID() != actor.credentialID) {
		return ErrUnauthenticated
	}
	_, hasTenant := sealed.TenantID()
	if actor.ScopeKind == ScopePlatform && (hasTenant || actor.tenantID != nil || actor.credentialKind != CredentialSession) {
		return ErrPermissionDenied
	}
	if actor.ScopeKind == ScopeTenant && (!allowTenant || !hasTenant || actor.tenantID == nil || *actor.tenantID != sealedTenantID(sealed)) {
		return ErrPermissionDenied
	}
	return nil
}

func sealedTenantID(authorization iamlock.Authorization) uuid.UUID {
	tenantID, _ := authorization.TenantID()
	return tenantID
}
