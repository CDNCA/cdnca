package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/bridgeauth"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ADR 0019 §4.4 billing bridge: the facade opens and disables customer
// accounts with a bridge actor. A (reseller) reuses the reseller customer
// paths with reseller.customers.manage; B (platform) opens and disables
// direct customers only (tenants.parent_scope_id IS NULL) with
// identity.users.manage. The actor has no session and is refused by every
// other identity path (they need a session or an administrator).

const PermissionUsersManage = "identity.users.manage"

// NewBridgeActor is the billing bridge facade's actor (owner scope, as the
// key's creator).
func NewBridgeActor(grant *bridgeauth.Grant) (Actor, error) {
	if !grant.Valid() {
		return Actor{}, ErrPermissionDenied
	}
	actor := Actor{UserID: grant.ActingUserID(), ScopeID: grant.OwnerScopeID(), ScopeKind: "tenant", bridge: grant}
	if grant.Platform() {
		actor.ScopeKind = "platform"
	}
	return actor, nil
}

// Bridge reports whether the actor came from the billing bridge facade.
func (actor Actor) Bridge() bool { return actor.bridge != nil }

// authorizeBridgeActor re-checks the key, owner and lease in tx and that
// permission is in the owner kind's fixed set.
func authorizeBridgeActor(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	grant := actor.bridge
	if tx == nil || !grant.Valid() || actor.SessionID != uuid.Nil || actor.UserID != grant.ActingUserID() ||
		actor.ScopeID != grant.OwnerScopeID() || !grant.Allows(permission) ||
		(grant.Platform() != (actor.ScopeKind == "platform")) {
		return ErrPermissionDenied
	}
	if err := grant.VerifyTx(ctx, tx); err != nil {
		if errors.Is(err, bridgeauth.ErrDenied) || errors.Is(err, bridgeauth.ErrNotLicensed) {
			return errors.Join(ErrPermissionDenied, err)
		}
		return err
	}
	return nil
}

// CreateBridgeCustomer opens the owner user of a new customer tenant for the
// bridge: under the reseller (A) or as a platform direct customer (B).
func (s *Service) CreateBridgeCustomer(ctx context.Context, actor Actor, input CreateUserInput) (ManagedUser, error) {
	if !actor.bridge.Valid() {
		return ManagedUser{}, ErrPermissionDenied
	}
	if actor.bridge.Reseller() {
		return s.CreateResellerCustomer(ctx, actor, input)
	}
	input.Username = strings.ToLower(strings.TrimSpace(input.Username))
	input.Role, input.GroupID = UserRoleOwner, nil
	if !validUsername(input.Username) || !validWriteMetadata(input.IdempotencyKey, input.RequestID) ||
		normalizeUserMetadata(input.Remark, input.QQ) != nil {
		return ManagedUser{}, ErrInvalidUserInput
	}
	if err := CheckNewPassword(input.Password); err != nil {
		return ManagedUser{}, err
	}
	if err := s.normalizeUserFieldsFor(ctx, actor, &input.Fields); err != nil {
		return ManagedUser{}, err
	}
	passwordHash, err := HashPassword(input.Password)
	if err != nil {
		return ManagedUser{}, ErrInvalidUserInput
	}
	digest, err := digestIdentityRequest(struct {
		Username string     `json:"username"`
		Fields   UserFields `json:"fields"`
		Bridge   string     `json:"bridge"`
	}{input.Username, input.Fields, "platform"})
	if err != nil {
		return ManagedUser{}, err
	}
	ids := make([]uuid.UUID, 5)
	for index := range ids {
		if ids[index], err = newUUID(); err != nil {
			return ManagedUser{}, err
		}
	}
	return s.store.CreateManagedUser(ctx, actor, createUserRecord{
		CreateUserInput: input,
		UserID:          ids[0], TenantID: ids[1], ScopeID: ids[2], OwnerRoleID: ids[3], ViewerRoleID: ids[4],
		PasswordHash: passwordHash, Digest: digest,
	})
}

// SetBridgeCustomerStatus disables or resumes a customer owner user for the
// bridge (Q3: terminate with no live service left disables the account). A
// reseller key reaches only its customers, a platform key only direct
// customers; anything else is ErrUserNotFound.
func (s *Service) SetBridgeCustomerStatus(ctx context.Context, actor Actor, input ResellerCustomerStatusInput) (ManagedUser, error) {
	if !actor.bridge.Valid() {
		return ManagedUser{}, ErrPermissionDenied
	}
	if actor.bridge.Reseller() {
		return s.SetResellerCustomerStatus(ctx, actor, input)
	}
	if input.UserID == uuid.Nil || input.ExpectedRevision < 1 || !validUserStatus(input.Status) ||
		strings.TrimSpace(input.RequestID) == "" {
		return ManagedUser{}, ErrInvalidUserInput
	}
	return s.store.setBridgeDirectCustomerStatus(ctx, actor, input)
}

func (s *Store) setBridgeDirectCustomerStatus(ctx context.Context, actor Actor, input ResellerCustomerStatusInput) (ManagedUser, error) {
	var scopeHints []uuid.UUID
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		scopeHints, err = collectUserAuthorityScopes(ctx, tx, input.UserID)
		return err
	})
	if err != nil {
		return ManagedUser{}, fmt.Errorf("prepare bridge customer status: %w", err)
	}
	if len(scopeHints) == 0 {
		return ManagedUser{}, ErrUserNotFound
	}
	var result ManagedUser
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationUserUpdate, mergeAuthorityScopes(scopeHints, actor.ScopeID),
		); err != nil {
			return err
		}
		if err := authorizeBridgeActor(ctx, tx, actor, PermissionUsersManage); err != nil {
			return err
		}
		current, err := collectUserAuthorityScopes(ctx, tx, input.UserID)
		if err != nil {
			return err
		}
		if !equalAuthorityScopes(current, scopeHints) {
			return ErrConflict
		}
		target, err := lockManagedUserTarget(ctx, tx, input.UserID)
		if err != nil {
			return err
		}
		direct := false
		if !target.platform && target.tenantID != nil && target.role == UserRoleOwner && target.deletedAt == nil {
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id=$1 AND parent_scope_id IS NULL)`,
				*target.tenantID).Scan(&direct); err != nil {
				return err
			}
		}
		if !direct {
			return ErrUserNotFound
		}
		if target.revision != input.ExpectedRevision {
			return ErrRevisionConflict
		}
		if target.status != input.Status {
			now := s.now().UTC()
			if _, err := tx.Exec(ctx, `UPDATE users SET status=$2, revision=revision+1, updated_at=$3 WHERE id=$1`,
				input.UserID, input.Status, now); err != nil {
				return err
			}
			if input.Status == UserStatusDisabled {
				if err := revokeUserSessions(ctx, tx, input.UserID, now, "account_disabled"); err != nil {
					return err
				}
			}
		}
		if result, err = getManagedUserTx(ctx, tx, input.UserID); err != nil {
			return err
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "identity.user.update",
			ResourceType: "user", ResourceID: input.UserID.String(), RequestID: input.RequestID, Result: "success",
			Payload: map[string]any{"previous_status": target.status, "status": input.Status,
				"tenant_scope_id": target.scopeID.String(), "revision": result.Revision, "source": "billing_bridge"},
		})
	})
	if err != nil {
		return ManagedUser{}, fmt.Errorf("set bridge customer status: %w", err)
	}
	return result, nil
}
