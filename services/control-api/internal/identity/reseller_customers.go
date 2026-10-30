package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ADR 0018 RS-05：代理商管理自己的客户（子租户）。代理商是租户会话，持
// reseller.customers.read（读）/ reseller.customers.manage（开户、停用、启用），
// 只能看到、改到 tenants.parent_scope_id = 本代理商 scope 的客户 owner 用户。
// 开户复用 CreateManagedUser 的事务，新租户带 parent_scope_id（480 守卫复核
// 有效代理商与客户上限）；客户永远是 tenant_owner，不进平台用户分组。

const (
	PermissionResellerCustomersRead   = "reseller.customers.read"
	PermissionResellerCustomersManage = "reseller.customers.manage"
)

var ErrResellerCustomerLimit = errors.New("reseller customer limit reached")

type ResellerCustomerListInput struct {
	Page   int
	Limit  int
	Search string
	Status string
}

type ResellerCustomerStatusInput struct {
	UserID           uuid.UUID
	ExpectedRevision int64
	Status           string
	RequestID        string
}

func validResellerActor(actor Actor) bool { return validTenantActor(actor) }

// ListResellerCustomers lists the owner users of the reseller's customer tenants.
func (s *Service) ListResellerCustomers(ctx context.Context, actor Actor, input ResellerCustomerListInput) (UserList, error) {
	input.Search = strings.TrimSpace(input.Search)
	if !validResellerActor(actor) || input.Page < 1 || input.Page > 1_000_000 || input.Limit < 1 || input.Limit > 100 ||
		utf8.RuneCountInString(input.Search) > 128 || (input.Status != "" && !validUserStatus(input.Status)) {
		return UserList{}, ErrInvalidUserInput
	}
	return s.store.ListResellerCustomers(ctx, actor, input)
}

// CreateResellerCustomer opens a customer tenant under the reseller.
func (s *Service) CreateResellerCustomer(ctx context.Context, actor Actor, input CreateUserInput) (ManagedUser, error) {
	input.Username = strings.ToLower(strings.TrimSpace(input.Username))
	input.Role, input.GroupID = UserRoleOwner, nil
	if !validResellerActor(actor) || !validWriteMetadata(input.IdempotencyKey, input.RequestID) {
		return ManagedUser{}, ErrInvalidUserInput
	}
	if err := usernameField(input.Username); err != nil {
		return ManagedUser{}, err
	}
	if err := normalizeUserMetadata(input.Remark, input.QQ); err != nil {
		return ManagedUser{}, err
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
		Parent   uuid.UUID  `json:"parent_scope_id"`
		Remark   *string    `json:"remark,omitempty"`
		QQ       *string    `json:"qq,omitempty"`
	}{input.Username, input.Fields, actor.ScopeID, input.Remark, input.QQ})
	if err != nil {
		return ManagedUser{}, err
	}
	ids := make([]uuid.UUID, 5)
	for index := range ids {
		if ids[index], err = newUUID(); err != nil {
			return ManagedUser{}, err
		}
	}
	parent := actor.ScopeID
	return s.store.CreateManagedUser(ctx, actor, createUserRecord{
		CreateUserInput: input,
		UserID:          ids[0], TenantID: ids[1], ScopeID: ids[2], OwnerRoleID: ids[3], ViewerRoleID: ids[4],
		PasswordHash: passwordHash, Digest: digest, ParentScopeID: &parent,
	})
}

// SetResellerCustomerStatus suspends (disabled) or resumes (active) a customer owner user.
func (s *Service) SetResellerCustomerStatus(ctx context.Context, actor Actor, input ResellerCustomerStatusInput) (ManagedUser, error) {
	if !validResellerActor(actor) || input.UserID == uuid.Nil || input.ExpectedRevision < 1 ||
		!validUserStatus(input.Status) || strings.TrimSpace(input.RequestID) == "" {
		return ManagedUser{}, ErrInvalidUserInput
	}
	return s.store.SetResellerCustomerStatus(ctx, actor, input)
}

const resellerCustomerPredicate = `scope.kind = 'tenant' AND assigned.role = 'tenant_owner'
	AND EXISTS (SELECT 1 FROM tenants customer WHERE customer.id = scope.tenant_id AND customer.parent_scope_id = $1)
	AND NOT EXISTS (SELECT 1 FROM identity_user_deletions deletion WHERE deletion.user_id = u.id)`

func (s *Store) ListResellerCustomers(ctx context.Context, actor Actor, input ResellerCustomerListInput) (UserList, error) {
	result := UserList{Items: []ManagedUser{}, Page: input.Page, Limit: input.Limit}
	var items []byte
	err := s.pool.QueryRow(ctx, `
		WITH filtered AS MATERIALIZED (`+managedUserQuery+`
			WHERE `+resellerCustomerPredicate+`
			  AND ($2 = '' OR position(lower($2) in lower(concat_ws(' ', u.username, u.display_name, u.email, u.phone, u.display_id::text))) > 0)
			  AND ($3 = '' OR u.status = $3)
		), page AS (
			SELECT * FROM filtered ORDER BY created_at DESC, id DESC LIMIT $4 OFFSET $5
		)
		SELECT (SELECT count(*) FROM filtered), COALESCE((
			SELECT jsonb_agg((to_jsonb(page)-'remark'-'qq') ||
				jsonb_build_object('metadata', jsonb_build_object('remark',remark,'qq',qq))
				ORDER BY created_at DESC, id DESC) FROM page
		), '[]'::jsonb)`,
		actor.ScopeID, input.Search, input.Status, input.Limit, (input.Page-1)*input.Limit,
	).Scan(&result.Total, &items)
	if err != nil {
		return UserList{}, fmt.Errorf("list reseller customers: %w", err)
	}
	if err := json.Unmarshal(items, &result.Items); err != nil {
		return UserList{}, fmt.Errorf("decode reseller customers: %w", err)
	}
	for index := range result.Items {
		result.Items[index].GroupID, result.Items[index].GroupName = nil, nil
	}
	return result, nil
}

func (s *Store) SetResellerCustomerStatus(ctx context.Context, actor Actor, input ResellerCustomerStatusInput) (ManagedUser, error) {
	var result ManagedUser
	var scopeHints []uuid.UUID
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		scopeHints, err = collectUserAuthorityScopes(ctx, tx, input.UserID)
		return err
	})
	if err != nil {
		return ManagedUser{}, fmt.Errorf("prepare reseller customer status: %w", err)
	}
	if len(scopeHints) == 0 {
		return ManagedUser{}, ErrUserNotFound
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationUserUpdate, mergeAuthorityScopes(scopeHints, actor.ScopeID),
		); err != nil {
			return err
		}
		if err := authorizeResellerCustomerManager(ctx, tx, actor); err != nil {
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
		// 只认本代理商客户租户的 owner；其它一律当不存在（不泄露别家用户）。
		var mine bool
		if !target.platform && target.tenantID != nil && target.role == UserRoleOwner && target.deletedAt == nil {
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE id=$1 AND parent_scope_id=$2)`,
				*target.tenantID, actor.ScopeID).Scan(&mine); err != nil {
				return err
			}
		}
		if !mine {
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
		result.GroupID, result.GroupName = nil, nil
		payload := map[string]any{"previous_status": target.status, "status": input.Status,
			"reseller_scope_id": actor.ScopeID.String(), "customer_scope_id": target.scopeID.String(), "revision": result.Revision}
		for _, scope := range []uuid.UUID{actor.ScopeID, target.scopeID} {
			if err := s.auditor.Append(ctx, tx, audit.Event{
				ScopeID: scope, ActorUserID: &actor.UserID, Action: "reseller.customer.status",
				ResourceType: "user", ResourceID: input.UserID.String(), RequestID: input.RequestID,
				Result: "success", Payload: payload,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return ManagedUser{}, fmt.Errorf("set reseller customer status: %w", err)
	}
	return result, nil
}

// authorizeResellerCustomerManager: the actor is an active member of an active
// reseller scope whose owner role carries reseller.customers.manage (480 grants
// it only while the profile is active, so a suspended reseller fails here).
func authorizeResellerCustomerManager(ctx context.Context, tx pgx.Tx, actor Actor) error {
	if actor.bridge != nil {
		return authorizeBridgeActor(ctx, tx, actor, PermissionResellerCustomersManage)
	}
	if !validResellerActor(actor) {
		return ErrPermissionDenied
	}
	var allowed bool
	if err := tx.QueryRow(ctx, `
		SELECT reseller_scope_active_480($2) AND EXISTS (
			SELECT 1 FROM users actor_user
			JOIN memberships membership ON membership.user_id = actor_user.id AND membership.status = 'active'
			JOIN role_assignments assignment ON assignment.scope_id = membership.scope_id AND assignment.user_id = actor_user.id
			JOIN role_permissions permission ON permission.role_id = assignment.role_id
			WHERE actor_user.id = $1 AND actor_user.status = 'active' AND membership.scope_id = $2
			  AND permission.permission_name = $3)`,
		actor.UserID, actor.ScopeID, PermissionResellerCustomersManage,
	).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}

// resellerCustomerError maps the 480 tenant parent guard: P4808 the
// reseller's customer limit, P4804 the reseller is no longer active.
func resellerCustomerError(err error) error {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		switch pgErr.SQLState() {
		case "P4808":
			return ErrResellerCustomerLimit
		case "P4804":
			return ErrPermissionDenied
		}
	}
	return err
}
