package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/cdnca/cdnca/services/control-api/internal/marketmanaged"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type PasswordCredential struct {
	PasswordHash string
	Revision     int64
}

type storedIdentityWrite struct {
	Replayed     bool
	ResponseBody []byte
	SecretHash   string
}

type identityRowScanner interface {
	Scan(dest ...any) error
}

func (s *Store) ListManagedUsers(ctx context.Context, input ListUsersInput) (UserList, error) {
	result := UserList{Items: []ManagedUser{}, Page: input.Page, Limit: input.Limit}
	var items []byte
	err := s.pool.QueryRow(ctx, `
		WITH candidates AS (`+managedUserQuery+`
			WHERE ($1 = '' OR position(lower($1) in lower(concat_ws(' ', u.username, u.display_name, u.email, u.phone))) > 0)
			  AND ($2 = '' OR u.status = $2)
			  AND ($3 = '' OR assigned.role = $3)
			  AND ($4::uuid IS NULL OR user_group.id=$4)
			  AND ($5 = '' OR u.display_id::text=$5)
			  AND ($6 = '' OR position(lower($6) in lower(u.remark)) > 0)
			  AND ($7 = '' OR position(lower($7) in lower(u.qq)) > 0)
			  AND ($8 = '' OR position(lower($8) in lower(u.username)) > 0)
			  AND ($9 = '' OR position(lower($9) in lower(u.display_name)) > 0)
			  AND ($10 = '' OR position(lower($10) in lower(u.email)) > 0)
			  AND ($11 = '' OR position(lower($11) in lower(u.phone)) > 0)
			  AND NOT EXISTS (SELECT 1 FROM identity_user_deletions deletion WHERE deletion.user_id=u.id)
			  AND (scope.kind = 'tenant' OR $16::boolean)
		), typed AS (
			-- ADR 0018 代理商投影与筛选：类型/所属代理商任一非空时只留租户用户（平台管理员没有租户）。
			SELECT base.*, tenant.parent_scope_id AS reseller_parent_scope_id,
			       profile.status AS reseller_status, parent_tenant.display_name AS reseller_parent_name
			FROM candidates base
			LEFT JOIN tenants tenant ON tenant.id = base.tenant_id
			LEFT JOIN reseller_profiles profile ON profile.scope_id = base.scope_id
			LEFT JOIN access_scopes parent_scope ON parent_scope.id = tenant.parent_scope_id
			LEFT JOIN tenants parent_tenant ON parent_tenant.id = parent_scope.tenant_id
			WHERE ($17 = '' AND $18 = '') OR (base.tenant_id IS NOT NULL
			  AND ($17 = '' OR ($17 = 'reseller' AND profile.scope_id IS NOT NULL) OR
			      ($17 = 'customer' AND tenant.parent_scope_id IS NOT NULL) OR
			      ($17 = 'direct' AND profile.scope_id IS NULL AND tenant.parent_scope_id IS NULL))
			  AND ($18 = '' OR ($18 = 'none' AND tenant.parent_scope_id IS NULL) OR
			      ($18 <> 'none' AND tenant.parent_scope_id::text = $18)))
		), verified AS (
			SELECT candidates.*,
				CASE WHEN $14 <> '' OR $15::boolean THEN EXISTS (
					SELECT 1 FROM (
						SELECT id,status,subject_fingerprint FROM identity_verification_cases
						WHERE tenant_scope_id=candidates.scope_id AND applicant_user_id=candidates.id
						  AND kind IN ('personal_initial','personal_reverification')
						ORDER BY created_at DESC,id DESC LIMIT 1
					) latest
					JOIN identity_verified_persons person ON person.tenant_scope_id=candidates.scope_id
					  AND person.applicant_user_id=candidates.id AND person.identity_fingerprint=latest.subject_fingerprint
					JOIN identity_verification_evidence_settlements settlement ON settlement.tenant_scope_id=candidates.scope_id
					  AND settlement.case_id=latest.id AND settlement.actor_user_id=candidates.id AND settlement.state='settled'
					WHERE latest.status='approved'
				) ELSE false END AS personal_verified,
				CASE WHEN $14 <> '' OR $15::boolean THEN EXISTS (
					SELECT 1 FROM (
						SELECT id,status,subject_fingerprint FROM identity_verification_cases
						WHERE tenant_scope_id=candidates.scope_id AND applicant_user_id=candidates.id AND kind='enterprise'
						ORDER BY created_at DESC,id DESC LIMIT 1
					) latest
					JOIN identity_verified_organizations organization ON organization.tenant_scope_id=candidates.scope_id
					  AND organization.subject_fingerprint=latest.subject_fingerprint AND organization.approved_case_id=latest.id
					JOIN identity_verification_evidence_settlements settlement ON settlement.tenant_scope_id=candidates.scope_id
					  AND settlement.case_id=latest.id AND settlement.actor_user_id=candidates.id AND settlement.state='settled'
					WHERE latest.status='approved'
				) ELSE false END AS company_verified
			FROM typed candidates
		), filtered AS MATERIALIZED (
			SELECT * FROM verified WHERE $14 = '' OR (personal_verified OR company_verified) = ($14 = 'verified')
		), page AS (
			SELECT * FROM filtered ORDER BY created_at DESC, id DESC LIMIT $12 OFFSET $13
		)
		SELECT (SELECT count(*) FROM filtered), COALESCE((
			SELECT jsonb_agg((to_jsonb(page)-'remark'-'qq'-'personal_verified'-'company_verified'-
				'reseller_parent_scope_id'-'reseller_status'-'reseller_parent_name') ||
				jsonb_build_object('metadata', jsonb_build_object('remark',remark,'qq',qq)) ||
				CASE WHEN $15::boolean THEN jsonb_build_object('verification', jsonb_build_object(
					'personal_verified',personal_verified,'company_verified',company_verified)) ELSE '{}'::jsonb END ||
				CASE WHEN $19::boolean THEN jsonb_build_object('reseller', jsonb_build_object(
					'is_reseller',reseller_status IS NOT NULL,'status',reseller_status,
					'parent_scope_id',reseller_parent_scope_id,'parent_name',reseller_parent_name)) ELSE '{}'::jsonb END
				ORDER BY created_at DESC, id DESC) FROM page
		), '[]'::jsonb)`,
		input.Search, input.Status, input.Role, input.GroupID, input.DisplayID, input.Remark, input.QQ,
		input.Username, input.DisplayName, input.Email, input.Phone,
		input.Limit, (input.Page-1)*input.Limit,
		input.RealNameStatus, input.IncludeVerification, input.IncludePlatformAdmins,
		input.Type, input.Parent, input.IncludeReseller,
	).Scan(&result.Total, &items)
	if err != nil {
		return UserList{}, fmt.Errorf("list managed users: %w", err)
	}
	if err := json.Unmarshal(items, &result.Items); err != nil {
		return UserList{}, fmt.Errorf("decode managed users: %w", err)
	}
	return result, nil
}

func (s *Store) GetManagedUser(ctx context.Context, id uuid.UUID) (ManagedUser, error) {
	item, err := scanManagedUser(s.pool.QueryRow(ctx, managedUserQuery+" WHERE u.id = $1 AND NOT EXISTS (SELECT 1 FROM identity_user_deletions deletion WHERE deletion.user_id=u.id)", id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ManagedUser{}, ErrUserNotFound
	}
	if err != nil {
		return ManagedUser{}, fmt.Errorf("get managed user: %w", err)
	}
	return item, nil
}

func (s *Store) CreateManagedUser(ctx context.Context, actor Actor, input createUserRecord) (ManagedUser, error) {
	var result ManagedUser
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationUserCreate, []uuid.UUID{actor.ScopeID, input.ScopeID},
		); err != nil {
			return err
		}
		write, err := s.claimIdentityWrite(
			ctx, tx, actor, "identity.user.create", input.IdempotencyKey, input.Digest, input.PasswordHash, input.Password,
		)
		if err != nil {
			return err
		}
		if write.Replayed {
			return json.Unmarshal(write.ResponseBody, &result)
		}
		if input.ParentScopeID != nil {
			if *input.ParentScopeID != actor.ScopeID {
				return ErrPermissionDenied
			}
			if err := authorizeResellerCustomerManager(ctx, tx, actor); err != nil {
				return err
			}
		} else if actor.bridge != nil {
			// ADR 0019 B: the platform bridge opens a direct customer.
			if input.Role != UserRoleOwner || input.GroupID != nil {
				return ErrPermissionDenied
			}
			if err := authorizeBridgeActor(ctx, tx, actor, PermissionUsersManage); err != nil {
				return err
			}
		}

		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `
			INSERT INTO tenants (id, display_name, created_at, updated_at, parent_scope_id)
			VALUES ($1, $2, $3, $3, $4)`, input.TenantID, input.Fields.DisplayName, now, input.ParentScopeID); err != nil {
			return resellerCustomerError(err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO access_scopes (id, kind, tenant_id, created_at)
			VALUES ($1, 'tenant', $2, $3)`, input.ScopeID, input.TenantID, now); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO users (
				id, username, display_name, email, phone, password_hash, created_at, updated_at, remark, qq
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $7, NULLIF($8,''), NULLIF($9,''))`,
			input.UserID, input.Username, input.Fields.DisplayName, nullableString(input.Fields.Email),
			nullableString(input.Fields.Phone), input.PasswordHash, now, input.Remark, input.QQ,
		); err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO memberships (scope_id, user_id, created_at)
			VALUES ($1, $2, $3)`, input.ScopeID, input.UserID, now); err != nil {
			return err
		}
		if err := SeedTenantSystemRoles(ctx, tx, input.ScopeID, input.OwnerRoleID, input.ViewerRoleID, now); err != nil {
			return err
		}
		assignedRoleID := input.OwnerRoleID
		if input.Role == UserRoleViewer {
			assignedRoleID = input.ViewerRoleID
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO role_assignments (scope_id, user_id, role_id, assigned_at)
			VALUES ($1, $2, $3, $4)`, input.ScopeID, input.UserID, assignedRoleID, now); err != nil {
			return err
		}
		if input.GroupID != nil {
			if err := requireUserGroup(ctx, tx, actor.ScopeID, *input.GroupID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO identity_user_group_memberships(platform_scope_id,group_id,user_id,created_at,updated_at)
				VALUES($1,$2,$3,$4,$4)`, actor.ScopeID, *input.GroupID, input.UserID, now,
			); err != nil {
				return err
			}
		}
		result, err = getManagedUserTx(ctx, tx, input.UserID)
		if err != nil {
			return err
		}
		auditScopes := []uuid.UUID{actor.ScopeID}
		payload := map[string]any{
			"tenant_id": input.TenantID.String(), "tenant_scope_id": input.ScopeID.String(),
			"role": input.Role, "group_id": input.GroupID,
			"remark_changed": userMetadataChanged(nil, input.Remark), "qq_changed": userMetadataChanged(nil, input.QQ),
		}
		if input.ParentScopeID != nil {
			// 代理商开户：代理商 scope 与客户 scope 各记一条（ADR 0018 §7 审计）。
			auditScopes = append(auditScopes, input.ScopeID)
			payload["reseller_scope_id"] = input.ParentScopeID.String()
			result.GroupID, result.GroupName = nil, nil
		}
		for _, scope := range auditScopes {
			if err := s.auditor.Append(ctx, tx, audit.Event{
				ScopeID: scope, ActorUserID: &actor.UserID, Action: "identity.user.create",
				ResourceType: "user", ResourceID: input.UserID.String(), RequestID: input.RequestID,
				Result: "success", Payload: payload,
			}); err != nil {
				return err
			}
		}
		return s.completeIdentityWrite(
			ctx, tx, actor.UserID, "identity.user.create", input.IdempotencyKey, input.UserID, 201, result,
		)
	})
	if err != nil {
		return ManagedUser{}, fmt.Errorf("create managed user: %w", err)
	}
	return result, nil
}

func (s *Store) UpdateManagedUser(
	ctx context.Context,
	actor Actor,
	input UpdateUserInput,
	digest [32]byte,
) (ManagedUser, error) {
	var targetScopeHint uuid.UUID
	var scopeHints []uuid.UUID
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := protocol.AcquireShared(ctx, tx); err != nil {
			return err
		}
		if err := authorizeManagedUserActor(ctx, tx, actor); err != nil {
			return err
		}
		var err error
		targetScopeHint, err = managedUserScopeHint(ctx, tx, input.ID)
		if err != nil {
			return err
		}
		scopeHints, err = collectUserAuthorityScopes(ctx, tx, input.ID)
		if err != nil {
			return err
		}
		if len(scopeHints) == 0 {
			return ErrUserNotFound
		}
		return nil
	})
	if err != nil {
		return ManagedUser{}, fmt.Errorf("prepare managed user update: %w", err)
	}
	var result ManagedUser
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationUserUpdate, mergeAuthorityScopes(scopeHints, actor.ScopeID),
		); err != nil {
			return err
		}
		if err := authorizeManagedUserActor(ctx, tx, actor); err != nil {
			return err
		}
		currentScopes, err := collectUserAuthorityScopes(ctx, tx, input.ID)
		if err != nil {
			return err
		}
		if !equalAuthorityScopes(currentScopes, scopeHints) {
			return ErrConflict
		}

		target, err := lockManagedUserTarget(ctx, tx, input.ID)
		if err != nil {
			return err
		}
		if target.scopeID != targetScopeHint {
			return ErrUserNotFound
		}
		scopeID, previousStatus, previousGroupID := target.scopeID, target.status, target.groupID
		previousRemark, previousQQ := target.remark, target.qq
		write, err := s.claimIdentityWrite(ctx, tx, actor, "identity.user.update", input.IdempotencyKey, digest, "", "")
		if err != nil {
			return err
		}
		if write.Replayed {
			return json.Unmarshal(write.ResponseBody, &result)
		}
		if target.revision != input.ExpectedRevision {
			return ErrRevisionConflict
		}
		if err := guardManagedUserUpdate(target, input.Role, input.GroupSet, input.GroupID); err != nil {
			return err
		}
		if input.Status == UserStatusDisabled && target.status != UserStatusDisabled {
			if err := marketmanaged.GuardUser(ctx, tx, actor.UserID, input.ID); err != nil {
				return err
			}
		}
		if target.role == UserRolePlatformOwner && target.status == UserStatusActive && input.Status == UserStatusDisabled {
			if err := requireRemainingPlatformOwner(ctx, tx, []uuid.UUID{input.ID}); err != nil {
				return err
			}
		}
		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `
			UPDATE users SET display_name = $2, email = $3, phone = $4, status = $5,
			                 revision = revision + 1, updated_at = $6,
			                 remark = CASE WHEN $7::text IS NULL THEN remark ELSE NULLIF($7,'') END,
			                 qq = CASE WHEN $8::text IS NULL THEN qq ELSE NULLIF($8,'') END
			WHERE id = $1`, input.ID, input.Fields.DisplayName, nullableString(input.Fields.Email),
			nullableString(input.Fields.Phone), input.Status, now, input.Remark, input.QQ,
		); err != nil {
			return err
		}
		if !target.platform {
			if err := replaceTenantUserRole(ctx, tx, *target.tenantID, scopeID, input.ID, input.Role, input.Fields.DisplayName, now); err != nil {
				return err
			}
		}
		if input.GroupSet && !target.platform {
			if err := setUserGroup(ctx, tx, actor.ScopeID, input.ID, input.GroupID, now); err != nil {
				return err
			}
		}
		if input.Status == UserStatusDisabled {
			if err := revokeUserSessions(ctx, tx, input.ID, now, "account_disabled"); err != nil {
				return err
			}
		}
		result, err = getManagedUserTx(ctx, tx, input.ID)
		if err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "identity.user.update",
			ResourceType: "user", ResourceID: input.ID.String(), RequestID: input.RequestID,
			Result: "success", Payload: map[string]any{
				"previous_status": previousStatus, "status": input.Status, "role": input.Role,
				"previous_group_id": previousGroupID, "group_id": result.GroupID, "revision": result.Revision,
				"remark_changed": userMetadataChanged(previousRemark, input.Remark), "qq_changed": userMetadataChanged(previousQQ, input.QQ),
			},
		}); err != nil {
			return err
		}
		return s.completeIdentityWrite(
			ctx, tx, actor.UserID, "identity.user.update", input.IdempotencyKey, input.ID, 200, result,
		)
	})
	if err != nil {
		return ManagedUser{}, fmt.Errorf("update managed user: %w", err)
	}
	return result, nil
}

// DeleteManagedUser records an immutable deletion marker, disables the user,
// revokes all sessions and appends an audit event in one transaction. The
// existing identity write receipt table is deliberately reused so replay and
// request-digest semantics remain identical to the other user mutations.
func (s *Store) DeleteManagedUser(
	ctx context.Context,
	actor Actor,
	input DeleteUserInput,
	digest [32]byte,
) error {
	var targetScopeHint uuid.UUID
	var scopeHints []uuid.UUID
	if err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := protocol.AcquireShared(ctx, tx); err != nil {
			return err
		}
		if err := authorizeManagedUserActor(ctx, tx, actor); err != nil {
			return err
		}
		var err error
		targetScopeHint, err = managedUserScopeHint(ctx, tx, input.ID)
		if err != nil {
			return err
		}
		scopeHints, err = collectUserAuthorityScopes(ctx, tx, input.ID)
		if err != nil {
			return err
		}
		if len(scopeHints) == 0 {
			return ErrUserNotFound
		}
		return nil
	}); err != nil {
		return fmt.Errorf("prepare managed user delete: %w", err)
	}

	returnErr := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(ctx, tx, protocol.OperationUserUpdate,
			mergeAuthorityScopes(scopeHints, actor.ScopeID)); err != nil {
			return err
		}
		if err := authorizeManagedUserActor(ctx, tx, actor); err != nil {
			return err
		}
		currentScopes, err := collectUserAuthorityScopes(ctx, tx, input.ID)
		if err != nil {
			return err
		}
		if !equalAuthorityScopes(currentScopes, scopeHints) {
			return ErrConflict
		}

		target, err := lockManagedUserTarget(ctx, tx, input.ID)
		if err != nil {
			return err
		}
		if target.scopeID != targetScopeHint {
			return ErrUserNotFound
		}
		revision, previousStatus, deletedAt := target.revision, target.status, target.deletedAt
		write, err := s.claimIdentityWrite(ctx, tx, actor, "identity.user.delete", input.IdempotencyKey, digest, "", "")
		if err != nil {
			return err
		}
		if write.Replayed {
			return nil
		}
		if revision != input.ExpectedRevision {
			return ErrRevisionConflict
		}
		if deletedAt != nil {
			return ErrUserNotFound
		}
		if input.ID == actor.UserID {
			return ErrUserProtected
		}
		if err := marketmanaged.GuardUser(ctx, tx, actor.UserID, input.ID); err != nil {
			return err
		}
		if target.role == UserRolePlatformOwner {
			if err := requireRemainingPlatformOwner(ctx, tx, []uuid.UUID{input.ID}); err != nil {
				return err
			}
		}
		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `
			INSERT INTO identity_user_deletions(user_id,platform_scope_id,deleted_by_user_id,deleted_at,revision)
			VALUES($1,$2,$3,$4,$5)`, input.ID, actor.ScopeID, actor.UserID, now, revision+1); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE users SET status='disabled',revision=revision+1,updated_at=$2 WHERE id=$1`, input.ID, now); err != nil {
			return err
		}
		if err := revokeUserSessions(ctx, tx, input.ID, now, "account_deleted"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM identity_user_group_memberships WHERE user_id=$1`, input.ID); err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "identity.user.delete",
			ResourceType: "user", ResourceID: input.ID.String(), RequestID: input.RequestID,
			Result: "success", Payload: map[string]any{
				"previous_status": previousStatus, "revision": revision + 1,
				"sessions_revoked": true,
			},
		}); err != nil {
			return err
		}
		return s.completeIdentityWrite(ctx, tx, actor.UserID, "identity.user.delete", input.IdempotencyKey,
			input.ID, 204, struct{}{})
	})
	if returnErr != nil {
		return fmt.Errorf("delete managed user: %w", returnErr)
	}
	return nil
}

func (s *Store) BatchUpdateManagedUsers(
	ctx context.Context,
	actor Actor,
	input BatchUpdateUsersInput,
	digest [32]byte,
) (BatchUpdateUsersResult, error) {
	scopeHints := make(map[uuid.UUID]uuid.UUID, len(input.Items))
	authorityHints := make(map[uuid.UUID][]uuid.UUID, len(input.Items))
	allAuthorityScopes := make([]uuid.UUID, 0, len(input.Items))
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := protocol.AcquireShared(ctx, tx); err != nil {
			return err
		}
		if err := authorizeManagedUserActor(ctx, tx, actor); err != nil {
			return err
		}
		for _, item := range input.Items {
			scopeID, err := managedUserScopeHint(ctx, tx, item.ID)
			if err != nil {
				return err
			}
			hints, err := collectUserAuthorityScopes(ctx, tx, item.ID)
			if err != nil {
				return err
			}
			if len(hints) == 0 {
				return ErrUserNotFound
			}
			scopeHints[item.ID] = scopeID
			authorityHints[item.ID] = hints
			allAuthorityScopes = append(allAuthorityScopes, hints...)
		}
		return nil
	})
	if err != nil {
		return BatchUpdateUsersResult{}, fmt.Errorf("prepare managed user batch update: %w", err)
	}

	var result BatchUpdateUsersResult
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationUserUpdate, mergeAuthorityScopes(allAuthorityScopes, actor.ScopeID),
		); err != nil {
			return err
		}
		if err := authorizeManagedUserActor(ctx, tx, actor); err != nil {
			return err
		}
		for _, item := range input.Items {
			current, err := collectUserAuthorityScopes(ctx, tx, item.ID)
			if err != nil {
				return err
			}
			if !equalAuthorityScopes(current, authorityHints[item.ID]) {
				return ErrConflict
			}
		}

		ordered := append([]BatchUpdateUserItem(nil), input.Items...)
		sort.Slice(ordered, func(left, right int) bool { return ordered[left].ID.String() < ordered[right].ID.String() })
		targets := make(map[uuid.UUID]managedUserTarget, len(ordered))
		for _, item := range ordered {
			target, err := lockManagedUserTarget(ctx, tx, item.ID)
			if err != nil {
				return err
			}
			if target.scopeID != scopeHints[item.ID] {
				return ErrUserNotFound
			}
			targets[item.ID] = target
		}

		write, err := s.claimIdentityWrite(
			ctx, tx, actor, "identity.user.update", input.IdempotencyKey, digest, "", "",
		)
		if err != nil {
			return err
		}
		if write.Replayed {
			return json.Unmarshal(write.ResponseBody, &result)
		}
		var disabledOwners []uuid.UUID
		for _, item := range input.Items {
			target := targets[item.ID]
			if target.revision != item.ExpectedRevision {
				return ErrRevisionConflict
			}
			if err := guardManagedUserUpdate(target, item.Role, item.GroupSet, item.GroupID); err != nil {
				return err
			}
			if item.Status == UserStatusDisabled && target.status != UserStatusDisabled {
				if err := marketmanaged.GuardUser(ctx, tx, actor.UserID, item.ID); err != nil {
					return err
				}
			}
			if target.role == UserRolePlatformOwner && target.status == UserStatusActive && item.Status == UserStatusDisabled {
				disabledOwners = append(disabledOwners, item.ID)
			}
		}
		if len(disabledOwners) > 0 {
			if err := requireRemainingPlatformOwner(ctx, tx, disabledOwners); err != nil {
				return err
			}
		}

		now := s.now().UTC()
		result.Items = make([]ManagedUser, 0, len(input.Items))
		for _, item := range input.Items {
			target := targets[item.ID]
			if _, err := tx.Exec(ctx, `
				UPDATE users SET display_name=$2,email=$3,phone=$4,status=$5,
				                 revision=revision+1,updated_at=$6,
				                 remark=CASE WHEN $7::text IS NULL THEN remark ELSE NULLIF($7,'') END,
				                 qq=CASE WHEN $8::text IS NULL THEN qq ELSE NULLIF($8,'') END
				WHERE id=$1`, item.ID, item.Fields.DisplayName, nullableString(item.Fields.Email),
				nullableString(item.Fields.Phone), item.Status, now, item.Remark, item.QQ,
			); err != nil {
				return err
			}
			if !target.platform {
				if err := replaceTenantUserRole(ctx, tx, *target.tenantID, target.scopeID, item.ID, item.Role, item.Fields.DisplayName, now); err != nil {
					return err
				}
			}
			if item.GroupSet && !target.platform {
				if err := setUserGroup(ctx, tx, actor.ScopeID, item.ID, item.GroupID, now); err != nil {
					return err
				}
			}
			if item.Status == UserStatusDisabled {
				if err := revokeUserSessions(ctx, tx, item.ID, now, "account_disabled"); err != nil {
					return err
				}
			}
			updated, err := getManagedUserTx(ctx, tx, item.ID)
			if err != nil {
				return err
			}
			if err := s.auditor.Append(ctx, tx, audit.Event{
				ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "identity.user.update",
				ResourceType: "user", ResourceID: item.ID.String(), RequestID: input.RequestID,
				Result: "success", Payload: map[string]any{
					"batch": true, "batch_size": len(input.Items), "previous_status": target.status,
					"status": item.Status, "role": item.Role, "previous_group_id": target.groupID,
					"group_id": updated.GroupID, "revision": updated.Revision,
					"remark_changed": userMetadataChanged(target.remark, item.Remark), "qq_changed": userMetadataChanged(target.qq, item.QQ),
				},
			}); err != nil {
				return err
			}
			result.Items = append(result.Items, updated)
		}
		return s.completeIdentityWrite(
			ctx, tx, actor.UserID, "identity.user.update", input.IdempotencyKey, input.Items[0].ID, 200, result,
		)
	})
	if err != nil {
		return BatchUpdateUsersResult{}, fmt.Errorf("batch update managed users: %w", err)
	}
	return result, nil
}

func (s *Store) ListUserGroups(
	ctx context.Context,
	actor Actor,
	input ListUserGroupsInput,
) (UserGroupList, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT user_group.id,user_group.platform_scope_id,user_group.name,user_group.revision,
		       count(group_membership.user_id),user_group.created_at,user_group.updated_at,count(*) OVER()
		FROM identity_user_groups user_group
		LEFT JOIN identity_user_group_memberships group_membership
		  ON group_membership.platform_scope_id=user_group.platform_scope_id AND group_membership.group_id=user_group.id
		WHERE user_group.platform_scope_id=$1
		  AND ($2='' OR position(lower($2) in lower(user_group.name))>0)
		GROUP BY user_group.id
		ORDER BY user_group.created_at DESC,user_group.id DESC
		LIMIT $3 OFFSET $4`, actor.ScopeID, input.Search, input.Limit, (input.Page-1)*input.Limit,
	)
	if err != nil {
		return UserGroupList{}, fmt.Errorf("list user groups: %w", err)
	}
	defer rows.Close()
	result := UserGroupList{Items: []UserGroup{}, Page: input.Page, Limit: input.Limit}
	for rows.Next() {
		var item UserGroup
		if err := rows.Scan(
			&item.ID, &item.ScopeID, &item.Name, &item.Revision, &item.MemberCount,
			&item.CreatedAt, &item.UpdatedAt, &result.Total,
		); err != nil {
			return UserGroupList{}, fmt.Errorf("scan user group: %w", err)
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return UserGroupList{}, fmt.Errorf("iterate user groups: %w", err)
	}
	return result, nil
}

func (s *Store) CreateUserGroup(
	ctx context.Context,
	actor Actor,
	input CreateUserGroupInput,
	digest [32]byte,
) (UserGroup, error) {
	id, err := newUUID()
	if err != nil {
		return UserGroup{}, err
	}
	var result UserGroup
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(ctx, tx, protocol.OperationUserUpdate, []uuid.UUID{actor.ScopeID}); err != nil {
			return err
		}
		if err := authorizeManagedUserActor(ctx, tx, actor); err != nil {
			return err
		}
		write, err := s.claimUserGroupWrite(
			ctx, tx, actor, "identity.user_group.create", input.IdempotencyKey, digest,
		)
		if err != nil {
			return err
		}
		if write.Replayed {
			return json.Unmarshal(write.ResponseBody, &result)
		}
		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `
			INSERT INTO identity_user_groups(id,platform_scope_id,name,revision,created_at,updated_at)
			VALUES($1,$2,$3,1,$4,$4)`, id, actor.ScopeID, input.Name, now,
		); err != nil {
			if isUniqueViolation(err) {
				return ErrUserGroupConflict
			}
			return err
		}
		result, err = getUserGroupTx(ctx, tx, actor.ScopeID, id)
		if err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "identity.user_group.create",
			ResourceType: "user_group", ResourceID: id.String(), RequestID: input.RequestID,
			Result: "success", Payload: map[string]any{"name": input.Name, "revision": result.Revision},
		}); err != nil {
			return err
		}
		return s.completeUserGroupWrite(
			ctx, tx, actor.UserID, "identity.user_group.create", input.IdempotencyKey, id, 201, result,
		)
	})
	if err != nil {
		return UserGroup{}, fmt.Errorf("create user group: %w", err)
	}
	return result, nil
}

func (s *Store) UpdateUserGroup(
	ctx context.Context,
	actor Actor,
	input UpdateUserGroupInput,
	digest [32]byte,
) (UserGroup, error) {
	var result UserGroup
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(ctx, tx, protocol.OperationUserUpdate, []uuid.UUID{actor.ScopeID}); err != nil {
			return err
		}
		if err := authorizeManagedUserActor(ctx, tx, actor); err != nil {
			return err
		}
		write, err := s.claimUserGroupWrite(
			ctx, tx, actor, "identity.user_group.update", input.IdempotencyKey, digest,
		)
		if err != nil {
			return err
		}
		if write.Replayed {
			return json.Unmarshal(write.ResponseBody, &result)
		}
		var revision int64
		if err := tx.QueryRow(ctx, `
			SELECT revision FROM identity_user_groups WHERE platform_scope_id=$1 AND id=$2 FOR UPDATE`,
			actor.ScopeID, input.ID,
		).Scan(&revision); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrUserGroupNotFound
			}
			return err
		}
		if revision != input.ExpectedRevision {
			return ErrRevisionConflict
		}
		if _, err := tx.Exec(ctx, `
			UPDATE identity_user_groups SET name=$3,revision=revision+1,updated_at=$4
			WHERE platform_scope_id=$1 AND id=$2`, actor.ScopeID, input.ID, input.Name, s.now().UTC(),
		); err != nil {
			if isUniqueViolation(err) {
				return ErrUserGroupConflict
			}
			return err
		}
		result, err = getUserGroupTx(ctx, tx, actor.ScopeID, input.ID)
		if err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "identity.user_group.update",
			ResourceType: "user_group", ResourceID: input.ID.String(), RequestID: input.RequestID,
			Result: "success", Payload: map[string]any{"name": input.Name, "revision": result.Revision},
		}); err != nil {
			return err
		}
		return s.completeUserGroupWrite(
			ctx, tx, actor.UserID, "identity.user_group.update", input.IdempotencyKey, input.ID, 200, result,
		)
	})
	if err != nil {
		return UserGroup{}, fmt.Errorf("update user group: %w", err)
	}
	return result, nil
}

func (s *Store) DeleteUserGroup(
	ctx context.Context,
	actor Actor,
	input DeleteUserGroupInput,
	digest [32]byte,
) error {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(ctx, tx, protocol.OperationUserUpdate, []uuid.UUID{actor.ScopeID}); err != nil {
			return err
		}
		if err := authorizeManagedUserActor(ctx, tx, actor); err != nil {
			return err
		}
		write, err := s.claimUserGroupWrite(
			ctx, tx, actor, "identity.user_group.delete", input.IdempotencyKey, digest,
		)
		if err != nil {
			return err
		}
		if write.Replayed {
			return nil
		}
		var revision, members int64
		if err := tx.QueryRow(ctx, `
			SELECT revision FROM identity_user_groups
			WHERE platform_scope_id=$1 AND id=$2 FOR UPDATE`, actor.ScopeID, input.ID,
		).Scan(&revision); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrUserGroupNotFound
			}
			return err
		}
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM identity_user_group_memberships
			WHERE platform_scope_id=$1 AND group_id=$2`, actor.ScopeID, input.ID,
		).Scan(&members); err != nil {
			return err
		}
		if revision != input.ExpectedRevision {
			return ErrRevisionConflict
		}
		if members != 0 {
			return ErrUserGroupInUse
		}
		if _, err := tx.Exec(ctx, `DELETE FROM identity_user_groups WHERE platform_scope_id=$1 AND id=$2`, actor.ScopeID, input.ID); err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "identity.user_group.delete",
			ResourceType: "user_group", ResourceID: input.ID.String(), RequestID: input.RequestID,
			Result: "success", Payload: map[string]any{"revision": revision},
		}); err != nil {
			return err
		}
		return s.completeUserGroupWrite(
			ctx, tx, actor.UserID, "identity.user_group.delete", input.IdempotencyKey, input.ID, 204, struct{}{},
		)
	})
	if err != nil {
		return fmt.Errorf("delete user group: %w", err)
	}
	return nil
}

func requireUserGroup(ctx context.Context, tx pgx.Tx, platformScopeID, groupID uuid.UUID) error {
	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT true FROM identity_user_groups WHERE platform_scope_id=$1 AND id=$2 FOR SHARE`,
		platformScopeID, groupID,
	).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrUserGroupNotFound
		}
		return err
	}
	return nil
}

func setUserGroup(
	ctx context.Context,
	tx pgx.Tx,
	platformScopeID, userID uuid.UUID,
	groupID *uuid.UUID,
	now time.Time,
) error {
	if groupID == nil {
		_, err := tx.Exec(ctx, `DELETE FROM identity_user_group_memberships WHERE user_id=$1`, userID)
		return err
	}
	if err := requireUserGroup(ctx, tx, platformScopeID, *groupID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO identity_user_group_memberships(platform_scope_id,group_id,user_id,created_at,updated_at)
		VALUES($1,$2,$3,$4,$4)
		ON CONFLICT(user_id) DO UPDATE
		SET platform_scope_id=EXCLUDED.platform_scope_id,group_id=EXCLUDED.group_id,updated_at=EXCLUDED.updated_at`,
		platformScopeID, *groupID, userID, now,
	)
	return err
}

func authorizeManagedUserActor(ctx context.Context, tx pgx.Tx, actor Actor) error {
	// ADR 0019 §4.4: a bridge key never inherits its creator's administrator
	// role; it has only CreateBridgeCustomer / SetBridgeCustomerStatus.
	if actor.bridge != nil {
		return ErrPermissionDenied
	}
	if tx == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ScopeKind != "platform" {
		return ErrPermissionDenied
	}
	var permission string
	err := tx.QueryRow(ctx, `
		SELECT role_permission.permission_name
		FROM users actor_user
		JOIN memberships actor_membership
		  ON actor_membership.user_id=actor_user.id AND actor_membership.status='active'
		JOIN access_scopes actor_scope
		  ON actor_scope.id=actor_membership.scope_id
		 AND actor_scope.kind='platform' AND actor_scope.tenant_id IS NULL
		JOIN role_assignments assignment
		  ON assignment.scope_id=actor_membership.scope_id AND assignment.user_id=actor_membership.user_id
		JOIN roles actor_role
		  ON actor_role.scope_id=assignment.scope_id AND actor_role.id=assignment.role_id
		 AND actor_role.system_role=true
		JOIN role_permissions role_permission ON role_permission.role_id=actor_role.id
		WHERE actor_user.id=$1 AND actor_user.status='active' AND actor_scope.id=$2
		  AND role_permission.permission_name IN ('platform.admin','identity.users.manage')
		ORDER BY role_permission.permission_name
		LIMIT 1
		FOR SHARE OF actor_user,actor_membership,actor_scope,assignment,actor_role,role_permission`,
		actor.UserID, actor.ScopeID,
	).Scan(&permission)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPermissionDenied
	}
	if err != nil {
		return err
	}
	if permission != "platform.admin" && permission != "identity.users.manage" {
		return ErrPermissionDenied
	}
	return nil
}

func (s *Store) GetAccountProfile(ctx context.Context, actor Actor) (AccountProfile, error) {
	profile, err := scanAccountProfile(s.pool.QueryRow(ctx, accountProfileQuery, actor.UserID, actor.ScopeID))
	if errors.Is(err, pgx.ErrNoRows) {
		return AccountProfile{}, ErrInvalidSession
	}
	if err != nil {
		return AccountProfile{}, fmt.Errorf("get account profile: %w", err)
	}
	return profile, nil
}

func (s *Store) UpdateAccountProfile(
	ctx context.Context,
	actor Actor,
	input UpdateProfileInput,
	digest [32]byte,
) (AccountProfile, error) {
	scopeHints, err := collectUserAuthorityScopes(ctx, s.pool, actor.UserID)
	if err != nil {
		return AccountProfile{}, fmt.Errorf("find account authority scopes: %w", err)
	}
	if len(scopeHints) == 0 {
		return AccountProfile{}, ErrInvalidSession
	}
	var result AccountProfile
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationSelfUpdate, mergeAuthorityScopes(scopeHints, actor.ScopeID),
		); err != nil {
			return err
		}
		currentScopes, err := collectUserAuthorityScopes(ctx, tx, actor.UserID)
		if err != nil {
			return err
		}
		if !equalAuthorityScopes(currentScopes, scopeHints) {
			return ErrConflict
		}
		write, err := s.claimIdentityWrite(ctx, tx, actor, "identity.self.update", input.IdempotencyKey, digest, "", "")
		if err != nil {
			return err
		}
		if write.Replayed {
			return json.Unmarshal(write.ResponseBody, &result)
		}
		var tenantID *uuid.UUID
		var revision int64
		var passwordHash string
		var email, phone *string
		if err := tx.QueryRow(ctx, `
			SELECT scope.tenant_id, u.revision, u.password_hash, u.email, u.phone
			FROM users u
			JOIN memberships m ON m.user_id = u.id AND m.scope_id = $2 AND m.status = 'active'
			JOIN access_scopes scope ON scope.id = m.scope_id
			  AND (scope.kind = 'tenant' OR (scope.kind = 'platform' AND scope.tenant_id IS NULL))
			WHERE u.id = $1 AND u.status = 'active'
			FOR UPDATE OF u, m`, actor.UserID, actor.ScopeID,
		).Scan(&tenantID, &revision, &passwordHash, &email, &phone); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidSession
			}
			return err
		}
		if revision != input.ExpectedRevision {
			return ErrRevisionConflict
		}
		currentEmail, currentPhone := "", ""
		if email != nil {
			currentEmail = *email
		}
		if phone != nil {
			currentPhone = *phone
		}
		emailChanged := currentEmail != input.Fields.Email
		phoneChanged := currentPhone != input.Fields.Phone
		reauthenticated := emailChanged || phoneChanged
		if reauthenticated && (input.Credential == nil || input.Credential.Revision != revision ||
			input.Credential.PasswordHash != passwordHash) {
			return ErrInvalidCredentials
		}
		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `
			UPDATE users SET display_name = $2, email = $3, phone = $4,
			                 revision = revision + 1, updated_at = $5
			WHERE id = $1`, actor.UserID, input.Fields.DisplayName, nullableString(input.Fields.Email),
			nullableString(input.Fields.Phone), now,
		); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" &&
				(pgErr.ConstraintName == "users_email_registration_unique_159" || pgErr.ConstraintName == "users_phone_registration_unique_159") {
				return ErrInvalidUserInput
			}
			return err
		}
		if tenantID != nil {
			if _, err := tx.Exec(ctx, `UPDATE tenants SET display_name = $2, revision = revision + 1, updated_at = $3 WHERE id = $1`,
				*tenantID, input.Fields.DisplayName, now); err != nil {
				return err
			}
		}
		result, err = getAccountProfileTx(ctx, tx, actor)
		if err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "identity.self.update",
			ResourceType: "user", ResourceID: actor.UserID.String(), RequestID: input.RequestID,
			Result: "success", Payload: map[string]any{
				"revision": result.Revision, "email_changed": emailChanged,
				"phone_changed": phoneChanged, "reauthenticated": reauthenticated,
			},
		}); err != nil {
			return err
		}
		return s.completeIdentityWrite(
			ctx, tx, actor.UserID, "identity.self.update", input.IdempotencyKey, actor.UserID, 200, result,
		)
	})
	if err != nil {
		return AccountProfile{}, fmt.Errorf("update account profile: %w", err)
	}
	return result, nil
}

func (s *Store) PasswordCredential(ctx context.Context, actor Actor) (PasswordCredential, error) {
	var result PasswordCredential
	err := s.pool.QueryRow(ctx, `
		SELECT u.password_hash, u.revision
		FROM users u
		JOIN memberships m ON m.user_id = u.id AND m.scope_id = $2 AND m.status = 'active'
		JOIN access_scopes scope ON scope.id = m.scope_id AND scope.kind = $3
		  AND (scope.kind = 'tenant' OR (scope.kind = 'platform' AND scope.tenant_id IS NULL))
		WHERE u.id = $1 AND u.status = 'active'`, actor.UserID, actor.ScopeID, actor.ScopeKind,
	).Scan(&result.PasswordHash, &result.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return PasswordCredential{}, ErrInvalidSession
	}
	if err != nil {
		return PasswordCredential{}, fmt.Errorf("load password credential: %w", err)
	}
	return result, nil
}

func (s *Store) ChangePassword(
	ctx context.Context,
	actor Actor,
	credential PasswordCredential,
	newHash string,
	requestID string,
) error {
	scopeHints, err := collectUserAuthorityScopes(ctx, s.pool, actor.UserID)
	if err != nil {
		return fmt.Errorf("find password authority scopes: %w", err)
	}
	if len(scopeHints) == 0 {
		return ErrInvalidSession
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.OperationPasswordChange, mergeAuthorityScopes(scopeHints, actor.ScopeID),
		); err != nil {
			return err
		}
		currentScopes, err := collectUserAuthorityScopes(ctx, tx, actor.UserID)
		if err != nil {
			return err
		}
		if !equalAuthorityScopes(currentScopes, scopeHints) {
			return ErrConflict
		}
		var currentHash string
		var revision int64
		if err := tx.QueryRow(ctx, `
			SELECT u.password_hash, u.revision
			FROM users u
			JOIN memberships m ON m.user_id = u.id AND m.scope_id = $2 AND m.status = 'active'
			JOIN access_scopes scope ON scope.id = m.scope_id AND scope.kind = $3
			  AND (scope.kind = 'tenant' OR (scope.kind = 'platform' AND scope.tenant_id IS NULL))
			WHERE u.id = $1 AND u.status = 'active'
			FOR UPDATE OF u, m`, actor.UserID, actor.ScopeID, actor.ScopeKind,
		).Scan(&currentHash, &revision); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidSession
			}
			return err
		}
		if currentHash != credential.PasswordHash || revision != credential.Revision {
			return ErrRevisionConflict
		}
		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `
			UPDATE users SET password_hash = $2, password_change_required = false, revision = revision + 1, updated_at = $3
			WHERE id = $1`, actor.UserID, newHash, now); err != nil {
			return err
		}
		if err := revokeUserSessions(ctx, tx, actor.UserID, now, "password_changed"); err != nil {
			return err
		}
		return s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: "identity.password.change",
			ResourceType: "user", ResourceID: actor.UserID.String(), RequestID: requestID,
			Result: "success", Payload: map[string]any{"sessions_revoked": true},
		})
	})
	if err != nil {
		return fmt.Errorf("change password: %w", err)
	}
	return nil
}

func (s *Store) claimIdentityWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation string,
	key string,
	digest [32]byte,
	secretHash string,
	rawSecret string,
) (storedIdentityWrite, error) {
	id, err := newUUID()
	if err != nil {
		return storedIdentityWrite{}, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO identity_write_requests (
			id, actor_user_id, actor_scope_id, operation, idempotency_key, request_digest, secret_hash
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (actor_user_id, operation, idempotency_key) DO NOTHING`,
		id, actor.UserID, actor.ScopeID, operation, key, digest[:], nullableString(secretHash),
	)
	if err != nil {
		return storedIdentityWrite{}, err
	}
	if command.RowsAffected() == 1 {
		return storedIdentityWrite{SecretHash: secretHash}, nil
	}
	var existingDigest []byte
	var existingSecret *string
	var responseBody []byte
	var completedAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT request_digest, secret_hash, response_body, completed_at
		FROM identity_write_requests
		WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3
		FOR UPDATE`, actor.UserID, operation, key,
	).Scan(&existingDigest, &existingSecret, &responseBody, &completedAt); err != nil {
		return storedIdentityWrite{}, err
	}
	if !bytes.Equal(existingDigest, digest[:]) || completedAt == nil ||
		(secretHash == "") != (existingSecret == nil) {
		return storedIdentityWrite{}, ErrIdempotencyConflict
	}
	if secretHash != "" && !VerifyPassword(*existingSecret, rawSecret) {
		return storedIdentityWrite{}, ErrIdempotencyConflict
	}
	existingSecretHash := ""
	if existingSecret != nil {
		existingSecretHash = *existingSecret
	}
	return storedIdentityWrite{Replayed: true, ResponseBody: responseBody, SecretHash: existingSecretHash}, nil
}

func (s *Store) completeIdentityWrite(
	ctx context.Context,
	tx pgx.Tx,
	actorUserID uuid.UUID,
	operation string,
	key string,
	resourceID uuid.UUID,
	status int,
	body any,
) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE identity_write_requests
		SET resource_id = $4, response_status = $5, response_body = $6, completed_at = $7
		WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3
		  AND completed_at IS NULL`,
		actorUserID, operation, key, resourceID, status, string(encoded), s.now().UTC(),
	)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func (s *Store) claimUserGroupWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation string,
	key string,
	digest [32]byte,
) (storedIdentityWrite, error) {
	id, err := newUUID()
	if err != nil {
		return storedIdentityWrite{}, err
	}
	command, err := tx.Exec(ctx, `
		INSERT INTO identity_user_group_write_requests (
			id, actor_user_id, actor_scope_id, operation, idempotency_key, request_digest
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (actor_user_id, operation, idempotency_key) DO NOTHING`,
		id, actor.UserID, actor.ScopeID, operation, key, digest[:],
	)
	if err != nil {
		return storedIdentityWrite{}, err
	}
	if command.RowsAffected() == 1 {
		return storedIdentityWrite{}, nil
	}
	var existingDigest []byte
	var responseBody []byte
	var completedAt *time.Time
	if err := tx.QueryRow(ctx, `
		SELECT request_digest, response_body, completed_at
		FROM identity_user_group_write_requests
		WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3
		FOR UPDATE`, actor.UserID, operation, key,
	).Scan(&existingDigest, &responseBody, &completedAt); err != nil {
		return storedIdentityWrite{}, err
	}
	if !bytes.Equal(existingDigest, digest[:]) || completedAt == nil {
		return storedIdentityWrite{}, ErrIdempotencyConflict
	}
	return storedIdentityWrite{Replayed: true, ResponseBody: responseBody}, nil
}

func (s *Store) completeUserGroupWrite(
	ctx context.Context,
	tx pgx.Tx,
	actorUserID uuid.UUID,
	operation string,
	key string,
	resourceID uuid.UUID,
	status int,
	body any,
) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `
		UPDATE identity_user_group_write_requests
		SET resource_id = $4, response_status = $5, response_body = $6, completed_at = $7
		WHERE actor_user_id = $1 AND operation = $2 AND idempotency_key = $3
		  AND completed_at IS NULL`,
		actorUserID, operation, key, resourceID, status, string(encoded), s.now().UTC(),
	)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func tenantRoleID(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, role string) (uuid.UUID, error) {
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `
		SELECT id FROM roles WHERE scope_id = $1 AND name = $2 AND system_role`, scopeID, role,
	).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("load tenant role: %w", err)
	}
	return id, nil
}

// replaceTenantUserRole mirrors the tenant display name and replaces the
// tenant user's system role assignment.
func replaceTenantUserRole(
	ctx context.Context, tx pgx.Tx, tenantID, scopeID, userID uuid.UUID, role, displayName string, now time.Time,
) error {
	roleID, err := tenantRoleID(ctx, tx, scopeID, role)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE tenants SET display_name = $2, revision = revision + 1, updated_at = $3 WHERE id = $1`,
		tenantID, displayName, now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM role_assignments WHERE scope_id = $1 AND user_id = $2`, scopeID, userID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO role_assignments (scope_id, user_id, role_id, assigned_at)
		VALUES ($1, $2, $3, $4)`, scopeID, userID, roleID, now)
	return err
}

func revokeUserSessions(ctx context.Context, tx pgx.Tx, userID uuid.UUID, now time.Time, reason string) error {
	_, err := tx.Exec(ctx, `
		UPDATE auth_sessions
		SET revoked_at = COALESCE(revoked_at, $2),
		    revocation_reason = COALESCE(revocation_reason, $3)
		WHERE user_id = $1`, userID, now, reason)
	return err
}

const managedUserQuery = `
	SELECT u.id, u.display_id::text, m.scope_id, scope.tenant_id, u.username, u.display_name,
	       u.email, u.phone, u.status, assigned.role, user_group.id AS group_id, user_group.name AS group_name,
	       u.revision, u.created_at, u.updated_at, u.remark, u.qq
	FROM users u
	JOIN memberships m ON m.user_id = u.id
	JOIN access_scopes scope ON scope.id = m.scope_id AND (` + managedUserScopePredicate + `)
	JOIN LATERAL (
		SELECT r.name AS role
		FROM role_assignments ra
		JOIN roles r ON r.id = ra.role_id AND r.scope_id = ra.scope_id
		WHERE ra.scope_id = m.scope_id AND ra.user_id = u.id AND r.system_role
		  AND (
		    (scope.kind = 'tenant' AND r.name IN ('tenant_owner', 'tenant_viewer')) OR
		    (scope.kind = 'platform' AND r.name IN ('platform_owner', 'platform_admin'))
		  )
		ORDER BY CASE r.name WHEN 'tenant_owner' THEN 0 WHEN 'platform_owner' THEN 0 ELSE 1 END
		LIMIT 1
	) assigned ON true
	LEFT JOIN identity_user_group_memberships group_membership ON group_membership.user_id=u.id
	LEFT JOIN identity_user_groups user_group ON user_group.id=group_membership.group_id`

// managedUserScopePredicate selects the one membership that represents a user
// in the managed user list: the tenant membership for tenant users, or the
// platform membership for platform administrators that hold no tenant scope.
// It references only the "m" membership and "scope" access scope aliases.
const managedUserScopePredicate = `scope.kind = 'tenant' OR (
		scope.kind = 'platform' AND scope.tenant_id IS NULL AND NOT EXISTS (
			SELECT 1 FROM memberships tenant_membership
			JOIN access_scopes tenant_scope ON tenant_scope.id = tenant_membership.scope_id AND tenant_scope.kind = 'tenant'
			WHERE tenant_membership.user_id = m.user_id))`

// managedUserTarget is the locked write-side view of one managed user.
type managedUserTarget struct {
	scopeID   uuid.UUID
	tenantID  *uuid.UUID
	platform  bool
	role      string
	revision  int64
	status    string
	groupID   *uuid.UUID
	remark    *string
	qq        *string
	deletedAt *time.Time
}

func managedUserScopeHint(ctx context.Context, tx pgx.Tx, id uuid.UUID) (uuid.UUID, error) {
	var scopeID uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT m.scope_id
		FROM memberships m
		JOIN access_scopes scope ON scope.id = m.scope_id AND (`+managedUserScopePredicate+`)
		WHERE m.user_id = $1`, id,
	).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrUserNotFound
	}
	return scopeID, err
}

// lockManagedUserTarget locks the user, its listed membership and, for tenant
// users, the tenant row in that order. Platform targets must still hold a
// platform administrator role, otherwise they are not managed users.
func lockManagedUserTarget(ctx context.Context, tx pgx.Tx, id uuid.UUID) (managedUserTarget, error) {
	var target managedUserTarget
	var kind string
	if err := tx.QueryRow(ctx, `
		SELECT m.scope_id, scope.tenant_id, scope.kind, u.revision, u.status, u.remark, u.qq
		FROM users u
		JOIN memberships m ON m.user_id = u.id
		JOIN access_scopes scope ON scope.id = m.scope_id AND (`+managedUserScopePredicate+`)
		WHERE u.id = $1
		FOR UPDATE OF u, m`, id,
	).Scan(&target.scopeID, &target.tenantID, &kind, &target.revision, &target.status, &target.remark, &target.qq); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return managedUserTarget{}, ErrUserNotFound
		}
		return managedUserTarget{}, err
	}
	target.platform = kind == "platform"
	if !target.platform {
		var locked uuid.UUID
		if target.tenantID == nil {
			return managedUserTarget{}, ErrUserNotFound
		}
		if err := tx.QueryRow(ctx, `SELECT id FROM tenants WHERE id = $1 FOR UPDATE`, *target.tenantID).Scan(&locked); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return managedUserTarget{}, ErrUserNotFound
			}
			return managedUserTarget{}, err
		}
	}
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE((
			SELECT r.name FROM role_assignments ra
			JOIN roles r ON r.id = ra.role_id AND r.scope_id = ra.scope_id
			WHERE ra.scope_id = $2 AND ra.user_id = $1 AND r.system_role
			  AND r.name IN ('tenant_owner', 'tenant_viewer', 'platform_owner', 'platform_admin')
			ORDER BY CASE r.name WHEN 'tenant_owner' THEN 0 WHEN 'platform_owner' THEN 0 ELSE 1 END
			LIMIT 1), ''),
		       (SELECT group_id FROM identity_user_group_memberships WHERE user_id = $1),
		       (SELECT deleted_at FROM identity_user_deletions WHERE user_id = $1)`, id, target.scopeID,
	).Scan(&target.role, &target.groupID, &target.deletedAt); err != nil {
		return managedUserTarget{}, err
	}
	if target.platform && !validPlatformUserRole(target.role) {
		return managedUserTarget{}, ErrUserNotFound
	}
	return target, nil
}

// guardManagedUserUpdate keeps platform administrators' type and group fixed
// and tenant users inside the tenant role family.
func guardManagedUserUpdate(target managedUserTarget, role string, groupSet bool, groupID *uuid.UUID) error {
	if !target.platform {
		if !validUserRole(role) {
			return ErrInvalidUserInput
		}
		return nil
	}
	if role != target.role || (groupSet && groupID != nil) {
		return ErrUserProtected
	}
	return nil
}

// requireRemainingPlatformOwner rejects a mutation that would leave no active,
// undeleted platform_owner once the excluded users are disabled or deleted.
// Callers hold the exclusive IAM authority mutation lock, so the count cannot
// race with another administrator mutation.
func requireRemainingPlatformOwner(ctx context.Context, tx pgx.Tx, excluded []uuid.UUID) error {
	var remaining int64
	if err := tx.QueryRow(ctx, `
		SELECT count(DISTINCT u.id)
		FROM users u
		JOIN memberships m ON m.user_id = u.id AND m.status = 'active'
		JOIN access_scopes scope ON scope.id = m.scope_id AND scope.kind = 'platform' AND scope.tenant_id IS NULL
		JOIN role_assignments ra ON ra.scope_id = m.scope_id AND ra.user_id = u.id
		JOIN roles r ON r.id = ra.role_id AND r.scope_id = ra.scope_id AND r.system_role AND r.name = 'platform_owner'
		WHERE u.status = 'active' AND NOT (u.id = ANY($1::uuid[]))
		  AND NOT EXISTS (SELECT 1 FROM identity_user_deletions deletion WHERE deletion.user_id = u.id)`, excluded,
	).Scan(&remaining); err != nil {
		return err
	}
	if remaining < 1 {
		return ErrUserProtected
	}
	return nil
}

const accountProfileQuery = `
	SELECT u.id, u.username, u.display_name, u.email, u.phone, u.revision, u.created_at, u.updated_at
	FROM users u
	JOIN memberships m ON m.user_id = u.id AND m.scope_id = $2 AND m.status = 'active'
	JOIN access_scopes scope ON scope.id = m.scope_id
	  AND (scope.kind = 'tenant' OR (scope.kind = 'platform' AND scope.tenant_id IS NULL))
	WHERE u.id = $1 AND u.status = 'active'`

func getManagedUserTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) (ManagedUser, error) {
	return scanManagedUser(tx.QueryRow(ctx, managedUserQuery+" WHERE u.id = $1 AND NOT EXISTS (SELECT 1 FROM identity_user_deletions deletion WHERE deletion.user_id=u.id)", id))
}

func getUserGroupTx(ctx context.Context, tx pgx.Tx, platformScopeID, id uuid.UUID) (UserGroup, error) {
	var item UserGroup
	err := tx.QueryRow(ctx, `
		SELECT user_group.id,user_group.platform_scope_id,user_group.name,user_group.revision,
		       count(group_membership.user_id),user_group.created_at,user_group.updated_at
		FROM identity_user_groups user_group
		LEFT JOIN identity_user_group_memberships group_membership
		  ON group_membership.platform_scope_id=user_group.platform_scope_id AND group_membership.group_id=user_group.id
		WHERE user_group.platform_scope_id=$1 AND user_group.id=$2
		GROUP BY user_group.id`, platformScopeID, id,
	).Scan(
		&item.ID, &item.ScopeID, &item.Name, &item.Revision, &item.MemberCount,
		&item.CreatedAt, &item.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserGroup{}, ErrUserGroupNotFound
	}
	return item, err
}

func getAccountProfileTx(ctx context.Context, tx pgx.Tx, actor Actor) (AccountProfile, error) {
	return scanAccountProfile(tx.QueryRow(ctx, accountProfileQuery, actor.UserID, actor.ScopeID))
}

func scanManagedUser(row identityRowScanner) (ManagedUser, error) {
	item := ManagedUser{Metadata: &UserMetadata{}}
	err := row.Scan(
		&item.ID, &item.DisplayID, &item.ScopeID, &item.TenantID, &item.Username, &item.DisplayName,
		&item.Email, &item.Phone, &item.Status, &item.Role, &item.GroupID, &item.GroupName,
		&item.Revision, &item.CreatedAt, &item.UpdatedAt, &item.Metadata.Remark, &item.Metadata.QQ,
	)
	return item, err
}

func scanAccountProfile(row identityRowScanner) (AccountProfile, error) {
	var item AccountProfile
	err := row.Scan(
		&item.ID, &item.Username, &item.DisplayName, &item.Email, &item.Phone,
		&item.Revision, &item.CreatedAt, &item.UpdatedAt,
	)
	return item, err
}

func userMetadataChanged(previous, supplied *string) bool {
	if supplied == nil {
		return false
	}
	if previous == nil {
		return *supplied != ""
	}
	return *previous != *supplied
}
