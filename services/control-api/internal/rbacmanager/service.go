package rbacmanager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	operationCreate     = "identity.custom_role.create"
	operationRename     = "identity.custom_role.rename"
	operationPublish    = "identity.custom_role.publish"
	operationDeactivate = "identity.custom_role.deactivate"
	operationAssign     = "identity.custom_role.assign"
	operationRevoke     = "identity.custom_role.revoke"
)

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Service struct {
	pool    *pgxpool.Pool
	auditor AuditAppender
	stepUp  StepUpVerifier
	now     Clock
}

type actorState struct {
	tenantID    uuid.UUID
	permissions map[string]struct{}
}

type mutationSpec[T any] struct {
	actor      Actor
	operation  string
	context    MutationContext
	digest     [32]byte
	markReplay func(*T)
	apply      func(context.Context, pgx.Tx, actorState) (T, error)
}

func NewService(pool *pgxpool.Pool, verifier StepUpVerifier) (*Service, error) {
	return NewServiceWithDependencies(pool, audit.New(pool), verifier, time.Now)
}

func NewServiceWithDependencies(
	pool *pgxpool.Pool,
	auditor AuditAppender,
	verifier StepUpVerifier,
	now Clock,
) (*Service, error) {
	if pool == nil || auditor == nil || verifier == nil || now == nil {
		return nil, ErrInvalidStore
	}
	return &Service{pool: pool, auditor: auditor, stepUp: verifier, now: now}, nil
}

func (s *Service) CreateRole(ctx context.Context, actor Actor, request CreateRoleRequest) (Role, error) {
	name, err := normalizeRoleName(request.Name)
	if err != nil || !validMutation(request.Mutation) {
		return Role{}, ErrInvalidInput
	}
	permissions, err := normalizePermissions(request.Permissions)
	if err != nil {
		return Role{}, err
	}
	digest := requestDigest(struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}{name, permissions})
	return runMutation(ctx, s, mutationSpec[Role]{
		actor: actor, operation: operationCreate, context: request.Mutation, digest: digest,
		markReplay: func(role *Role) { role.Replayed = true },
		apply: func(ctx context.Context, tx pgx.Tx, state actorState) (Role, error) {
			critical, err := authorizeDelegation(ctx, tx, state, permissions)
			if err != nil {
				return Role{}, err
			}
			roleID, err := uuid.NewV7()
			if err != nil {
				return Role{}, err
			}
			evidence, err := s.verifyStepUp(ctx, tx, actor, state.tenantID, request.Mutation.StepUp,
				request.Mutation, digest, StepUpCheck{
					Action: operationCreate, RoleID: roleID, Permissions: permissions,
				}, critical)
			if err != nil {
				return Role{}, err
			}
			now := storeTime(s.now())
			_, err = tx.Exec(ctx, `INSERT INTO custom_roles(
				id,tenant_id,tenant_scope_id,current_revision,current_name,created_by_user_id,
				created_by_scope_id,created_at,updated_at
			) VALUES($1,$2,$3,0,$4,$5,$3,$6,$6)`,
				roleID, state.tenantID, actor.ScopeID, name, actor.UserID, now)
			if err != nil {
				return Role{}, mapDatabaseError(err)
			}
			if err := insertRevision(ctx, tx, roleID, state.tenantID, actor, 1, name,
				permissions, operationCreate, evidence, now); err != nil {
				return Role{}, err
			}
			command, err := tx.Exec(ctx, `UPDATE custom_roles
				SET current_revision=1,updated_at=$3
				WHERE id=$1 AND tenant_scope_id=$2 AND current_revision=0 AND deactivated_at IS NULL`,
				roleID, actor.ScopeID, now)
			if err != nil {
				return Role{}, err
			}
			if command.RowsAffected() != 1 {
				return Role{}, ErrRevisionConflict
			}
			role, err := loadRole(ctx, tx, actor.ScopeID, roleID, false)
			if err != nil {
				return Role{}, err
			}
			if err := s.appendAudit(ctx, tx, actor, operationCreate, role.ID.String(), request.Mutation,
				map[string]any{"revision": role.CurrentRevision, "name": role.Name, "permissions": role.Permissions}); err != nil {
				return Role{}, err
			}
			return role, nil
		},
	})
}

func (s *Service) RenameRole(ctx context.Context, actor Actor, request RenameRoleRequest) (Role, error) {
	name, err := normalizeRoleName(request.Name)
	if err != nil || request.RoleID == uuid.Nil || request.ExpectedRevision < 1 || !validMutation(request.Mutation) {
		return Role{}, ErrInvalidInput
	}
	digest := requestDigest(struct {
		RoleID   uuid.UUID `json:"role_id"`
		Expected int64     `json:"expected_revision"`
		Name     string    `json:"name"`
	}{request.RoleID, request.ExpectedRevision, name})
	return runMutation(ctx, s, mutationSpec[Role]{
		actor: actor, operation: operationRename, context: request.Mutation, digest: digest,
		markReplay: func(role *Role) { role.Replayed = true },
		apply: func(ctx context.Context, tx pgx.Tx, state actorState) (Role, error) {
			role, err := loadRoleForMutation(ctx, tx, actor.ScopeID, request.RoleID)
			if err != nil {
				return Role{}, err
			}
			if role.DeactivatedAt != nil {
				return Role{}, ErrRoleInactive
			}
			if role.CurrentRevision != request.ExpectedRevision {
				return Role{}, ErrRevisionConflict
			}
			now := storeTime(s.now())
			next := role.CurrentRevision + 1
			if err := insertRevision(ctx, tx, role.ID, state.tenantID, actor, next, name,
				role.Permissions, operationRename, StepUpEvidence{}, now); err != nil {
				return Role{}, err
			}
			command, err := tx.Exec(ctx, `UPDATE custom_roles
				SET current_revision=$3,current_name=$4,updated_at=$5
				WHERE id=$1 AND tenant_scope_id=$2 AND current_revision=$6 AND deactivated_at IS NULL`,
				role.ID, actor.ScopeID, next, name, now, request.ExpectedRevision)
			if err != nil {
				return Role{}, mapDatabaseError(err)
			}
			if command.RowsAffected() != 1 {
				return Role{}, ErrRevisionConflict
			}
			role, err = loadRole(ctx, tx, actor.ScopeID, role.ID, false)
			if err != nil {
				return Role{}, err
			}
			if err := s.appendAudit(ctx, tx, actor, operationRename, role.ID.String(), request.Mutation,
				map[string]any{"revision": role.CurrentRevision, "name": role.Name}); err != nil {
				return Role{}, err
			}
			return role, nil
		},
	})
}

func (s *Service) PublishRevision(ctx context.Context, actor Actor, request PublishRevisionRequest) (Role, error) {
	if request.RoleID == uuid.Nil || request.ExpectedRevision < 1 || !validMutation(request.Mutation) {
		return Role{}, ErrInvalidInput
	}
	permissions, err := normalizePermissions(request.Permissions)
	if err != nil {
		return Role{}, err
	}
	digest := requestDigest(struct {
		RoleID      uuid.UUID `json:"role_id"`
		Expected    int64     `json:"expected_revision"`
		Permissions []string  `json:"permissions"`
	}{request.RoleID, request.ExpectedRevision, permissions})
	return runMutation(ctx, s, mutationSpec[Role]{
		actor: actor, operation: operationPublish, context: request.Mutation, digest: digest,
		markReplay: func(role *Role) { role.Replayed = true },
		apply: func(ctx context.Context, tx pgx.Tx, state actorState) (Role, error) {
			role, err := loadRoleForMutation(ctx, tx, actor.ScopeID, request.RoleID)
			if err != nil {
				return Role{}, err
			}
			if role.DeactivatedAt != nil {
				return Role{}, ErrRoleInactive
			}
			if role.CurrentRevision != request.ExpectedRevision {
				return Role{}, ErrRevisionConflict
			}
			critical, err := authorizeDelegation(ctx, tx, state, permissions)
			if err != nil {
				return Role{}, err
			}
			if !sameStrings(role.Permissions, permissions) {
				oldCritical, err := containsCriticalPermission(ctx, tx, role.Permissions)
				if err != nil {
					return Role{}, err
				}
				critical = critical || oldCritical
			}
			evidence, err := s.verifyStepUp(ctx, tx, actor, state.tenantID, request.Mutation.StepUp,
				request.Mutation, digest, StepUpCheck{
					Action: operationPublish, RoleID: role.ID, ExpectedRevision: request.ExpectedRevision,
					Permissions: permissions,
				}, critical)
			if err != nil {
				return Role{}, err
			}
			now := storeTime(s.now())
			next := role.CurrentRevision + 1
			if err := insertRevision(ctx, tx, role.ID, state.tenantID, actor, next, role.Name,
				permissions, operationPublish, evidence, now); err != nil {
				return Role{}, err
			}
			command, err := tx.Exec(ctx, `UPDATE custom_roles SET current_revision=$3,updated_at=$4
				WHERE id=$1 AND tenant_scope_id=$2 AND current_revision=$5 AND deactivated_at IS NULL`,
				role.ID, actor.ScopeID, next, now, request.ExpectedRevision)
			if err != nil {
				return Role{}, err
			}
			if command.RowsAffected() != 1 {
				return Role{}, ErrRevisionConflict
			}
			role, err = loadRole(ctx, tx, actor.ScopeID, role.ID, false)
			if err != nil {
				return Role{}, err
			}
			if err := s.appendAudit(ctx, tx, actor, operationPublish, role.ID.String(), request.Mutation,
				map[string]any{"revision": role.CurrentRevision, "permissions": role.Permissions}); err != nil {
				return Role{}, err
			}
			return role, nil
		},
	})
}

func (s *Service) DeactivateRole(ctx context.Context, actor Actor, request DeactivateRoleRequest) (Role, error) {
	if request.RoleID == uuid.Nil || request.ExpectedRevision < 1 || !validMutation(request.Mutation) {
		return Role{}, ErrInvalidInput
	}
	digest := requestDigest(struct {
		RoleID   uuid.UUID `json:"role_id"`
		Expected int64     `json:"expected_revision"`
	}{request.RoleID, request.ExpectedRevision})
	return runMutation(ctx, s, mutationSpec[Role]{
		actor: actor, operation: operationDeactivate, context: request.Mutation, digest: digest,
		markReplay: func(role *Role) { role.Replayed = true },
		apply: func(ctx context.Context, tx pgx.Tx, state actorState) (Role, error) {
			role, err := loadRoleForMutation(ctx, tx, actor.ScopeID, request.RoleID)
			if err != nil {
				return Role{}, err
			}
			if role.DeactivatedAt != nil {
				return Role{}, ErrRoleInactive
			}
			if role.CurrentRevision != request.ExpectedRevision {
				return Role{}, ErrRevisionConflict
			}
			critical, err := containsCriticalPermission(ctx, tx, role.Permissions)
			if err != nil {
				return Role{}, err
			}
			evidence, err := s.verifyStepUp(ctx, tx, actor, state.tenantID, request.Mutation.StepUp,
				request.Mutation, digest, StepUpCheck{
					Action: operationDeactivate, RoleID: role.ID, ExpectedRevision: request.ExpectedRevision,
					Permissions: role.Permissions,
				}, critical)
			if err != nil {
				return Role{}, err
			}
			now := storeTime(s.now())
			deactivationID, err := uuid.NewV7()
			if err != nil {
				return Role{}, err
			}
			_, err = tx.Exec(ctx, `INSERT INTO custom_role_deactivations(
				id,tenant_id,tenant_scope_id,role_id,role_revision,deactivated_by_user_id,
				deactivated_by_scope_id,step_up_proof_id,step_up_method,step_up_verified_at,deactivated_at
			) VALUES($1,$2,$3,$4,$5,$6,$3,$7,$8,$9,$10)`,
				deactivationID, role.TenantID, role.TenantScopeID, role.ID, role.CurrentRevision,
				actor.UserID, nullableEvidenceID(evidence), nullableEvidenceMethod(evidence),
				nullableEvidenceTime(evidence), now)
			if err != nil {
				return Role{}, mapDatabaseError(err)
			}
			role, err = loadRole(ctx, tx, actor.ScopeID, role.ID, false)
			if err != nil {
				return Role{}, err
			}
			if role.DeactivatedAt == nil {
				return Role{}, ErrRevisionConflict
			}
			if err := s.appendAudit(ctx, tx, actor, operationDeactivate, role.ID.String(), request.Mutation,
				map[string]any{"revision": role.CurrentRevision}); err != nil {
				return Role{}, err
			}
			return role, nil
		},
	})
}

func (s *Service) AssignRole(ctx context.Context, actor Actor, request AssignRoleRequest) (Grant, error) {
	if request.RoleID == uuid.Nil || request.SubjectUserID == uuid.Nil || request.ExpectedRoleRevision < 1 ||
		!validMutation(request.Mutation) {
		return Grant{}, ErrInvalidInput
	}
	digest := requestDigest(struct {
		RoleID    uuid.UUID `json:"role_id"`
		Revision  int64     `json:"role_revision"`
		SubjectID uuid.UUID `json:"subject_user_id"`
	}{request.RoleID, request.ExpectedRoleRevision, request.SubjectUserID})
	return runMutation(ctx, s, mutationSpec[Grant]{
		actor: actor, operation: operationAssign, context: request.Mutation, digest: digest,
		markReplay: func(grant *Grant) { grant.Replayed = true },
		apply: func(ctx context.Context, tx pgx.Tx, state actorState) (Grant, error) {
			if request.SubjectUserID == actor.UserID {
				return Grant{}, ErrSelfAssignment
			}
			role, err := loadRoleForMutation(ctx, tx, actor.ScopeID, request.RoleID)
			if err != nil {
				return Grant{}, err
			}
			if role.DeactivatedAt != nil {
				return Grant{}, ErrRoleInactive
			}
			if role.CurrentRevision != request.ExpectedRoleRevision {
				return Grant{}, ErrRevisionConflict
			}
			if err := requireActiveTenantMember(ctx, tx, actor.ScopeID, request.SubjectUserID); err != nil {
				return Grant{}, err
			}
			critical, err := authorizeDelegation(ctx, tx, state, role.Permissions)
			if err != nil {
				return Grant{}, err
			}
			evidence, err := s.verifyStepUp(ctx, tx, actor, state.tenantID, request.Mutation.StepUp,
				request.Mutation, digest, StepUpCheck{
					Action: operationAssign, RoleID: role.ID, SubjectUserID: request.SubjectUserID,
					ExpectedRevision: request.ExpectedRoleRevision, Permissions: role.Permissions,
				}, critical)
			if err != nil {
				return Grant{}, err
			}
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
				"custom-rbac-grant:"+actor.ScopeID.String()+":"+request.SubjectUserID.String()+":"+role.ID.String()); err != nil {
				return Grant{}, err
			}
			var active bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(
				SELECT 1 FROM custom_role_grants grant_row
				WHERE grant_row.tenant_scope_id=$1 AND grant_row.subject_user_id=$2 AND grant_row.role_id=$3
				  AND NOT EXISTS(SELECT 1 FROM custom_role_grant_revocations revocation WHERE revocation.grant_id=grant_row.id)
			)`, actor.ScopeID, request.SubjectUserID, role.ID).Scan(&active); err != nil {
				return Grant{}, err
			}
			if active {
				return Grant{}, ErrRevisionConflict
			}
			now := storeTime(s.now())
			grantID, err := uuid.NewV7()
			if err != nil {
				return Grant{}, err
			}
			_, err = tx.Exec(ctx, `INSERT INTO custom_role_grants(
				id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
				granted_by_user_id,granted_by_scope_id,step_up_proof_id,step_up_method,step_up_verified_at,granted_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$3,$8,$9,$10,$11)`,
				grantID, role.TenantID, role.TenantScopeID, role.ID, role.CurrentRevision,
				request.SubjectUserID, actor.UserID, nullableEvidenceID(evidence),
				nullableEvidenceMethod(evidence), nullableEvidenceTime(evidence), now)
			if err != nil {
				return Grant{}, mapDatabaseError(err)
			}
			grant := Grant{
				ID: grantID, TenantID: role.TenantID, TenantScopeID: role.TenantScopeID,
				RoleID: role.ID, RoleRevision: role.CurrentRevision, SubjectUserID: request.SubjectUserID,
				GrantedByUserID: actor.UserID, GrantedAt: now,
			}
			if err := s.appendAudit(ctx, tx, actor, operationAssign, grant.ID.String(), request.Mutation,
				map[string]any{"role_id": role.ID.String(), "role_revision": role.CurrentRevision,
					"subject_user_id": request.SubjectUserID.String()}); err != nil {
				return Grant{}, err
			}
			return grant, nil
		},
	})
}

func (s *Service) RevokeGrant(ctx context.Context, actor Actor, request RevokeGrantRequest) (Revocation, error) {
	if request.GrantID == uuid.Nil || !validMutation(request.Mutation) {
		return Revocation{}, ErrInvalidInput
	}
	digest := requestDigest(struct {
		GrantID uuid.UUID `json:"grant_id"`
	}{request.GrantID})
	return runMutation(ctx, s, mutationSpec[Revocation]{
		actor: actor, operation: operationRevoke, context: request.Mutation, digest: digest,
		markReplay: func(revocation *Revocation) { revocation.Replayed = true },
		apply: func(ctx context.Context, tx pgx.Tx, state actorState) (Revocation, error) {
			var tenantID, scopeID, roleID, subjectID uuid.UUID
			var roleRevision int64
			var permissions []string
			err := tx.QueryRow(ctx, `SELECT grant_row.tenant_id,grant_row.tenant_scope_id,
				grant_row.role_id,grant_row.role_revision,grant_row.subject_user_id,revision.permissions
			FROM custom_role_grants grant_row
			JOIN custom_role_revisions revision ON revision.role_id=grant_row.role_id
			 AND revision.revision=grant_row.role_revision
			WHERE grant_row.id=$1 FOR UPDATE OF grant_row`, request.GrantID).
				Scan(&tenantID, &scopeID, &roleID, &roleRevision, &subjectID, &permissions)
			if errors.Is(err, pgx.ErrNoRows) {
				return Revocation{}, ErrNotFound
			}
			if err != nil {
				return Revocation{}, err
			}
			if scopeID != actor.ScopeID {
				return Revocation{}, ErrTenantBoundary
			}
			var revoked bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(
				SELECT 1 FROM custom_role_grant_revocations WHERE grant_id=$1)`, request.GrantID).Scan(&revoked); err != nil {
				return Revocation{}, err
			}
			if revoked {
				return Revocation{}, ErrGrantRevoked
			}
			critical, err := containsCriticalPermission(ctx, tx, permissions)
			if err != nil {
				return Revocation{}, err
			}
			evidence, err := s.verifyStepUp(ctx, tx, actor, state.tenantID, request.Mutation.StepUp,
				request.Mutation, digest, StepUpCheck{
					Action: operationRevoke, RoleID: roleID, GrantID: request.GrantID,
					SubjectUserID: subjectID, ExpectedRevision: roleRevision, Permissions: permissions,
				}, critical)
			if err != nil {
				return Revocation{}, err
			}
			now := storeTime(s.now())
			revocationID, err := uuid.NewV7()
			if err != nil {
				return Revocation{}, err
			}
			_, err = tx.Exec(ctx, `INSERT INTO custom_role_grant_revocations(
				id,grant_id,tenant_id,tenant_scope_id,role_id,role_revision,subject_user_id,
				revoked_by_user_id,revoked_by_scope_id,step_up_proof_id,step_up_method,step_up_verified_at,revoked_at
			) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$4,$9,$10,$11,$12)`,
				revocationID, request.GrantID, tenantID, scopeID, roleID, roleRevision, subjectID,
				actor.UserID, nullableEvidenceID(evidence), nullableEvidenceMethod(evidence),
				nullableEvidenceTime(evidence), now)
			if err != nil {
				return Revocation{}, mapDatabaseError(err)
			}
			result := Revocation{ID: revocationID, GrantID: request.GrantID,
				RevokedByUserID: actor.UserID, RevokedAt: now}
			if err := s.appendAudit(ctx, tx, actor, operationRevoke, request.GrantID.String(), request.Mutation,
				map[string]any{"role_id": roleID.String(), "subject_user_id": subjectID.String()}); err != nil {
				return Revocation{}, err
			}
			return result, nil
		},
	})
}

func (s *Service) EffectivePermissions(ctx context.Context, tenantScopeID, userID uuid.UUID) ([]string, error) {
	if tenantScopeID == uuid.Nil || userID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	rows, err := s.pool.Query(ctx, `SELECT permission_name
		FROM custom_rbac_effective_permissions($1,$2) ORDER BY permission_name`, tenantScopeID, userID)
	if err != nil {
		return nil, fmt.Errorf("load effective custom RBAC permissions: %w", err)
	}
	defer rows.Close()
	permissions := make([]string, 0)
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return permissions, nil
}

func runMutation[T any](ctx context.Context, service *Service, spec mutationSpec[T]) (T, error) {
	var zero T
	if !validActor(spec.actor) {
		return zero, ErrPermissionDenied
	}
	var result T
	err := pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		if _, err := protocol.BeginAuthorityMutation(
			ctx, tx, protocol.Operation(spec.operation), []uuid.UUID{spec.actor.ScopeID},
		); err != nil {
			return err
		}
		state, err := authorizeActor(ctx, tx, spec.actor, storeTime(service.now()))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`,
			"custom-rbac-write:"+spec.actor.ScopeID.String()+":"+spec.actor.UserID.String()+":"+
				spec.operation+":"+spec.context.IdempotencyKey); err != nil {
			return err
		}
		storedDigest, response, found, err := findWrite(ctx, tx, spec.actor, spec.operation, spec.context.IdempotencyKey)
		if err != nil {
			return err
		}
		if found {
			if !bytes.Equal(storedDigest, spec.digest[:]) {
				return ErrIdempotencyConflict
			}
			if err := json.Unmarshal(response, &result); err != nil {
				return ErrIdempotencyConflict
			}
			spec.markReplay(&result)
			return nil
		}
		result, err = spec.apply(ctx, tx, state)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return err
		}
		writeID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO custom_rbac_write_requests(
			id,tenant_scope_id,actor_user_id,actor_scope_id,operation,idempotency_key,
			request_digest,request_id,trace_id,response_body,created_at
		) VALUES($1,$2,$3,$2,$4,$5,$6,$7,$8,$9,$10)`, writeID, spec.actor.ScopeID,
			spec.actor.UserID, spec.operation, spec.context.IdempotencyKey, spec.digest[:],
			spec.context.RequestID, spec.context.TraceID, encoded, storeTime(service.now()))
		return mapDatabaseError(err)
	})
	if err != nil {
		return zero, fmt.Errorf("%s: %w", spec.operation, err)
	}
	return result, nil
}

// AuthorizeTenantSessionTx validates a tenant session and required permission while
// retaining the revocation locks in tx. The caller owns the transaction lifecycle.
func (s *Service) AuthorizeTenantSessionTx(
	ctx context.Context,
	tx pgx.Tx,
	session AuthenticatedSessionReference,
	requiredPermission string,
) (uuid.UUID, error) {
	if s == nil || s.now == nil || tx == nil || session.UserID == uuid.Nil ||
		session.ScopeID == uuid.Nil || session.SessionID == uuid.Nil ||
		requiredPermission != strings.ToLower(strings.TrimSpace(requiredPermission)) ||
		!validText(requiredPermission, 1, 128) {
		return uuid.Nil, ErrPermissionDenied
	}
	state, err := authorizeTenantSession(ctx, tx, session, requiredPermission, storeTime(s.now()))
	if err != nil {
		return uuid.Nil, err
	}
	return state.tenantID, nil
}

func authorizeActor(ctx context.Context, tx pgx.Tx, actor Actor, now time.Time) (actorState, error) {
	return authorizeTenantSession(ctx, tx, AuthenticatedSessionReference{
		UserID: actor.UserID, ScopeID: actor.ScopeID, SessionID: actor.SessionID,
	}, ManagePermission, now)
}

func authorizeTenantSession(
	ctx context.Context,
	tx pgx.Tx,
	session AuthenticatedSessionReference,
	requiredPermission string,
	now time.Time,
) (actorState, error) {
	if err := protocol.AcquireShared(ctx, tx); err != nil {
		return actorState{}, err
	}
	if _, err := protocol.AcquireScopes(ctx, tx, []uuid.UUID{session.ScopeID}); err != nil {
		return actorState{}, err
	}
	tenantID, err := lockActiveActorPrincipal(ctx, tx, Actor{
		UserID: session.UserID, ScopeID: session.ScopeID, SessionID: session.SessionID,
	}, now)
	if err != nil {
		return actorState{}, err
	}
	if err := lockRequiredPermission(ctx, tx, session.ScopeID, session.UserID, requiredPermission); err != nil {
		return actorState{}, err
	}
	rows, err := tx.Query(ctx, `SELECT permission_name
		FROM custom_rbac_effective_permissions($1,$2) ORDER BY permission_name`, session.ScopeID, session.UserID)
	if err != nil {
		return actorState{}, principalLockError(err, ErrPermissionDenied)
	}
	defer rows.Close()
	permissions := make(map[string]struct{})
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return actorState{}, principalLockError(err, ErrPermissionDenied)
		}
		permissions[permission] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return actorState{}, principalLockError(err, ErrPermissionDenied)
	}
	if _, ok := permissions[requiredPermission]; !ok {
		return actorState{}, ErrPermissionDenied
	}
	return actorState{tenantID: tenantID, permissions: permissions}, nil
}

func lockRequiredPermission(
	ctx context.Context,
	tx pgx.Tx,
	scopeID, userID uuid.UUID,
	requiredPermission string,
) error {
	var permission string
	err := tx.QueryRow(ctx, `SELECT permission.permission_name
		FROM role_assignments assignment
		JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions permission ON permission.role_id=role.id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND permission.permission_name=$3
		ORDER BY role.id LIMIT 1 FOR SHARE OF assignment,role,permission`,
		scopeID, userID, requiredPermission).Scan(&permission)
	return principalLockError(err, ErrPermissionDenied)
}

func lockActiveActorPrincipal(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	now time.Time,
) (uuid.UUID, error) {
	var kind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes
		WHERE id=$1 FOR SHARE`, actor.ScopeID).Scan(&kind, &tenantID); err != nil {
		return uuid.Nil, principalLockError(err, ErrPermissionDenied)
	}
	if kind != "tenant" || tenantID == nil {
		return uuid.Nil, ErrPermissionDenied
	}
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1 FOR SHARE`, *tenantID).Scan(&status); err != nil {
		return uuid.Nil, principalLockError(err, ErrPermissionDenied)
	}
	if status != "active" {
		return uuid.Nil, ErrPermissionDenied
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR SHARE`, actor.UserID).Scan(&status); err != nil {
		return uuid.Nil, principalLockError(err, ErrPermissionDenied)
	}
	if status != "active" {
		return uuid.Nil, ErrPermissionDenied
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships
		WHERE scope_id=$1 AND user_id=$2 FOR SHARE`, actor.ScopeID, actor.UserID).Scan(&status); err != nil {
		return uuid.Nil, principalLockError(err, ErrPermissionDenied)
	}
	if status != "active" {
		return uuid.Nil, ErrPermissionDenied
	}
	var revokedAt *time.Time
	var expiresAt time.Time
	if err := tx.QueryRow(ctx, `SELECT revoked_at,expires_at FROM auth_sessions
		WHERE id=$1 AND user_id=$2 AND scope_id=$3 FOR SHARE`, actor.SessionID,
		actor.UserID, actor.ScopeID).Scan(&revokedAt, &expiresAt); err != nil {
		return uuid.Nil, principalLockError(err, ErrPermissionDenied)
	}
	if revokedAt != nil || !now.Before(expiresAt) {
		return uuid.Nil, ErrPermissionDenied
	}
	return *tenantID, nil
}

func principalLockError(err, denied error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return denied
	}
	return fmt.Errorf("%w: read authorization state", protocol.ErrUnavailable)
}

func authorizeDelegation(ctx context.Context, tx pgx.Tx, actor actorState, permissions []string) (bool, error) {
	rows, err := tx.Query(ctx, `SELECT permission_name,step_up_required
		FROM custom_rbac_permission_catalog WHERE permission_name=ANY($1::text[])`, permissions)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	allowed := make(map[string]bool, len(permissions))
	critical := false
	for rows.Next() {
		var permission string
		var stepUp bool
		if err := rows.Scan(&permission, &stepUp); err != nil {
			return false, err
		}
		allowed[permission] = true
		critical = critical || stepUp
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	for _, permission := range permissions {
		if !allowed[permission] {
			return false, ErrPermissionNotAllowed
		}
		if _, ok := actor.permissions[permission]; !ok {
			return false, ErrPermissionEscalation
		}
	}
	return critical, nil
}

func containsCriticalPermission(ctx context.Context, tx pgx.Tx, permissions []string) (bool, error) {
	var critical bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM custom_rbac_permission_catalog
		WHERE permission_name=ANY($1::text[]) AND step_up_required)`, permissions).Scan(&critical)
	return critical, err
}

func (s *Service) verifyStepUp(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	tenantID uuid.UUID,
	proof StepUpProof,
	mutation MutationContext,
	payloadDigest [sha256.Size]byte,
	check StepUpCheck,
	required bool,
) (StepUpEvidence, error) {
	if !required {
		return StepUpEvidence{}, nil
	}
	if !validText(proof.Token, 1, 512) {
		return StepUpEvidence{}, ErrStepUpRequired
	}
	check.Actor = actor
	check.TenantID = tenantID
	check.Audience = "custom-rbac"
	check.MutationDigest = mutationAuthorizationDigest(check.Action, mutation.IdempotencyKey, payloadDigest)
	check.RequestID = mutation.RequestID
	check.TraceID = mutation.TraceID
	evidence, err := s.stepUp.VerifyAndConsume(ctx, tx, proof, check)
	if err != nil {
		return StepUpEvidence{}, ErrStepUpRequired
	}
	now := storeTime(s.now())
	verifiedAt := storeTime(evidence.VerifiedAt)
	if evidence.ProofID == uuid.Nil ||
		(evidence.Method != "totp" && evidence.Method != "recovery_code" && evidence.Method != "webauthn") ||
		verifiedAt.After(now) || verifiedAt.Before(now.Add(-StepUpMaxAge)) {
		return StepUpEvidence{}, ErrStepUpRequired
	}
	evidence.VerifiedAt = verifiedAt
	return evidence, nil
}

func mutationAuthorizationDigest(
	operation, idempotencyKey string,
	payloadDigest [sha256.Size]byte,
) []byte {
	digest := requestDigest(struct {
		Version        int    `json:"version"`
		Operation      string `json:"operation"`
		IdempotencyKey string `json:"idempotency_key"`
		PayloadSHA256  string `json:"payload_sha256"`
	}{1, operation, idempotencyKey, hex.EncodeToString(payloadDigest[:])})
	return append([]byte(nil), digest[:]...)
}

func loadRoleForMutation(ctx context.Context, tx pgx.Tx, scopeID, roleID uuid.UUID) (Role, error) {
	role, err := loadRole(ctx, tx, scopeID, roleID, true)
	if !errors.Is(err, ErrNotFound) {
		return role, err
	}
	var system bool
	err = tx.QueryRow(ctx, `SELECT system_role FROM roles WHERE scope_id=$1 AND id=$2`, scopeID, roleID).Scan(&system)
	if err == nil && system {
		return Role{}, ErrSystemRoleImmutable
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Role{}, err
	}
	return Role{}, ErrNotFound
}

func loadRole(ctx context.Context, tx pgx.Tx, scopeID, roleID uuid.UUID, lock bool) (Role, error) {
	query := `SELECT role_row.id,role_row.tenant_id,role_row.tenant_scope_id,
		role_row.current_name,role_row.current_revision,revision.permissions,
		role_row.deactivated_at,role_row.created_at
	FROM custom_roles role_row
	JOIN custom_role_revisions revision ON revision.role_id=role_row.id
	 AND revision.revision=role_row.current_revision
	WHERE role_row.tenant_scope_id=$1 AND role_row.id=$2`
	if lock {
		query += " FOR UPDATE OF role_row"
	}
	var role Role
	err := tx.QueryRow(ctx, query, scopeID, roleID).Scan(&role.ID, &role.TenantID,
		&role.TenantScopeID, &role.Name, &role.CurrentRevision, &role.Permissions,
		&role.DeactivatedAt, &role.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Role{}, ErrNotFound
	}
	return role, err
}

func insertRevision(
	ctx context.Context,
	tx pgx.Tx,
	roleID, tenantID uuid.UUID,
	actor Actor,
	revision int64,
	name string,
	permissions []string,
	action string,
	evidence StepUpEvidence,
	now time.Time,
) error {
	_, err := tx.Exec(ctx, `INSERT INTO custom_role_revisions(
		role_id,tenant_id,tenant_scope_id,revision,name,permissions,action,
		created_by_user_id,created_by_scope_id,step_up_proof_id,step_up_method,step_up_verified_at,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$3,$9,$10,$11,$12)`,
		roleID, tenantID, actor.ScopeID, revision, name, permissions, action, actor.UserID,
		nullableEvidenceID(evidence), nullableEvidenceMethod(evidence), nullableEvidenceTime(evidence), now)
	return mapDatabaseError(err)
}

func requireActiveTenantMember(ctx context.Context, tx pgx.Tx, scopeID, userID uuid.UUID) error {
	var kind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes
		WHERE id=$1 FOR SHARE`, scopeID).Scan(&kind, &tenantID); err != nil {
		return principalLockError(err, ErrTenantBoundary)
	}
	if kind != "tenant" || tenantID == nil {
		return ErrTenantBoundary
	}
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1 FOR UPDATE`, *tenantID).Scan(&status); err != nil {
		return principalLockError(err, ErrTenantBoundary)
	}
	if status != "active" {
		return ErrTenantBoundary
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR UPDATE`, userID).Scan(&status); err != nil {
		return principalLockError(err, ErrTenantBoundary)
	}
	if status != "active" {
		return ErrTenantBoundary
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships
		WHERE scope_id=$1 AND user_id=$2 FOR UPDATE`, scopeID, userID).Scan(&status); err != nil {
		return principalLockError(err, ErrTenantBoundary)
	}
	if status != "active" {
		return ErrTenantBoundary
	}
	return nil
}

func findWrite(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	operation, key string,
) ([]byte, []byte, bool, error) {
	var digest, response []byte
	err := tx.QueryRow(ctx, `SELECT request_digest,response_body
		FROM custom_rbac_write_requests
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND idempotency_key=$4`,
		actor.ScopeID, actor.UserID, operation, key).Scan(&digest, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, err
	}
	return digest, response, true, nil
}

func (s *Service) appendAudit(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	action, resourceID string,
	mutation MutationContext,
	payload map[string]any,
) error {
	payload["trace_id"] = mutation.TraceID
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: action,
		ResourceType: "custom_rbac", ResourceID: resourceID, RequestID: mutation.RequestID,
		Result: "success", Payload: payload,
	})
}

func normalizeRoleName(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if !validText(value, 1, 128) {
		return "", ErrInvalidInput
	}
	return value, nil
}

func normalizePermissions(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 128 {
		return nil, ErrInvalidInput
	}
	result := append([]string(nil), values...)
	for _, value := range result {
		if value != strings.ToLower(strings.TrimSpace(value)) || !validText(value, 1, 128) {
			return nil, ErrInvalidInput
		}
	}
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, ErrInvalidInput
		}
	}
	return result, nil
}

func validActor(actor Actor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.SessionID != uuid.Nil && actor.ScopeKind == "tenant" &&
		actor.IdentityDomain == CustomerControlIdentityDomain
}

func validMutation(value MutationContext) bool {
	return tokenPattern.MatchString(value.IdempotencyKey) && validText(value.RequestID, 1, 128) &&
		validText(value.TraceID, 1, 128)
}

func validText(value string, minimum, maximum int) bool {
	if value != strings.TrimSpace(value) || !utf8.ValidString(value) {
		return false
	}
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	return true
}

func requestDigest(value any) [32]byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic("rbacmanager request digest contains unsupported value: " + err.Error())
	}
	return sha256.Sum256(encoded)
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func nullableEvidenceID(evidence StepUpEvidence) any {
	if evidence.ProofID == uuid.Nil {
		return nil
	}
	return evidence.ProofID
}

func nullableEvidenceMethod(evidence StepUpEvidence) any {
	if evidence.Method == "" {
		return nil
	}
	return evidence.Method
}

func nullableEvidenceTime(evidence StepUpEvidence) any {
	if evidence.VerifiedAt.IsZero() {
		return nil
	}
	return storeTime(evidence.VerifiedAt)
}

func storeTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}

func mapDatabaseError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return err
	}
	if pgErr.Code == "23505" {
		if strings.Contains(pgErr.ConstraintName, "current_name") || strings.Contains(pgErr.ConstraintName, "roles_scope_id_name") {
			return ErrNameConflict
		}
		return ErrRevisionConflict
	}
	return err
}
