package rbacmanagerhttp

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/rbacmanager"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresReadStore struct {
	pool *pgxpool.Pool
}

func newPostgresReadStore(pool *pgxpool.Pool) *postgresReadStore {
	return &postgresReadStore{pool: pool}
}

func (store *postgresReadStore) ListRoles(
	ctx context.Context,
	actor rbacmanager.Actor,
	query RolePageQuery,
) (RolePageFacts, error) {
	result := RolePageFacts{}
	err := store.authorizedRead(ctx, actor, func(tx pgx.Tx) error {
		snapshot, err := readSnapshotVersion(ctx, tx, query.SnapshotVersion)
		if err != nil {
			return err
		}
		result.SnapshotVersion = &snapshot
		rows, err := tx.Query(ctx, `SELECT role_row.id,revision.name,revision.revision,
			revision.permissions,deactivation.deactivated_at,role_row.created_at,
			role_row.created_state_version
			FROM custom_roles role_row
			JOIN LATERAL (
				SELECT candidate.name,candidate.revision,candidate.permissions
				FROM custom_role_revisions candidate
				WHERE candidate.role_id=role_row.id AND candidate.state_version<=$2
				ORDER BY candidate.state_version DESC LIMIT 1
			) revision ON true
			LEFT JOIN LATERAL (
				SELECT candidate.deactivated_at
				FROM custom_role_deactivations candidate
				WHERE candidate.role_id=role_row.id AND candidate.state_version<=$2
				ORDER BY candidate.state_version DESC LIMIT 1
			) deactivation ON true
			WHERE role_row.tenant_scope_id=$1 AND role_row.created_state_version<=$2
			  AND ($3 OR deactivation.deactivated_at IS NULL)
			  AND ($4::bigint IS NULL OR (role_row.created_state_version,role_row.id)<($4,$5))
			ORDER BY role_row.created_state_version DESC,role_row.id DESC LIMIT $6`,
			actor.ScopeID, snapshot, query.IncludeDeactivated, query.AfterVersion, query.AfterID, query.Limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		result.Items = make([]RoleView, 0, query.Limit)
		for rows.Next() {
			var role RoleView
			if err := rows.Scan(&role.ID, &role.Name, &role.CurrentRevision, &role.Permissions,
				&role.DeactivatedAt, &role.CreatedAt, &role.StateVersion); err != nil {
				return err
			}
			result.Items = append(result.Items, role)
		}
		return rows.Err()
	})
	return result, err
}

func (store *postgresReadStore) GetRole(
	ctx context.Context,
	actor rbacmanager.Actor,
	roleID uuid.UUID,
) (RoleView, error) {
	var result RoleView
	err := store.authorizedRead(ctx, actor, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT role_row.id,role_row.current_name,
			role_row.current_revision,revision.permissions,role_row.deactivated_at,role_row.created_at
			FROM custom_roles role_row
			JOIN custom_role_revisions revision ON revision.role_id=role_row.id
			 AND revision.revision=role_row.current_revision
			WHERE role_row.tenant_scope_id=$1 AND role_row.id=$2`, actor.ScopeID, roleID).
			Scan(&result.ID, &result.Name, &result.CurrentRevision, &result.Permissions,
				&result.DeactivatedAt, &result.CreatedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	})
	return result, err
}

func (store *postgresReadStore) PermissionCatalog(
	ctx context.Context,
	actor rbacmanager.Actor,
) ([]PermissionView, error) {
	result := []PermissionView{}
	err := store.authorizedRead(ctx, actor, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT permission_name,step_up_required
			FROM custom_rbac_permission_catalog ORDER BY permission_name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var permission PermissionView
			if err := rows.Scan(&permission.Name, &permission.StepUpRequired); err != nil {
				return err
			}
			result = append(result, permission)
		}
		return rows.Err()
	})
	return result, err
}

func (store *postgresReadStore) ListGrants(
	ctx context.Context,
	actor rbacmanager.Actor,
	query GrantPageQuery,
) (GrantPageFacts, error) {
	result := GrantPageFacts{}
	err := store.authorizedRead(ctx, actor, func(tx pgx.Tx) error {
		snapshot, err := readSnapshotVersion(ctx, tx, query.SnapshotVersion)
		if err != nil {
			return err
		}
		result.SnapshotVersion = &snapshot
		rows, err := tx.Query(ctx, `SELECT grant_row.id,grant_row.role_id,grant_row.role_revision,
			grant_row.subject_user_id,grant_row.granted_by_user_id,grant_row.granted_at,
			revocation.revoked_at,grant_row.state_version
			FROM custom_role_grants grant_row
			LEFT JOIN LATERAL (
				SELECT candidate.revoked_at
				FROM custom_role_grant_revocations candidate
				WHERE candidate.grant_id=grant_row.id AND candidate.state_version<=$4
				ORDER BY candidate.state_version DESC LIMIT 1
			) revocation ON true
			WHERE grant_row.tenant_scope_id=$1 AND grant_row.state_version<=$4
			  AND ($2::uuid IS NULL OR grant_row.role_id=$2)
			  AND ($3::uuid IS NULL OR grant_row.subject_user_id=$3)
			  AND ($5='all' OR ($5='active' AND revocation.revoked_at IS NULL) OR
			       ($5='revoked' AND revocation.revoked_at IS NOT NULL))
			  AND ($6::bigint IS NULL OR (grant_row.state_version,grant_row.id)<($6,$7))
			ORDER BY grant_row.state_version DESC,grant_row.id DESC LIMIT $8`,
			actor.ScopeID, query.RoleID, query.SubjectUserID, snapshot, query.State,
			query.AfterVersion, query.AfterID, query.Limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		result.Items = make([]GrantView, 0, query.Limit)
		for rows.Next() {
			var grant GrantView
			if err := rows.Scan(&grant.ID, &grant.RoleID, &grant.RoleRevision,
				&grant.SubjectUserID, &grant.GrantedByUserID, &grant.GrantedAt, &grant.RevokedAt,
				&grant.StateVersion); err != nil {
				return err
			}
			result.Items = append(result.Items, grant)
		}
		return rows.Err()
	})
	return result, err
}

func readSnapshotVersion(ctx context.Context, tx pgx.Tx, requested *int64) (int64, error) {
	if requested != nil {
		if *requested < 1 {
			return 0, ErrInvalidStoreResponse
		}
		return *requested, nil
	}
	var version int64
	if err := tx.QueryRow(ctx, `SELECT current_version FROM custom_rbac_state_watermark
		WHERE singleton FOR SHARE`).Scan(&version); err != nil || version < 0 {
		if err != nil {
			return 0, err
		}
		return 0, ErrInvalidStoreResponse
	}
	return version, nil
}

func (store *postgresReadStore) authorizedRead(
	ctx context.Context,
	actor rbacmanager.Actor,
	read func(pgx.Tx) error,
) error {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`,
		"custom-rbac-tenant:"+actor.ScopeID.String()); err != nil {
		return err
	}
	var kind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes
		WHERE id=$1 FOR SHARE`, actor.ScopeID).Scan(&kind, &tenantID); err != nil {
		return readPrincipalError(err)
	}
	if kind != "tenant" || tenantID == nil {
		return ErrPermissionDenied
	}
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1 FOR SHARE`, *tenantID).Scan(&status); err != nil {
		return readPrincipalError(err)
	}
	if status != "active" {
		return ErrPermissionDenied
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR SHARE`, actor.UserID).Scan(&status); err != nil {
		return readPrincipalError(err)
	}
	if status != "active" {
		return ErrPermissionDenied
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships
		WHERE scope_id=$1 AND user_id=$2 FOR SHARE`, actor.ScopeID, actor.UserID).Scan(&status); err != nil {
		return readPrincipalError(err)
	}
	if status != "active" {
		return ErrPermissionDenied
	}
	var sessionActive bool
	if err := tx.QueryRow(ctx, `SELECT revoked_at IS NULL AND expires_at>CURRENT_TIMESTAMP
		FROM auth_sessions WHERE id=$1 AND user_id=$2 AND scope_id=$3 FOR SHARE`,
		actor.SessionID, actor.UserID, actor.ScopeID).Scan(&sessionActive); err != nil {
		return readPrincipalError(err)
	}
	if !sessionActive {
		return ErrPermissionDenied
	}
	var allowed bool
	if err := tx.QueryRow(ctx, `SELECT custom_rbac_actor_can_manage($1,$2)`,
		actor.ScopeID, actor.UserID).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	if err := read(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func readPrincipalError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPermissionDenied
	}
	return err
}
