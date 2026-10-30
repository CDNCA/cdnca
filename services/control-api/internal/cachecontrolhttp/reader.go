package cachecontrolhttp

import (
	"context"
	"errors"

	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresReader struct {
	pool       *pgxpool.Pool
	authorizer *iamlock.Authorizer
}

func newProductionPostgresReader(pool *pgxpool.Pool, authorizer *iamlock.Authorizer) (*PostgresReader, error) {
	if pool == nil || authorizer == nil || !authorizer.Configured() {
		return nil, ErrInvalidRequest
	}
	return &PostgresReader{pool: pool, authorizer: authorizer}, nil
}

func NewPostgresReader(pool *pgxpool.Pool) (*PostgresReader, error) {
	if pool == nil {
		return nil, ErrInvalidRequest
	}
	return &PostgresReader{pool: pool}, nil
}

func (reader *PostgresReader) ListPolicyRevisions(
	ctx context.Context,
	actor cachecontrol.Actor,
	siteID uuid.UUID,
	query PolicyPageQuery,
) (PolicyReadPage, error) {
	if ctx == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ActorScopeID == uuid.Nil || siteID == uuid.Nil ||
		query.SnapshotRevision < 0 || query.BeforeRevision < 0 || query.Limit < 1 || query.Limit > 100 {
		return PolicyReadPage{}, ErrInvalidRequest
	}
	var result PolicyReadPage
	err := pgx.BeginTxFunc(ctx, reader.pool, reader.transactionOptions(), func(tx pgx.Tx) error {
		if err := reader.authorize(ctx, tx, actor, PermissionPoliciesRead); err != nil {
			return err
		}
		var siteExists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(
			SELECT 1 FROM sites WHERE scope_id=$1 AND id=$2 AND deleted_at IS NULL
		)`, actor.ScopeID, siteID).Scan(&siteExists); err != nil {
			return ErrStoreUnavailable
		}
		if !siteExists {
			return ErrNotFound
		}
		result.SnapshotRevision = query.SnapshotRevision
		if result.SnapshotRevision == 0 {
			if err := tx.QueryRow(ctx, `SELECT COALESCE(max(revision),0)
				FROM cache_policy_revisions WHERE scope_id=$1 AND site_id=$2`,
				actor.ScopeID, siteID).Scan(&result.SnapshotRevision); err != nil {
				return ErrStoreUnavailable
			}
		}
		rows, err := tx.Query(ctx, `
			SELECT binding.site_id,binding.scope_id,binding.tenant_id,binding.revision,
			       binding.binding_mode,binding.definition_id,binding.definition_revision,
			       definition.schema_version,definition.mode,definition.rules,definition.query_mode,
			       definition.query_names,definition.vary_headers,definition.disk_quota_bytes,
			       binding.created_by_user_id,binding.request_id,binding.created_at,definition.extensions
			FROM cache_policy_revisions binding
			JOIN cache_policy_definition_revisions definition
			  ON definition.scope_id=binding.scope_id AND definition.definition_id=binding.definition_id
			 AND definition.revision=binding.definition_revision
			WHERE binding.scope_id=$1 AND binding.site_id=$2 AND binding.revision <= $3
			  AND ($4::bigint=0 OR binding.revision < $4)
			ORDER BY binding.revision DESC LIMIT $5`, actor.ScopeID, siteID, result.SnapshotRevision,
			query.BeforeRevision, query.Limit+1)
		if err != nil {
			return ErrStoreUnavailable
		}
		defer rows.Close()
		for rows.Next() {
			var item cachecontrol.PolicyRevision
			var schemaVersion int
			var mode cachecontrol.PolicyMode
			var queryMode cachecontrol.QueryMode
			var queryNames, varyHeaders []string
			var diskQuotaBytes int64
			var rules, extensions []byte
			if err := rows.Scan(
				&item.SiteID, &item.ScopeID, &item.TenantID, &item.Revision,
				&item.BindingMode, &item.DefinitionID, &item.DefinitionRevision,
				&schemaVersion, &mode, &rules, &queryMode, &queryNames,
				&varyHeaders, &diskQuotaBytes,
				&item.CreatedByUserID, &item.RequestID, &item.CreatedAt, &extensions,
			); err != nil {
				return ErrInvalidStoreResponse
			}
			item.Document, err = cachecontrol.DecodeStoredPolicyDocument(
				schemaVersion, mode, rules, queryMode, queryNames, varyHeaders, diskQuotaBytes, extensions,
			)
			if err != nil {
				return ErrInvalidStoreResponse
			}
			result.Items = append(result.Items, item)
		}
		if err := rows.Err(); err != nil {
			return ErrStoreUnavailable
		}
		if len(result.Items) > query.Limit {
			result.Items = result.Items[:query.Limit]
			result.HasMore = true
		}
		return nil
	})
	return result, normalizeReadError(ctx, err)
}

func (reader *PostgresReader) ListOperations(
	ctx context.Context,
	actor cachecontrol.Actor,
	query OperationPageQuery,
) (OperationReadPage, error) {
	if ctx == nil || actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil || actor.ActorScopeID == uuid.Nil ||
		query.Limit < 1 || query.Limit > 100 ||
		query.SnapshotPosition < 0 || (query.BeforeCreated == nil) != (query.BeforeID == nil) {
		return OperationReadPage{}, ErrInvalidRequest
	}
	result := OperationReadPage{Items: []OperationSummary{}}
	err := pgx.BeginTxFunc(ctx, reader.pool, reader.transactionOptions(), func(tx pgx.Tx) error {
		if err := reader.authorize(ctx, tx, actor, PermissionOperationsRead); err != nil {
			return err
		}
		var audited bool
		if err := tx.QueryRow(ctx, `SELECT NOT EXISTS(
			SELECT 1
			FROM cache_operations operation
			LEFT JOIN LATERAL (
				SELECT count(*) AS count
				FROM audit_events event
				WHERE event.scope_id=operation.scope_id
				  AND event.action='cache.operation.create'
				  AND event.resource_type='cache_operation'
				  AND event.resource_id=operation.id::text
				  AND event.result='success'
			) creation ON true
			WHERE operation.scope_id=$1 AND creation.count <> 1
		)`, actor.ScopeID).Scan(&audited); err != nil {
			return ErrStoreUnavailable
		}
		if !audited {
			return ErrInvalidStoreResponse
		}
		result.SnapshotPosition = query.SnapshotPosition
		if result.SnapshotPosition == 0 {
			if err := tx.QueryRow(ctx, `SELECT COALESCE(max(stream_position),0)
				FROM audit_events WHERE scope_id=$1`, actor.ScopeID).Scan(&result.SnapshotPosition); err != nil {
				return ErrStoreUnavailable
			}
		}
		states := make([]string, len(query.Filters.States))
		for index, state := range query.Filters.States {
			states[index] = string(state)
		}
		if query.SnapshotPosition == 0 {
			// First page: per-state counts under the other filters, for the
			// state pills. Every operation has its one creation audit (checked
			// above), so no audit join; (scope_id,state,...) serves the scan.
			counts, err := tx.Query(ctx, `
				SELECT operation.state,count(*) FROM cache_operations operation
				WHERE operation.scope_id=$1
				  AND ($2::uuid IS NULL OR operation.site_id=$2)
				  AND ($3::text='' OR EXISTS (SELECT 1 FROM sites site WHERE site.scope_id=operation.scope_id
					AND site.id=operation.site_id AND site.display_id::text=$3))
				  AND ($4::text='' OR operation.action=$4)
				  AND ($5::text='' OR operation.target_type=$5)
				  AND ($6::text='' OR operation.display_id::text=$6 OR EXISTS (
					SELECT 1 FROM sites site WHERE site.scope_id=operation.scope_id
					  AND site.id=operation.site_id AND site.display_id::text=$6
				  ) OR EXISTS (
					SELECT 1 FROM cache_operation_targets target
					WHERE target.scope_id=operation.scope_id AND target.operation_id=operation.id
					  AND strpos(lower(target.canonical_url),lower($6))>0
				  ))
				GROUP BY operation.state`, actor.ScopeID, query.Filters.SiteID, query.Filters.SiteDisplayID,
				query.Filters.Action, query.Filters.TargetType, query.Filters.Search)
			if err != nil {
				return ErrStoreUnavailable
			}
			result.StateCounts = StateCounts{}
			for _, state := range operationStates {
				result.StateCounts[state] = 0
			}
			for counts.Next() {
				var state cachecontrol.State
				var count int64
				if err := counts.Scan(&state, &count); err != nil {
					counts.Close()
					return ErrInvalidStoreResponse
				}
				if _, known := result.StateCounts[state]; !known {
					counts.Close()
					return ErrInvalidStoreResponse
				}
				result.StateCounts[state] = count
			}
			counts.Close()
			if counts.Err() != nil {
				return ErrStoreUnavailable
			}
		}
		rows, err := tx.Query(ctx, `
			SELECT operation.id,operation.display_id::text,operation.site_id,site.display_id::text,
			       operation.action,operation.target_type,operation.state,
			       operation.max_attempts,operation.target_count,operation.node_count,
			       operation.total_count,operation.completed_count,operation.succeeded_count,
			       operation.failed_count,operation.cancelled_count,operation.created_at,
			       operation.updated_at,operation.completed_at,operation.auto_nodes,
			       operation.parent_operation_id,first_target.canonical_url,first_target.canonical_path
			FROM cache_operations operation
			JOIN sites site ON site.scope_id=operation.scope_id AND site.id=operation.site_id
			JOIN cache_operation_targets first_target
			  ON first_target.scope_id=operation.scope_id AND first_target.operation_id=operation.id
			 AND first_target.ordinal=1
			JOIN audit_events creation
			  ON creation.scope_id=operation.scope_id
			 AND creation.action='cache.operation.create'
			 AND creation.resource_type='cache_operation'
			 AND creation.resource_id=operation.id::text
			 AND creation.result='success'
			WHERE operation.scope_id=$1 AND creation.stream_position <= $2
			  AND ($3::uuid IS NULL OR operation.site_id=$3)
			  AND ($4::text='' OR site.display_id::text=$4)
			  AND ($5::text='' OR operation.action=$5)
			  AND ($6::text='' OR operation.target_type=$6)
			  AND (cardinality($7::text[])=0 OR operation.state=ANY($7))
			  AND ($8::text='' OR operation.display_id::text=$8 OR site.display_id::text=$8 OR EXISTS (
				SELECT 1 FROM cache_operation_targets target
				WHERE target.scope_id=operation.scope_id AND target.operation_id=operation.id
				  AND strpos(lower(target.canonical_url),lower($8))>0
			  ))
			  AND ($9::timestamptz IS NULL OR (operation.created_at,operation.id) < ($9,$10::uuid))
			ORDER BY operation.created_at DESC,operation.id DESC LIMIT $11`, actor.ScopeID, result.SnapshotPosition,
			query.Filters.SiteID, query.Filters.SiteDisplayID, query.Filters.Action, query.Filters.TargetType,
			states, query.Filters.Search, query.BeforeCreated, query.BeforeID, query.Limit+1)
		if err != nil {
			return ErrStoreUnavailable
		}
		defer rows.Close()
		for rows.Next() {
			var item OperationSummary
			var maximum int
			var first cachecontrol.Target
			if err := rows.Scan(
				&item.ID, &item.DisplayID, &item.SiteID, &item.SiteDisplayID,
				&item.Action, &item.TargetType, &item.State, &maximum,
				&item.TargetCount, &item.NodeCount, &item.Progress.Total, &item.Progress.Completed,
				&item.Progress.Succeeded, &item.Progress.Failed, &item.Progress.Cancelled,
				&item.CreatedAt, &item.UpdatedAt, &item.CompletedAt, &item.AutoNodes,
				&item.ParentOperationID, &first.CanonicalURL, &first.CanonicalPath,
			); err != nil || maximum < 1 {
				return ErrInvalidStoreResponse
			}
			first.Ordinal = 1
			item.FirstTarget = targetView(first)
			item.MaxAttempts = uint32(maximum)
			result.Items = append(result.Items, item)
		}
		if err := rows.Err(); err != nil {
			return ErrStoreUnavailable
		}
		if len(result.Items) > query.Limit {
			result.Items = result.Items[:query.Limit]
			result.HasMore = true
		}
		return nil
	})
	return result, normalizeReadError(ctx, err)
}

func (reader *PostgresReader) transactionOptions() pgx.TxOptions {
	if reader.authorizer != nil {
		return pgx.TxOptions{IsoLevel: pgx.ReadCommitted}
	}
	return pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}
}

func (reader *PostgresReader) authorize(
	ctx context.Context,
	tx pgx.Tx,
	actor cachecontrol.Actor,
	permission string,
) error {
	if reader.authorizer == nil {
		return authorizeReader(ctx, tx, actor, permission)
	}
	session, err := runtimeSessionFromContext(ctx)
	if err != nil || session.rawToken == "" || session.principal.UserID != actor.UserID || session.principal.ScopeID == uuid.Nil ||
		actor.ScopeID == uuid.Nil || actor.ActorScopeID == uuid.Nil ||
		session.principal.ScopeID != actor.ActorScopeID {
		return ErrNotFound
	}
	sealed, err := reader.authorizer.AuthorizeSession(ctx, tx, session.rawToken, actor.ScopeID, permission)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, iamlock.ErrPermissionDenied) {
			return ErrNotFound
		}
		return ErrStoreUnavailable
	}
	if !sealed.Valid() || sealed.UserID() != actor.UserID ||
		sealed.AuthenticationScopeID() != actor.ActorScopeID || sealed.TargetScopeID() != actor.ScopeID ||
		sealed.CredentialKind() != "session" || sealed.CredentialID() != session.sessionID ||
		sealed.CredentialRevision() != 0 {
		return ErrNotFound
	}
	tenantID, hasTenant := sealed.TenantID()
	if !hasTenant || tenantID == uuid.Nil {
		return ErrNotFound
	}
	if session.principal.ScopeKind == string(AudienceTenant) {
		if session.principal.ScopeID != actor.ScopeID || session.principal.TenantID == nil ||
			*session.principal.TenantID != tenantID {
			return ErrNotFound
		}
	} else if session.principal.ScopeKind != string(AudiencePlatform) || session.principal.TenantID != nil {
		return ErrNotFound
	}
	return nil
}

func authorizeReader(ctx context.Context, tx pgx.Tx, actor cachecontrol.Actor, permission string) error {
	var allowed bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1
		FROM access_scopes target_scope
		JOIN tenants target_tenant ON target_tenant.id=target_scope.tenant_id
		JOIN users actor_user ON actor_user.id=$2
		WHERE target_scope.id=$1 AND target_scope.kind='tenant'
		  AND target_tenant.status='active' AND actor_user.status='active'
		  AND (
			EXISTS(
				SELECT 1
				FROM memberships membership
				JOIN role_assignments assignment
				  ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
				JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
				JOIN role_permissions role_permission ON role_permission.role_id=role.id
				WHERE membership.scope_id=target_scope.id AND membership.user_id=actor_user.id
				  AND membership.status='active' AND role_permission.permission_name=$3
			)
			OR EXISTS(
				SELECT 1
				FROM access_scopes platform_scope
				JOIN memberships membership ON membership.scope_id=platform_scope.id
				JOIN role_assignments assignment
				  ON assignment.scope_id=membership.scope_id AND assignment.user_id=membership.user_id
				JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
				JOIN role_permissions role_permission ON role_permission.role_id=role.id
				WHERE platform_scope.kind='platform' AND membership.user_id=actor_user.id
				  AND membership.status='active' AND role_permission.permission_name='platform.admin'
			)
		  )
	)`, actor.ScopeID, actor.UserID, permission).Scan(&allowed); err != nil {
		return ErrStoreUnavailable
	}
	if !allowed {
		return ErrNotFound
	}
	return nil
}

func normalizeReadError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, ErrInvalidRequest) || errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrInvalidStoreResponse) || errors.Is(err, ErrStoreUnavailable) {
		return err
	}
	return ErrStoreUnavailable
}

var _ ReadStore = (*PostgresReader)(nil)
