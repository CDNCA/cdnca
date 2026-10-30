package sitegroup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (service *Service) ListAdmin(ctx context.Context, actor Actor, page, limit int) (AdminGroupList, error) {
	if page < 1 || page > 1_000_000 || limit < 1 || limit > 100 {
		return AdminGroupList{}, ErrInvalidInput
	}
	result := AdminGroupList{Items: []AdminGroup{}, Page: page, Limit: limit}
	err := pgx.BeginFunc(ctx, service.pool, func(tx pgx.Tx) error {
		if err := service.authorizeAdmin(ctx, tx, actor); err != nil {
			return err
		}
		var encoded []byte
		if err := tx.QueryRow(ctx, `WITH active_groups AS MATERIALIZED (
			SELECT g.id,g.scope_id,d.display_id::text,g.name,g.remark,g.revision,g.created_at,g.updated_at
			FROM site_groups g JOIN site_group_display_ids d ON d.scope_id=g.scope_id AND d.group_id=g.id
			WHERE g.deleted_at IS NULL
		), page AS (
			SELECT * FROM active_groups ORDER BY created_at,id,scope_id LIMIT $1 OFFSET $2
		), items AS (
			SELECT p.*,CASE WHEN owners.total=1 THEN owners.items->0 ELSE NULL END AS "user",
				CASE owners.total WHEN 0 THEN 'missing' WHEN 1 THEN 'resolved' ELSE 'ambiguous' END AS user_state
			FROM page p CROSS JOIN LATERAL (
				SELECT count(*) AS total,jsonb_agg(jsonb_build_object('id',u.id,'display_id',u.display_id::text,'username',u.username)) AS items
				FROM users u JOIN memberships m ON m.user_id=u.id AND m.scope_id=p.scope_id AND m.status='active'
				WHERE NOT EXISTS(SELECT 1 FROM identity_user_deletions deletion WHERE deletion.user_id=u.id)
				AND EXISTS(SELECT 1 FROM role_assignments ra JOIN roles r ON r.id=ra.role_id AND r.scope_id=ra.scope_id
					WHERE ra.scope_id=p.scope_id AND ra.user_id=u.id AND r.system_role AND r.name='tenant_owner')
			) owners
		) SELECT (SELECT count(*) FROM active_groups),COALESCE((SELECT jsonb_agg(to_jsonb(items) ORDER BY created_at,id,scope_id) FROM items),'[]'::jsonb)`,
			limit, (page-1)*limit).Scan(&result.Total, &encoded); err != nil {
			return err
		}
		return json.Unmarshal(encoded, &result.Items)
	})
	if err != nil {
		return AdminGroupList{}, fmt.Errorf("list administrator site groups: %w", err)
	}
	return result, nil
}

func (service *Service) authorizeAdmin(ctx context.Context, tx pgx.Tx, actor Actor) error {
	var platform uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&platform); err != nil {
		return ErrUnavailable
	}
	for _, permission := range []string{readPermission, "identity.users.manage"} {
		var authorization iamlock.Authorization
		var err error
		switch actor.Credential.Kind {
		case CredentialSession:
			authorization, err = service.authorizer.AuthorizeSession(ctx, tx, actor.Credential.Raw, platform, permission)
		case CredentialAPIKey:
			authorization, err = service.authorizer.AuthorizeAPIKey(ctx, tx, actor.Credential.Raw, platform, permission)
		default:
			return ErrAuthenticationRequired
		}
		if errors.Is(err, iamlock.ErrInvalidCredential) {
			return ErrAuthenticationRequired
		}
		if errors.Is(err, iamlock.ErrPermissionDenied) {
			return ErrPermissionDenied
		}
		if err != nil {
			return ErrUnavailable
		}
		_, tenant := authorization.TenantID()
		if !authorization.Valid() || tenant || authorization.AuthenticationScopeID() != platform || authorization.TargetScopeID() != platform {
			return ErrPermissionDenied
		}
	}
	return nil
}
