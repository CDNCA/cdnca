package site

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const siteUserDefaultColumns = `d.id, d.display_id::text, d.scope_id, d.owner_user_id, d.setting_name, d.setting_value,
	d.scope_name, d.group_id, g.name, d.enabled, d.revision, d.created_at, d.updated_at`

const siteUserDefaultFrom = ` FROM site_user_defaults d
	LEFT JOIN site_groups g ON g.scope_id = d.scope_id AND g.id = d.group_id`

func scanSiteUserDefault(row rowScanner) (SiteUserDefault, error) {
	var item SiteUserDefault
	err := row.Scan(&item.ID, &item.DisplayID, &item.ScopeID, &item.OwnerUserID, &item.SettingName, &item.Value,
		&item.ScopeName, &item.GroupID, &item.GroupName, &item.Enabled, &item.Revision, &item.CreatedAt, &item.UpdatedAt)
	return item, err
}

// ListUserDefaults: a tenant sees only its own scope's rows.
func (s *Store) ListUserDefaults(ctx context.Context, actor Actor, filter SiteUserDefaultListFilter) (SiteUserDefaultListResult, error) {
	where := ` WHERE ($1 = 'platform' OR d.scope_id = $2) AND ($3 = '' OR d.setting_name = $3)
		AND ($4::boolean IS NULL OR d.enabled = $4)`
	args := []any{actor.ScopeKind, actor.ScopeID, filter.SettingName, filter.Enabled}
	result := SiteUserDefaultListResult{Items: []SiteUserDefault{}, Page: filter.Page, Limit: filter.Limit}
	if err := s.pool.QueryRow(ctx, `SELECT count(*)`+siteUserDefaultFrom+where, args...).Scan(&result.Total); err != nil {
		return SiteUserDefaultListResult{}, fmt.Errorf("count site defaults: %w", err)
	}
	rows, err := s.pool.Query(ctx, `SELECT `+siteUserDefaultColumns+siteUserDefaultFrom+where+`
		ORDER BY d.created_at DESC, d.id DESC LIMIT $5 OFFSET $6`,
		append(args, filter.Limit, (filter.Page-1)*filter.Limit)...)
	if err != nil {
		return SiteUserDefaultListResult{}, fmt.Errorf("list site defaults: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		item, err := scanSiteUserDefault(rows)
		if err != nil {
			return SiteUserDefaultListResult{}, err
		}
		result.Items = append(result.Items, item)
	}
	return result, rows.Err()
}

func (s *Store) CreateUserDefault(ctx context.Context, actor Actor, request SiteUserDefaultCreateRequest,
	id uuid.UUID, digest [32]byte) (SiteUserDefault, error) {
	var result SiteUserDefault
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeTargetScope(ctx, tx, actor, request.TargetScopeID, request.OwnerUserID); err != nil {
			return err
		}
		write, err := s.claimWrite(ctx, tx, actor.UserID, request.TargetScopeID, "site_default.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			return json.Unmarshal(write.ResponseBody, &result)
		}
		if request.Fields.GroupID != nil {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM site_groups
				WHERE scope_id=$1 AND id=$2 AND deleted_at IS NULL)`, request.TargetScopeID, *request.Fields.GroupID).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return ErrInvalidInput
			}
		}
		if err := checkSiteDefaultReference(ctx, tx, request.TargetScopeID, request.Fields.SettingName, request.Fields.Value); err != nil {
			return err
		}
		if err := checkSiteDefaultPolicy(ctx, tx, request.TargetScopeID, request.OwnerUserID, request.Fields.SettingName, request.Fields.Value); err != nil {
			return err
		}
		// Display IDs count per tenant scope, as the site list's.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('site_user_defaults:'||$1::text, 0))`,
			request.TargetScopeID); err != nil {
			return err
		}
		now := s.now().UTC()
		if _, err := tx.Exec(ctx, `INSERT INTO site_user_defaults (id, scope_id, display_id, owner_user_id, setting_name,
				setting_value, scope_name, group_id, created_by_user_id, updated_by_user_id, created_at, updated_at)
			SELECT $1, $2, COALESCE(max(display_id), 0) + 1, $3, $4, $5, $6, $7, $8, $8, $9, $9
			FROM site_user_defaults WHERE scope_id = $2`,
			id, request.TargetScopeID, request.OwnerUserID, request.Fields.SettingName, request.Fields.Value,
			request.Fields.ScopeName, request.Fields.GroupID, actor.UserID, now); err != nil {
			if isUniqueViolation(err) {
				return ErrSiteDefaultConflict
			}
			return err
		}
		if result, err = scanSiteUserDefault(tx.QueryRow(ctx, `SELECT `+siteUserDefaultColumns+siteUserDefaultFrom+
			` WHERE d.id = $1`, id)); err != nil {
			return err
		}
		if err := s.appendUserDefaultAudit(ctx, tx, actor, result, "site_default.create", request.RequestID); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, "site_default.create", request.IdempotencyKey, id, 201, result)
	})
	if err != nil {
		return SiteUserDefault{}, err
	}
	return result, nil
}

func (s *Store) UpdateUserDefault(ctx context.Context, actor Actor, request SiteUserDefaultUpdateRequest, digest [32]byte) (SiteUserDefault, error) {
	var result SiteUserDefault
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		current, err := s.lockUserDefault(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		write, err := s.claimWrite(ctx, tx, actor.UserID, current.ScopeID, "site_default.update", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			return json.Unmarshal(write.ResponseBody, &result)
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		value, enabled := current.Value, current.Enabled
		if request.Value != nil {
			normalized, ok := normalizeSiteDefaultValue(current.SettingName, *request.Value)
			if !ok {
				return ErrInvalidInput
			}
			value = normalized
			if err := checkSiteDefaultReference(ctx, tx, current.ScopeID, current.SettingName, value); err != nil {
				return err
			}
			if err := checkSiteDefaultPolicy(ctx, tx, current.ScopeID, current.OwnerUserID, current.SettingName, value); err != nil {
				return err
			}
		}
		if request.Enabled != nil {
			enabled = *request.Enabled
		}
		if _, err := tx.Exec(ctx, `UPDATE site_user_defaults SET setting_value=$2, enabled=$3, revision=revision+1,
			updated_by_user_id=$4, updated_at=$5 WHERE id=$1`, request.ID, value, enabled, actor.UserID, s.now().UTC()); err != nil {
			return err
		}
		if result, err = scanSiteUserDefault(tx.QueryRow(ctx, `SELECT `+siteUserDefaultColumns+siteUserDefaultFrom+
			` WHERE d.id = $1`, request.ID)); err != nil {
			return err
		}
		if err := s.appendUserDefaultAudit(ctx, tx, actor, result, "site_default.update", request.RequestID); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, "site_default.update", request.IdempotencyKey, request.ID, 200, result)
	})
	if err != nil {
		return SiteUserDefault{}, err
	}
	return result, nil
}

func (s *Store) DeleteUserDefault(ctx context.Context, actor Actor, request SiteUserDefaultDeleteRequest, digest [32]byte) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// A replayed delete answers like the first one, even though the row is gone.
		if write, found, err := s.findWrite(ctx, tx, actor.UserID, "site_default.delete", request.IdempotencyKey, digest); err != nil || found {
			if err == nil && write.ResourceID != request.ID {
				return ErrIdempotencyConflict
			}
			return err
		}
		current, err := s.lockUserDefault(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		if _, err := s.claimWrite(ctx, tx, actor.UserID, current.ScopeID, "site_default.delete", request.IdempotencyKey, digest); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM site_user_defaults WHERE id=$1`, request.ID); err != nil {
			return err
		}
		if err := s.appendUserDefaultAudit(ctx, tx, actor, current, "site_default.delete", request.RequestID); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, "site_default.delete", request.IdempotencyKey, request.ID, 204, nil)
	})
}

// checkSiteDefaultReference: a default that names another resource must
// name one of the scope's that is usable now (默认设置 > DNS API: a verified,
// unrevoked DNS account of the scope; another tenant's reads as unusable).
func checkSiteDefaultReference(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, name, value string) error {
	if name != SiteDefaultDNSProvider {
		return nil
	}
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM dns_providers WHERE scope_id=$1 AND id=$2::uuid
		AND status='verified' AND NOT credential_revoked AND `+ownAutoDNSProviderSQL+`)`,
		scopeID, value, dnsacme.PlatformProviderCopyID(scopeID)).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrAutoDNSProvider
	}
	return nil
}

// lockUserDefault: another tenant's row is ErrNotFound, as if it did not exist.
func (s *Store) lockUserDefault(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID) (SiteUserDefault, error) {
	item, err := scanSiteUserDefault(tx.QueryRow(ctx, `SELECT `+siteUserDefaultColumns+siteUserDefaultFrom+`
		WHERE d.id = $1 AND ($2 = 'platform' OR d.scope_id = $3) FOR UPDATE OF d`, id, actor.ScopeKind, actor.ScopeID))
	if errors.Is(err, pgx.ErrNoRows) {
		return SiteUserDefault{}, ErrNotFound
	}
	return item, err
}

func (s *Store) appendUserDefaultAudit(ctx context.Context, tx pgx.Tx, actor Actor, item SiteUserDefault, action, requestID string) error {
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: item.ScopeID, ActorUserID: &actor.UserID, Action: action, ResourceType: "site_default",
		ResourceID: item.ID.String(), RequestID: requestID, Result: "success",
		Payload: map[string]any{"setting_name": item.SettingName, "setting_value": item.Value,
			"scope_name": item.ScopeName, "enabled": item.Enabled},
	})
}
