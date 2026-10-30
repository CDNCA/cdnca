package l4forward

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// userDefaultSelect 输出「默认设置」表格的 ID/用户/设置项/设置值/生效范围 五列所需字段，
// display_id 由迁移 236 的分配器按租户写入，读路径与创建响应取同一列。
const userDefaultSelect = `SELECT d.id, d.display_id::text,
	d.scope_id, d.owner_user_id, d.setting_name, d.setting_value, d.scope_name, d.group_id, d.created_at,
	u.display_name, g.name, g.remark`

func scanUserDefault(scanner rowScanner) (UserDefault, error) {
	var item UserDefault
	var ownerName string
	var groupID *uuid.UUID
	var groupName, groupRemark *string
	if err := scanner.Scan(
		&item.ID, &item.DisplayID, &item.ScopeID, &item.ownerUserID, &item.SettingName, &item.Value,
		&item.ScopeName, &groupID, &item.CreatedAt, &ownerName, &groupName, &groupRemark,
	); err != nil {
		return UserDefault{}, err
	}
	item.Owner = &OwnerReference{ID: item.ownerUserID, DisplayName: ownerName}
	if groupName != nil {
		group := GroupReference{Name: *groupName}
		if groupID != nil {
			group.ID = *groupID
		}
		if groupRemark != nil {
			group.Remark = *groupRemark
		}
		item.Group = &group
	}
	return item, nil
}

func (s *Store) CreateUserDefault(ctx context.Context, actor Actor, request UserDefaultCreateRequest, defaultID uuid.UUID, digest [32]byte) (UserDefaultWriteResult, error) {
	var result UserDefaultWriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeTarget(ctx, tx, actor, request.TargetScopeID, request.OwnerUserID); err != nil {
			return err
		}
		if request.Fields.ScopeName == DefaultScopeGroup {
			if request.Fields.GroupID == nil {
				return ErrDefaultScopeNeedID
			}
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(
				SELECT 1 FROM l4_stream_groups
				WHERE id = $1 AND scope_id = $2 AND owner_user_id = $3 AND deleted_at IS NULL
			)`, *request.Fields.GroupID, request.TargetScopeID, request.OwnerUserID).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return ErrGroupNotFound
			}
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, "stream_default.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			if err := json.Unmarshal(write.ResponseBody, &result.Default); err != nil {
				return fmt.Errorf("decode stored stream default create response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		write, err = s.claimWrite(ctx, tx, actor.UserID, request.TargetScopeID, "stream_default.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := json.Unmarshal(write.ResponseBody, &result.Default); err != nil {
				return fmt.Errorf("decode stored stream default create response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		now := s.now().UTC()
		item, err := scanUserDefault(tx.QueryRow(ctx, `
			WITH inserted AS (
				INSERT INTO l4_stream_user_defaults (
					id, scope_id, owner_user_id, setting_name, setting_value, scope_name, group_id,
					created_by_user_id, created_at
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
				RETURNING *
			)
			SELECT d.id, d.display_id::text, d.scope_id, d.owner_user_id, d.setting_name, d.setting_value,
				d.scope_name, d.group_id, d.created_at, u.display_name, g.name, g.remark
			FROM inserted d JOIN users u ON u.id = d.owner_user_id
			LEFT JOIN l4_stream_groups g ON g.id = d.group_id`,
			defaultID, request.TargetScopeID, request.OwnerUserID, request.Fields.SettingName, request.Fields.Value,
			request.Fields.ScopeName, request.Fields.GroupID, actor.UserID, now))
		if err != nil {
			return classifyDefaultConflict(err)
		}
		result.Default = item
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: request.TargetScopeID, ActorUserID: &actor.UserID, Action: "stream_default.create",
			ResourceType: "stream_default", ResourceID: item.ID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{"setting_name": item.SettingName, "scope_name": item.ScopeName},
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, "stream_default.create", request.IdempotencyKey, item.ID, 201, item)
	})
	if err != nil {
		return UserDefaultWriteResult{}, fmt.Errorf("create stream default: %w", err)
	}
	return result, nil
}

func (s *Store) DeleteUserDefault(ctx context.Context, actor Actor, request UserDefaultDeleteRequest, digest [32]byte) (bool, error) {
	var replayed bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		current, err := s.lockUserDefault(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, "stream_default.delete", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			replayed = true
			return nil
		}
		write, err = s.claimWrite(ctx, tx, actor.UserID, current.ScopeID, "stream_default.delete", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			replayed = true
			return nil
		}
		command, err := tx.Exec(ctx, `DELETE FROM l4_stream_user_defaults WHERE id = $1`, request.ID)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrDefaultNotFound
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: current.ScopeID, ActorUserID: &actor.UserID, Action: "stream_default.delete",
			ResourceType: "stream_default", ResourceID: request.ID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{"setting_name": current.SettingName, "scope_name": current.ScopeName},
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, "stream_default.delete", request.IdempotencyKey, request.ID, 204, map[string]any{})
	})
	if err != nil {
		return false, fmt.Errorf("delete stream default: %w", err)
	}
	return replayed, nil
}

func (s *Store) ListUserDefaults(ctx context.Context, actor Actor, filter UserDefaultListFilter) (UserDefaultListResult, error) {
	conditions := []string{"1 = 1"}
	args := []any{}
	if actor.ScopeKind == "tenant" {
		args = append(args, actor.ScopeID, actor.UserID)
		conditions = append(conditions, fmt.Sprintf("d.scope_id = $%d AND d.owner_user_id = $%d", len(args)-1, len(args)))
	}
	if filter.Search != "" {
		args = append(args, "%"+strings.ToLower(filter.Search)+"%")
		conditions = append(conditions, fmt.Sprintf("lower(d.setting_name) LIKE $%d", len(args)))
	}
	where := " WHERE " + strings.Join(conditions, " AND ")
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return UserDefaultListResult{}, fmt.Errorf("begin stream default list transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var total int64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM l4_stream_user_defaults d JOIN users u ON u.id = d.owner_user_id`+where, args...).Scan(&total); err != nil {
		return UserDefaultListResult{}, fmt.Errorf("count stream defaults: %w", err)
	}
	args = append(args, filter.Limit, (filter.Page-1)*filter.Limit)
	rows, err := tx.Query(ctx, userDefaultSelect+`
		FROM l4_stream_user_defaults d JOIN users u ON u.id = d.owner_user_id
		LEFT JOIN l4_stream_groups g ON g.id = d.group_id`+where+
		fmt.Sprintf(" ORDER BY d.created_at, d.id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		return UserDefaultListResult{}, fmt.Errorf("list stream defaults: %w", err)
	}
	defer rows.Close()
	items := make([]UserDefault, 0, filter.Limit)
	for rows.Next() {
		item, err := scanUserDefault(rows)
		if err != nil {
			return UserDefaultListResult{}, fmt.Errorf("scan stream default: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return UserDefaultListResult{}, fmt.Errorf("iterate stream defaults: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return UserDefaultListResult{}, fmt.Errorf("commit stream default list transaction: %w", err)
	}
	return UserDefaultListResult{Items: items, Total: total, Page: filter.Page, Limit: filter.Limit}, nil
}

func (s *Store) lockUserDefault(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID) (UserDefault, error) {
	query := `SELECT id, scope_id, owner_user_id, setting_name, scope_name FROM l4_stream_user_defaults WHERE id = $1`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND scope_id = $2 AND owner_user_id = $3"
		args = append(args, actor.ScopeID, actor.UserID)
	}
	var item UserDefault
	err := tx.QueryRow(ctx, query+" FOR UPDATE", args...).Scan(
		&item.ID, &item.ScopeID, &item.ownerUserID, &item.SettingName, &item.ScopeName)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserDefault{}, ErrDefaultNotFound
	}
	if err != nil {
		return UserDefault{}, err
	}
	return item, nil
}

func classifyDefaultConflict(err error) error {
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "23505" {
		return err
	}
	switch postgresError.ConstraintName {
	case "l4_stream_user_defaults_global_236_idx", "l4_stream_user_defaults_group_236_idx":
		return ErrNameConflict
	default:
		return err
	}
}

// ResolveFieldDefaults 解析新建转发时要带入的默认设置：先取全局默认，再由命中的分组默认覆盖。
func (s *Store) ResolveFieldDefaults(ctx context.Context, tx pgx.Tx, scopeID, ownerID uuid.UUID, groupIDs []uuid.UUID) (FieldDefaults, error) {
	groupTexts := make([]string, 0, len(groupIDs))
	for _, id := range groupIDs {
		groupTexts = append(groupTexts, id.String())
	}
	rows, err := tx.Query(ctx, `
		SELECT d.setting_name, d.setting_value
		FROM l4_stream_user_defaults d
		WHERE d.scope_id = $1 AND d.owner_user_id = $2
		  AND (d.group_id IS NULL OR d.group_id = ANY($3::uuid[]))
		ORDER BY (d.group_id IS NOT NULL), d.created_at, d.id`, scopeID, ownerID, groupTexts)
	if err != nil {
		return FieldDefaults{}, err
	}
	defer rows.Close()
	var defaults FieldDefaults
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return FieldDefaults{}, err
		}
		applyDefaultValue(&defaults, name, value)
	}
	return defaults, rows.Err()
}

func applyDefaultValue(defaults *FieldDefaults, name, value string) {
	switch name {
	case SettingListenProtocol:
		protocol := value
		defaults.Protocol = &protocol
	case SettingBalanceWay:
		balanceWay := value
		defaults.BalanceWay = &balanceWay
	case SettingProxyProtocol:
		enabled := value == DefaultValueEnabled
		defaults.ProxyProtocolInbound = &enabled
	}
}

// applyFieldDefaults 把默认设置填进尚未显式指定的字段；显式传入的值一律优先。
// 协议/负载方式的空串表示未指定。proxy_protocol_inbound 在公开契约里是必填布尔，
// false 与「未填」无法区分，所以「接收 PROXY」默认只用于前端预填新建草稿，
// 服务端不覆盖提交的值（L4-DEFAULT-01：原先 false 被默认 true 覆盖后配对校验失败，
// 连原幂等 key 的成功回执都取不回）。
func applyFieldDefaults(fields *Fields, defaults FieldDefaults) {
	if defaults.Protocol != nil && fields.Protocol == "" {
		fields.Protocol = *defaults.Protocol
	}
	if defaults.BalanceWay != nil && fields.BalanceWay == "" {
		fields.BalanceWay = *defaults.BalanceWay
	}
}
