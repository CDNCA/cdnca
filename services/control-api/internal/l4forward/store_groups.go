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

// groupSelect 输出分组表格「ID/用户/名称/备注/操作」五列所需字段，display_id 由迁移 236 的
// 分配器按租户写入，读路径与创建响应取同一列。
const groupSelect = `SELECT g.id, g.display_id::text, g.scope_id,
	g.owner_user_id, g.name, g.remark, g.revision, g.created_at, g.updated_at, u.display_name,
	(SELECT count(*) FROM l4_stream_group_members m WHERE m.group_id = g.id)`

func scanGroup(scanner rowScanner) (Group, error) {
	var item Group
	var ownerName string
	if err := scanner.Scan(
		&item.ID, &item.DisplayID, &item.ScopeID, &item.ownerUserID, &item.Name, &item.Remark,
		&item.Revision, &item.CreatedAt, &item.UpdatedAt, &ownerName, &item.StreamCount,
	); err != nil {
		return Group{}, err
	}
	item.Owner = &OwnerReference{ID: item.ownerUserID, DisplayName: ownerName}
	return item, nil
}

func (s *Store) CreateGroup(ctx context.Context, actor Actor, request GroupCreateRequest, groupID uuid.UUID, digest [32]byte) (GroupWriteResult, error) {
	var result GroupWriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeTarget(ctx, tx, actor, request.TargetScopeID, request.OwnerUserID); err != nil {
			return err
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, "stream_group.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			if err := json.Unmarshal(write.ResponseBody, &result.Group); err != nil {
				return fmt.Errorf("decode stored stream group create response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		write, err = s.claimWrite(ctx, tx, actor.UserID, request.TargetScopeID, "stream_group.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := json.Unmarshal(write.ResponseBody, &result.Group); err != nil {
				return fmt.Errorf("decode stored stream group create response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		now := s.now().UTC()
		item, err := scanGroup(tx.QueryRow(ctx, `
			WITH inserted AS (
				INSERT INTO l4_stream_groups (
					id, scope_id, owner_user_id, name, remark,
					created_by_user_id, updated_by_user_id, created_at, updated_at
				) VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $7)
				RETURNING *
			)
			SELECT inserted.id, inserted.display_id::text, inserted.scope_id, inserted.owner_user_id,
				inserted.name, inserted.remark, inserted.revision, inserted.created_at, inserted.updated_at,
				u.display_name, 0
			FROM inserted JOIN users u ON u.id = inserted.owner_user_id`,
			groupID, request.TargetScopeID, request.OwnerUserID, request.Fields.Name, request.Fields.Remark, actor.UserID, now))
		if err != nil {
			return classifyGroupConflict(err)
		}
		result.Group = item
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: request.TargetScopeID, ActorUserID: &actor.UserID, Action: "stream_group.create",
			ResourceType: "stream_group", ResourceID: item.ID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{"revision": item.Revision, "name": item.Name},
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, "stream_group.create", request.IdempotencyKey, item.ID, 201, item)
	})
	if err != nil {
		return GroupWriteResult{}, fmt.Errorf("create stream group: %w", err)
	}
	return result, nil
}

func (s *Store) UpdateGroup(ctx context.Context, actor Actor, request GroupUpdateRequest, digest [32]byte) (GroupWriteResult, error) {
	var result GroupWriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		current, err := s.lockGroup(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, "stream_group.update", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			if err := json.Unmarshal(write.ResponseBody, &result.Group); err != nil {
				return fmt.Errorf("decode stored stream group update response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		write, err = s.claimWrite(ctx, tx, actor.UserID, current.ScopeID, "stream_group.update", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := json.Unmarshal(write.ResponseBody, &result.Group); err != nil {
				return fmt.Errorf("decode stored stream group update response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		command, err := tx.Exec(ctx, `
			UPDATE l4_stream_groups SET
				name = $2, remark = $3, revision = revision + 1,
				updated_by_user_id = $4, updated_at = $5
			WHERE id = $1 AND revision = $6 AND deleted_at IS NULL`,
			request.ID, request.Fields.Name, request.Fields.Remark, actor.UserID, s.now().UTC(), request.ExpectedRevision)
		if err != nil {
			return classifyGroupConflict(err)
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		item, err := s.readGroup(ctx, tx, request.ID)
		if err != nil {
			return err
		}
		result.Group = item
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: current.ScopeID, ActorUserID: &actor.UserID, Action: "stream_group.update",
			ResourceType: "stream_group", ResourceID: item.ID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{"revision": item.Revision, "name": item.Name},
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, "stream_group.update", request.IdempotencyKey, item.ID, 200, item)
	})
	if err != nil {
		return GroupWriteResult{}, fmt.Errorf("update stream group: %w", err)
	}
	return result, nil
}

func (s *Store) DeleteGroup(ctx context.Context, actor Actor, request GroupDeleteRequest, digest [32]byte) (bool, error) {
	var replayed bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		current, err := s.lockGroup(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, "stream_group.delete", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			replayed = true
			return nil
		}
		write, err = s.claimWrite(ctx, tx, actor.UserID, current.ScopeID, "stream_group.delete", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			replayed = true
			return nil
		}
		now := s.now().UTC()
		command, err := tx.Exec(ctx, `
			UPDATE l4_stream_groups SET
				deleted_at = $3, revision = revision + 1, updated_by_user_id = $2, updated_at = $3
			WHERE id = $1 AND revision = $4 AND deleted_at IS NULL`,
			request.ID, actor.UserID, now, request.ExpectedRevision)
		if err != nil {
			return classifyGroupConflict(err)
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		// 分组是软删，l4_stream_user_defaults.group_id 的外键在软删时不会触发，
		// 因此这里显式检查引用，避免删掉仍被默认设置引用的分组。版本校验通过后再判引用，
		// 保证「版本过旧」不会被误报成「仍被引用」。
		var referenced bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM l4_stream_user_defaults WHERE group_id = $1)`,
			request.ID).Scan(&referenced); err != nil {
			return err
		}
		if referenced {
			return ErrGroupInUse
		}
		if _, err := tx.Exec(ctx, `DELETE FROM l4_stream_group_members WHERE group_id = $1`, request.ID); err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: current.ScopeID, ActorUserID: &actor.UserID, Action: "stream_group.delete",
			ResourceType: "stream_group", ResourceID: request.ID.String(), RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{"name": current.Name},
		}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, "stream_group.delete", request.IdempotencyKey, request.ID, 204, map[string]any{})
	})
	if err != nil {
		return false, fmt.Errorf("delete stream group: %w", err)
	}
	return replayed, nil
}

func (s *Store) ListGroups(ctx context.Context, actor Actor, filter GroupListFilter) (GroupListResult, error) {
	where, args := groupListWhere(actor, filter)
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return GroupListResult{}, fmt.Errorf("begin stream group list transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var total int64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM l4_stream_groups g JOIN users u ON u.id = g.owner_user_id`+where, args...).Scan(&total); err != nil {
		return GroupListResult{}, fmt.Errorf("count stream groups: %w", err)
	}
	args = append(args, filter.Limit, (filter.Page-1)*filter.Limit)
	rows, err := tx.Query(ctx, groupSelect+` FROM l4_stream_groups g JOIN users u ON u.id = g.owner_user_id`+
		where+fmt.Sprintf(" ORDER BY g.created_at, g.id LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	// 展示列与排序一致，分页时 ID 才是连续的。
	if err != nil {
		return GroupListResult{}, fmt.Errorf("list stream groups: %w", err)
	}
	defer rows.Close()
	items := make([]Group, 0, filter.Limit)
	for rows.Next() {
		item, err := scanGroup(rows)
		if err != nil {
			return GroupListResult{}, fmt.Errorf("scan stream group: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return GroupListResult{}, fmt.Errorf("iterate stream groups: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return GroupListResult{}, fmt.Errorf("commit stream group list transaction: %w", err)
	}
	return GroupListResult{Items: items, Total: total, Page: filter.Page, Limit: filter.Limit}, nil
}

func groupListWhere(actor Actor, filter GroupListFilter) (string, []any) {
	conditions := []string{"g.deleted_at IS NULL"}
	args := []any{}
	if actor.ScopeKind == "tenant" {
		args = append(args, actor.ScopeID, actor.UserID)
		conditions = append(conditions, fmt.Sprintf("g.scope_id = $%d AND g.owner_user_id = $%d", len(args)-1, len(args)))
	}
	if filter.Search != "" {
		args = append(args, "%"+strings.ToLower(filter.Search)+"%")
		conditions = append(conditions, fmt.Sprintf("lower(g.name) LIKE $%d", len(args)))
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}

func (s *Store) lockGroup(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID) (Group, error) {
	query := `SELECT id, scope_id, owner_user_id, name FROM l4_stream_groups WHERE id = $1 AND deleted_at IS NULL`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND scope_id = $2 AND owner_user_id = $3"
		args = append(args, actor.ScopeID, actor.UserID)
	}
	var item Group
	err := tx.QueryRow(ctx, query+" FOR UPDATE", args...).Scan(&item.ID, &item.ScopeID, &item.ownerUserID, &item.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, ErrGroupNotFound
	}
	if err != nil {
		return Group{}, err
	}
	return item, nil
}

// readGroup 重新读取刚写完的分组，用于补齐 CREATE/UPDATE 之后的行。
func (s *Store) readGroup(ctx context.Context, tx pgx.Tx, id uuid.UUID) (Group, error) {
	item, err := scanGroup(tx.QueryRow(ctx, groupSelect+`
		FROM l4_stream_groups g JOIN users u ON u.id = g.owner_user_id
		WHERE g.id = $1 AND g.deleted_at IS NULL`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, ErrGroupNotFound
	}
	if err != nil {
		return Group{}, err
	}
	return item, nil
}

func classifyGroupConflict(err error) error {
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) {
		return err
	}
	switch postgresError.ConstraintName {
	case "l4_stream_groups_scope_name_lower_active_236_idx":
		return ErrGroupNameConflict
	case "l4_stream_user_defaults_group_id_fkey":
		return ErrGroupInUse
	default:
		return err
	}
}
