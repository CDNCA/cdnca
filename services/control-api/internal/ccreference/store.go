package ccreference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	now     func() time.Time
}

func NewStoreWithClock(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, auditor: audit.New(pool), now: now}
}

func (s *Store) List(ctx context.Context, actor Actor, kind Kind, filter ListFilter) (ListResult, error) {
	if actor.ScopeKind == "platform" {
		return s.listPlatform(ctx, kind, filter)
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ListResult{}, fmt.Errorf("begin CC reference list: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	table, alias := tableFor(kind)
	where, args := listWhere(actor, filter, alias)
	var total int64
	countQuery := `SELECT count(*) FROM ` + table + ` ` + alias + ` JOIN users u ON u.id=` + alias + `.owner_user_id ` + where
	if err := tx.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return ListResult{}, fmt.Errorf("count CC references: %w", err)
	}
	limitPosition := len(args) + 1
	offsetPosition := len(args) + 2
	args = append(args, filter.Limit, (filter.Page-1)*filter.Limit)
	listQuery := `SELECT ` + itemColumns(alias, kind) + `,u.display_name FROM ` + table + ` ` + alias + ` JOIN users u ON u.id=` + alias + `.owner_user_id ` + where + `
		ORDER BY ` + alias + `.created_at DESC,` + alias + `.id DESC LIMIT $` + fmt.Sprint(limitPosition) + ` OFFSET $` + fmt.Sprint(offsetPosition)
	rows, err := tx.Query(ctx, listQuery, args...)
	if err != nil {
		return ListResult{}, fmt.Errorf("list CC references: %w", err)
	}
	defer rows.Close()
	items := make([]Item, 0, filter.Limit)
	for rows.Next() {
		item, err := scanItem(rows, kind)
		if err != nil {
			return ListResult{}, fmt.Errorf("scan CC reference: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, fmt.Errorf("list CC references: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ListResult{}, fmt.Errorf("commit CC reference list: %w", err)
	}
	return ListResult{Items: items, Total: total, Page: filter.Page, Limit: filter.Limit}, nil
}

func (s *Store) listPlatform(ctx context.Context, kind Kind, filter ListFilter) (ListResult, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ListResult{}, fmt.Errorf("begin CC reference list: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	table, alias := tableFor(kind)
	baseFilter := filter
	baseFilter.Status = ""
	where, baseArgs := listWhere(Actor{ScopeKind: "platform"}, baseFilter, alias)
	logicalKey := `CASE WHEN ` + alias + `.system_rule THEN 'system:' || COALESCE(NULLIF(` + alias + `.system_rule_key,''),NULLIF(` + alias + `.system_rule_id,''),` + alias + `.id::text) ELSE 'reference:' || ` + alias + `.id::text END`
	queryArgs := append([]any(nil), baseArgs...)
	statusClause := ""
	statusCountClause := ""
	if filter.Status != "" {
		queryArgs = append(queryArgs, filter.Status == "enabled")
		statusClause = fmt.Sprintf(" HAVING bool_and(enabled)=$%d", len(queryArgs))
		statusCountClause = fmt.Sprintf(" HAVING bool_and(%s.enabled)=$%d", alias, len(queryArgs))
	}

	countQuery := `SELECT count(*) FROM (
		SELECT ` + logicalKey + ` AS logical_key, bool_and(` + alias + `.enabled) AS enabled
		FROM ` + table + ` ` + alias + ` JOIN users u ON u.id=` + alias + `.owner_user_id ` + where + `
		GROUP BY ` + logicalKey + statusCountClause + `
	) logical`
	var total int64
	if err := tx.QueryRow(ctx, countQuery, queryArgs...).Scan(&total); err != nil {
		return ListResult{}, fmt.Errorf("count logical CC references: %w", err)
	}

	itemAlias := "representative"
	selectColumns := strings.Replace(itemColumns(itemAlias, kind), itemAlias+".enabled", "logical.enabled", 1)
	query := `WITH filtered AS (
		SELECT ` + itemColumns(alias, kind) + `,u.display_name,` + logicalKey + ` AS logical_key
		FROM ` + table + ` ` + alias + ` JOIN users u ON u.id=` + alias + `.owner_user_id ` + where + `
	), logical AS (
		SELECT logical_key,bool_and(enabled) AS enabled FROM filtered GROUP BY logical_key` + statusClause + `
	), representatives AS (
		SELECT DISTINCT ON (logical_key) * FROM filtered
		ORDER BY logical_key,system_rule DESC,scope_id,updated_at DESC,id DESC
	)
	SELECT ` + selectColumns + `,` + itemAlias + `.display_name
	FROM representatives ` + itemAlias + ` JOIN logical ON logical.logical_key=` + itemAlias + `.logical_key
	ORDER BY ` + itemAlias + `.created_at DESC,` + itemAlias + `.id DESC`
	limitPosition := len(queryArgs) + 1
	offsetPosition := len(queryArgs) + 2
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", limitPosition, offsetPosition)
	queryArgs = append(queryArgs, filter.Limit, (filter.Page-1)*filter.Limit)
	rows, err := tx.Query(ctx, query, queryArgs...)
	if err != nil {
		return ListResult{}, fmt.Errorf("list logical CC references: %w", err)
	}
	defer rows.Close()
	items := make([]Item, 0, filter.Limit)
	for rows.Next() {
		item, err := scanItem(rows, kind)
		if err != nil {
			return ListResult{}, fmt.Errorf("scan logical CC reference: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, fmt.Errorf("list logical CC references: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ListResult{}, fmt.Errorf("commit CC reference list: %w", err)
	}
	return ListResult{Items: items, Total: total, Page: filter.Page, Limit: filter.Limit}, nil
}

func (s *Store) Get(ctx context.Context, actor Actor, kind Kind, id uuid.UUID) (Item, error) {
	table, alias := tableFor(kind)
	query := `SELECT ` + itemColumns(alias, kind) + `,u.display_name FROM ` + table + ` ` + alias + ` JOIN users u ON u.id=` + alias + `.owner_user_id WHERE ` + alias + `.id=$1 AND ` + alias + `.deleted_at IS NULL`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND " + alias + ".scope_id=$2"
		args = append(args, actor.ScopeID)
	}
	item, err := scanItem(s.pool.QueryRow(ctx, query, args...), kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return Item{}, ErrNotFound
	}
	if err != nil {
		return Item{}, fmt.Errorf("get CC reference: %w", err)
	}
	return item, nil
}

func (s *Store) Create(ctx context.Context, actor Actor, request CreateRequest, digest [32]byte) (result WriteResult, err error) {
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeTarget(ctx, tx, actor, request.TargetScopeID, request.OwnerUserID); err != nil {
			return err
		}
		operation := operationFor(request.Kind, "create")
		if stored, found, err := s.findWrite(ctx, tx, actor.UserID, request.Kind, operation, request.IdempotencyKey, digest); err != nil {
			return err
		} else if found {
			if err := json.Unmarshal(stored.ResponseBody, &result.Item); err != nil {
				return fmt.Errorf("decode stored CC reference create response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		claimed, err := s.claimWrite(ctx, tx, actor, request.TargetScopeID, request.Kind, operation, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if len(claimed.ResponseBody) > 0 {
			if err := json.Unmarshal(claimed.ResponseBody, &result.Item); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		now := s.now().UTC()
		if err := insertItem(ctx, tx, request.Kind, id, actor, request.TargetScopeID, request.OwnerUserID, request, now); err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
		item, err := selectItemTx(ctx, tx, request.Kind, id, false)
		if err != nil {
			return err
		}
		if err := s.insertVersion(ctx, tx, item, actor.UserID, now); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, item, request.RequestID, operation); err != nil {
			return err
		}
		if err := s.completeWrite(ctx, tx, actor.UserID, request.Kind, operation, request.IdempotencyKey, item.ID, item); err != nil {
			return err
		}
		result.Item = item
		return nil
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("create CC reference: %w", err)
	}
	return result, nil
}

func (s *Store) Update(ctx context.Context, actor Actor, request UpdateRequest, digest [32]byte) (result WriteResult, err error) {
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		current, err := lockItem(ctx, tx, actor, request.Kind, request.ID)
		if err != nil {
			return err
		}
		if current.SystemRule && !request.SystemStateOnly {
			return ErrSystemRuleManaged
		}
		operation := operationFor(request.Kind, "update")
		if stored, found, err := s.findWrite(ctx, tx, actor.UserID, request.Kind, operation, request.IdempotencyKey, digest); err != nil {
			return err
		} else if found {
			if err := json.Unmarshal(stored.ResponseBody, &result.Item); err != nil {
				return fmt.Errorf("decode stored CC reference update response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		claimed, err := s.claimWrite(ctx, tx, actor, current.ScopeID, request.Kind, operation, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if len(claimed.ResponseBody) > 0 {
			if err := json.Unmarshal(claimed.ResponseBody, &result.Item); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		now := s.now().UTC()
		if err := updateItem(ctx, tx, request, actor.UserID, now); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrRevisionConflict
			}
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
		item, err := selectItemTx(ctx, tx, request.Kind, request.ID, false)
		if err != nil {
			return err
		}
		if err := s.insertVersion(ctx, tx, item, actor.UserID, now); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, item, request.RequestID, operation); err != nil {
			return err
		}
		if err := s.completeWrite(ctx, tx, actor.UserID, request.Kind, operation, request.IdempotencyKey, item.ID, item); err != nil {
			return err
		}
		result.Item = item
		return nil
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("update CC reference: %w", err)
	}
	return result, nil
}

func (s *Store) Delete(ctx context.Context, actor Actor, request DeleteRequest, digest [32]byte) (result DeleteResult, err error) {
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		current, err := lockItem(ctx, tx, actor, request.Kind, request.ID)
		if err != nil {
			return err
		}
		if current.SystemRule {
			return ErrSystemRuleManaged
		}
		operation := operationFor(request.Kind, "delete")
		if stored, found, err := s.findWrite(ctx, tx, actor.UserID, request.Kind, operation, request.IdempotencyKey, digest); err != nil {
			return err
		} else if found {
			if err := json.Unmarshal(stored.ResponseBody, &result); err != nil {
				return fmt.Errorf("decode stored CC reference delete response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		claimed, err := s.claimWrite(ctx, tx, actor, current.ScopeID, request.Kind, operation, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if len(claimed.ResponseBody) > 0 {
			if err := json.Unmarshal(claimed.ResponseBody, &result); err != nil {
				return err
			}
			result.Replayed = true
			return nil
		}
		now := s.now().UTC()
		table, _ := tableFor(request.Kind)
		command, err := tx.Exec(ctx, `UPDATE `+table+` SET deleted_at=$2,updated_at=$2,updated_by_user_id=$3,revision=revision+1 WHERE id=$1 AND revision=$4 AND deleted_at IS NULL`, request.ID, now, actor.UserID, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		result = DeleteResult{ID: request.ID, Deleted: true, Revision: request.ExpectedRevision + 1}
		deleted := current
		deleted.Revision = result.Revision
		deleted.UpdatedAt = now
		if err := s.insertVersion(ctx, tx, deleted, actor.UserID, now); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, deleted, request.RequestID, operation); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, request.Kind, operation, request.IdempotencyKey, request.ID, result)
	})
	if err != nil {
		return DeleteResult{}, fmt.Errorf("delete CC reference: %w", err)
	}
	return result, nil
}

type storedWrite struct {
	ResourceID   *uuid.UUID
	ResponseBody []byte
}

func (s *Store) findWrite(ctx context.Context, tx pgx.Tx, actorUserID uuid.UUID, kind Kind, operation, key string, digest [32]byte) (storedWrite, bool, error) {
	var existing []byte
	var id *uuid.UUID
	var response []byte
	var completedAt *time.Time
	err := tx.QueryRow(ctx, `SELECT request_digest,resource_id,response_body,completed_at FROM cc_reference_write_requests WHERE actor_user_id=$1 AND reference_kind=$2 AND operation=$3 AND idempotency_key=$4`, actorUserID, kind, operation, key).Scan(&existing, &id, &response, &completedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedWrite{}, false, nil
	}
	if err != nil {
		return storedWrite{}, false, err
	}
	if !bytes.Equal(existing, digest[:]) || id == nil || len(response) == 0 || completedAt == nil {
		return storedWrite{}, false, ErrIdempotencyConflict
	}
	return storedWrite{ResourceID: id, ResponseBody: response}, true, nil
}

func (s *Store) claimWrite(ctx context.Context, tx pgx.Tx, actor Actor, scopeID uuid.UUID, kind Kind, operation, key string, digest [32]byte) (storedWrite, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return storedWrite{}, err
	}
	command, err := tx.Exec(ctx, `INSERT INTO cc_reference_write_requests(id,actor_user_id,actor_scope_id,target_scope_id,reference_kind,operation,idempotency_key,request_digest,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(actor_user_id,reference_kind,operation,idempotency_key) DO NOTHING`, id, actor.UserID, actor.ScopeID, scopeID, kind, operation, key, digest[:], s.now().UTC())
	if err != nil {
		return storedWrite{}, err
	}
	if command.RowsAffected() == 1 {
		return storedWrite{}, nil
	}
	stored, found, err := s.findWrite(ctx, tx, actor.UserID, kind, operation, key, digest)
	if err != nil {
		return storedWrite{}, err
	}
	if !found {
		return storedWrite{}, ErrIdempotencyConflict
	}
	return stored, nil
}

func (s *Store) completeWrite(ctx context.Context, tx pgx.Tx, actor uuid.UUID, kind Kind, operation, key string, resourceID uuid.UUID, response any) error {
	body, err := json.Marshal(response)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE cc_reference_write_requests SET resource_id=$5,response_body=$6,completed_at=$7 WHERE actor_user_id=$1 AND reference_kind=$2 AND operation=$3 AND idempotency_key=$4`, actor, kind, operation, key, resourceID, body, s.now().UTC())
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func (s *Store) insertVersion(ctx context.Context, tx pgx.Tx, item Item, actor uuid.UUID, now time.Time) error {
	document, err := json.Marshal(item)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO cc_reference_versions(reference_kind,reference_id,revision,document,created_by_user_id,created_at) VALUES($1,$2,$3,$4,$5,$6)`, item.Kind, item.ID, item.Revision, document, actor, now)
	return err
}

func (s *Store) appendAudit(ctx context.Context, tx pgx.Tx, actor Actor, item Item, requestID, operation string) error {
	return s.auditor.Append(ctx, tx, audit.Event{ScopeID: item.ScopeID, ActorUserID: &actor.UserID, Action: "cc_reference." + operation, ResourceType: "cc_reference_" + string(item.Kind), ResourceID: item.ID.String(), RequestID: requestID, Result: "success", Payload: map[string]any{"kind": item.Kind, "version": item.Revision, "enabled": item.Enabled}})
}

func tableFor(kind Kind) (string, string) {
	if kind == KindFilter {
		return "cc_reference_filters", "f"
	}
	return "cc_reference_matchers", "m"
}

func itemColumns(alias string, kind Kind) string {
	if kind == KindMatcher {
		return alias + `.id,` + alias + `.scope_id,` + alias + `.owner_user_id,` + alias + `.name,` + alias + `.description,` + alias + `.enabled,` + alias + `.revision,` + alias + `.created_at,` + alias + `.updated_at,` + alias + `.system_rule,` + alias + `.system_rule_id,` + alias + `.system_rule_key,` + alias + `.system_rule_sort,` + alias + `.source_policy_id,` + alias + `.source_rule_id,` + alias + `.source_index,` + alias + `.field,` + alias + `.operator,` + alias + `.condition_key,` + alias + `.values,NULL::text,'{}'::jsonb`
	}
	return alias + `.id,` + alias + `.scope_id,` + alias + `.owner_user_id,` + alias + `.name,` + alias + `.description,` + alias + `.enabled,` + alias + `.revision,` + alias + `.created_at,` + alias + `.updated_at,` + alias + `.system_rule,` + alias + `.system_rule_id,` + alias + `.system_rule_key,` + alias + `.system_rule_sort,` + alias + `.source_policy_id,` + alias + `.source_rule_id,` + alias + `.source_index,NULL::text,NULL::text,NULL::text,'[]'::jsonb,` + alias + `.filter_type,` + alias + `.parameters`
}

func scanItem(row rowScanner, kind Kind) (Item, error) {
	var item Item
	var ownerID uuid.UUID
	var systemRule bool
	var systemRuleID, systemRuleKey string
	var systemRuleSort int
	var sourcePolicy, sourceRule *uuid.UUID
	var sourceIndex *int
	var field, operator, key, filterType *string
	var values, parameters []byte
	var ownerName string
	// The owner display name is the final column in both list and detail rows.
	if err := row.Scan(&item.ID, &item.ScopeID, &ownerID, &item.Name, &item.Description, &item.Enabled, &item.Revision, &item.CreatedAt, &item.UpdatedAt, &systemRule, &systemRuleID, &systemRuleKey, &systemRuleSort, &sourcePolicy, &sourceRule, &sourceIndex, &field, &operator, &key, &values, &filterType, &parameters, &ownerName); err != nil {
		return Item{}, err
	}
	item.Kind, item.PolicyID, item.RuleID = kind, uuid.Nil, uuid.Nil
	item.SystemRule, item.SystemRuleID, item.SystemRuleKey, item.Sort = systemRule, systemRuleID, systemRuleKey, systemRuleSort
	if sourcePolicy != nil {
		item.PolicyID = *sourcePolicy
	}
	if sourceRule != nil {
		item.RuleID = *sourceRule
	}
	if sourceIndex != nil {
		item.Sort = *sourceIndex
	}
	if field != nil {
		item.Field = *field
	}
	if operator != nil {
		item.Operator = *operator
	}
	if key != nil {
		item.Key = *key
	}
	if filterType != nil {
		item.Type = *filterType
	}
	if len(values) > 0 {
		_ = json.Unmarshal(values, &item.Values)
	}
	if len(parameters) > 0 {
		item.Parameters = append(item.Parameters[:0], parameters...)
	}
	item.Owner = &OwnerReference{ID: ownerID, DisplayName: ownerName}
	return item, nil
}

// ownerRowScanner keeps the scan contract explicit and avoids exposing the
// database owner display name to the JSON document when it is unavailable.
type rowScanner interface{ Scan(dest ...any) error }

func selectItemTx(ctx context.Context, tx pgx.Tx, kind Kind, id uuid.UUID, includeDeleted bool) (Item, error) {
	table, alias := tableFor(kind)
	where := " WHERE " + alias + ".id=$1"
	if !includeDeleted {
		where += " AND " + alias + ".deleted_at IS NULL"
	}
	return scanItem(tx.QueryRow(ctx, `SELECT `+itemColumns(alias, kind)+`,u.display_name FROM `+table+` `+alias+` JOIN users u ON u.id=`+alias+`.owner_user_id`+where, id), kind)
}

func lockItem(ctx context.Context, tx pgx.Tx, actor Actor, kind Kind, id uuid.UUID) (Item, error) {
	table, alias := tableFor(kind)
	query := `SELECT ` + itemColumns(alias, kind) + `,u.display_name FROM ` + table + ` ` + alias + ` JOIN users u ON u.id=` + alias + `.owner_user_id WHERE ` + alias + `.id=$1 AND ` + alias + `.deleted_at IS NULL`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND " + alias + ".scope_id=$2"
		args = append(args, actor.ScopeID)
	}
	query += " FOR UPDATE OF " + alias
	item, err := scanItem(tx.QueryRow(ctx, query, args...), kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return Item{}, ErrNotFound
	}
	return item, err
}

func insertItem(ctx context.Context, tx pgx.Tx, kind Kind, id uuid.UUID, actor Actor, scopeID, ownerID uuid.UUID, request CreateRequest, now time.Time) error {
	table, _ := tableFor(kind)
	if kind == KindMatcher {
		values, err := json.Marshal(request.Matcher.Values)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO `+table+`(id,scope_id,tenant_id,owner_user_id,name,description,field,operator,condition_key,values,enabled,revision,created_by_user_id,updated_by_user_id,created_at,updated_at) SELECT $1,$2,scope.tenant_id,$3,$4,$5,$6,$7,$8,$9,$10,1,$3,$3,$11,$11 FROM access_scopes scope WHERE scope.id=$2`, id, scopeID, ownerID, request.Matcher.Name, request.Matcher.Description, request.Matcher.Field, request.Matcher.Operator, request.Matcher.Key, values, request.Matcher.Enabled, now)
		return err
	}
	parameters := request.Filter.Parameters
	_, err := tx.Exec(ctx, `INSERT INTO `+table+`(id,scope_id,tenant_id,owner_user_id,name,description,filter_type,parameters,enabled,revision,created_by_user_id,updated_by_user_id,created_at,updated_at) SELECT $1,$2,scope.tenant_id,$3,$4,$5,$6,$7,$8,1,$3,$3,$9,$9 FROM access_scopes scope WHERE scope.id=$2`, id, scopeID, ownerID, request.Filter.Name, request.Filter.Description, request.Filter.Type, parameters, request.Filter.Enabled, now)
	return err
}

func updateItem(ctx context.Context, tx pgx.Tx, request UpdateRequest, actor uuid.UUID, now time.Time) error {
	table, _ := tableFor(request.Kind)
	if request.Kind == KindMatcher {
		values, err := json.Marshal(request.Matcher.Values)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE `+table+` SET name=$2,description=$3,field=$4,operator=$5,condition_key=$6,values=$7,enabled=$8,revision=revision+1,updated_by_user_id=$9,updated_at=$10 WHERE id=$1 AND revision=$11 AND deleted_at IS NULL`, request.ID, request.Matcher.Name, request.Matcher.Description, request.Matcher.Field, request.Matcher.Operator, request.Matcher.Key, values, request.Matcher.Enabled, actor, now, request.ExpectedRevision)
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE `+table+` SET name=$2,description=$3,filter_type=$4,parameters=$5,enabled=$6,revision=revision+1,updated_by_user_id=$7,updated_at=$8 WHERE id=$1 AND revision=$9 AND deleted_at IS NULL`, request.ID, request.Filter.Name, request.Filter.Description, request.Filter.Type, request.Filter.Parameters, request.Filter.Enabled, actor, now, request.ExpectedRevision)
	return err
}

func authorizeTarget(ctx context.Context, tx pgx.Tx, actor Actor, scopeID, ownerID uuid.UUID) error {
	var kind string
	var tenantID *uuid.UUID
	var member bool
	err := tx.QueryRow(ctx, `SELECT scope.kind,scope.tenant_id,EXISTS(SELECT 1 FROM memberships m WHERE m.scope_id=scope.id AND m.user_id=$2 AND m.status='active') FROM access_scopes scope WHERE scope.id=$1`, scopeID, ownerID).Scan(&kind, &tenantID, &member)
	if errors.Is(err, pgx.ErrNoRows) || kind != "tenant" || tenantID == nil || !member {
		if err == nil {
			return ErrInvalidInput
		}
		return ErrInvalidInput
	}
	if actor.ScopeKind == "tenant" && (actor.ScopeID != scopeID || actor.UserID != ownerID) {
		return ErrPermissionDenied
	}
	return err
}

func listWhere(actor Actor, filter ListFilter, alias string) (string, []any) {
	conditions := []string{alias + ".deleted_at IS NULL"}
	args := make([]any, 0, 6)
	add := func(format string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(format, len(args)))
	}
	if actor.ScopeKind == "tenant" {
		add(alias+".scope_id=$%d", actor.ScopeID)
	}
	if filter.Status != "" {
		add(alias+".enabled=$%d", filter.Status == "enabled")
	}
	if filter.Name != "" {
		add("position($%d in lower("+alias+".name))>0", strings.ToLower(filter.Name))
	}
	if filter.ID != uuid.Nil {
		add(alias+".id=$%d", filter.ID)
	}
	if filter.Owner != "" {
		args = append(args, strings.ToLower(filter.Owner))
		position := len(args)
		conditions = append(conditions, fmt.Sprintf("(lower(u.display_name) LIKE '%%' || $%d || '%%' OR lower(u.username) LIKE '%%' || $%d || '%%' OR u.id::text=$%d)", position, position, position))
	}
	if filter.Type != "" {
		add(alias+".filter_type=$%d", filter.Type)
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func operationFor(kind Kind, action string) string { return string(kind) + "." + action }

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
