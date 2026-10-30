package errorpagecontrol

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Service) CreateRule(ctx context.Context, actor Actor, request CreateRuleRequest) (WriteResult[Rule], error) {
	if validateActor(actor) != nil || validateRuleTarget(request.Target) != nil ||
		validateWriteMetadata(request.WriteMetadata) != nil {
		return WriteResult[Rule]{}, ErrInvalidInput
	}
	fields, err := normalizeRuleFields(request.Target, request.Fields)
	if err != nil {
		return WriteResult[Rule]{}, err
	}
	request.Fields = fields
	digest, _ := digestRequest(struct {
		Target RuleTarget `json:"target"`
		Fields RuleFields `json:"fields"`
	}{request.Target, request.Fields})
	var result Rule
	var replayed bool
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeActor(ctx, tx, actor,
			authorizationTarget(actor, request.Target.ScopeID), permissionManage); err != nil {
			return err
		}
		target, tenantID, err := authorizeRuleTarget(ctx, tx, actor, request.Target)
		if err != nil {
			return err
		}
		limits, err := s.checkEntitlement(ctx, tx, actor, EntitlementCheck{
			Operation: operationRuleCreate, ScopeID: target.ID, ResourceID: request.Fields.AssetID,
			RequestID: request.RequestID, Expands: true, Publishes: true,
		})
		if err != nil {
			return err
		}
		stored, exists, err := s.claimWrite(ctx, tx, actor, target.ID, operationRuleCreate, request.WriteMetadata, digest)
		if err != nil {
			return err
		}
		if exists {
			decoded, err := decodeReplay[Rule](stored)
			if err != nil {
				return err
			}
			if !decoded.Value.Deleted {
				if err := lockPublication(ctx, tx); err != nil {
					return err
				}
				if err := lockActiveRuleSite(ctx, tx, decoded.Value.Target); err != nil {
					return err
				}
			}
			result, replayed = decoded.Value, true
			return nil
		}
		if err := lockPublication(ctx, tx); err != nil {
			return err
		}
		if err := lockActiveRuleSite(ctx, tx, request.Target); err != nil {
			return err
		}
		if err := validateRuleAsset(ctx, tx, target.ID, request.Fields.AssetID, request.Fields.Enabled); err != nil {
			return err
		}
		if err := ensureRuleCapacity(ctx, tx, request.Target, limits.MaxRulesPerScope); err != nil {
			return err
		}
		if request.Fields.Enabled {
			if err := rejectRuleConflict(ctx, tx, uuid.Nil, request.Target, request.Fields); err != nil {
				return err
			}
		}
		ruleID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		now := storeTime(s.now())
		_, err = tx.Exec(ctx, `INSERT INTO error_page_rules (
			id,scope_kind,scope_id,tenant_id,site_id,created_by_user_id,created_by_scope_id,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, ruleID, request.Target.Kind, target.ID, tenantID,
			request.Target.SiteID, actor.UserID, actor.ScopeID, now)
		if err != nil {
			return err
		}
		if err := insertRuleRevision(ctx, tx, actor, request.WriteMetadata, ruleID, 1, request.Fields, false, now); err != nil {
			return err
		}
		result, err = loadRule(ctx, tx, actor, ruleID, false)
		if err != nil {
			return err
		}
		publication, err := s.appendPublication(ctx, tx, actor, request.WriteMetadata, target.ID, limits)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, &actor, target.ID, operationRuleCreate, "error_page_rule",
			ruleID.String(), request.WriteMetadata, "success", map[string]any{
				"revision": 1, "enabled": request.Fields.Enabled,
				"publication_revision": publication.Policy.Revision, "snapshot_sha256": publication.SHA256,
			}); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor, operationRuleCreate, request.WriteMetadata, ruleID, 201, result)
	})
	if err != nil {
		return WriteResult[Rule]{}, fmt.Errorf("create error page rule: %w", normalizeDatabaseError(err))
	}
	return WriteResult[Rule]{Value: result, Replayed: replayed}, nil
}

func (s *Service) UpdateRule(ctx context.Context, actor Actor, request UpdateRuleRequest) (WriteResult[Rule], error) {
	if validateActor(actor) != nil || request.RuleID == uuid.Nil || request.ExpectedRevision < 1 ||
		validateWriteMetadata(request.WriteMetadata) != nil {
		return WriteResult[Rule]{}, ErrInvalidInput
	}
	digest, _ := digestRequest(struct {
		RuleID   uuid.UUID  `json:"rule_id"`
		Revision int64      `json:"expected_revision"`
		Fields   RuleFields `json:"fields"`
	}{request.RuleID, request.ExpectedRevision, request.Fields})
	return s.changeRule(ctx, actor, request.RuleID, request.ExpectedRevision, request.Fields,
		false, operationRuleUpdate, request.WriteMetadata, digest)
}

func (s *Service) EnableRule(ctx context.Context, actor Actor, request ChangeRuleStateRequest) (WriteResult[Rule], error) {
	return s.changeRuleState(ctx, actor, request, true, operationRuleEnable)
}

func (s *Service) DisableRule(ctx context.Context, actor Actor, request ChangeRuleStateRequest) (WriteResult[Rule], error) {
	return s.changeRuleState(ctx, actor, request, false, operationRuleDisable)
}

func (s *Service) DeleteRule(ctx context.Context, actor Actor, request ChangeRuleStateRequest) (WriteResult[Rule], error) {
	if validateActor(actor) != nil || request.RuleID == uuid.Nil || request.ExpectedRevision < 1 ||
		validateWriteMetadata(request.WriteMetadata) != nil {
		return WriteResult[Rule]{}, ErrInvalidInput
	}
	digest, _ := digestRequest(struct {
		RuleID   uuid.UUID `json:"rule_id"`
		Revision int64     `json:"expected_revision"`
	}{request.RuleID, request.ExpectedRevision})
	return s.changeRule(ctx, actor, request.RuleID, request.ExpectedRevision, RuleFields{},
		true, operationRuleDelete, request.WriteMetadata, digest)
}

func (s *Service) changeRuleState(
	ctx context.Context,
	actor Actor,
	request ChangeRuleStateRequest,
	enabled bool,
	operation string,
) (WriteResult[Rule], error) {
	if validateActor(actor) != nil || request.RuleID == uuid.Nil || request.ExpectedRevision < 1 ||
		validateWriteMetadata(request.WriteMetadata) != nil {
		return WriteResult[Rule]{}, ErrInvalidInput
	}
	digest, _ := digestRequest(struct {
		RuleID   uuid.UUID `json:"rule_id"`
		Revision int64     `json:"expected_revision"`
		Enabled  bool      `json:"enabled"`
	}{request.RuleID, request.ExpectedRevision, enabled})
	fields := RuleFields{Enabled: enabled}
	return s.changeRule(ctx, actor, request.RuleID, request.ExpectedRevision, fields,
		false, operation, request.WriteMetadata, digest)
}

func (s *Service) changeRule(
	ctx context.Context,
	actor Actor,
	ruleID uuid.UUID,
	expectedRevision int64,
	requested RuleFields,
	deleted bool,
	operation string,
	metadata WriteMetadata,
	digest [32]byte,
) (WriteResult[Rule], error) {
	var result Rule
	var replayed bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, found, err := ruleScopeForAuthorization(ctx, tx, actor, ruleID)
		if err != nil {
			return err
		}
		if err := s.authorizeActor(ctx, tx, actor, targetScopeID, permissionManage); err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		preflight, err := loadRule(ctx, tx, actor, ruleID, false)
		if err != nil {
			return err
		}
		limits := baselineEntitlementLimits()
		if operation == operationRuleUpdate || operation == operationRuleEnable {
			limits, err = s.checkEntitlement(ctx, tx, actor, EntitlementCheck{
				Operation: operation, ScopeID: preflight.Target.ScopeID, ResourceID: ruleID,
				RequestID: metadata.RequestID, Expands: true, Publishes: true,
			})
			if err != nil {
				return err
			}
		}
		stored, exists, err := s.claimWrite(ctx, tx, actor, preflight.Target.ScopeID, operation, metadata, digest)
		if err != nil {
			return err
		}
		if exists {
			decoded, err := decodeReplay[Rule](stored)
			if err != nil {
				return err
			}
			if !decoded.Value.Deleted {
				if err := lockPublication(ctx, tx); err != nil {
					return err
				}
				if err := lockActiveRuleSite(ctx, tx, decoded.Value.Target); err != nil {
					return err
				}
			}
			result, replayed = decoded.Value, true
			return nil
		}
		if err := lockPublication(ctx, tx); err != nil {
			return err
		}
		current, err := loadRule(ctx, tx, actor, ruleID, true)
		if err != nil {
			return err
		}
		if current.Target.ScopeID != preflight.Target.ScopeID || current.Target.Kind != preflight.Target.Kind ||
			nullableUUIDPointer(current.Target.SiteID) != nullableUUIDPointer(preflight.Target.SiteID) {
			return ErrConflict
		}
		if current.Deleted {
			return ErrNotFound
		}
		if current.Revision != expectedRevision {
			return ErrRevisionConflict
		}
		fields := requested
		if deleted {
			fields = current.Fields
			fields.Enabled = false
		} else if operation == operationRuleEnable || operation == operationRuleDisable {
			fields.Category = current.Fields.Category
			fields.Match = current.Fields.Match
			fields.AssetID = current.Fields.AssetID
		}
		fields, err = normalizeRuleFields(current.Target, fields)
		if err != nil {
			return err
		}
		if !deleted {
			if err := lockActiveRuleSite(ctx, tx, current.Target); err != nil {
				return err
			}
		}
		if err := validateRuleAsset(ctx, tx, current.Target.ScopeID, fields.AssetID, fields.Enabled && !deleted); err != nil {
			return err
		}
		if fields.Enabled && !deleted {
			if err := rejectRuleConflict(ctx, tx, ruleID, current.Target, fields); err != nil {
				return err
			}
		}
		now := storeTime(s.now())
		if err := insertRuleRevision(ctx, tx, actor, metadata, ruleID, current.Revision+1, fields, deleted, now); err != nil {
			return err
		}
		result, err = loadRule(ctx, tx, actor, ruleID, false)
		if err != nil {
			return err
		}
		publication, err := s.appendPublication(ctx, tx, actor, metadata, current.Target.ScopeID, limits)
		if err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, &actor, current.Target.ScopeID, operation, "error_page_rule",
			ruleID.String(), metadata, "success", map[string]any{
				"from_revision": expectedRevision, "to_revision": result.Revision,
				"enabled": result.Fields.Enabled, "deleted": result.Deleted,
				"publication_revision": publication.Policy.Revision, "snapshot_sha256": publication.SHA256,
			}); err != nil {
			return err
		}
		status := 200
		if deleted {
			status = 202
		}
		return s.completeWrite(ctx, tx, actor, operation, metadata, ruleID, status, result)
	})
	if err != nil {
		return WriteResult[Rule]{}, fmt.Errorf("%s: %w", operation, normalizeDatabaseError(err))
	}
	return WriteResult[Rule]{Value: result, Replayed: replayed}, nil
}

func authorizeRuleTarget(ctx context.Context, tx pgx.Tx, actor Actor, requested RuleTarget) (scopeRecord, *uuid.UUID, error) {
	target, err := resolveTargetScope(ctx, tx, actor, requested.ScopeID)
	if err != nil {
		return scopeRecord{}, nil, err
	}
	if requested.Kind == ScopeGlobal {
		if actor.ScopeKind != "platform" || target.Kind != "platform" || requested.SiteID != nil {
			return scopeRecord{}, nil, ErrPermissionDenied
		}
		return target, nil, nil
	}
	if target.Kind != "tenant" || target.TenantID == nil || requested.SiteID == nil {
		return scopeRecord{}, nil, ErrInvalidInput
	}
	var siteScope uuid.UUID
	err = tx.QueryRow(ctx, `SELECT scope_id FROM sites WHERE id=$1 AND deleted_at IS NULL`, *requested.SiteID).Scan(&siteScope)
	if errors.Is(err, pgx.ErrNoRows) || siteScope != target.ID {
		return scopeRecord{}, nil, ErrNotFound
	}
	if err != nil {
		return scopeRecord{}, nil, err
	}
	return target, target.TenantID, nil
}

func lockActiveRuleSite(ctx context.Context, tx pgx.Tx, target RuleTarget) error {
	if target.Kind == ScopeGlobal {
		return nil
	}
	if target.Kind != ScopeSite || target.SiteID == nil || *target.SiteID == uuid.Nil {
		return ErrInvalidInput
	}
	var scopeID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT scope_id FROM sites
		WHERE id=$1 AND deleted_at IS NULL FOR SHARE`, *target.SiteID).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) || scopeID != target.ScopeID {
		return ErrNotFound
	}
	return err
}

func validateRuleAsset(ctx context.Context, tx pgx.Tx, scopeID, assetID uuid.UUID, requireReady bool) error {
	var status string
	err := tx.QueryRow(ctx, `SELECT status FROM error_page_assets WHERE id=$1 AND scope_id=$2`, assetID, scopeID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if requireReady && status != StatusReady {
		return ErrConflict
	}
	return nil
}

func ensureRuleCapacity(ctx context.Context, tx pgx.Tx, target RuleTarget, maximum int) error {
	var count int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM error_page_rules identity
		JOIN LATERAL (
			SELECT revision.deleted FROM error_page_rule_revisions revision
			WHERE revision.rule_id=identity.id ORDER BY revision.revision DESC LIMIT 1
		) current ON true
		WHERE identity.scope_kind=$1 AND identity.scope_id=$2
		  AND identity.site_id IS NOT DISTINCT FROM $3 AND NOT current.deleted`,
		target.Kind, target.ScopeID, target.SiteID).Scan(&count)
	if err != nil {
		return err
	}
	if maximum < 1 {
		return ErrUnavailable
	}
	if maximum > MaxEdgeRulesPerScope {
		maximum = MaxEdgeRulesPerScope
	}
	if count >= maximum {
		return ErrQuotaExceeded
	}
	return nil
}

func rejectRuleConflict(ctx context.Context, tx pgx.Tx, ruleID uuid.UUID, target RuleTarget, fields RuleFields) error {
	priority := fields.Match.To - fields.Match.From + 1
	var conflict bool
	err := tx.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM error_page_rules identity
		JOIN LATERAL (
			SELECT revision.* FROM error_page_rule_revisions revision
			WHERE revision.rule_id=identity.id ORDER BY revision.revision DESC LIMIT 1
		) current ON true
		WHERE identity.id <> $1 AND identity.scope_kind=$2 AND identity.scope_id=$3
		  AND identity.site_id IS NOT DISTINCT FROM $4 AND current.enabled AND NOT current.deleted
		  AND current.category=$5 AND current.priority=$6
		  AND int4range(current.code_from,current.code_to,'[]') && int4range($7,$8,'[]')
	)`, ruleID, target.Kind, target.ScopeID, target.SiteID, fields.Category, priority,
		fields.Match.From, fields.Match.To).Scan(&conflict)
	if err != nil {
		return err
	}
	if conflict {
		return ErrConflict
	}
	return nil
}

func insertRuleRevision(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	metadata WriteMetadata,
	ruleID uuid.UUID,
	revision int64,
	fields RuleFields,
	deleted bool,
	now time.Time,
) error {
	_, err := tx.Exec(ctx, `INSERT INTO error_page_rule_revisions (
		rule_id,revision,category,match_kind,code_from,code_to,asset_id,enabled,deleted,
		created_by_user_id,created_by_scope_id,request_id,trace_id,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, ruleID, revision,
		fields.Category, fields.Match.Kind, fields.Match.From, fields.Match.To, fields.AssetID,
		fields.Enabled, deleted, actor.UserID, actor.ScopeID, metadata.RequestID, metadata.TraceID, now)
	return err
}

func (s *Service) GetRule(ctx context.Context, actor Actor, id uuid.UUID) (Rule, error) {
	if validateActor(actor) != nil || id == uuid.Nil {
		return Rule{}, ErrInvalidInput
	}
	var result Rule
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		targetScopeID, found, err := ruleScopeForAuthorization(ctx, tx, actor, id)
		if err != nil {
			return err
		}
		if err := s.authorizeActor(ctx, tx, actor, targetScopeID, permissionRead); err != nil {
			return err
		}
		if !found {
			return ErrNotFound
		}
		result, err = loadRule(ctx, tx, actor, id, false)
		return err
	})
	if err != nil {
		return Rule{}, fmt.Errorf("get error page rule: %w", err)
	}
	return result, nil
}

func (s *Service) ListRules(ctx context.Context, actor Actor, request RulePageRequest) (RulePage, error) {
	if validateActor(actor) != nil || request.Limit < 1 || request.Limit > MaxPageSize ||
		(request.SiteID != nil && *request.SiteID == uuid.Nil) {
		return RulePage{}, ErrInvalidInput
	}
	var page RulePage
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeActor(ctx, tx, actor,
			authorizationTarget(actor, request.TargetScopeID), permissionRead); err != nil {
			return err
		}
		targetScope := request.TargetScopeID
		if actor.ScopeKind == "tenant" {
			if targetScope != uuid.Nil && targetScope != actor.ScopeID {
				return ErrPermissionDenied
			}
			targetScope = actor.ScopeID
		}
		cursorEndpoint := "rules?site_id="
		if request.SiteID != nil {
			cursorEndpoint += request.SiteID.String()
		}
		cursorEndpoint += "&enabled="
		if request.Enabled != nil {
			cursorEndpoint += strconv.FormatBool(*request.Enabled)
		}
		cursor, err := decodePageCursor(request.Cursor, cursorEndpoint, actor, targetScope)
		if err != nil {
			return err
		}
		where := `WHERE ($1::uuid IS NULL OR identity.scope_id=$1)
			AND ($2::uuid IS NULL OR identity.site_id=$2) AND ($3::boolean IS NULL OR current.enabled=$3)`
		args := []any{nullableUUID(targetScope), nullableUUIDPointer(request.SiteID), request.Enabled}
		if cursor != nil {
			where += ` AND (identity.created_at,identity.id) < ($4,$5)`
			args = append(args, cursor.CreatedAt, cursor.ID)
		}
		args = append(args, request.Limit+1)
		rows, err := tx.Query(ctx, `SELECT `+ruleColumns+`
			FROM error_page_rules identity
			JOIN LATERAL (
				SELECT revision.* FROM error_page_rule_revisions revision
				WHERE revision.rule_id=identity.id ORDER BY revision.revision DESC LIMIT 1
			) current ON true `+where+`
			ORDER BY identity.created_at DESC,identity.id DESC LIMIT $`+fmt.Sprint(len(args)), args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			rule, err := scanRule(rows)
			if err != nil {
				return err
			}
			page.Items = append(page.Items, rule)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Items) > request.Limit {
			last := page.Items[request.Limit-1]
			page.Items = page.Items[:request.Limit]
			page.NextCursor, err = encodePageCursor(cursorEndpoint, actor, targetScope, last.CreatedAt, last.ID)
			return err
		}
		return nil
	})
	if err != nil {
		return RulePage{}, fmt.Errorf("list error page rules: %w", err)
	}
	if page.Items == nil {
		page.Items = []Rule{}
	}
	return page, nil
}

func ruleScopeForAuthorization(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	ruleID uuid.UUID,
) (uuid.UUID, bool, error) {
	query := `SELECT scope_id FROM error_page_rules WHERE id=$1`
	args := []any{ruleID}
	if actor.ScopeKind == "tenant" {
		query += ` AND scope_id=$2`
		args = append(args, actor.ScopeID)
	}
	var scopeID uuid.UUID
	err := tx.QueryRow(ctx, query, args...).Scan(&scopeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return actor.ScopeID, false, nil
	}
	if err != nil || scopeID == uuid.Nil {
		return uuid.Nil, false, err
	}
	return scopeID, true, nil
}

func loadRule(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID, lock bool) (Rule, error) {
	query := `SELECT ` + ruleColumns + `
		FROM error_page_rules identity
		JOIN LATERAL (
			SELECT revision.* FROM error_page_rule_revisions revision
			WHERE revision.rule_id=identity.id ORDER BY revision.revision DESC LIMIT 1
		) current ON true WHERE identity.id=$1`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += ` AND identity.scope_id=$2`
		args = append(args, actor.ScopeID)
	}
	if lock {
		query += ` FOR UPDATE OF identity`
	}
	rule, err := scanRule(tx.QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return Rule{}, ErrNotFound
	}
	return rule, err
}

const ruleColumns = `identity.id,identity.scope_kind,identity.scope_id,identity.tenant_id,identity.site_id,
	current.category,current.match_kind,current.code_from,current.code_to,current.asset_id,current.enabled,
	current.priority,current.revision,current.deleted,identity.created_by_user_id,identity.created_at,current.created_at`

func scanRule(row rowScanner) (Rule, error) {
	var rule Rule
	var siteID *uuid.UUID
	err := row.Scan(&rule.ID, &rule.Target.Kind, &rule.Target.ScopeID, &rule.TenantID, &siteID,
		&rule.Fields.Category, &rule.Fields.Match.Kind, &rule.Fields.Match.From, &rule.Fields.Match.To,
		&rule.Fields.AssetID, &rule.Fields.Enabled, &rule.Priority, &rule.Revision, &rule.Deleted,
		&rule.CreatedBy, &rule.CreatedAt, &rule.UpdatedAt)
	if err != nil {
		return Rule{}, err
	}
	rule.Target.SiteID = siteID
	return rule, nil
}

func nullableUUIDPointer(value *uuid.UUID) any {
	if value == nil {
		return nil
	}
	return *value
}

func normalizeDatabaseError(err error) error {
	if sqlState(err) == "P0001" {
		return ErrConflict
	}
	return err
}
