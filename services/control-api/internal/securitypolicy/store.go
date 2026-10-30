package securitypolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock"
	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
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

type rowScanner interface {
	Scan(dest ...any) error
}

type storedWrite struct {
	Replayed     bool
	ResourceID   uuid.UUID
	ResponseBody []byte
}

func NewStore(pool *pgxpool.Pool) *Store {
	return NewStoreWithClock(pool, time.Now)
}

func NewStoreWithClock(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, auditor: audit.New(pool), now: now}
}

func (s *Store) Create(ctx context.Context, actor Actor, request CreateRequest, digest [32]byte) (WriteResult, error) {
	var result WriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tenantID, err := authorizeTargetScope(ctx, tx, actor, request.TargetScopeID, request.OwnerUserID)
		if err != nil {
			return err
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, "security_policy.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			if err := json.Unmarshal(write.ResponseBody, &result.Policy); err != nil {
				return fmt.Errorf("decode stored security policy create response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if request.Fields.Kind == KindCC {
			if err := requireOwnerCustomCC(ctx, tx, request.TargetScopeID, request.OwnerUserID, s.now().UTC()); err != nil {
				return err
			}
		}
		write, err = s.claimWrite(ctx, tx, actor, request.TargetScopeID, "security_policy.create", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := json.Unmarshal(write.ResponseBody, &result.Policy); err != nil {
				return fmt.Errorf("decode stored security policy create response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if err := requireUsableIPLists(ctx, tx, request.TargetScopeID, request.Fields.Rules); err != nil {
			return err
		}
		policyID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		if err := assignRuleIDs(request.Fields.Rules, nil); err != nil {
			return err
		}
		if err := assignCCSettingsRuleIDs(policyID, request.Fields.Rules, request.Fields.CCSettings, nil); err != nil {
			return err
		}
		rules, err := json.Marshal(request.Fields.Rules)
		if err != nil {
			return err
		}
		settings, err := encodeCCSettings(request.Fields.CCSettings)
		if err != nil {
			return err
		}
		wafSettings, err := encodeWAFSettings(request.Fields.WAFSettings)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		_, err = tx.Exec(ctx, `
			INSERT INTO security_policies (
				id, scope_id, tenant_id, owner_user_id, kind, name, description,
				enabled, default_action, rules, created_by_user_id, updated_by_user_id,
				created_at, updated_at, cc_settings, waf_settings
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,$12,$12,$13,$14)`,
			policyID, request.TargetScopeID, tenantID, request.OwnerUserID,
			request.Fields.Kind, request.Fields.Name, request.Fields.Description,
			request.Fields.Enabled, request.Fields.DefaultAction, rules, actor.UserID, now, settings, wafSettings)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
		item, err := selectPolicy(ctx, tx, policyID, false)
		if err != nil {
			return err
		}
		if err := s.insertVersion(ctx, tx, item, actor.UserID, now); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, item, request.RequestID, "security_policy.create"); err != nil {
			return err
		}
		if err := s.completeWrite(ctx, tx, actor.UserID, "security_policy.create", request.IdempotencyKey, item.ID, item); err != nil {
			return err
		}
		result.Policy = item
		return nil
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("create security policy: %w", err)
	}
	return result, nil
}

func (s *Store) Update(ctx context.Context, actor Actor, request UpdateRequest, digest [32]byte) (WriteResult, error) {
	var result WriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var featureErr error
		// Subscription locks precede policy locks, as they do during activation.
		if request.Fields.Kind == KindCC {
			policy, err := selectPolicy(ctx, tx, request.ID, true)
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && actor.ScopeKind == "tenant" && policy.ScopeID != actor.ScopeID) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
			featureErr = requireOwnerCustomCC(ctx, tx, policy.ScopeID, policy.ownerID, s.now().UTC())
			if featureErr != nil && !errors.Is(featureErr, packageaddon.ErrFeatureDenied) {
				return featureErr
			}
		}
		current, err := lockPolicy(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, "security_policy.update", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			if err := json.Unmarshal(write.ResponseBody, &result.Policy); err != nil {
				return fmt.Errorf("decode stored security policy update response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if current.deleted {
			return ErrNotFound
		}
		if _, protected := licensedWAFMetadata(current.policy); protected && !request.AllowProtected {
			return ErrPermissionDenied
		}
		if current.policy.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if featureErr != nil && !disableOnly(current.policy, request.Fields) {
			return featureErr
		}
		if err := requireUsableIPLists(ctx, tx, current.policy.ScopeID, request.Fields.Rules); err != nil {
			return err
		}
		existing := current.policy.Rules
		if block := current.policy.QuickBlock; block != nil {
			// The re-derived quick block rules keep their reserved IDs.
			existing = append(slices.Clone(existing), QuickBlockRules(current.policy.ID, *block)...)
		}
		if err := assignRuleIDs(request.Fields.Rules, existing); err != nil {
			return err
		}
		if err := assignCCSettingsRuleIDs(current.policy.ID, request.Fields.Rules, request.Fields.CCSettings,
			current.policy.CCSettings); err != nil {
			return err
		}
		write, err = s.claimWrite(ctx, tx, actor, current.policy.ScopeID, "security_policy.update", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := json.Unmarshal(write.ResponseBody, &result.Policy); err != nil {
				return fmt.Errorf("decode stored security policy update response: %w", err)
			}
			result.Replayed = true
			return nil
		}

		rules, err := json.Marshal(request.Fields.Rules)
		if err != nil {
			return err
		}
		settings, err := encodeCCSettings(request.Fields.CCSettings)
		if err != nil {
			return err
		}
		wafSettings, err := encodeWAFSettings(request.Fields.WAFSettings)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		item, err := scanPolicy(tx.QueryRow(ctx, `
			UPDATE security_policies SET
				kind=$2, name=$3, description=$4, enabled=$5, default_action=$6,
				rules=$7, revision=revision+1, updated_by_user_id=$8, updated_at=$9, cc_settings=$11,
				quick_block=CASE WHEN $2='waf' THEN quick_block END, waf_settings=$12
			WHERE id=$1 AND revision=$10 AND deleted_at IS NULL
			RETURNING `+policyColumns("security_policies")+`,
			          (SELECT display_name FROM users WHERE id=security_policies.owner_user_id)`,
			request.ID, request.Fields.Kind, request.Fields.Name, request.Fields.Description,
			request.Fields.Enabled, request.Fields.DefaultAction, rules, actor.UserID, now,
			request.ExpectedRevision, settings, wafSettings))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevisionConflict
		}
		if err != nil {
			if isUniqueViolation(err) {
				return ErrConflict
			}
			return err
		}
		if err := s.insertVersion(ctx, tx, item, actor.UserID, now); err != nil {
			return err
		}
		if err := CheckSiteQuickBlockOverridesTx(ctx, tx, item); err != nil {
			return err
		}
		if err := applyLibraryProfileChangeTx(ctx, tx, actor, request.RequestID, current.policy, item, now); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, item, request.RequestID, "security_policy.update"); err != nil {
			return err
		}
		if err := s.completeWrite(ctx, tx, actor.UserID, "security_policy.update", request.IdempotencyKey, item.ID, item); err != nil {
			return err
		}
		result.Policy = item
		return nil
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("update security policy: %w", err)
	}
	return result, nil
}

// SetQuickBlock stores a WAF policy's quick block switches and replaces its
// system-managed rules with theirs (quick_block.go), as one policy version
// with an audit event. Turning any block on needs a verified IP intelligence
// library on the control plane.
func (s *Store) SetQuickBlock(ctx context.Context, actor Actor, request QuickBlockRequest, digest [32]byte) (WriteResult, error) {
	const operation = "security_policy.quick_block"
	var result WriteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		current, err := lockPolicy(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, operation, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			if err := json.Unmarshal(write.ResponseBody, &result.Policy); err != nil {
				return fmt.Errorf("decode stored security policy quick block response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if current.deleted {
			return ErrNotFound
		}
		if _, protected := licensedWAFMetadata(current.policy); protected {
			return ErrQuickBlockUnsupported
		}
		if current.policy.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if current.policy.Kind != KindWAF || current.policy.DefaultAction != ActionAllow {
			return ErrQuickBlockUnsupported
		}
		if request.QuickBlock.Active() {
			revision, err := s.ipIntelRevision(ctx, tx)
			if err != nil {
				return err
			}
			if revision == 0 {
				return ErrQuickBlockIPIntelUnavailable
			}
		}
		fields, err := quickBlockFields(current.policy, request.QuickBlock)
		if err != nil {
			return err
		}
		write, err = s.claimWrite(ctx, tx, actor, current.policy.ScopeID, operation, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := json.Unmarshal(write.ResponseBody, &result.Policy); err != nil {
				return fmt.Errorf("decode stored security policy quick block response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		rules, err := json.Marshal(fields.Rules)
		if err != nil {
			return err
		}
		block, err := json.Marshal(request.QuickBlock)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		item, err := scanPolicy(tx.QueryRow(ctx, `
			UPDATE security_policies SET rules=$2, quick_block=$3, revision=revision+1,
				updated_by_user_id=$4, updated_at=$5
			WHERE id=$1 AND revision=$6 AND deleted_at IS NULL
			RETURNING `+policyColumns("security_policies")+`,
			          (SELECT display_name FROM users WHERE id=security_policies.owner_user_id)`,
			request.ID, rules, block, actor.UserID, now, request.ExpectedRevision))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRevisionConflict
		}
		if err != nil {
			return err
		}
		if err := s.insertVersion(ctx, tx, item, actor.UserID, now); err != nil {
			return err
		}
		if err := CheckSiteQuickBlockOverridesTx(ctx, tx, item); err != nil {
			return err
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: item.ScopeID, ActorUserID: &actor.UserID, Action: operation,
			ResourceType: "security_policy", ResourceID: item.ID.String(), RequestID: request.RequestID,
			Result: "success", Payload: map[string]any{
				"kind": item.Kind, "version": item.Revision, "rule_count": len(item.Rules),
				"block_idc_cn": request.QuickBlock.BlockIDCCN, "block_idc_global": request.QuickBlock.BlockIDCGlobal,
				"carriers": request.QuickBlock.Carriers, "allowed_crawlers": len(request.QuickBlock.AllowedCrawlers),
				"previous": current.policy.QuickBlock,
			},
		}); err != nil {
			return err
		}
		if err := s.completeWrite(ctx, tx, actor.UserID, operation, request.IdempotencyKey, item.ID, item); err != nil {
			return err
		}
		result.Policy = item
		return nil
	})
	if err != nil {
		return WriteResult{}, fmt.Errorf("set security policy quick block: %w", err)
	}
	return result, nil
}

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Store) ipIntelRevision(ctx context.Context, db queryRower) (uint64, error) {
	return IPIntelRevision(ctx, db)
}

// IPIntelRevision is the downloaded revision of the control plane's IP
// intelligence base library (artifact ipintel/base, free, kept by
// artifactsync) while its catalog entry is active; 0 when it has none.
// Quick block (library and site override) turns an item on only when it
// is above 0.
func IPIntelRevision(ctx context.Context, db interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}) (uint64, error) {
	var revision int64
	err := db.QueryRow(ctx, `SELECT local.current_revision FROM local_artifacts local
		JOIN artifact_catalog_entries entry ON entry.artifact_id=local.artifact_id
		WHERE local.artifact_id='ipintel/base' AND local.current_revision IS NOT NULL
		  AND entry.status='active' AND entry.requires_feature=''`).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read ip intel library revision: %w", err)
	}
	return uint64(revision), nil
}

func (s *Store) Delete(ctx context.Context, actor Actor, request DeleteRequest, digest [32]byte) (DeleteResult, error) {
	var result DeleteResult
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		current, err := lockPolicy(ctx, tx, actor, request.ID)
		if err != nil {
			return err
		}
		write, found, err := s.findWrite(ctx, tx, actor.UserID, "security_policy.delete", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			if err := json.Unmarshal(write.ResponseBody, &result); err != nil {
				return fmt.Errorf("decode stored security policy delete response: %w", err)
			}
			result.Replayed = true
			return nil
		}
		if current.deleted {
			return ErrNotFound
		}
		if _, protected := licensedWAFMetadata(current.policy); protected && !request.AllowProtected {
			return ErrPermissionDenied
		}
		if current.policy.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if err := refuseDeleteInUse(ctx, tx, current.policy); err != nil {
			return err
		}
		write, err = s.claimWrite(ctx, tx, actor, current.policy.ScopeID, "security_policy.delete", request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if write.Replayed {
			if err := json.Unmarshal(write.ResponseBody, &result); err != nil {
				return fmt.Errorf("decode stored security policy delete response: %w", err)
			}
			result.Replayed = true
			return nil
		}

		now := s.now().UTC()
		command, err := tx.Exec(ctx, `
			UPDATE security_policies SET deleted_at=$2, updated_at=$2,
				updated_by_user_id=$3, revision=revision+1
			WHERE id=$1 AND revision=$4 AND deleted_at IS NULL`,
			request.ID, now, actor.UserID, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		result = DeleteResult{ID: request.ID, Deleted: true, Revision: request.ExpectedRevision + 1}
		deletedPolicy := current.policy
		deletedPolicy.Revision = result.Revision
		deletedPolicy.UpdatedAt = now
		if err := s.insertVersion(ctx, tx, deletedPolicy, actor.UserID, now); err != nil {
			return err
		}
		if err := s.appendAudit(ctx, tx, actor, deletedPolicy, request.RequestID, "security_policy.delete"); err != nil {
			return err
		}
		return s.completeWrite(ctx, tx, actor.UserID, "security_policy.delete", request.IdempotencyKey, request.ID, result)
	})
	if err != nil {
		return DeleteResult{}, fmt.Errorf("delete security policy: %w", err)
	}
	return result, nil
}

func (s *Store) Get(ctx context.Context, actor Actor, id uuid.UUID) (Policy, error) {
	query := `SELECT ` + policyColumns("p") + `, u.display_name
		FROM security_policies p JOIN users u ON u.id=p.owner_user_id
		WHERE p.id=$1 AND p.deleted_at IS NULL`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND p.scope_id=$2"
		args = append(args, actor.ScopeID)
	}
	item, err := scanPolicy(s.pool.QueryRow(ctx, query, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("get security policy: %w", err)
	}
	return item, nil
}

func (s *Store) List(ctx context.Context, actor Actor, filter ListFilter) (ListResult, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ListResult{}, fmt.Errorf("begin security policy list transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()

	// Counts take every filter but status; total is the status-filtered one.
	unfiltered := filter
	unfiltered.Status = ""
	where, args := listWhere(actor, unfiltered)
	statusCondition := "true"
	if filter.Status != "" {
		args = append(args, filter.Status == "enabled")
		statusCondition = fmt.Sprintf("p.enabled=$%d", len(args))
	}
	var total int64
	var counts ListCounts
	if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE `+statusCondition+`),count(*),
		count(*) FILTER (WHERE p.enabled),count(*) FILTER (WHERE NOT p.enabled)
		FROM security_policies p JOIN users u ON u.id=p.owner_user_id `+where, args...).Scan(
		&total, &counts.All, &counts.Enabled, &counts.Disabled); err != nil {
		return ListResult{}, fmt.Errorf("count security policies: %w", err)
	}
	where += " AND " + statusCondition
	limitPosition := len(args) + 1
	offsetPosition := len(args) + 2
	args = append(args, filter.Limit, (filter.Page-1)*filter.Limit)
	rows, err := tx.Query(ctx, `SELECT `+policyColumns("p")+`, u.display_name
		FROM security_policies p JOIN users u ON u.id=p.owner_user_id `+where+`
		ORDER BY p.created_at DESC,p.id DESC
		LIMIT $`+fmt.Sprint(limitPosition)+` OFFSET $`+fmt.Sprint(offsetPosition), args...)
	if err != nil {
		return ListResult{}, fmt.Errorf("list security policies: %w", err)
	}
	defer rows.Close()
	items := make([]Policy, 0, filter.Limit)
	for rows.Next() {
		item, err := scanPolicy(rows)
		if err != nil {
			return ListResult{}, fmt.Errorf("scan security policy list item: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return ListResult{}, fmt.Errorf("list security policies: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ListResult{}, fmt.Errorf("commit security policy list transaction: %w", err)
	}
	return ListResult{Items: items, Total: total, Page: filter.Page, Limit: filter.Limit, Counts: counts}, nil
}

type lockedPolicy struct {
	policy  Policy
	deleted bool
}

func disableOnly(current Policy, fields PolicyFields) bool {
	return current.Enabled && !fields.Enabled && current.Kind == fields.Kind &&
		current.Name == fields.Name && current.Description == fields.Description &&
		current.DefaultAction == fields.DefaultAction && reflect.DeepEqual(current.Rules, fields.Rules) &&
		reflect.DeepEqual(current.CCSettings, fields.CCSettings) && reflect.DeepEqual(current.WAFSettings, fields.WAFSettings)
}

func requireOwnerCustomCC(ctx context.Context, tx pgx.Tx, scopeID, ownerID uuid.UUID, at time.Time) error {
	if err := iamlock.AcquireShared(ctx, tx); err != nil {
		return err
	}
	if _, err := iamlock.AcquireScopes(ctx, tx, []uuid.UUID{scopeID}); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT s.id FROM package_subscriptions s
		JOIN package_subscription_state_versions state ON state.subscription_id=s.id
		  AND state.tenant_scope_id=s.tenant_scope_id AND state.revision=s.revision
		WHERE s.tenant_scope_id=$1 AND state.owner_user_id=$2
		ORDER BY s.id FOR UPDATE OF s`, scopeID, ownerID)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	for _, id := range ids {
		limits, err := packageaddon.LockRuntimeLimits(ctx, tx, scopeID, id, at)
		if errors.Is(err, packageaddon.ErrSubscriptionInactive) {
			continue
		}
		if err != nil {
			return err
		}
		if limits.OwnerUserID == ownerID && limits.CustomCC {
			return nil
		}
	}
	return packageaddon.ErrFeatureDenied
}

func lockPolicy(ctx context.Context, tx pgx.Tx, actor Actor, id uuid.UUID) (lockedPolicy, error) {
	query := `SELECT ` + policyColumns("p") + `, u.display_name,p.deleted_at
		FROM security_policies p JOIN users u ON u.id=p.owner_user_id WHERE p.id=$1`
	args := []any{id}
	if actor.ScopeKind == "tenant" {
		query += " AND p.scope_id=$2"
		args = append(args, actor.ScopeID)
	}
	query += " FOR UPDATE OF p"
	var item Policy
	var rules, settings, quickBlock, wafSettings []byte
	var deletedAt *time.Time
	err := tx.QueryRow(ctx, query, args...).Scan(
		&item.ID, &item.ScopeID, &item.ownerID, &item.Kind, &item.Name, &item.Description,
		&item.Enabled, &item.DefaultAction, &rules, &item.Revision, &item.CreatedAt,
		&item.UpdatedAt, &settings, &quickBlock, &wafSettings, new(string), &deletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return lockedPolicy{}, ErrNotFound
	}
	if err != nil {
		return lockedPolicy{}, err
	}
	if err := json.Unmarshal(rules, &item.Rules); err != nil {
		return lockedPolicy{}, err
	}
	if item.CCSettings, err = decodeCCSettings(settings); err != nil {
		return lockedPolicy{}, err
	}
	if item.QuickBlock, err = decodeQuickBlock(quickBlock); err != nil {
		return lockedPolicy{}, err
	}
	if item.WAFSettings, err = decodeWAFSettings(wafSettings); err != nil {
		return lockedPolicy{}, err
	}
	var ownerName string
	if err := tx.QueryRow(ctx, "SELECT display_name FROM users WHERE id=$1", item.ownerID).Scan(&ownerName); err != nil {
		return lockedPolicy{}, err
	}
	item.Owner = &OwnerReference{ID: item.ownerID, DisplayName: ownerName}
	return lockedPolicy{policy: item, deleted: deletedAt != nil}, nil
}

func selectPolicy(ctx context.Context, tx pgx.Tx, id uuid.UUID, includeDeleted bool) (Policy, error) {
	query := `SELECT ` + policyColumns("p") + `,u.display_name FROM security_policies p
		JOIN users u ON u.id=p.owner_user_id WHERE p.id=$1`
	if !includeDeleted {
		query += " AND p.deleted_at IS NULL"
	}
	return scanPolicy(tx.QueryRow(ctx, query, id))
}

func policyColumns(alias string) string {
	return alias + `.id,` + alias + `.scope_id,` + alias + `.owner_user_id,` +
		alias + `.kind,` + alias + `.name,` + alias + `.description,` + alias + `.enabled,` +
		alias + `.default_action,` + alias + `.rules,` + alias + `.revision,` +
		alias + `.created_at,` + alias + `.updated_at,` + alias + `.cc_settings,` + alias + `.quick_block,` + alias + `.waf_settings`
}

func scanPolicy(row rowScanner) (Policy, error) {
	var item Policy
	var rules, settings, quickBlock, wafSettings []byte
	var ownerName string
	err := row.Scan(&item.ID, &item.ScopeID, &item.ownerID, &item.Kind, &item.Name,
		&item.Description, &item.Enabled, &item.DefaultAction, &rules, &item.Revision,
		&item.CreatedAt, &item.UpdatedAt, &settings, &quickBlock, &wafSettings, &ownerName)
	if err != nil {
		return Policy{}, err
	}
	if err := json.Unmarshal(rules, &item.Rules); err != nil {
		return Policy{}, err
	}
	if item.CCSettings, err = decodeCCSettings(settings); err != nil {
		return Policy{}, err
	}
	if item.QuickBlock, err = decodeQuickBlock(quickBlock); err != nil {
		return Policy{}, err
	}
	if item.WAFSettings, err = decodeWAFSettings(wafSettings); err != nil {
		return Policy{}, err
	}
	item.Owner = &OwnerReference{ID: item.ownerID, DisplayName: ownerName}
	return item, nil
}

func encodeWAFSettings(settings *WAFSettings) ([]byte, error) {
	if settings == nil {
		return nil, nil
	}
	return json.Marshal(settings)
}

func decodeWAFSettings(raw []byte) (*WAFSettings, error) {
	if raw == nil {
		return nil, nil
	}
	var settings WAFSettings
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, err
	}
	return &settings, nil
}

func encodeCCSettings(settings *CCSettings) ([]byte, error) {
	if settings == nil {
		return nil, nil
	}
	return json.Marshal(settings)
}

func decodeQuickBlock(raw []byte) (*QuickBlock, error) {
	if raw == nil {
		return nil, nil
	}
	var block QuickBlock
	if err := json.Unmarshal(raw, &block); err != nil {
		return nil, err
	}
	return &block, nil
}

func decodeCCSettings(raw []byte) (*CCSettings, error) {
	if raw == nil {
		return nil, nil
	}
	var settings CCSettings
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, err
	}
	return &settings, nil
}

// assignCCSettingsRuleIDs gives new auto switch rules an ID derived from the
// policy and the rule's position (stable across saves of the same rules;
// system-mode rules arrive with these IDs already). An ID the request names
// must be one of the stored switch rules' or derived; every ID differs from
// the policy rules'.
func assignCCSettingsRuleIDs(policyID uuid.UUID, rules []Rule, settings, existing *CCSettings) error {
	if settings == nil || settings.AutoSwitch == nil {
		return nil
	}
	known := map[uuid.UUID]struct{}{}
	if existing != nil && existing.AutoSwitch != nil {
		for _, rule := range existing.AutoSwitch.Rules {
			known[rule.ID] = struct{}{}
		}
	}
	switchRules := settings.AutoSwitch.Rules
	for index := range switchRules {
		derived := ccAutoSwitchRuleID(policyID, index)
		switch _, stored := known[switchRules[index].ID]; {
		case switchRules[index].ID == uuid.Nil:
			switchRules[index].ID = derived
		case switchRules[index].ID != derived && !stored:
			return ErrInvalidInput
		}
	}
	sortRules(switchRules)
	assignCCAutoSwitchRuleSetIDs(policyID, settings.AutoSwitch)
	return validateCCSettingsRuleIDs(rules, settings)
}

// assignCCAutoSwitchRuleSetIDs gives every rule set rule its derived ID
// (rule sets are always system resolutions, re-derived on every save).
func assignCCAutoSwitchRuleSetIDs(policyID uuid.UUID, value *CCAutoSwitch) {
	for setIndex := range value.RuleSets {
		set := &value.RuleSets[setIndex]
		for index := range set.Rules {
			set.Rules[index].ID = ccAutoSwitchRuleSetRuleID(policyID, set.Group, index)
		}
		sortRules(set.Rules)
	}
}

func ccAutoSwitchRuleID(policyID uuid.UUID, index int) uuid.UUID {
	return uuid.NewSHA1(policyID, []byte(fmt.Sprintf("cc-auto-switch-rule:%d", index)))
}

func assignRuleIDs(rules []Rule, existing []Rule) error {
	known := make(map[uuid.UUID]struct{}, len(existing))
	for _, rule := range existing {
		known[rule.ID] = struct{}{}
	}
	for index := range rules {
		if rules[index].ID != uuid.Nil {
			if _, ok := known[rules[index].ID]; !ok {
				return ErrInvalidInput
			}
			continue
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		rules[index].ID = id
	}
	sortRules(rules)
	return nil
}

func authorizeTargetScope(ctx context.Context, tx pgx.Tx, actor Actor, scopeID, ownerID uuid.UUID) (uuid.UUID, error) {
	var kind string
	var tenantID *uuid.UUID
	var ownerMember bool
	err := tx.QueryRow(ctx, `SELECT scope.kind,scope.tenant_id,
		EXISTS(SELECT 1 FROM memberships m WHERE m.scope_id=scope.id AND m.user_id=$2 AND m.status='active')
		FROM access_scopes scope WHERE scope.id=$1`, scopeID, ownerID).Scan(&kind, &tenantID, &ownerMember)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrInvalidInput
	}
	if err != nil {
		return uuid.Nil, err
	}
	if kind != "tenant" || tenantID == nil || !ownerMember {
		return uuid.Nil, ErrInvalidInput
	}
	if actor.ScopeKind == "tenant" && (actor.ScopeID != scopeID || actor.UserID != ownerID) {
		return uuid.Nil, ErrPermissionDenied
	}
	return *tenantID, nil
}

func listWhere(actor Actor, filter ListFilter) (string, []any) {
	conditions := []string{"p.deleted_at IS NULL"}
	args := make([]any, 0, 6)
	add := func(format string, value any) {
		args = append(args, value)
		conditions = append(conditions, fmt.Sprintf(format, len(args)))
	}
	if actor.ScopeKind == "tenant" {
		add("p.scope_id=$%d", actor.ScopeID)
	}
	if filter.Kind != "" {
		add("p.kind=$%d", filter.Kind)
	}
	if filter.Status != "" {
		add("p.enabled=$%d", filter.Status == "enabled")
	}
	if filter.Name != "" {
		add("position($%d in lower(p.name))>0", strings.ToLower(filter.Name))
	}
	if filter.ID != uuid.Nil {
		add("p.id=$%d", filter.ID)
	}
	if filter.Scope != "" {
		// System libraries carry the licensed description marker (redact /
		// licensedWAFMetadata); site libraries are bound to a site.
		args = append(args, licensedWAFDescriptionPrefix)
		system := fmt.Sprintf("starts_with(p.description,$%d)", len(args))
		bound := `EXISTS (SELECT 1 FROM security_policy_site_bindings b
			WHERE b.tenant_scope_id=p.scope_id AND b.policy_id=p.id AND b.policy_kind=p.kind)`
		switch filter.Scope {
		case ScopeSystem:
			conditions = append(conditions, system)
		case ScopeSite:
			conditions = append(conditions, "NOT "+system, bound)
		default:
			conditions = append(conditions, "NOT "+system, "NOT "+bound)
		}
	}
	if filter.Owner != "" {
		args = append(args, strings.ToLower(filter.Owner))
		position := len(args)
		conditions = append(conditions, fmt.Sprintf(
			"(lower(u.display_name) LIKE '%%' || $%d || '%%' OR lower(u.username) LIKE '%%' || $%d || '%%' OR u.id::text=$%d)",
			position, position, position))
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func (s *Store) insertVersion(ctx context.Context, tx pgx.Tx, item Policy, actorUserID uuid.UUID, now time.Time) error {
	document, err := json.Marshal(item)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO security_policy_versions
		(policy_id,revision,document,created_by_user_id,created_at) VALUES($1,$2,$3,$4,$5)`,
		item.ID, item.Revision, document, actorUserID, now)
	return err
}

func (s *Store) appendAudit(ctx context.Context, tx pgx.Tx, actor Actor, item Policy, requestID, action string) error {
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: item.ScopeID, ActorUserID: &actor.UserID, Action: action,
		ResourceType: "security_policy", ResourceID: item.ID.String(), RequestID: requestID,
		Result: "success", Payload: auditPayload(item),
	})
}

// auditPayload summarizes the policy for the audit log; a WAF policy names
// its observe mode and auto block (ge-waf), whose full values are in the
// version document.
func auditPayload(item Policy) map[string]any {
	payload := map[string]any{
		"kind": item.Kind, "version": item.Revision, "enabled": item.Enabled,
		"rule_count": len(item.Rules),
	}
	if item.Kind == KindWAF {
		mode := WAFModeDefend
		if item.WAFSettings != nil {
			mode = item.WAFSettings.Mode
		}
		if mode == WAFModeDefend {
			mode = "defend"
		}
		payload["waf_mode"] = mode
		payload["waf_auto_block"] = item.WAFSettings != nil && item.WAFSettings.AutoBlock != nil
	}
	return payload
}

func (s *Store) findWrite(ctx context.Context, tx pgx.Tx, actorUserID uuid.UUID, operation, key string, digest [32]byte) (storedWrite, bool, error) {
	var existingDigest []byte
	var resourceID *uuid.UUID
	var responseBody []byte
	var completedAt *time.Time
	err := tx.QueryRow(ctx, `SELECT request_digest,resource_id,response_body,completed_at
		FROM security_policy_write_requests
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3`,
		actorUserID, operation, key).Scan(&existingDigest, &resourceID, &responseBody, &completedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedWrite{}, false, nil
	}
	if err != nil {
		return storedWrite{}, false, err
	}
	if !bytes.Equal(existingDigest, digest[:]) || resourceID == nil || completedAt == nil || len(responseBody) == 0 {
		return storedWrite{}, false, ErrIdempotencyConflict
	}
	return storedWrite{Replayed: true, ResourceID: *resourceID, ResponseBody: responseBody}, true, nil
}

func (s *Store) claimWrite(ctx context.Context, tx pgx.Tx, actor Actor, targetScopeID uuid.UUID, operation, key string, digest [32]byte) (storedWrite, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return storedWrite{}, err
	}
	command, err := tx.Exec(ctx, `INSERT INTO security_policy_write_requests
		(id,actor_user_id,actor_scope_id,target_scope_id,operation,idempotency_key,request_digest,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT(actor_user_id,operation,idempotency_key) DO NOTHING`,
		id, actor.UserID, actor.ScopeID, targetScopeID, operation, key, digest[:], s.now().UTC())
	if err != nil {
		return storedWrite{}, err
	}
	if command.RowsAffected() == 1 {
		return storedWrite{}, nil
	}
	stored, found, err := s.findWrite(ctx, tx, actor.UserID, operation, key, digest)
	if err != nil {
		return storedWrite{}, err
	}
	if !found {
		return storedWrite{}, ErrIdempotencyConflict
	}
	return stored, nil
}

func (s *Store) completeWrite(ctx context.Context, tx pgx.Tx, actorUserID uuid.UUID, operation, key string, resourceID uuid.UUID, body any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	command, err := tx.Exec(ctx, `UPDATE security_policy_write_requests
		SET resource_id=$4,response_body=$5,completed_at=$6
		WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3 AND completed_at IS NULL`,
		actorUserID, operation, key, resourceID, encoded, s.now().UTC())
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrIdempotencyConflict
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var databaseError *pgconn.PgError
	return errors.As(err, &databaseError) && databaseError.Code == "23505"
}

// ErrIPListUnavailable: an ip_list condition names a list that does not
// exist, was deleted, or belongs to another tenant.
var ErrIPListUnavailable = errors.New("security policy references an unavailable IP list")

// requireUsableIPLists checks that every list the rules reference is a live
// list of the policy's scope or a platform list. Rows are locked FOR SHARE so
// a concurrent delete waits for the write.
func requireUsableIPLists(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, rules []Rule) error {
	ids := IPListReferences(rules)
	if len(ids) == 0 {
		return nil
	}
	var usable int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM (SELECT list.id FROM security_ip_lists list
		JOIN access_scopes owner ON owner.id=list.owner_scope_id
		WHERE list.id=ANY($1::uuid[]) AND list.deleted_at IS NULL AND (list.owner_scope_id=$2 OR owner.kind='platform')
		FOR SHARE OF list) usable`, ids, scopeID).Scan(&usable); err != nil {
		return err
	}
	if usable != len(ids) {
		return ErrIPListUnavailable
	}
	return nil
}
