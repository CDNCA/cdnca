package openrestysecurity

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type SecretSealer interface {
	Seal(context.Context, []byte) ([]byte, error)
}

type Store struct {
	pool       *pgxpool.Pool
	authorizer TxAuthorizer
	sealer     SecretSealer
	auditor    interface {
		Append(context.Context, pgx.Tx, audit.Event) error
	}
	now func() time.Time
}

func NewStore(pool *pgxpool.Pool, authorizer TxAuthorizer, sealer SecretSealer, now func() time.Time) (*Store, error) {
	if pool == nil || authorizer == nil || sealer == nil {
		return nil, ErrInvalidInput
	}
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, authorizer: authorizer, sealer: sealer, auditor: audit.NewWithClock(pool, now), now: now}, nil
}

func (store *Store) GetGlobal(ctx context.Context, request ReadGlobalRequest) (Document, error) {
	if err := validateActor(request.Actor, request.TargetScopeID, PermissionRead); err != nil {
		return Document{}, err
	}
	var result Document
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorizer.Authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionRead); err != nil {
			return err
		}
		var err error
		result, err = readGlobal(ctx, tx, request.TargetScopeID, false, store.now())
		return err
	})
	return result, mapStoreError(err)
}

func (store *Store) PatchGlobal(ctx context.Context, request PatchGlobalRequest) (WriteResult, error) {
	if err := validateWrite(request.Actor, request.TargetScopeID, request.ExpectedRevision, request.IdempotencyKey, request.RequestID); err != nil {
		return WriteResult{}, err
	}
	if len(request.Patch) == 0 || ValidateConfig(request.Patch, false) != nil {
		return WriteResult{}, ErrInvalidInput
	}
	requestDigest, err := requestSHA256(struct {
		Expected int64  `json:"expected_revision"`
		Patch    Config `json:"patch"`
	}{request.ExpectedRevision, request.Patch})
	if err != nil {
		return WriteResult{}, err
	}
	var result WriteResult
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorizer.Authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionManage); err != nil {
			return err
		}
		if replayed, found, err := readReceipt(ctx, tx, request.TargetScopeID, request.IdempotencyKey, requestDigest); err != nil {
			return err
		} else if found {
			result = WriteResult{Document: replayed, Replayed: true}
			return nil
		}
		current, err := readGlobal(ctx, tx, request.TargetScopeID, true, store.now())
		if err != nil {
			return err
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		patch, secret, err := StripSecret(request.Patch)
		if err != nil {
			return err
		}
		nextConfig, err := ApplyPatch(current.Config, patch, false)
		if err != nil {
			return err
		}
		encoded, digest, err := Canonical(nextConfig)
		if err != nil {
			return err
		}
		ciphertext, configured, err := nextSecret(ctx, tx, store.sealer, current.ID, current.KeyConfigured, secret)
		if err != nil {
			return err
		}
		now := store.now().UTC().Truncate(time.Microsecond)
		next := Document{ID: current.ID, TargetScopeID: request.TargetScopeID, ScopeType: ScopeGlobal, ScopeID: "0",
			Revision: current.Revision + 1, Config: nextConfig, KeyConfigured: configured, KeyOverride: true,
			UpdatedAt: now, DocumentSHA256: digest}
		var command pgconn.CommandTag
		if current.Revision == 0 {
			command, err = tx.Exec(ctx, `INSERT INTO openresty_security_configs(
				id,tenant_scope_id,scope_type,scope_id,document,document_sha256,key_override,secret_ciphertext,revision,created_at,updated_at
			) VALUES($1,$2,'global','0',$3,$4,true,$5,$6,$7,$7)
			ON CONFLICT DO NOTHING`, next.ID, request.TargetScopeID, encoded, digest[:], ciphertext, next.Revision, now)
		} else {
			command, err = tx.Exec(ctx, `UPDATE openresty_security_configs SET
				document=$3,document_sha256=$4,key_override=true,secret_ciphertext=$5,revision=$6,updated_at=$7
			WHERE id=$1 AND tenant_scope_id=$2 AND scope_type='global' AND scope_id='0' AND revision=$8 AND deleted_at IS NULL`,
				next.ID, request.TargetScopeID, encoded, digest[:], ciphertext, next.Revision, now, current.Revision)
		}
		if err != nil {
			return err
		}
		if err := requireSingleRevisionWrite(command.RowsAffected()); err != nil {
			return err
		}
		if err := store.recordWrite(ctx, tx, request.Actor, request.TargetScopeID, next, "global.patch", request.RequestID,
			request.IdempotencyKey, requestDigest); err != nil {
			return err
		}
		result.Document = next
		return nil
	})
	return result, mapStoreError(err)
}

func (store *Store) ListOverrides(ctx context.Context, request ListOverridesRequest) (OverridePage, error) {
	if err := validateActor(request.Actor, request.TargetScopeID, PermissionRead); err != nil {
		return OverridePage{}, err
	}
	if request.ScopeType != "" && request.ScopeType != ScopeRegion && request.ScopeType != ScopeNode ||
		!validPage(request.Page, request.PageSize) || len(request.Query) > 128 {
		return OverridePage{}, ErrInvalidInput
	}
	var result OverridePage
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorizer.Authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionRead); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT config.id,config.scope_type,config.scope_id,
			CASE WHEN config.scope_type='node' THEN COALESCE(NULLIF(node.name,''),'#'||node.display_id::text,'') ELSE config.scope_id END,
			config.revision,config.document,config.secret_ciphertext IS NOT NULL,config.updated_at,count(*) OVER()
			FROM openresty_security_configs config
			LEFT JOIN nodes node ON config.scope_type='node' AND node.scope_id=config.tenant_scope_id
			  AND node.id::text=config.scope_id AND node.admin_state<>'retired'
			WHERE config.tenant_scope_id=$1 AND config.scope_type IN('region','node') AND config.deleted_at IS NULL
			  AND ($2='' OR config.scope_type=$2) AND ($3='' OR config.scope_id ILIKE '%'||$3||'%'
			    OR node.name ILIKE '%'||$3||'%' OR node.display_id::text ILIKE '%'||$3||'%')
			ORDER BY config.updated_at DESC,config.id DESC LIMIT $4 OFFSET $5`, request.TargetScopeID, request.ScopeType,
			strings.TrimSpace(request.Query), request.PageSize, (request.Page-1)*request.PageSize)
		if err != nil {
			return err
		}
		defer rows.Close()
		result = OverridePage{Items: []Document{}, Page: request.Page, PageSize: request.PageSize}
		for rows.Next() {
			var item Document
			var raw []byte
			if err := rows.Scan(&item.ID, &item.ScopeType, &item.ScopeID, &item.ScopeLabel, &item.Revision, &raw,
				&item.KeyConfigured, &item.UpdatedAt, &result.Total); err != nil {
				return err
			}
			item.TargetScopeID = request.TargetScopeID
			item.Config, err = DecodeConfig(raw, true)
			if err != nil {
				return err
			}
			result.Items = append(result.Items, item)
		}
		return rows.Err()
	})
	return result, mapStoreError(err)
}

func (store *Store) CreateOverride(ctx context.Context, request CreateOverrideRequest) (WriteResult, error) {
	if err := validateWrite(request.Actor, request.TargetScopeID, 0, request.IdempotencyKey, request.RequestID); err != nil {
		return WriteResult{}, err
	}
	if !validScope(request.ScopeType, request.ScopeID) || request.ScopeType == ScopeGlobal || len(request.Config) == 0 ||
		ValidateConfig(request.Config, true) != nil {
		return WriteResult{}, ErrInvalidInput
	}
	requestDigest, err := createOverrideRequestDigest(request)
	if err != nil {
		return WriteResult{}, err
	}
	var result WriteResult
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorizer.Authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionManage); err != nil {
			return err
		}
		if replayed, found, err := readReceipt(ctx, tx, request.TargetScopeID, request.IdempotencyKey, requestDigest); err != nil {
			return err
		} else if found {
			result = WriteResult{Document: replayed, Replayed: true}
			return nil
		}
		if err := requireTarget(ctx, tx, request.TargetScopeID, request.ScopeType, request.ScopeID); err != nil {
			return err
		}
		config, secret, err := StripSecret(request.Config)
		if err != nil {
			return err
		}
		encoded, digest, err := canonicalOverride(config)
		if err != nil {
			return err
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		var ciphertext []byte
		keyOverride := secret != nil
		if secret != nil && *secret != "" {
			ciphertext, err = store.sealer.Seal(ctx, []byte(*secret))
			if err != nil {
				return err
			}
		}
		now := store.now().UTC().Truncate(time.Microsecond)
		next := Document{ID: id, TargetScopeID: request.TargetScopeID, ScopeType: request.ScopeType, ScopeID: request.ScopeID,
			Revision: 1, Config: config, KeyConfigured: len(ciphertext) != 0, KeyOverride: keyOverride,
			UpdatedAt: now, DocumentSHA256: digest}
		if _, err := tx.Exec(ctx, `INSERT INTO openresty_security_configs(
			id,tenant_scope_id,scope_type,scope_id,document,document_sha256,key_override,secret_ciphertext,revision,created_at,updated_at
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,$9,$9)`, id, request.TargetScopeID, request.ScopeType, request.ScopeID,
			encoded, digest[:], keyOverride, ciphertext, now); err != nil {
			return err
		}
		if err := store.recordWrite(ctx, tx, request.Actor, request.TargetScopeID, next, "override.create", request.RequestID,
			request.IdempotencyKey, requestDigest); err != nil {
			return err
		}
		result.Document = next
		return nil
	})
	return result, mapStoreError(err)
}

func (store *Store) PatchOverride(ctx context.Context, request PatchOverrideRequest) (WriteResult, error) {
	if request.ID == uuid.Nil || ValidateOverridePatch(request.Patch, request.RemovedFields) != nil {
		return WriteResult{}, ErrInvalidInput
	}
	if err := validateWrite(request.Actor, request.TargetScopeID, request.ExpectedRevision, request.IdempotencyKey, request.RequestID); err != nil {
		return WriteResult{}, err
	}
	requestDigest, err := patchOverrideRequestDigest(request)
	if err != nil {
		return WriteResult{}, err
	}
	var result WriteResult
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorizer.Authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionManage); err != nil {
			return err
		}
		if replayed, found, err := readReceipt(ctx, tx, request.TargetScopeID, request.IdempotencyKey, requestDigest); err != nil {
			return err
		} else if found {
			result = WriteResult{Document: replayed, Replayed: true}
			return nil
		}
		current, ciphertext, err := readOverride(ctx, tx, request.TargetScopeID, request.ID, true)
		if err != nil {
			return err
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		if slices.Contains(request.RemovedFields, "key") && !current.KeyOverride {
			return ErrInvalidInput
		}
		nextConfigWithSecret, err := ApplyOverridePatch(current.Config, request.Patch, request.RemovedFields)
		if err != nil {
			return err
		}
		nextConfig, secret, err := StripSecret(nextConfigWithSecret)
		if err != nil {
			return err
		}
		encoded, digest, err := canonicalOverride(nextConfig)
		if err != nil {
			return err
		}
		keyOverride := current.KeyOverride
		if slices.Contains(request.RemovedFields, "key") {
			keyOverride = false
			ciphertext = nil
		}
		if secret != nil {
			keyOverride = true
			ciphertext = nil
			if *secret != "" {
				ciphertext, err = store.sealer.Seal(ctx, []byte(*secret))
				if err != nil {
					return err
				}
			}
		}
		now := store.now().UTC().Truncate(time.Microsecond)
		next := current
		next.Revision++
		next.Config, next.KeyConfigured, next.KeyOverride, next.UpdatedAt, next.DocumentSHA256 =
			nextConfig, len(ciphertext) != 0, keyOverride, now, digest
		command, err := tx.Exec(ctx, `UPDATE openresty_security_configs SET document=$4,document_sha256=$5,
			key_override=$6,secret_ciphertext=$7,revision=$8,updated_at=$9 WHERE tenant_scope_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL`,
			request.TargetScopeID, request.ID, request.ExpectedRevision, encoded, digest[:], keyOverride, ciphertext, next.Revision, now)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		if err := store.recordWrite(ctx, tx, request.Actor, request.TargetScopeID, next, "override.patch", request.RequestID,
			request.IdempotencyKey, requestDigest); err != nil {
			return err
		}
		result.Document = next
		return nil
	})
	return result, mapStoreError(err)
}

func (store *Store) DeleteOverride(ctx context.Context, request DeleteOverrideRequest) (bool, error) {
	if request.ID == uuid.Nil {
		return false, ErrInvalidInput
	}
	if err := validateWrite(request.Actor, request.TargetScopeID, request.ExpectedRevision, request.IdempotencyKey, request.RequestID); err != nil {
		return false, err
	}
	requestDigest, err := deleteOverrideRequestDigest(request)
	if err != nil {
		return false, err
	}
	replayed := false
	err = pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorizer.Authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionManage); err != nil {
			return err
		}
		if _, found, err := readReceipt(ctx, tx, request.TargetScopeID, request.IdempotencyKey, requestDigest); err != nil {
			return err
		} else if found {
			replayed = true
			return nil
		}
		current, _, err := readOverride(ctx, tx, request.TargetScopeID, request.ID, true)
		if err != nil {
			return err
		}
		if current.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		now := store.now().UTC().Truncate(time.Microsecond)
		command, err := tx.Exec(ctx, `UPDATE openresty_security_configs SET revision=revision+1,deleted_at=$4,updated_at=$4
			WHERE tenant_scope_id=$1 AND id=$2 AND revision=$3 AND deleted_at IS NULL`, request.TargetScopeID, request.ID,
			request.ExpectedRevision, now)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		current.Revision++
		current.UpdatedAt = now
		if err := store.recordWrite(ctx, tx, request.Actor, request.TargetScopeID, current, "override.delete", request.RequestID,
			request.IdempotencyKey, requestDigest); err != nil {
			return err
		}
		return nil
	})
	return replayed, mapStoreError(err)
}

func (store *Store) SearchTargets(ctx context.Context, request SearchTargetsRequest) (TargetPage, error) {
	if err := validateActor(request.Actor, request.TargetScopeID, PermissionRead); err != nil {
		return TargetPage{}, err
	}
	if request.ScopeType != ScopeNode && request.ScopeType != ScopeRegion || !validPage(request.Page, request.PageSize) || len(request.Query) > 128 {
		return TargetPage{}, ErrInvalidInput
	}
	var result TargetPage
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorizer.Authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionRead); err != nil {
			return err
		}
		result = TargetPage{Items: []TargetOption{}, Page: request.Page, PageSize: request.PageSize}
		query := strings.TrimSpace(request.Query)
		var rows pgx.Rows
		var err error
		if request.ScopeType == ScopeNode {
			rows, err = tx.Query(ctx, `SELECT id::text,COALESCE(NULLIF(name,''),'#'||display_id::text),COALESCE(host(ipv4),host(ipv6),''),count(*) OVER()
				FROM nodes WHERE scope_id=$1 AND admin_state<>'retired' AND
				($2='' OR id::text ILIKE '%'||$2||'%' OR display_id::text ILIKE '%'||$2||'%' OR name ILIKE '%'||$2||'%'
				  OR host(ipv4) ILIKE '%'||$2||'%' OR host(ipv6) ILIKE '%'||$2||'%')
				ORDER BY name,id LIMIT $3 OFFSET $4`, request.TargetScopeID, query, request.PageSize, (request.Page-1)*request.PageSize)
		} else {
			rows, err = tx.Query(ctx, `SELECT region,region,count(*) OVER() FROM (
				SELECT DISTINCT region FROM nodes WHERE scope_id=$1 AND region<>'' AND ($2='' OR region ILIKE '%'||$2||'%')
			) regions ORDER BY region LIMIT $3 OFFSET $4`, request.TargetScopeID, query, request.PageSize, (request.Page-1)*request.PageSize)
		}
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item TargetOption
			if request.ScopeType == ScopeNode {
				if err := rows.Scan(&item.Value, &item.Label, &item.Description, &result.Total); err != nil {
					return err
				}
			} else if err := rows.Scan(&item.Value, &item.Label, &result.Total); err != nil {
				return err
			}
			result.Items = append(result.Items, item)
		}
		return rows.Err()
	})
	return result, mapStoreError(err)
}

func (store *Store) Effective(ctx context.Context, request EffectiveRequest) (Document, error) {
	if request.NodeID == uuid.Nil {
		return Document{}, ErrInvalidInput
	}
	if err := validateActor(request.Actor, request.TargetScopeID, PermissionRead); err != nil {
		return Document{}, err
	}
	var result Document
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorizer.Authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionRead); err != nil {
			return err
		}
		var region string
		if err := tx.QueryRow(ctx, `SELECT region FROM nodes WHERE scope_id=$1 AND id=$2 AND admin_state<>'retired'`,
			request.TargetScopeID, request.NodeID).Scan(&region); err != nil {
			return err
		}
		global, err := readGlobal(ctx, tx, request.TargetScopeID, false, store.now())
		if err != nil {
			return err
		}
		regionConfig, regionKeyOverride, regionKeyConfigured, err := readConfigByTarget(ctx, tx, request.TargetScopeID, ScopeRegion, region)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		nodeConfig, nodeKeyOverride, nodeKeyConfigured, err := readConfigByTarget(ctx, tx, request.TargetScopeID, ScopeNode, request.NodeID.String())
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		effective, err := Effective(global.Config, regionConfig, nodeConfig)
		if err != nil {
			return err
		}
		keyConfigured := global.KeyConfigured
		if regionKeyOverride {
			keyConfigured = regionKeyConfigured
		}
		if nodeKeyOverride {
			keyConfigured = nodeKeyConfigured
		}
		result = Document{ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(request.TargetScopeID.String()+":"+request.NodeID.String())),
			TargetScopeID: request.TargetScopeID, ScopeType: ScopeNode, ScopeID: request.NodeID.String(), Revision: global.Revision,
			Config: effective, KeyConfigured: keyConfigured, UpdatedAt: global.UpdatedAt,
			Sources: EffectiveSources(global.Config, regionConfig, nodeConfig)}
		return nil
	})
	return result, mapStoreError(err)
}

func ruleGroupReferenceScope(scopeKind string) string {
	if scopeKind == ScopePlatform {
		return "(scope_id=$1 OR scope_id IN (SELECT id FROM access_scopes WHERE kind='tenant'))"
	}
	return "scope_id=$1"
}

func systemRuleLogicalKey(systemRuleKey, systemRuleID string) string {
	if key := strings.TrimSpace(systemRuleKey); key != "" {
		return key
	}
	return strings.TrimSpace(systemRuleID)
}

func (store *Store) RuleGroups(ctx context.Context, request RuleGroupsRequest) ([]RuleGroup, error) {
	if err := validateRuleGroupActor(request.Actor, request.TargetScopeID); err != nil {
		return nil, err
	}
	custom := []RuleGroup{}
	system := []RuleGroup{}
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if authorizer, ok := store.authorizer.(ruleGroupAuthorizer); ok {
			if err := authorizer.AuthorizeRuleGroups(ctx, tx, request.Actor, request.TargetScopeID); err != nil {
				return err
			}
		} else if err := store.authorizer.Authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionRead); err != nil {
			return err
		}
		var referencesAvailable bool
		if err := tx.QueryRow(ctx, `SELECT to_regclass('cc_reference_matchers') IS NOT NULL AND to_regclass('cc_reference_filters') IS NOT NULL AND
			EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='cc_reference_matchers' AND column_name='system_rule_id') AND
			EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='cc_reference_filters' AND column_name='system_rule_id')`).Scan(&referencesAvailable); err != nil {
			return err
		}
		if referencesAvailable {
			// Platform operators do not own a tenant scope. Aggregate the signed
			// system catalog across tenant projections for the admin view.
			referenceScope := ruleGroupReferenceScope(request.Actor.ScopeKind)
			if rows, err := tx.Query(ctx, `SELECT logical_key, min(system_rule_id), min(system_rule_key), min(name), bool_and(enabled), min(system_rule_sort), min(created_at)
			FROM (
				SELECT 'system:' || COALESCE(NULLIF(system_rule_key,''),NULLIF(system_rule_id,'')) AS logical_key,system_rule_id,system_rule_key,name,enabled,system_rule_sort,created_at FROM cc_reference_matchers WHERE `+referenceScope+` AND deleted_at IS NULL AND system_rule=true
				UNION ALL
				SELECT 'system:' || COALESCE(NULLIF(system_rule_key,''),NULLIF(system_rule_id,'')) AS logical_key,system_rule_id,system_rule_key,name,enabled,system_rule_sort,created_at FROM cc_reference_filters WHERE `+referenceScope+` AND deleted_at IS NULL AND system_rule=true
			) refs WHERE logical_key <> '' GROUP BY logical_key ORDER BY min(system_rule_sort), min(created_at), logical_key`, request.TargetScopeID); err == nil {
				for rows.Next() {
					var item RuleGroup
					if err := rows.Scan(&item.ID, &item.SystemRuleID, &item.SystemRuleKey, &item.Name, &item.Enabled, &item.Sort, &item.CreatedAt); err != nil {
						rows.Close()
						return err
					}
					item.ID = systemRuleLogicalKey(item.SystemRuleKey, item.SystemRuleID)
					item.Kind, item.SystemRule = "system", true
					system = append(system, item)
				}
				if err := rows.Err(); err != nil {
					rows.Close()
					return err
				}
				rows.Close()
			}
		}
		rows, err := tx.Query(ctx, `SELECT policy.id::text,policy.name,policy.enabled,
			COALESCE(NULLIF(owner.display_name,''),policy.owner_user_id::text),policy.created_at
			FROM security_policies policy
			LEFT JOIN users owner ON owner.id=policy.owner_user_id
			WHERE policy.scope_id=$1 AND policy.kind='cc' AND policy.deleted_at IS NULL ORDER BY policy.created_at,policy.id`, request.TargetScopeID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item RuleGroup
			if err := rows.Scan(&item.ID, &item.Name, &item.Enabled, &item.Owner, &item.CreatedAt); err != nil {
				return err
			}
			item.Kind = "custom"
			item.SystemRule = false
			custom = append(custom, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, mapStoreError(err)
	}
	return mergeRuleGroups(system, custom), nil
}

func (store *Store) SetRuleGroupEnabled(ctx context.Context, request RuleGroupStateRequest) error {
	// 启用/禁用是写操作：要求 manage 权限，且只允许平台作用域（共享系统规则投影）。
	if err := validateActor(request.Actor, request.TargetScopeID, PermissionManage); err != nil {
		return err
	}
	if request.SystemRuleID == "" {
		return ErrInvalidInput
	}
	return pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorizer.Authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionManage); err != nil {
			return err
		}
		// ruleGroupReferenceScope 约定 $1 为作用域 ID。
		scope := ruleGroupReferenceScope(request.Actor.ScopeKind)
		args := []any{request.TargetScopeID, request.Enabled, store.now().UTC(), request.Actor.UserID, request.SystemRuleID}
		for _, table := range []string{"cc_reference_matchers", "cc_reference_filters"} {
			query := `UPDATE ` + table + ` SET enabled=$2,revision=revision+1,updated_at=$3,updated_by_user_id=$4
				WHERE system_rule=true AND (system_rule_key=$5 OR system_rule_id=$5) AND deleted_at IS NULL AND ` + scope
			if _, err := tx.Exec(ctx, query, args...); err != nil {
				return err
			}
		}
		return nil
	})
}

func mergeRuleGroups(system, custom []RuleGroup) []RuleGroup {
	groups := append([]RuleGroup(nil), system...)
	seen := make(map[string]struct{}, len(groups)+len(custom))
	for _, group := range groups {
		seen[group.ID] = struct{}{}
	}
	for _, group := range custom {
		if _, exists := seen[group.ID]; exists {
			continue
		}
		seen[group.ID] = struct{}{}
		groups = append(groups, group)
	}
	return groups
}

func (store *Store) DownloadCCImage(ctx context.Context, request DownloadCCImageRequest) (bool, error) {
	if err := validateWrite(request.Actor, request.TargetScopeID, 0, request.IdempotencyKey, request.RequestID); err != nil {
		return false, err
	}
	replayed := false
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if err := store.authorizer.Authorize(ctx, tx, request.Actor, request.TargetScopeID, PermissionManage); err != nil {
			return err
		}
		digest := sha256.Sum256([]byte("download_cc_img"))
		if _, found, err := readReceipt(ctx, tx, request.TargetScopeID, request.IdempotencyKey, digest); err != nil {
			return err
		} else if found {
			replayed = true
			return nil
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		now := store.now().UTC().Truncate(time.Microsecond)
		if _, err := tx.Exec(ctx, `INSERT INTO openresty_security_task_outbox(
			id,tenant_scope_id,task_type,idempotency_key,state,created_at,updated_at
		) VALUES($1,$2,'download_cc_img',$3,'pending',$4,$4)`, id, request.TargetScopeID, request.IdempotencyKey, now); err != nil {
			return err
		}
		response, _ := json.Marshal(Document{ID: id, TargetScopeID: request.TargetScopeID, ScopeType: ScopeGlobal,
			ScopeID: "0", Revision: 0, Config: Config{}, UpdatedAt: now})
		if _, err := tx.Exec(ctx, `INSERT INTO openresty_security_write_receipts(
			tenant_scope_id,idempotency_key,request_sha256,actor_scope_id,actor_user_id,response_body,created_at
		) VALUES($1,$2,$3,$4,$5,$6,$7)`, request.TargetScopeID, request.IdempotencyKey, digest[:], request.Actor.ScopeID,
			request.Actor.UserID, response, now); err != nil {
			return err
		}
		return store.auditor.Append(ctx, tx, audit.Event{ScopeID: request.TargetScopeID, ActorUserID: &request.Actor.UserID,
			Action: "openresty_security.download_cc_image", ResourceType: "openresty_security_task", ResourceID: id.String(),
			RequestID: request.RequestID, Result: "success", Payload: map[string]any{"task_type": "download_cc_img"}})
	})
	return replayed, mapStoreError(err)
}

func (store *Store) recordWrite(ctx context.Context, tx pgx.Tx, actor Actor, targetScopeID uuid.UUID, document Document,
	operation, requestID, idempotencyKey string, requestDigest [sha256.Size]byte) error {
	encoded, err := json.Marshal(document.Config)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO openresty_security_config_revisions(
		tenant_scope_id,config_id,revision,scope_type,scope_id,operation,document,document_sha256,key_configured,
		actor_scope_id,actor_user_id,request_id,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, targetScopeID, document.ID, document.Revision,
		document.ScopeType, document.ScopeID, operation, encoded, document.DocumentSHA256[:], document.KeyConfigured,
		actor.ScopeID, actor.UserID, requestID, document.UpdatedAt); err != nil {
		return err
	}
	outboxID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO openresty_security_publication_outbox(
		id,tenant_scope_id,config_id,revision,scope_type,scope_id,operation,document,document_sha256,state,available_at,created_at,updated_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',$10,$10,$10)`, outboxID, targetScopeID, document.ID,
		document.Revision, document.ScopeType, document.ScopeID, operation, encoded, document.DocumentSHA256[:], document.UpdatedAt); err != nil {
		return err
	}
	responseBody, err := json.Marshal(document)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO openresty_security_write_receipts(
		tenant_scope_id,idempotency_key,request_sha256,actor_scope_id,actor_user_id,response_body,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, targetScopeID, idempotencyKey, requestDigest[:], actor.ScopeID, actor.UserID,
		responseBody, document.UpdatedAt); err != nil {
		return err
	}
	return store.auditor.Append(ctx, tx, audit.Event{ScopeID: targetScopeID, ActorUserID: &actor.UserID,
		Action: "openresty_security." + operation, ResourceType: "openresty_security_config", ResourceID: document.ID.String(),
		RequestID: requestID, Result: "success", Payload: map[string]any{"scope_type": document.ScopeType,
			"scope_id": document.ScopeID, "revision": document.Revision, "key_configured": document.KeyConfigured}})
}

func readGlobal(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, lock bool, now time.Time) (Document, error) {
	query := `SELECT id,revision,document,key_override,secret_ciphertext IS NOT NULL,updated_at,document_sha256
		FROM openresty_security_configs WHERE tenant_scope_id=$1 AND scope_type='global' AND scope_id='0' AND deleted_at IS NULL`
	if lock {
		query += " FOR UPDATE"
	}
	var result Document
	var raw, digest []byte
	err := tx.QueryRow(ctx, query, scopeID).Scan(&result.ID, &result.Revision, &raw, &result.KeyOverride,
		&result.KeyConfigured, &result.UpdatedAt, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		config := DefaultGlobalConfig()
		_, sum, canonicalErr := Canonical(config)
		if canonicalErr != nil {
			return Document{}, canonicalErr
		}
		return Document{ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte(scopeID.String()+":global")), TargetScopeID: scopeID,
			ScopeType: ScopeGlobal, ScopeID: "0", Revision: 0, Config: config, UpdatedAt: now.UTC(), DocumentSHA256: sum}, nil
	}
	if err != nil {
		return Document{}, err
	}
	result.TargetScopeID, result.ScopeType, result.ScopeID = scopeID, ScopeGlobal, "0"
	result.Config, err = DecodeConfig(raw, false)
	if err != nil || len(digest) != sha256.Size {
		return Document{}, ErrUnavailable
	}
	copy(result.DocumentSHA256[:], digest)
	return result, nil
}

func readOverride(ctx context.Context, tx pgx.Tx, scopeID, id uuid.UUID, lock bool) (Document, []byte, error) {
	query := `SELECT scope_type,scope_id,revision,document,key_override,secret_ciphertext,updated_at,document_sha256
		FROM openresty_security_configs WHERE tenant_scope_id=$1 AND id=$2 AND scope_type IN('region','node') AND deleted_at IS NULL`
	if lock {
		query += " FOR UPDATE"
	}
	var result Document
	var raw, ciphertext, digest []byte
	err := tx.QueryRow(ctx, query, scopeID, id).Scan(&result.ScopeType, &result.ScopeID, &result.Revision, &raw,
		&result.KeyOverride, &ciphertext,
		&result.UpdatedAt, &digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return Document{}, nil, ErrNotFound
	}
	if err != nil {
		return Document{}, nil, err
	}
	result.ID, result.TargetScopeID, result.KeyConfigured = id, scopeID, len(ciphertext) != 0
	result.Config, err = DecodeConfig(raw, true)
	if err != nil || len(digest) != sha256.Size {
		return Document{}, nil, ErrUnavailable
	}
	copy(result.DocumentSHA256[:], digest)
	return result, ciphertext, nil
}

func readConfigByTarget(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, scopeType, targetID string) (Config, bool, bool, error) {
	var raw []byte
	var override, configured bool
	err := tx.QueryRow(ctx, `SELECT document,key_override,secret_ciphertext IS NOT NULL FROM openresty_security_configs
		WHERE tenant_scope_id=$1 AND scope_type=$2 AND scope_id=$3 AND deleted_at IS NULL`, scopeID, scopeType, targetID).
		Scan(&raw, &override, &configured)
	if err != nil {
		return nil, false, false, err
	}
	config, err := DecodeConfig(raw, true)
	return config, override, configured, err
}

func readReceipt(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, key string, digest [sha256.Size]byte) (Document, bool, error) {
	var storedDigest, body []byte
	err := tx.QueryRow(ctx, `SELECT request_sha256,response_body FROM openresty_security_write_receipts
		WHERE tenant_scope_id=$1 AND idempotency_key=$2`, scopeID, key).Scan(&storedDigest, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return Document{}, false, nil
	}
	if err != nil {
		return Document{}, false, err
	}
	if len(storedDigest) != sha256.Size || !equalBytes(storedDigest, digest[:]) {
		return Document{}, false, ErrIdempotencyConflict
	}
	var document Document
	if err := json.Unmarshal(body, &document); err != nil {
		return Document{}, false, ErrUnavailable
	}
	document.TargetScopeID = scopeID
	return document, true, nil
}

func nextSecret(ctx context.Context, tx pgx.Tx, sealer SecretSealer, id uuid.UUID, configured bool, secret *string) ([]byte, bool, error) {
	var current []byte
	if configured {
		if err := tx.QueryRow(ctx, `SELECT secret_ciphertext FROM openresty_security_configs WHERE id=$1`, id).Scan(&current); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, false, err
		}
	}
	if secret == nil {
		return current, len(current) != 0, nil
	}
	if *secret == "" {
		return nil, false, nil
	}
	ciphertext, err := sealer.Seal(ctx, []byte(*secret))
	return ciphertext, err == nil && len(ciphertext) != 0, err
}

func requireTarget(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID, scopeType, targetID string) error {
	var exists bool
	var err error
	if scopeType == ScopeNode {
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE scope_id=$1 AND id=$2::uuid AND admin_state<>'retired')`,
			scopeID, targetID).Scan(&exists)
	} else {
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM nodes WHERE scope_id=$1 AND region=$2 AND region<>'')`, scopeID, targetID).Scan(&exists)
	}
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func canonicalOverride(config Config) ([]byte, [sha256.Size]byte, error) {
	if err := ValidateConfig(config, true); err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, [sha256.Size]byte{}, ErrInvalidInput
	}
	return encoded, sha256.Sum256(encoded), nil
}

func validateWrite(actor Actor, scopeID uuid.UUID, expected int64, key, requestID string) error {
	if err := validateActor(actor, scopeID, PermissionManage); err != nil {
		return err
	}
	if expected < 0 || expected > 1<<53-1 || !idempotencyPattern.MatchString(key) || len(requestID) < 1 || len(requestID) > 128 {
		return ErrInvalidInput
	}
	return nil
}

func validPage(page, pageSize int) bool { return page >= 1 && pageSize >= 1 && pageSize <= 100 }

func requestSHA256(value any) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func createOverrideRequestDigest(request CreateOverrideRequest) ([sha256.Size]byte, error) {
	return requestSHA256(struct {
		TargetScopeID uuid.UUID `json:"target_scope_id"`
		ScopeType     string    `json:"scope_type"`
		ScopeID       string    `json:"scope_id"`
		Config        Config    `json:"config"`
	}{request.TargetScopeID, request.ScopeType, request.ScopeID, request.Config})
}

func patchOverrideRequestDigest(request PatchOverrideRequest) ([sha256.Size]byte, error) {
	removedFields := append([]string{}, request.RemovedFields...)
	slices.Sort(removedFields)
	return requestSHA256(struct {
		TargetScopeID    uuid.UUID `json:"target_scope_id"`
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
		Patch            Config    `json:"patch"`
		RemovedFields    []string  `json:"removed_fields"`
	}{request.TargetScopeID, request.ID, request.ExpectedRevision, request.Patch, removedFields})
}

func deleteOverrideRequestDigest(request DeleteOverrideRequest) ([sha256.Size]byte, error) {
	return requestSHA256(struct {
		TargetScopeID    uuid.UUID `json:"target_scope_id"`
		ID               uuid.UUID `json:"id"`
		ExpectedRevision int64     `json:"expected_revision"`
	}{request.TargetScopeID, request.ID, request.ExpectedRevision})
}

func requireSingleRevisionWrite(rowsAffected int64) error {
	if rowsAffected != 1 {
		return ErrRevisionConflict
	}
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}

func mapStoreError(err error) error {
	if err == nil || errors.Is(err, ErrUnauthenticated) || errors.Is(err, ErrPermissionDenied) || errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrRevisionConflict) || errors.Is(err, ErrIdempotencyConflict) ||
		errors.Is(err, ErrDuplicateTarget) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		if postgresError.Code == "23505" {
			return ErrDuplicateTarget
		}
		if postgresError.Code == "40001" || postgresError.Code == "40P01" {
			return ErrRevisionConflict
		}
	}
	return fmt.Errorf("%w: %v", ErrUnavailable, err)
}
