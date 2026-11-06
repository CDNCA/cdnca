package plugininstallation

// Tenants of a platform-confirmed tenant plugin ("这不是应该是
// 主控的管理员来操作么"). A tenant plugin (ui_page, external_https) the controller's platform administrator
// confirms is held in the platform scope with a target set: every tenant (including tenants created later) or a
// list of tenant scopes. Tenants then use it directly; they never confirm it. One license authorization still has
// exactly one local head (migration 586), so its lifecycle and license reports are unchanged.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TargetsView is what the platform administrator reads about a tenant plugin's targets.
type TargetsView struct {
	AllTenants bool
	Revision   uint64
	Tenants    []TargetTenant
}

// TargetTenant is one listed tenant scope with its display name (empty when the tenant is gone).
type TargetTenant struct {
	ScopeID     uuid.UUID
	DisplayName string
	DisplayID   string
}

// TargetsUpdate replaces the targets of a platform-held tenant plugin under If-Match.
type TargetsUpdate struct {
	AuthorizationID  uuid.UUID
	ExpectedRevision uint64
	IdempotencyKey   string
	RequestID        string
	Targets          Targets
}

// TargetsRepository is an InstallationRepository that can change a tenant plugin's targets.
type TargetsRepository interface {
	UpdateTargets(context.Context, Actor, TargetsUpdate) (InstallationView, error)
}

// TargetsDomain is a Domain that serves PUT /v1/platform/plugin-installations/{authorization_id}/targets.
type TargetsDomain interface {
	UpdateTargets(context.Context, Actor, TargetsUpdate) (InstallationView, error)
}

// UpdateTargets is the platform administrator changing who a tenant plugin is installed for.
func (domain *ProductionDomain) UpdateTargets(ctx context.Context, actor Actor, update TargetsUpdate) (InstallationView, error) {
	if domain == nil || domain.repository == nil {
		return InstallationView{}, ErrFactUnavailable
	}
	if actor.resourceScope() != ResourceScopePlatform {
		return InstallationView{}, ErrPlatformManaged
	}
	repository, ok := domain.repository.(TargetsRepository)
	if !ok {
		return InstallationView{}, ErrFactUnavailable
	}
	return repository.UpdateTargets(ctx, actor, update)
}

func targetsDigest(targets Targets, expectedRevision uint64) []byte {
	encoded, _ := json.Marshal(struct {
		Targets          Targets `json:"targets"`
		ExpectedRevision uint64  `json:"expected_revision"`
	}{CanonicalTargets(targets), expectedRevision})
	sum := sha256.Sum256(encoded)
	return sum[:]
}

// SaveTargets records the targets of a tenant plugin the platform administrator confirms, in the confirmation's
// transaction (the commit-time check of migration 636 refuses a platform-held tenant head without them).
func (transaction *postgresTransaction) SaveTargets(value Installation, receipt Receipt, targets Targets) error {
	if transaction.actor.resourceScope() != ResourceScopePlatform || value.ResourceScope != ResourceScopeTenant ||
		receipt.FromRevision != 0 || !validTargets(targets) {
		return ErrTargetsInvalid
	}
	return writePluginInstallationTargets(transaction.ctx, transaction.tx, transaction.actor, transaction.auditor,
		value.AuthorizationID, 0, targets, receipt.IdempotencyKey, targetsDigest(targets, 0), receipt.RequestID, value.PluginID)
}

// writePluginInstallationTargets inserts (from 0) or replaces (from the current revision) the target set.
func writePluginInstallationTargets(ctx context.Context, tx pgx.Tx, actor Actor, auditor *audit.Log,
	authorizationID uuid.UUID, from uint64, targets Targets, idempotencyKey string, digest []byte, requestID, pluginID string) error {
	targets = CanonicalTargets(targets)
	if !targets.AllTenants {
		var known int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM access_scopes WHERE kind='tenant' AND id=ANY($1)`,
			targets.TenantScopeIDs).Scan(&known); err != nil {
			return postgresError(ctx, err)
		}
		if known != len(targets.TenantScopeIDs) {
			return ErrTargetsInvalid
		}
	}
	if from == 0 {
		if _, err := tx.Exec(ctx, `INSERT INTO plugin_installation_targets(authorization_id,all_tenants,revision,
			last_idempotency_key,last_request_sha256,updated_by_user_id,created_at,updated_at)
			VALUES($1,$2,1,$3,$4,$5,transaction_timestamp(),transaction_timestamp())`,
			authorizationID, targets.AllTenants, idempotencyKey, digest, actor.UserID); err != nil {
			return postgresError(ctx, err)
		}
	} else {
		command, err := tx.Exec(ctx, `UPDATE plugin_installation_targets SET all_tenants=$2,revision=revision+1,
			last_idempotency_key=$3,last_request_sha256=$4,updated_by_user_id=$5,updated_at=transaction_timestamp()
			WHERE authorization_id=$1 AND revision=$6`, authorizationID, targets.AllTenants, idempotencyKey, digest,
			actor.UserID, from)
		if err != nil {
			return postgresError(ctx, err)
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		if _, err := tx.Exec(ctx, `DELETE FROM plugin_installation_target_tenants WHERE authorization_id=$1`,
			authorizationID); err != nil {
			return postgresError(ctx, err)
		}
	}
	if len(targets.TenantScopeIDs) > 0 {
		if _, err := tx.Exec(ctx, `INSERT INTO plugin_installation_target_tenants(authorization_id,tenant_scope_id)
			SELECT $1, unnest($2::uuid[])`, authorizationID, targets.TenantScopeIDs); err != nil {
			return postgresError(ctx, err)
		}
	}
	payload := map[string]any{"plugin_id": pluginID, "all_tenants": targets.AllTenants,
		"tenant_count": len(targets.TenantScopeIDs), "revision": from + 1}
	if len(targets.TenantScopeIDs) <= 100 {
		ids := make([]string, len(targets.TenantScopeIDs))
		for index, id := range targets.TenantScopeIDs {
			ids[index] = id.String()
		}
		payload["tenant_scope_ids"] = ids
	}
	return auditor.Append(ctx, tx, audit.Event{ScopeID: actor.TenantID, ActorUserID: &actor.UserID,
		Action: "plugin_installation.targets", ResourceType: "plugin_installation", ResourceID: authorizationID.String(),
		RequestID: requestID, Result: "success", Payload: payload})
}

// UpdateTargets replaces the targets of a platform-held tenant plugin. The same key with the same body (targets and
// If-Match) while it is still the last change answers the current state again; the same key with another body is an
// idempotency conflict.
func (repository *PostgresRepository) UpdateTargets(ctx context.Context, actor Actor, update TargetsUpdate) (InstallationView, error) {
	if update.Targets.AllTenants && len(update.Targets.TenantScopeIDs) > 0 {
		return InstallationView{}, ErrTargetsInvalid
	}
	update.Targets = CanonicalTargets(update.Targets)
	if ctx == nil || repository == nil || repository.pool == nil || actor.resourceScope() != ResourceScopePlatform ||
		update.AuthorizationID == uuid.Nil || update.ExpectedRevision == 0 || !idempotencyPattern.MatchString(update.IdempotencyKey) ||
		!validRequestID(update.RequestID) {
		return InstallationView{}, ErrInvalidInput
	}
	if !validTargets(update.Targets) {
		return InstallationView{}, ErrTargetsInvalid
	}
	tx, err := repository.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return InstallationView{}, postgresError(ctx, err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := authorizePluginInstallationActor(ctx, tx, actor, PermissionManage); err != nil {
		return InstallationView{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('plugin-installation:' || $1::text,0))`,
		update.AuthorizationID); err != nil {
		return InstallationView{}, postgresError(ctx, err)
	}
	current, err := loadPluginInstallation(ctx, tx, actor.TenantID, update.AuthorizationID, true)
	if err != nil {
		return InstallationView{}, err
	}
	if current.ResourceScope != ResourceScopeTenant {
		return InstallationView{}, ErrTargetsInvalid
	}
	if current.Status == StatusUninstalled {
		return InstallationView{}, ErrTransitionInvalid
	}
	var revision uint64
	var lastKey string
	var lastDigest []byte
	if err := tx.QueryRow(ctx, `SELECT revision,last_idempotency_key,last_request_sha256 FROM plugin_installation_targets
		WHERE authorization_id=$1 FOR UPDATE`, update.AuthorizationID).Scan(&revision, &lastKey, &lastDigest); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return InstallationView{}, ErrStorageUnavailable
		}
		return InstallationView{}, postgresError(ctx, err)
	}
	digest := targetsDigest(update.Targets, update.ExpectedRevision)
	if lastKey != update.IdempotencyKey || string(lastDigest) != string(digest) {
		if lastKey == update.IdempotencyKey {
			return InstallationView{}, ErrIdempotencyConflict
		}
		if revision != update.ExpectedRevision {
			return InstallationView{}, ErrRevisionConflict
		}
		if err := writePluginInstallationTargets(ctx, tx, actor, repository.auditor, update.AuthorizationID, revision,
			update.Targets, update.IdempotencyKey, digest, update.RequestID, current.PluginID); err != nil {
			return InstallationView{}, err
		}
	}
	view := installationView(current)
	view.ManagedBy = ManagedByPlatform
	if view.Targets, err = loadTargets(ctx, tx, update.AuthorizationID); err != nil {
		return InstallationView{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return InstallationView{}, fmt.Errorf("%w: commit plugin installation targets", ErrResultUnknown)
	}
	return view, nil
}

// loadTargets reads one target set with tenant names (nil when the head has none: platform plugins, tenant heads).
func loadTargets(ctx context.Context, query interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, authorizationID uuid.UUID) (*TargetsView, error) {
	targets, err := loadTargetsFor(ctx, query, []uuid.UUID{authorizationID})
	if err != nil {
		return nil, err
	}
	return targets[authorizationID], nil
}

func loadTargetsFor(ctx context.Context, query interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, authorizationIDs []uuid.UUID) (map[uuid.UUID]*TargetsView, error) {
	result := map[uuid.UUID]*TargetsView{}
	if len(authorizationIDs) == 0 {
		return result, nil
	}
	rows, err := query.Query(ctx, `SELECT target.authorization_id,target.all_tenants,target.revision,listed.tenant_scope_id,
		COALESCE(tenant.display_name,''),COALESCE(tenant.display_id::text,'')
		FROM plugin_installation_targets target
		LEFT JOIN plugin_installation_target_tenants listed ON listed.authorization_id=target.authorization_id
		LEFT JOIN access_scopes scope ON scope.id=listed.tenant_scope_id
		LEFT JOIN tenants tenant ON tenant.id=scope.tenant_id
		WHERE target.authorization_id=ANY($1)
		ORDER BY target.authorization_id,tenant.display_name,listed.tenant_scope_id`, authorizationIDs)
	if err != nil {
		return nil, postgresError(ctx, err)
	}
	defer rows.Close()
	for rows.Next() {
		var authorizationID uuid.UUID
		var allTenants bool
		var revision uint64
		var scopeID *uuid.UUID
		var name, displayID string
		if err := rows.Scan(&authorizationID, &allTenants, &revision, &scopeID, &name, &displayID); err != nil {
			return nil, postgresError(ctx, err)
		}
		view := result[authorizationID]
		if view == nil {
			view = &TargetsView{AllTenants: allTenants, Revision: revision, Tenants: []TargetTenant{}}
			result[authorizationID] = view
		}
		if scopeID != nil {
			view.Tenants = append(view.Tenants, TargetTenant{ScopeID: *scopeID, DisplayName: name, DisplayID: displayID})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, postgresError(ctx, err)
	}
	return result, nil
}
