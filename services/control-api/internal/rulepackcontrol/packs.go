package rulepackcontrol

import (
	"context"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/libs/rulepack"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Import compiles an authored pack and keeps its canonical bytes as a
// downloaded local artifact. Platform operators import system / developer
// packs; a tenant creates user packs in its own namespace. Importing never
// enables anything.
func (s *Service) Import(ctx context.Context, actor Actor, content []byte) (Pack, error) {
	compiled, err := rulepack.Compile(content)
	if err != nil {
		return Pack{}, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	pack := compiled.Pack
	var owner *uuid.UUID
	source := "import"
	if pack.Layer == rulepack.LayerUser {
		scope, _ := rulepack.UserPackScope(pack.PackID)
		parsed := uuid.MustParse(scope)
		owner, source = &parsed, "tenant"
	}
	if !mayManagePack(actor, string(pack.Layer), owner) {
		return Pack{}, ErrPermissionDenied
	}
	if IsSubscriptionPack(pack.PackID) {
		// The waf-sub-* names belong to WAF rule subscriptions, which add
		// their versions themselves.
		return Pack{}, fmt.Errorf("%w: pack name prefix %s is reserved for WAF rule subscriptions", ErrInvalidInput,
			SubscriptionPackPrefix)
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		_, err := AddVersion(ctx, tx, s.now(), NewVersion{Compiled: compiled, Source: source, CreatedBy: actor.UserID, Actor: &actor})
		return err
	})
	if err != nil {
		return Pack{}, err
	}
	return s.getPack(ctx, s.pool, pack.PackID)
}

// PackUpdate changes the current version and / or the update policy.
type PackUpdate struct {
	CurrentVersion *string `json:"current_version"`
	UpdatePolicy   *string `json:"update_policy"`
}

func (s *Service) UpdatePack(ctx context.Context, actor Actor, packID string, update PackUpdate) (Pack, error) {
	record := auditRecord{scopeID: actor.ScopeID, resourceType: "rule_pack", resourceID: packID,
		payload: map[string]any{"pack_id": packID, "requested": map[string]any{
			"current_version": stringOrNil(update.CurrentVersion), "update_policy": stringOrNil(update.UpdatePolicy)}}}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		row, err := lockPack(ctx, tx, packID)
		if err != nil {
			return err
		}
		record.payload["layer"] = row.layer
		if !mayManagePack(actor, row.layer, row.ownerScopeID) {
			return ErrPermissionDenied
		}
		if update.UpdatePolicy != nil && *update.UpdatePolicy != "auto" && *update.UpdatePolicy != "manual" {
			return ErrInvalidInput
		}
		if update.CurrentVersion != nil {
			var downloaded bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM rule_pack_artifacts WHERE pack_id=$1 AND version=$2
				AND state='downloaded')`, packID, *update.CurrentVersion).Scan(&downloaded); err != nil {
				return err
			}
			if !downloaded {
				return fmt.Errorf("%w: version %s is not downloaded", ErrInvalidInput, *update.CurrentVersion)
			}
		}
		_, err = tx.Exec(ctx, `UPDATE rule_packs SET current_version=coalesce($2,current_version),
			update_policy=coalesce($3,update_policy), updated_by_user_id=$4, updated_at=$5 WHERE pack_id=$1`,
			packID, update.CurrentVersion, update.UpdatePolicy, actor.UserID, s.now())
		if err != nil {
			return err
		}
		record.changes = map[string]any{}
		if update.CurrentVersion != nil && (row.currentVersion == nil || *row.currentVersion != *update.CurrentVersion) {
			record.changes["current_version"] = change(stringOrNil(row.currentVersion), *update.CurrentVersion)
		}
		if update.UpdatePolicy != nil && row.updatePolicy != *update.UpdatePolicy {
			record.changes["update_policy"] = change(row.updatePolicy, *update.UpdatePolicy)
		}
		return s.appendAudit(ctx, tx, actor, AuditPackUpdate, record, nil)
	})
	if err != nil {
		return Pack{}, s.auditDenied(ctx, actor, AuditPackUpdate, record, err)
	}
	return s.getPack(ctx, s.pool, packID)
}

// DeleteVersion deletes one local artifact. Deleting is a separate,
// explicit operation and is refused while the version is current and the
// pack is enabled at any level, or while a published site mounts it.
// Deleting the last version removes the pack (and its now meaningless
// disabled / inherit rows).
func (s *Service) DeleteVersion(ctx context.Context, actor Actor, packID, version string) error {
	record := auditRecord{scopeID: actor.ScopeID, resourceType: "rule_pack", resourceID: packID + "@" + version,
		payload: map[string]any{"pack_id": packID, "version": version}}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		row, err := lockPack(ctx, tx, packID)
		if err != nil {
			return err
		}
		record.payload["layer"] = row.layer
		if !mayManagePack(actor, row.layer, row.ownerScopeID) {
			return ErrPermissionDenied
		}
		var exists, mounted, enabled bool
		if err := tx.QueryRow(ctx, `SELECT
			EXISTS(SELECT 1 FROM rule_pack_artifacts WHERE pack_id=$1 AND version=$2),
			EXISTS(SELECT 1 FROM rule_pack_site_mount_artifacts WHERE pack_id=$1 AND version=$2),
			EXISTS(SELECT 1 FROM rule_pack_enablements WHERE pack_id=$1 AND rule_id IS NULL AND state='enabled')`,
			packID, version).Scan(&exists, &mounted, &enabled); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		current := row.currentVersion != nil && *row.currentVersion == version
		record.payload["current"], record.payload["mounted"], record.payload["enabled"] = current, mounted, enabled
		if mounted || current && enabled {
			return ErrInUse
		}
		record.changes = map[string]any{"versions": map[string]any{"removed": version}}
		if current {
			var next *string
			if err := tx.QueryRow(ctx, `UPDATE rule_packs SET current_version=(
				SELECT version FROM rule_pack_artifacts WHERE pack_id=$1 AND version<>$2 AND state='downloaded'
				ORDER BY created_at DESC, version DESC LIMIT 1), updated_by_user_id=$3, updated_at=$4 WHERE pack_id=$1
				RETURNING current_version`, packID, version, actor.UserID, s.now()).Scan(&next); err != nil {
				return err
			}
			record.changes["current_version"] = change(version, stringOrNil(next))
		}
		if _, err := tx.Exec(ctx, `DELETE FROM rule_pack_artifacts WHERE pack_id=$1 AND version=$2`, packID, version); err != nil {
			return err
		}
		command, err := tx.Exec(ctx, `DELETE FROM rule_packs pack WHERE pack_id=$1 AND NOT EXISTS(
			SELECT 1 FROM rule_pack_artifacts artifact WHERE artifact.pack_id=pack.pack_id)`, packID)
		if err != nil {
			return err
		}
		record.payload["pack_removed"] = command.RowsAffected() == 1
		return s.appendAudit(ctx, tx, actor, AuditVersionDelete, record, nil)
	})
	if err != nil {
		return s.auditDenied(ctx, actor, AuditVersionDelete, record, err)
	}
	return nil
}

func lockPack(ctx context.Context, tx pgx.Tx, packID string) (packRow, error) {
	var row packRow
	err := tx.QueryRow(ctx, `SELECT pack_id, layer, owner_scope_id, current_version, update_policy, updated_at
		FROM rule_packs WHERE pack_id=$1 FOR UPDATE`, packID).Scan(&row.packID, &row.layer, &row.ownerScopeID,
		&row.currentVersion, &row.updatePolicy, &row.updatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return packRow{}, ErrNotFound
	}
	return row, err
}

func (s *Service) getPack(ctx context.Context, q querier, packID string) (Pack, error) {
	rows, err := loadPacks(ctx, q, packID)
	if err != nil {
		return Pack{}, err
	}
	if len(rows) != 1 {
		return Pack{}, ErrNotFound
	}
	versions, err := loadVersions(ctx, q, packID)
	if err != nil {
		return Pack{}, err
	}
	return packView(rows[0], versions[packID], nil), nil
}

func loadVersions(ctx context.Context, q querier, packID string) (map[string][]Version, error) {
	rows, err := q.Query(ctx, `SELECT pack_id, version, engine, engine_min_version, sha256, size_bytes, source, state,
		downloaded_at, created_at FROM rule_pack_artifacts WHERE $1::text='' OR pack_id=$1
		ORDER BY pack_id, created_at DESC, version DESC`, packID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]Version{}
	for rows.Next() {
		var id string
		var version Version
		if err := rows.Scan(&id, &version.Version, &version.Engine, &version.EngineMinVersion, &version.SHA256,
			&version.SizeBytes, &version.Source, &version.State, &version.DownloadedAt, &version.CreatedAt); err != nil {
			return nil, err
		}
		out[id] = append(out[id], version)
	}
	return out, rows.Err()
}

func packView(row packRow, versions []Version, effect *rulepack.Effect) Pack {
	pack := Pack{PackID: row.packID, Layer: row.layer, OwnerScopeID: row.ownerScopeID, UpdatePolicy: row.updatePolicy,
		Versions: versions, UpdatedAt: row.updatedAt, Exports: []ExportedRule{}, Requires: []string{}}
	if pack.Versions == nil {
		pack.Versions = []Version{}
	}
	if row.currentVersion != nil {
		pack.CurrentVersion = *row.currentVersion
	}
	if compiled := row.compiled; compiled != nil {
		pack.Name, pack.Description, pack.Engine = compiled.Pack.Name, compiled.Pack.Description, string(compiled.Pack.Engine)
		pack.ParamsSchema, pack.Defaults, pack.Requires, pack.Cost = compiled.Pack.ParamsSchema, compiled.Pack.Defaults,
			compiled.Requires, compiled.Cost
		for _, id := range compiled.Pack.Exports {
			name := compiled.ExportName(id)
			if name == "" {
				name = "CRS " + id
			}
			pack.Exports = append(pack.Exports, ExportedRule{RuleID: id, Name: name})
		}
	}
	if effect != nil {
		pack.Effect = &Effect{Enabled: effect.Enabled, EnabledAt: effect.EnabledAt, Adjustable: effect.Adjustable,
			Priority: effect.Priority, Params: effect.Params, RuleStates: effect.RuleStates, RuleSource: effect.RuleSource,
			Ignored: len(effect.Ignored), Inherited: effect.Inherited}
	}
	return pack
}

// View is the page of one level: the visible packs with the state they
// inherit there, and the rows set at that level.
func (s *Service) View(ctx context.Context, actor Actor, level LevelInput) (LevelView, error) {
	subject, ref, err := subjectFor(ctx, s.pool, actor, level)
	if err != nil {
		return LevelView{}, err
	}
	rows, err := loadPacks(ctx, s.pool, "")
	if err != nil {
		return LevelView{}, err
	}
	versions, err := loadVersions(ctx, s.pool, "")
	if err != nil {
		return LevelView{}, err
	}
	overrides, err := loadOverrides(ctx, s.pool, subject, "")
	if err != nil {
		return LevelView{}, err
	}
	effects := map[string]rulepack.Effect{}
	for _, effect := range rulepack.Effective(compiledPacks(rows), toLibOverrides(overrides), subject) {
		effects[effect.Pack.Pack.PackID] = effect
	}
	view := LevelView{Level: ref, Packs: []Pack{}, Overrides: []Override{}}
	for _, row := range rows {
		if row.layer == string(rulepack.LayerUser) &&
			(row.ownerScopeID == nil || row.ownerScopeID.String() != subject.TenantScopeID) {
			continue
		}
		var effect *rulepack.Effect
		if value, ok := effects[row.packID]; ok {
			effect = &value
		}
		view.Packs = append(view.Packs, packView(row, versions[row.packID], effect))
	}
	for _, row := range overrides {
		objectID := ""
		if row.LevelObjectID != nil {
			objectID = row.LevelObjectID.String()
		}
		if row.Level == ref.Level && objectID == ref.ObjectID {
			view.Overrides = append(view.Overrides, row)
		}
	}
	return view, nil
}
