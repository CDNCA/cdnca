package edgepublish

import (
	"context"
	"errors"
	"slices"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Module revocation (ADR 0007 §4.3/§9): when the lease
// stops granting a module, pack or theme, the scopes whose latest publication
// uses it are marked pending republication (edge_module_publication_holds,
// migration 364) and the page says so; their nodes keep the published
// release, the control plane does not rewrite the sites. When the lease grants
// the module again, those scopes are republished by the system channel with
// trigger module_entitlement.

const (
	// ModulePendingRepublicationAction audits each scope a revoked module
	// left pending republication.
	ModulePendingRepublicationAction = "site.publication.module_pending"
	// ModuleRestoredAction audits each scope a restored module republishes.
	ModuleRestoredAction = "site.publication.module_restored"
)

// ModulePublicationHold is one module a scope's latest publication uses and
// the lease no longer grants.
type ModulePublicationHold struct {
	Module         string
	SourceRevision int64
}

// ModuleRequirementsUsedBy is the codes of requirements a snapshot uses, sorted.
func ModuleRequirementsUsedBy(requirements []ModuleRequirement, snapshot []byte) []string {
	var used []string
	for _, requirement := range requirements {
		if requirement.RequiredBy(snapshot) {
			used = append(used, requirement.Module.Code)
		}
	}
	slices.Sort(used)
	return slices.Compact(used)
}

// MarkModuleRevocationTx records, for each tenant scope whose latest
// publication uses one of revoked, that the scope is pending republication
// for that module, and audits it once per (scope, module). It returns the
// scopes newly marked, in scope order.
func MarkModuleRevocationTx(ctx context.Context, tx pgx.Tx, auditor AuditAppender,
	requirements []ModuleRequirement, revoked []string) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil || auditor == nil {
		return nil, ErrInvalidInput
	}
	revoked = slices.DeleteFunc(slices.Clone(revoked), func(code string) bool {
		return !slices.ContainsFunc(requirements, func(requirement ModuleRequirement) bool {
			return requirement.Module.Code == code
		})
	})
	if len(revoked) == 0 {
		return nil, nil
	}
	releases, err := latestTenantReleasesTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	var marked []uuid.UUID
	for _, release := range releases {
		var held []string
		for _, code := range ModuleRequirementsUsedBy(requirements, release.snapshot) {
			if !slices.Contains(revoked, code) {
				continue
			}
			command, err := tx.Exec(ctx, `INSERT INTO edge_module_publication_holds(scope_id,module_code,source_revision,held_at)
				VALUES($1,$2,$3,clock_timestamp()) ON CONFLICT (scope_id,module_code) DO NOTHING`,
				release.scopeID, code, release.sourceRevision)
			if err != nil {
				return nil, err
			}
			if command.RowsAffected() > 0 {
				held = append(held, code)
			}
		}
		if len(held) == 0 {
			continue
		}
		if err := auditor.Append(ctx, tx, audit.Event{
			ScopeID: release.scopeID, Action: ModulePendingRepublicationAction, ResourceType: "edge_configuration_scope",
			ResourceID: release.scopeID.String(), RequestID: "module-revoked." + release.scopeID.String(), Result: "success",
			Payload: map[string]any{
				"actor": "system", "ip": "", "scope_id": release.scopeID.String(),
				"object_type": "edge_configuration_scope", "object_id": release.scopeID.String(),
				"source_revision": release.sourceRevision, "reason": "entitlement_module_revoked",
				"changes": map[string]any{"pending_republication": map[string]any{"before": false, "after": true},
					"revoked_modules": held},
			},
		}); err != nil {
			return nil, err
		}
		marked = append(marked, release.scopeID)
	}
	return marked, nil
}

// ReleaseModuleHoldsTx deletes the holds of the modules the lease grants
// again and returns the scopes left with no hold, in scope order (the lock
// order of their republication); each is audited.
func ReleaseModuleHoldsTx(ctx context.Context, tx pgx.Tx, auditor AuditAppender, granted []string) ([]uuid.UUID, error) {
	if ctx == nil || tx == nil || auditor == nil {
		return nil, ErrInvalidInput
	}
	if len(granted) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `DELETE FROM edge_module_publication_holds WHERE module_code=ANY($1)
		RETURNING scope_id,module_code`, granted)
	if err != nil {
		return nil, err
	}
	type released struct {
		scopeID uuid.UUID
		module  string
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (released, error) {
		var item released
		return item, row.Scan(&item.scopeID, &item.module)
	})
	if err != nil {
		return nil, err
	}
	byScope := map[uuid.UUID][]string{}
	for _, item := range items {
		byScope[item.scopeID] = append(byScope[item.scopeID], item.module)
	}
	var scopes []uuid.UUID
	for scopeID, modules := range byScope {
		var remaining bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM edge_module_publication_holds WHERE scope_id=$1)`,
			scopeID).Scan(&remaining); err != nil {
			return nil, err
		}
		slices.Sort(modules)
		if err := auditor.Append(ctx, tx, audit.Event{
			ScopeID: scopeID, Action: ModuleRestoredAction, ResourceType: "edge_configuration_scope",
			ResourceID: scopeID.String(), RequestID: "module-restored." + scopeID.String(), Result: "success",
			Payload: map[string]any{
				"actor": "system", "ip": "", "scope_id": scopeID.String(),
				"object_type": "edge_configuration_scope", "object_id": scopeID.String(),
				"reason": "entitlement_module_granted",
				"changes": map[string]any{"pending_republication": map[string]any{"before": true, "after": remaining},
					"restored_modules": modules},
			},
		}); err != nil {
			return nil, err
		}
		if !remaining {
			scopes = append(scopes, scopeID)
		}
	}
	slices.SortFunc(scopes, compareUUID)
	return scopes, nil
}

// ModulePublicationHoldsTx lists a scope's pending-republication modules.
func ModulePublicationHoldsTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) ([]ModulePublicationHold, error) {
	if ctx == nil || tx == nil || scopeID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	rows, err := tx.Query(ctx, `SELECT module_code,source_revision FROM edge_module_publication_holds
		WHERE scope_id=$1 ORDER BY module_code`, scopeID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (ModulePublicationHold, error) {
		var hold ModulePublicationHold
		return hold, row.Scan(&hold.Module, &hold.SourceRevision)
	})
}

// clearModuleHoldsTx runs with a publication the module gate accepted: the
// scope's new release uses only granted modules.
func clearModuleHoldsTx(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) error {
	_, err := tx.Exec(ctx, `DELETE FROM edge_module_publication_holds WHERE scope_id=$1`, scopeID)
	return err
}

type tenantRelease struct {
	scopeID        uuid.UUID
	sourceRevision int64
	snapshot       []byte
}

// latestTenantReleasesTx is every tenant scope's latest publication snapshot,
// in scope order.
func latestTenantReleasesTx(ctx context.Context, tx pgx.Tx) ([]tenantRelease, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT ON (publication.configuration_scope_id)
			publication.configuration_scope_id,publication.source_revision,version.canonical_snapshot
		FROM edge_config_publications publication
		JOIN access_scopes scope ON scope.id=publication.configuration_scope_id AND scope.kind='tenant'
		JOIN config_versions version ON version.id=publication.config_version_id
		WHERE publication.contract_version=1
		ORDER BY publication.configuration_scope_id,publication.source_revision DESC`)
	if err != nil {
		return nil, errors.Join(ErrPersistence, err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (tenantRelease, error) {
		var item tenantRelease
		return item, row.Scan(&item.scopeID, &item.sourceRevision, &item.snapshot)
	})
}
