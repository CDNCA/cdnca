package statuspage

import (
	"context"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Service) saveComponents(ctx context.Context, tx pgx.Tx, actor Actor, request SaveRequest) error {
	now := s.clock()
	existing := map[uuid.UUID]bool{}
	rows, err := tx.Query(ctx, `SELECT id FROM status_page_components FOR UPDATE`)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	for _, id := range ids {
		existing[id] = true
	}
	kept := make([]uuid.UUID, 0, len(request.Components))
	for index, item := range request.Components {
		if item.ID != nil {
			if !existing[*item.ID] {
				return ErrNotFound
			}
			kept = append(kept, *item.ID)
			continue
		}
		id, err := uuid.NewV7()
		if err != nil {
			return err
		}
		request.Components[index].ID = &id
	}
	for _, item := range request.Components {
		if item.Source == SourceNode {
			var found bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nodes n JOIN access_scopes s ON s.id = n.scope_id
				WHERE n.id = $1 AND s.kind = 'platform' AND s.tenant_id IS NULL)`, *item.NodeID).Scan(&found); err != nil {
				return err
			}
			if !found {
				return ErrNodeNotFound
			}
		}
		if item.Source != SourceLineGroup {
			continue
		}
		var found bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM node_line_groups WHERE tenant_scope_id = $1 AND id = $2
			AND deleted_at IS NULL AND purpose = 'general')`, actor.ScopeID, *item.LineGroupID).Scan(&found); err != nil {
			return err
		}
		if !found {
			return ErrLineGroupNotFound
		}
	}
	groupIDs := make([]uuid.UUID, len(request.Groups))
	for i, group := range request.Groups {
		groupIDs[i] = group.ID
	}
	var clash bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM status_page_components WHERE id = ANY($1::uuid[]))`, groupIDs).Scan(&clash); err != nil {
		return err
	}
	if clash {
		return ErrInvalidInput
	}
	if _, err := tx.Exec(ctx, `DELETE FROM status_page_components WHERE NOT (id = ANY($1::uuid[]))`, kept); err != nil {
		return err
	}
	if err := saveGroups(ctx, tx, request.Groups, now); err != nil {
		return err
	}
	// Free the names first: two components may swap names in one save.
	if _, err := tx.Exec(ctx, `UPDATE status_page_components SET name = id::text`); err != nil {
		return err
	}
	all := make([]uuid.UUID, 0, len(request.Components))
	for order, item := range request.Components {
		var scope *uuid.UUID
		if item.Source == SourceLineGroup {
			scope = &actor.ScopeID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO status_page_components
			(id, name, name_en, description, source, line_group_scope_id, line_group_id, node_id, group_id, manual_status, hidden,
			 sort_order, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13)
			ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, name_en = EXCLUDED.name_en, description = EXCLUDED.description,
			  source = EXCLUDED.source, line_group_scope_id = EXCLUDED.line_group_scope_id,
			  line_group_id = EXCLUDED.line_group_id, node_id = EXCLUDED.node_id, group_id = EXCLUDED.group_id,
			  manual_status = EXCLUDED.manual_status, hidden = EXCLUDED.hidden,
			  sort_order = EXCLUDED.sort_order, updated_at = EXCLUDED.updated_at`,
			*item.ID, item.Name, item.NameEN, item.Description, item.Source, scope, item.LineGroupID, item.NodeID, item.GroupID,
			item.ManualStatus, item.Hidden, order, now); err != nil {
			return err
		}
		if item.Source == SourceLineGroup {
			if _, err := tx.Exec(ctx, `INSERT INTO status_page_line_group_seen (line_group_id, seen_at) VALUES ($1, $2)
				ON CONFLICT DO NOTHING`, *item.LineGroupID, now); err != nil {
				return err
			}
		}
		all = append(all, *item.ID)
	}
	if _, err := tx.Exec(ctx, `UPDATE status_page_incidents
		SET component_ids = ARRAY(SELECT unnest(component_ids) INTERSECT SELECT unnest($1::uuid[]))
		WHERE NOT (component_ids <@ $1::uuid[])`, append(all, groupIDs...)); err != nil {
		return err
	}
	settings := request.Settings
	if _, err := tx.Exec(ctx, `UPDATE status_page_settings SET enabled = $1, title = $2, description = $3, show_logo = $4,
		revision = revision + 1, updated_at = $5, updated_by_user_id = $6 WHERE id = 1`,
		settings.Enabled, settings.Title, settings.Description, settings.ShowLogo, now, actor.UserID); err != nil {
		return err
	}
	if _, err := syncLineGroups(ctx, tx, now); err != nil {
		return err
	}
	// The administrator's own list is the list: recommended defaults are only offered to an empty page.
	if len(request.Components) > 0 || len(request.Groups) > 0 {
		if err := markSeeded(ctx, tx, now); err != nil {
			return err
		}
	}
	if _, err := seedDefaults(ctx, tx, now); err != nil {
		return err
	}
	return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: OperationSave,
		ResourceType: "status_page", ResourceID: "default", RequestID: actor.RequestID, Result: "success",
		Payload: map[string]any{"enabled": settings.Enabled, "components": len(request.Components), "groups": len(request.Groups),
			"revision": request.ExpectedRevision + 1}, OccurredAt: now})
}

// saveGroups replaces the groups with the request's, in order. Components of a removed group
// fall out of it (ON DELETE SET NULL) and show on their own.
func saveGroups(ctx context.Context, tx pgx.Tx, groups []GroupInput, now time.Time) error {
	ids := make([]uuid.UUID, len(groups))
	for i, group := range groups {
		ids[i] = group.ID
	}
	if _, err := tx.Exec(ctx, `DELETE FROM status_page_groups WHERE NOT (id = ANY($1::uuid[]))`, ids); err != nil {
		return err
	}
	// Free the names first: two groups may swap names in one save.
	if _, err := tx.Exec(ctx, `UPDATE status_page_groups SET name = id::text`); err != nil {
		return err
	}
	for order, group := range groups {
		if _, err := tx.Exec(ctx, `INSERT INTO status_page_groups (id, name, name_en, sort_order, hidden, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $6)
			ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, name_en = EXCLUDED.name_en, sort_order = EXCLUDED.sort_order,
			  hidden = EXCLUDED.hidden, updated_at = EXCLUDED.updated_at`,
			group.ID, group.Name, group.NameEN, order, group.Hidden, now); err != nil {
			return err
		}
	}
	return nil
}
