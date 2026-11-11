package statuspage

import (
	"context"

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
	if _, err := tx.Exec(ctx, `DELETE FROM status_page_components WHERE NOT (id = ANY($1::uuid[]))`, kept); err != nil {
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
			(id, name, description, source, line_group_scope_id, line_group_id, manual_status, sort_order, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
			ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description,
			  source = EXCLUDED.source, line_group_scope_id = EXCLUDED.line_group_scope_id,
			  line_group_id = EXCLUDED.line_group_id, manual_status = EXCLUDED.manual_status,
			  sort_order = EXCLUDED.sort_order, updated_at = EXCLUDED.updated_at`,
			*item.ID, item.Name, item.Description, item.Source, scope, item.LineGroupID, item.ManualStatus, order, now); err != nil {
			return err
		}
		all = append(all, *item.ID)
	}
	if _, err := tx.Exec(ctx, `UPDATE status_page_incidents
		SET component_ids = ARRAY(SELECT unnest(component_ids) INTERSECT SELECT unnest($1::uuid[]))
		WHERE NOT (component_ids <@ $1::uuid[])`, all); err != nil {
		return err
	}
	settings := request.Settings
	if _, err := tx.Exec(ctx, `UPDATE status_page_settings SET enabled = $1, title = $2, description = $3, show_logo = $4,
		revision = revision + 1, updated_at = $5, updated_by_user_id = $6 WHERE id = 1`,
		settings.Enabled, settings.Title, settings.Description, settings.ShowLogo, now, actor.UserID); err != nil {
		return err
	}
	return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: OperationSave,
		ResourceType: "status_page", ResourceID: "default", RequestID: actor.RequestID, Result: "success",
		Payload: map[string]any{"enabled": settings.Enabled, "components": len(request.Components),
			"revision": request.ExpectedRevision + 1}, OccurredAt: now})
}
