package statuspage

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// componentStatesSQL lists every component with its line group's endpoint
// counts. An endpoint of an own node can serve when the node is active, its
// health is not unhealthy and either the external probe says healthy or the
// node is online (the probe writes nothing while monitoring is off). A
// subscribed market node endpoint has no presence here: only its health counts.
// The counts never leave this package.
const componentStatesSQL = `
SELECT c.id, c.name, c.description, c.source, c.line_group_id, c.manual_status,
       g.id IS NOT NULL, COALESCE(g.name, ''), COALESCE(counts.total, 0), COALESCE(counts.available, 0)
FROM status_page_components c
LEFT JOIN node_line_groups g
  ON c.source = 'line_group' AND g.tenant_scope_id = c.line_group_scope_id AND g.id = c.line_group_id
 AND g.deleted_at IS NULL AND g.purpose = 'general'
LEFT JOIN LATERAL (
  SELECT count(*)::int AS total,
         count(*) FILTER (WHERE CASE WHEN e.node_id IS NOT NULL THEN
             n.admin_state = 'active' AND COALESCE(h.status, 'unknown') <> 'unhealthy'
             AND (h.status = 'healthy' OR p.status = 'online')
           ELSE h.status = 'healthy' END)::int AS available
  FROM node_line_endpoints e
  LEFT JOIN node_line_endpoint_health h
    ON h.tenant_scope_id = e.tenant_scope_id AND h.line_group_id = e.line_group_id
   AND h.config_revision = e.config_revision AND h.endpoint_id = e.id
  LEFT JOIN nodes n ON n.id = e.node_id
  LEFT JOIN node_presence p ON p.node_id = e.node_id
  WHERE g.id IS NOT NULL AND e.tenant_scope_id = g.tenant_scope_id AND e.line_group_id = g.id
    AND e.config_revision = g.current_revision AND e.enabled
) counts ON true
ORDER BY c.sort_order, c.id`

// componentStates computes every component's status at now: the worst of
// its automatic status (line groups), manual status, open incidents and the
// maintenance windows in progress.
func componentStates(ctx context.Context, q queryer, now time.Time) ([]AdminComponent, error) {
	impacts, err := openImpacts(ctx, q, now)
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, componentStatesSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []AdminComponent{}
	for rows.Next() {
		var item AdminComponent
		var groupFound bool
		var total, available int
		if err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.Source, &item.LineGroupID,
			&item.ManualStatus, &groupFound, &item.LineGroupName, &total, &available); err != nil {
			return nil, err
		}
		statuses := append([]string{item.ManualStatus}, impacts[item.ID]...)
		if item.Source == SourceLineGroup {
			if groupFound {
				item.AutoStatus = lineGroupStatus(total, available)
				statuses = append(statuses, item.AutoStatus)
			} else {
				// A deleted line group shows as operational; the editor flags it.
				item.LineGroupMissing, item.AutoStatus = true, StatusOperational
			}
		}
		item.Status = worst(statuses...)
		result = append(result, item)
	}
	return result, rows.Err()
}

// openImpacts maps component id to the impacts of open incidents and of
// maintenance windows in progress.
func openImpacts(ctx context.Context, q queryer, now time.Time) (map[uuid.UUID][]string, error) {
	rows, err := q.Query(ctx, `SELECT impact, component_ids FROM status_page_incidents
		WHERE resolved_at IS NULL AND (kind = 'incident' OR scheduled_start <= $1 AND scheduled_end > $1)`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[uuid.UUID][]string{}
	for rows.Next() {
		var impact string
		var ids []uuid.UUID
		if err := rows.Scan(&impact, &ids); err != nil {
			return nil, err
		}
		for _, id := range ids {
			result[id] = append(result[id], impact)
		}
	}
	return result, rows.Err()
}

// authorize checks an active platform administrator holding permission, as
// the website content editor does.
func authorize(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if actor.UserID == uuid.Nil || actor.ScopeID == uuid.Nil {
		return ErrPermissionDenied
	}
	var allowed bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
		  SELECT 1 FROM access_scopes scope
		  JOIN users account ON account.id = $2 AND account.status = 'active'
		  JOIN memberships membership ON membership.scope_id = scope.id AND membership.user_id = account.id
		   AND membership.status = 'active'
		  JOIN role_assignments assignment ON assignment.scope_id = scope.id AND assignment.user_id = account.id
		  JOIN roles role ON role.id = assignment.role_id AND role.scope_id = assignment.scope_id
		  JOIN role_permissions grant_row ON grant_row.role_id = role.id AND grant_row.permission_name = $3
		  WHERE scope.id = $1 AND scope.kind = 'platform' AND scope.tenant_id IS NULL)`,
		actor.ScopeID, actor.UserID, permission).Scan(&allowed)
	if err != nil {
		return err
	}
	if !allowed {
		return ErrPermissionDenied
	}
	return nil
}
