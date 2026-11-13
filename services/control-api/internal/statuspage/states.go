package statuspage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// taskWindow is how far back DNS and certificate task outcomes are judged.
const taskWindow = 24 * time.Hour

// componentStatesSQL lists every component with its line group's endpoint
// counts. An endpoint of an own node can serve when the node is active, its
// health is not unhealthy and either the external probe says healthy or the
// node is online (the probe writes nothing while monitoring is off). A
// subscribed market node endpoint has no presence here: only its health counts.
// The counts never leave this package.
const componentStatesSQL = `
SELECT c.id, c.name, c.name_en, c.description, c.source, c.line_group_id, c.node_id, c.group_id, c.manual_status, c.hidden,
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

type evidence struct {
	status string
	note   Text
	// reason is a short English summary of why the status is not operational (for the per-minute detail).
	reason string
}

func unmonitored(zh, en string) evidence {
	return evidence{status: StatusUnconfigured, note: Text{ZH: zh, EN: en}}
}

// componentStates computes every component's status at now: the worst of
// its automatic status, manual status, open incidents (on the component or its
// group) and the maintenance windows in progress. A component with nothing to
// judge by is unconfigured, not operational and not an outage.
func (s *Service) componentStates(ctx context.Context, q queryer, now time.Time) ([]AdminComponent, error) {
	impacts, err := openImpacts(ctx, q, now)
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, componentStatesSQL)
	if err != nil {
		return nil, err
	}
	type row struct {
		item             AdminComponent
		groupFound       bool
		total, available int
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var item row
		return item, r.Scan(&item.item.ID, &item.item.Name, &item.item.NameEN, &item.item.Description, &item.item.Source,
			&item.item.LineGroupID, &item.item.NodeID, &item.item.GroupID, &item.item.ManualStatus, &item.item.Hidden,
			&item.groupFound, &item.item.LineGroupName, &item.total, &item.available)
	})
	if err != nil {
		return nil, err
	}
	need := map[string]bool{}
	nodeIDs := []uuid.UUID{}
	for _, item := range items {
		need[item.item.Source] = true
		if item.item.NodeID != nil {
			nodeIDs = append(nodeIDs, *item.item.NodeID)
		}
	}
	nodes, overall, dns, cert := map[uuid.UUID]evidence{}, evidence{}, evidence{}, evidence{}
	names := map[uuid.UUID]string{}
	if need[SourceNode] {
		if nodes, names, err = nodeEvidence(ctx, q, nodeIDs); err != nil {
			return nil, err
		}
	}
	if need[SourceNodeOverall] {
		if overall, err = nodeOverallEvidence(ctx, q); err != nil {
			return nil, err
		}
	}
	if need[SourceDNSSync] {
		if dns, err = taskEvidence(ctx, q, dnsSQL, now); err != nil {
			return nil, err
		}
	}
	if need[SourceCertIssue] {
		if cert, err = taskEvidence(ctx, q, certSQL, now); err != nil {
			return nil, err
		}
	}
	result := make([]AdminComponent, 0, len(items))
	for _, entry := range items {
		item := entry.item
		var auto evidence
		switch item.Source {
		case SourceLineGroup:
			switch {
			case !entry.groupFound:
				item.LineGroupMissing = true
				auto = unmonitored("线路组已删除", "The line group was deleted")
			case entry.total == 0:
				auto = unmonitored("线路组没有启用的节点", "The line group has no enabled node")
			default:
				auto = evidence{status: lineGroupStatus(entry.total, entry.available)}
				auto.reason = fmt.Sprintf("%d/%d line endpoints available", entry.available, entry.total)
			}
		case SourceNode:
			if item.NodeID != nil {
				item.NodeName = names[*item.NodeID]
				auto = nodes[*item.NodeID]
			}
			if auto.status == "" {
				auto = unmonitored("节点已删除", "The node was deleted")
			}
		case SourceNodeOverall:
			auto = overall
		case SourceDNSSync:
			auto = dns
		case SourceCertIssue:
			auto = cert
		case SourceGateway, SourceControlAPI, SourceWebConsole:
			status, note := s.probed(item.Source, now)
			auto = evidence{status: status, note: note, reason: s.probes.reasonFor(item.Source)}
		}
		item.AutoStatus, item.Note = auto.status, auto.note
		item.reason = auto.reason
		statuses := append([]string{item.ManualStatus}, impacts[item.ID]...)
		if item.GroupID != nil {
			statuses = append(statuses, impacts[*item.GroupID]...)
		}
		if auto.status != "" && auto.status != StatusUnconfigured {
			statuses = append(statuses, auto.status)
		}
		item.Status = worst(statuses...)
		if item.Status != auto.status && item.Status != StatusOperational {
			item.reason = "manual status or open incident"
		}
		if auto.status == StatusUnconfigured && len(statuses) == 1 && item.ManualStatus == StatusOperational {
			item.Status = StatusUnconfigured
		}
		result = append(result, item)
	}
	return result, nil
}

// nodeEvidence judges single nodes: active and online operational, active and
// offline an outage, draining maintenance; pending, disabled, retired or never
// seen online has nothing to judge.
func nodeEvidence(ctx context.Context, q queryer, ids []uuid.UUID) (map[uuid.UUID]evidence, map[uuid.UUID]string, error) {
	states, names := map[uuid.UUID]evidence{}, map[uuid.UUID]string{}
	if len(ids) == 0 {
		return states, names, nil
	}
	rows, err := q.Query(ctx, `SELECT n.id, n.name, n.admin_state, COALESCE(p.status, '')
		FROM nodes n LEFT JOIN node_presence p ON p.node_id = n.id WHERE n.id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var name, admin, presence string
		if err := rows.Scan(&id, &name, &admin, &presence); err != nil {
			return nil, nil, err
		}
		names[id] = name
		switch {
		case admin == "draining":
			states[id] = evidence{status: StatusMaintenance}
		case admin != "active":
			states[id] = unmonitored("节点未启用", "The node is not enabled")
		case presence == "online":
			states[id] = evidence{status: StatusOperational}
		case presence == "offline":
			states[id] = evidence{status: StatusOutage, reason: "node offline"}
		default:
			states[id] = unmonitored("节点尚未上线", "The node has not come online yet")
		}
	}
	return states, names, rows.Err()
}

// nodeOverallEvidence is the share of active nodes (with a presence record) that are online.
func nodeOverallEvidence(ctx context.Context, q queryer) (evidence, error) {
	var total, online int
	err := q.QueryRow(ctx, `SELECT count(*)::int, count(*) FILTER (WHERE p.status = 'online')::int
		FROM nodes n JOIN node_presence p ON p.node_id = n.id
		JOIN access_scopes s ON s.id = n.scope_id AND s.kind = 'platform' AND s.tenant_id IS NULL
		WHERE n.admin_state = 'active'`).Scan(&total, &online)
	if err != nil {
		return evidence{}, err
	}
	status := ratioStatus(total, online)
	if status == StatusUnconfigured {
		return unmonitored("没有已启用的节点", "No enabled node"), nil
	}
	return evidence{status: status, reason: fmt.Sprintf("%d/%d nodes online", online, total)}, nil
}

// dnsSQL counts DNS reconcile jobs finished since $1 and how many of them failed.
const dnsSQL = `SELECT count(*) FILTER (WHERE state IN ('succeeded', 'partial_failed', 'failed'))::int,
	count(*) FILTER (WHERE state IN ('partial_failed', 'failed'))::int, 0::int
	FROM background_jobs WHERE kind = 'dns_reconcile' AND completed_at > $1`

// certSQL counts certificate orders settled since $1 and how many failed. An
// auto-renewing certificate that expired in the last 7 days without a renewal
// counts as one more failed task.
const certSQL = `SELECT
	(SELECT count(*) FROM certificate_orders WHERE updated_at > $1 AND status IN ('issued', 'deploying', 'active', 'failed'))::int,
	(SELECT count(*) FROM certificate_orders WHERE updated_at > $1 AND status = 'failed')::int,
	(SELECT count(*) FROM certificate_orders WHERE auto_renew AND status IN ('active', 'renewal_due')
	   AND not_after < $2 AND not_after > $2 - interval '7 days')::int`

// taskEvidence judges the outcomes of the last 24 hours; no task means nothing to judge.
func taskEvidence(ctx context.Context, q queryer, sql string, now time.Time) (evidence, error) {
	var total, failed, overdue int
	args := []any{now.Add(-taskWindow)}
	if sql == certSQL {
		args = append(args, now)
	}
	if err := q.QueryRow(ctx, sql, args...).Scan(&total, &failed, &overdue); err != nil {
		return evidence{}, err
	}
	status := shareStatus(total+overdue, failed+overdue)
	if status == StatusUnconfigured {
		return unmonitored("近 24 小时没有任务", "No task in the last 24 hours"), nil
	}
	return evidence{status: status, reason: fmt.Sprintf("%d/%d tasks failed in 24h", failed+overdue, total+overdue)}, nil
}

// openImpacts maps component or group id to the impacts of open incidents and of
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
