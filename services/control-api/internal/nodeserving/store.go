package nodeserving

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/nodemonitoringconfig"
	"github.com/cdnca/cdnca/services/control-api/internal/systemconfig"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	alerts  AlertEnqueuer
}

func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, ErrInvalidInput
	}
	return &Store{pool: pool, auditor: audit.New(pool)}, nil
}

// MonitorCandidate is one node and its availability decision input.
type MonitorCandidate struct {
	NodeID   uuid.UUID
	ScopeID  uuid.UUID
	Revision int64
	Input    MonitorInput
	// Alert is the offline alert state (node_availability_alert_states),
	// tracked independently of the serving hold and its failure action.
	Alert AlertState
}

// AlertState is a node's current availability alert.
type AlertState struct {
	Offline       bool
	Reason        string
	Revision      int64
	RecentHealthy int
}

// MonitorCandidates reads, in one repeatable snapshot, every node that is not
// retired (plus any retired node still held) with its newest probe report,
// effective monitoring policy and current availability hold.
func (store *Store) MonitorCandidates(ctx context.Context) ([]MonitorCandidate, time.Time, error) {
	if store == nil || ctx == nil {
		return nil, time.Time{}, ErrInvalidInput
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, time.Time{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return nil, time.Time{}, err
	}
	rows, err := tx.Query(ctx, `SELECT node.id,node.scope_id,node.admin_state='active',
			sample.healthy,sample.probe_succeeded,sample.ingested_at,
			COALESCE(hold.held,false),COALESCE(hold.reason_code,''),COALESCE(hold.revision,0),hold.held_since,
			COALESCE(alert.offline,false),COALESCE(alert.reason_code,''),COALESCE(alert.revision,0),alert.offline_since,
			override.revision,override.monitor_enabled,override.protocol,override.probe_timeout_ms,
			override.monitor_port,override.monitor_action,dnspup.failing
		FROM nodes node
		LEFT JOIN LATERAL (SELECT healthy,probe_succeeded,ingested_at FROM node_metric_samples
			WHERE node_id=node.id AND record_kind='metric' ORDER BY publication_sequence DESC LIMIT 1) sample ON true
		LEFT JOIN node_serving_holds hold ON hold.node_id=node.id AND hold.source=$1
		LEFT JOIN node_availability_alert_states alert ON alert.node_id=node.id
		LEFT JOIN node_monitoring_overrides override ON override.node_id=node.id AND override.scope_id=node.scope_id
		LEFT JOIN node_dnspup_probe_states dnspup ON dnspup.node_id=node.id AND dnspup.fresh_until>clock_timestamp()
		WHERE node.admin_state<>'retired' OR hold.held OR alert.offline
		ORDER BY node.scope_id,node.id`, SourceAvailabilityMonitor)
	if err != nil {
		return nil, time.Time{}, err
	}
	type row struct {
		candidate    MonitorCandidate
		override     nodemonitoringconfig.Override
		heldSince    *time.Time
		offlineSince *time.Time
	}
	var scanned []row
	for rows.Next() {
		var item row
		var healthy, succeeded *bool
		var ingested *time.Time
		var overrideRevision *int64
		var protocol, action *string
		var timeout, port *int32
		var dnspupFailing *bool
		if err := rows.Scan(&item.candidate.NodeID, &item.candidate.ScopeID, &item.candidate.Input.NodeActive,
			&healthy, &succeeded, &ingested, &item.candidate.Input.Held, &item.candidate.Input.Reason,
			&item.candidate.Revision, &item.heldSince,
			&item.candidate.Alert.Offline, &item.candidate.Alert.Reason, &item.candidate.Alert.Revision, &item.offlineSince,
			&overrideRevision, &item.override.MonitorEnabled,
			&protocol, &timeout, &port, &action, &dnspupFailing); err != nil {
			rows.Close()
			return nil, time.Time{}, err
		}
		if dnspupFailing != nil {
			item.candidate.Input.DNSPup = &DNSPupVerdict{Failing: *dnspupFailing}
		}
		if healthy != nil && succeeded != nil && ingested != nil {
			item.candidate.Input.Sample = &MonitorSample{Healthy: *healthy, ProbeSucceeded: *succeeded, IngestedAt: ingested.UTC()}
		}
		if overrideRevision != nil {
			item.override.Revision = *overrideRevision
			if protocol != nil {
				item.override.Protocol = *protocol
			}
			if action != nil {
				item.override.MonitorAction = *action
			}
			if timeout != nil {
				value := int(*timeout)
				item.override.ProbeTimeoutMS = &value
			}
			if port != nil && *port > 0 && *port <= 65535 {
				value := uint16(*port)
				item.override.MonitorPort = &value
			}
		}
		scanned = append(scanned, item)
	}
	if err := rows.Err(); err != nil {
		return nil, time.Time{}, err
	}
	rows.Close()
	type scopePolicy struct {
		active bool
		value  systemconfig.NodeMonitoringConfiguration
	}
	policies := map[uuid.UUID]scopePolicy{}
	for _, item := range scanned {
		if _, ok := policies[item.candidate.ScopeID]; ok {
			continue
		}
		configuration, value, err := systemconfig.ReadActiveNodeMonitoring(ctx, tx, item.candidate.ScopeID)
		switch {
		case errors.Is(err, systemconfig.ErrPermissionDenied):
			policies[item.candidate.ScopeID] = scopePolicy{}
		case err != nil:
			return nil, time.Time{}, fmt.Errorf("read monitoring policy: %w", err)
		default:
			policies[item.candidate.ScopeID] = scopePolicy{active: configuration.State == "active", value: value}
		}
	}
	result := make([]MonitorCandidate, 0, len(scanned))
	freshScopes := map[uuid.UUID]bool{}
	for _, item := range scanned {
		policy := policies[item.candidate.ScopeID]
		item.candidate.Input.Now = now
		item.candidate.Input.PolicyActive = policy.active
		if policy.active {
			override := item.override
			if !nodemonitoringconfig.ValidOverride(override) {
				override = nodemonitoringconfig.Override{}
			}
			item.candidate.Input.Effective = nodemonitoringconfig.ApplyOverride(policy.value, override)
			sample := item.candidate.Input.Sample
			if sample != nil && !sample.IngestedAt.Before(now.Add(-StaleAfter(item.candidate.Input.Effective))) {
				freshScopes[item.candidate.ScopeID] = true
			}
		}
		need := max(item.candidate.Input.Effective.RecoveryThreshold, 1)
		if item.candidate.Input.Held && item.heldSince != nil {
			if err := countRecentHealthy(ctx, tx, item.candidate.NodeID, need, *item.heldSince, &item.candidate.Input.RecentHealthy); err != nil {
				return nil, time.Time{}, err
			}
		}
		if item.candidate.Alert.Offline && item.offlineSince != nil {
			if err := countRecentHealthy(ctx, tx, item.candidate.NodeID, need, *item.offlineSince, &item.candidate.Alert.RecentHealthy); err != nil {
				return nil, time.Time{}, err
			}
		}
		result = append(result, item.candidate)
	}
	for index := range result {
		result[index].Input.IngestionStale = !freshScopes[result[index].ScopeID]
	}
	return result, now, tx.Commit(ctx)
}

func countRecentHealthy(ctx context.Context, tx pgx.Tx, nodeID uuid.UUID, need int, since time.Time, target *int) error {
	return tx.QueryRow(ctx, `SELECT count(*) FROM (
		SELECT healthy AND probe_succeeded AS good,ingested_at FROM node_metric_samples
		WHERE node_id=$1 AND record_kind='metric' ORDER BY publication_sequence DESC LIMIT $2) recent
		WHERE good AND ingested_at>$3`, nodeID, need, since).Scan(target)
}

// Apply records one transition idempotently: a decision equal to the stored
// state changes nothing, and a concurrent writer that already advanced the
// revision makes this call a no-op. A held node whose hold reason changes keeps
// its held_since and records a new "held" event with the new reason.
func (store *Store) Apply(ctx context.Context, nodeID, scopeID uuid.UUID, source string, expectedRevision int64, decision Decision) (bool, error) {
	if store == nil || ctx == nil || nodeID == uuid.Nil || scopeID == uuid.Nil ||
		(source != SourceAvailabilityMonitor && source != SourceAutoDisable && source != SourceConfigSync &&
			source != SourceExternalProbe) || decision.Reason == "" {
		return false, ErrInvalidInput
	}
	detail := decision.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		return false, ErrInvalidInput
	}
	changed := false
	err = pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,280))`, nodeID.String()+"/"+source); err != nil {
			return err
		}
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		var held bool
		var reason string
		var revision int64
		var since *time.Time
		err := tx.QueryRow(ctx, `SELECT held,reason_code,revision,held_since FROM node_serving_holds
			WHERE node_id=$1 AND source=$2 FOR UPDATE`, nodeID, source).Scan(&held, &reason, &revision, &since)
		found := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if revision != expectedRevision || held == decision.Held && (!held || reason == decision.Reason) {
			return nil
		}
		var heldSince any
		if decision.Held {
			heldSince = now
			if held && since != nil {
				heldSince = *since
			}
		}
		next := revision + 1
		if found {
			// A reason change while held keeps the protection count; a release clears it.
			_, err = tx.Exec(ctx, `UPDATE node_serving_holds SET held=$3,reason_code=$4,revision=$5,held_since=$6,
				protected_groups=CASE WHEN $3 THEN protected_groups ELSE 0 END,detail=$7,changed_at=$8,updated_at=$8
				WHERE node_id=$1 AND source=$2`,
				nodeID, source, decision.Held, decision.Reason, next, heldSince, encoded, now)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO node_serving_holds(node_id,source,held,reason_code,revision,held_since,
				detail,changed_at,updated_at) VALUES($1,$2,$3,$4,1,$5,$6,$7,$7)`,
				nodeID, source, decision.Held, decision.Reason, heldSince, encoded, now)
		}
		if err != nil {
			return err
		}
		event := EventReleased
		if decision.Held {
			event = EventHeld
		}
		if err := store.appendEvent(ctx, tx, nodeID, scopeID, source, event, decision.Reason, next, detail, now); err != nil {
			return err
		}
		store.enqueueBandwidthAlert(ctx, tx, nodeID, scopeID, bandwidthAlertEvent(source, held, reason, decision), next, detail, now)
		changed = true
		return nil
	})
	return changed, err
}

func (store *Store) appendEvent(ctx context.Context, tx pgx.Tx, nodeID, scopeID uuid.UUID, source, event, reason string,
	revision int64, detail map[string]any, now time.Time) error {
	encoded, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO node_serving_events(id,node_id,source,event,reason_code,hold_revision,detail,occurred_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, uuid.New(), nodeID, source, event, reason, revision, encoded, now); err != nil {
		return err
	}
	payload := map[string]any{"source": source, "event": event, "reason_code": reason, "hold_revision": revision}
	for key, value := range detail {
		payload[key] = value
	}
	return store.auditor.Append(ctx, tx, audit.Event{
		ScopeID: scopeID, Action: "node.serving." + event, ResourceType: "node", ResourceID: nodeID.String(),
		RequestID: "node-serving/" + source + "/" + strconv.FormatInt(revision, 10), Result: "success", Payload: payload,
	})
}

type groupRevision struct {
	scopeID, groupID uuid.UUID
	revision         int64
}

// SyncProtection records, for every held node, how many current line groups
// keep serving it because it is the last admin-enabled endpoint of its address
// family there (the view's fail-open). A change of "protected or not" is an
// audited transition; a changed count alone only refreshes the row.
func (store *Store) SyncProtection(ctx context.Context) error {
	if store == nil || ctx == nil {
		return ErrInvalidInput
	}
	return pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('node-serving-protection',280))`); err != nil {
			return err
		}
		var now time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT line_group.tenant_scope_id,line_group.id,line_group.current_revision
			FROM node_serving_holds hold
			JOIN node_line_endpoints endpoint ON endpoint.node_id=hold.node_id
			JOIN node_line_groups line_group ON line_group.tenant_scope_id=endpoint.tenant_scope_id
			 AND line_group.id=endpoint.line_group_id AND line_group.current_revision=endpoint.config_revision
			 AND line_group.deleted_at IS NULL
			WHERE hold.held`)
		if err != nil {
			return err
		}
		groups, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (groupRevision, error) {
			var value groupRevision
			return value, row.Scan(&value.scopeID, &value.groupID, &value.revision)
		})
		if err != nil {
			return err
		}
		protected := map[uuid.UUID]map[uuid.UUID]struct{}{}
		for _, group := range groups {
			rows, err := tx.Query(ctx, `SELECT DISTINCT node_id FROM node_line_endpoint_serving
				WHERE tenant_scope_id=$1 AND line_group_id=$2 AND config_revision=$3 AND protected AND node_id IS NOT NULL`,
				group.scopeID, group.groupID, group.revision)
			if err != nil {
				return err
			}
			nodes, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
			if err != nil {
				return err
			}
			for _, nodeID := range nodes {
				if protected[nodeID] == nil {
					protected[nodeID] = map[uuid.UUID]struct{}{}
				}
				protected[nodeID][group.groupID] = struct{}{}
			}
		}
		rows, err = tx.Query(ctx, `SELECT hold.node_id,node.scope_id,hold.source,hold.revision,hold.protected_groups
			FROM node_serving_holds hold JOIN nodes node ON node.id=hold.node_id
			WHERE hold.held ORDER BY hold.node_id,hold.source FOR UPDATE OF hold`)
		if err != nil {
			return err
		}
		type held struct {
			nodeID, scopeID uuid.UUID
			source          string
			revision        int64
			protectedGroups int
		}
		holds, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (held, error) {
			var value held
			return value, row.Scan(&value.nodeID, &value.scopeID, &value.source, &value.revision, &value.protectedGroups)
		})
		if err != nil {
			return err
		}
		for _, hold := range holds {
			count := len(protected[hold.nodeID])
			if count == hold.protectedGroups {
				continue
			}
			if (count > 0) == (hold.protectedGroups > 0) {
				if _, err := tx.Exec(ctx, `UPDATE node_serving_holds SET protected_groups=$3,updated_at=$4
					WHERE node_id=$1 AND source=$2`, hold.nodeID, hold.source, count, now); err != nil {
					return err
				}
				continue
			}
			next := hold.revision + 1
			event := EventProtectionCleared
			if count > 0 {
				event = EventProtected
			}
			groupIDs := make([]string, 0, min(count, 20))
			for groupID := range protected[hold.nodeID] {
				if len(groupIDs) < 20 {
					groupIDs = append(groupIDs, groupID.String())
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE node_serving_holds SET protected_groups=$3,revision=$4,changed_at=$5,updated_at=$5
				WHERE node_id=$1 AND source=$2`, hold.nodeID, hold.source, count, next, now); err != nil {
				return err
			}
			detail := map[string]any{"protected_groups": count, "line_group_ids": groupIDs}
			if err := store.appendEvent(ctx, tx, hold.nodeID, hold.scopeID, hold.source, event, ReasonLastEndpoint,
				next, detail, now); err != nil {
				return err
			}
		}
		return nil
	})
}
