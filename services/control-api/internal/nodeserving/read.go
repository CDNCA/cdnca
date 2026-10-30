package nodeserving

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	MaxEventWindow = 31 * 24 * time.Hour
	MaxEventLimit  = 100
	MaxEventPage   = 1000
)

// ActiveHolds returns the current holds of the given nodes in the caller's
// snapshot, ordered by node and source.
func ActiveHolds(ctx context.Context, tx pgx.Tx, nodeIDs []uuid.UUID) (map[uuid.UUID][]Hold, error) {
	rows, err := tx.Query(ctx, `SELECT node_id,source,held,reason_code,revision,held_since,protected_groups,changed_at
		FROM node_serving_holds WHERE node_id=ANY($1::uuid[]) AND held ORDER BY node_id,source`, nodeIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[uuid.UUID][]Hold{}
	for rows.Next() {
		var hold Hold
		if err := rows.Scan(&hold.NodeID, &hold.Source, &hold.Held, &hold.ReasonCode, &hold.Revision,
			&hold.HeldSince, &hold.ProtectedGroups, &hold.ChangedAt); err != nil {
			return nil, err
		}
		hold.ChangedAt = hold.ChangedAt.UTC()
		if hold.HeldSince != nil {
			value := hold.HeldSince.UTC()
			hold.HeldSince = &value
		}
		result[hold.NodeID] = append(result[hold.NodeID], hold)
	}
	return result, rows.Err()
}

// Events pages one node's serving transitions, newest first. The node must
// belong to scopeID; otherwise ErrNotFound.
func (store *Store) Events(ctx context.Context, scopeID, nodeID uuid.UUID, from, to time.Time, page, limit int) (EventPage, error) {
	if store == nil || ctx == nil || scopeID == uuid.Nil || nodeID == uuid.Nil || !from.Before(to) ||
		to.Sub(from) > MaxEventWindow || page < 1 || page > MaxEventPage || limit < 1 || limit > MaxEventLimit {
		return EventPage{}, ErrInvalidInput
	}
	result := EventPage{SchemaVersion: 1, NodeID: nodeID, From: from.UTC(), To: to.UTC(), Page: page, Limit: limit,
		Items: make([]Event, 0, limit)}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return EventPage{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nodes WHERE id=$1 AND scope_id=$2)`, nodeID, scopeID).Scan(&exists); err != nil {
		return EventPage{}, err
	}
	if !exists {
		return EventPage{}, ErrNotFound
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM node_serving_events WHERE node_id=$1 AND occurred_at>=$2 AND occurred_at<=$3`,
		nodeID, result.From, result.To).Scan(&result.Total); err != nil {
		return EventPage{}, err
	}
	rows, err := tx.Query(ctx, `SELECT id,source,event,reason_code,hold_revision,detail,occurred_at FROM node_serving_events
		WHERE node_id=$1 AND occurred_at>=$2 AND occurred_at<=$3 ORDER BY occurred_at DESC,id DESC LIMIT $4 OFFSET $5`,
		nodeID, result.From, result.To, limit, (page-1)*limit)
	if err != nil {
		return EventPage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var event Event
		var detail []byte
		if err := rows.Scan(&event.ID, &event.Source, &event.Event, &event.ReasonCode, &event.HoldRevision, &detail,
			&event.OccurredAt); err != nil {
			return EventPage{}, err
		}
		if err := json.Unmarshal(detail, &event.Detail); err != nil {
			return EventPage{}, err
		}
		event.OccurredAt = event.OccurredAt.UTC()
		result.Items = append(result.Items, event)
	}
	if err := rows.Err(); err != nil {
		return EventPage{}, err
	}
	rows.Close()
	return result, tx.Commit(ctx)
}

// ScopeEventQuery filters the scope-wide switch log (A10/N06). Empty filters
// match everything; NodeID and IP narrow to one node.
type ScopeEventQuery struct {
	From, To time.Time
	Source   string
	Event    string
	NodeID   uuid.UUID
	IP       string
	Page     int
	Limit    int
}

type ScopeEvent struct {
	Event
	NodeID   uuid.UUID `json:"node_id"`
	NodeName string    `json:"node_name"`
	IPv4     string    `json:"ipv4"`
	IPv6     string    `json:"ipv6"`
}

type ScopeEventPage struct {
	SchemaVersion int          `json:"schema_version"`
	From          time.Time    `json:"from"`
	To            time.Time    `json:"to"`
	Page          int          `json:"page"`
	Limit         int          `json:"limit"`
	Total         int64        `json:"total"`
	Items         []ScopeEvent `json:"items"`
}

var scopeEventSources = map[string]bool{SourceAvailabilityMonitor: true, SourceAutoDisable: true, "config_sync": true, "external_probe": true}
var scopeEventKinds = map[string]bool{EventHeld: true, EventReleased: true, EventProtected: true, EventProtectionCleared: true}

// ScopeEvents pages the serving transitions of every node in scopeID, newest
// first. Events of purged nodes cascade away with the node (migration 284).
func (store *Store) ScopeEvents(ctx context.Context, scopeID uuid.UUID, query ScopeEventQuery) (ScopeEventPage, error) {
	if store == nil || ctx == nil || scopeID == uuid.Nil || !query.From.Before(query.To) ||
		query.To.Sub(query.From) > MaxEventWindow || query.Page < 1 || query.Page > MaxEventPage ||
		query.Limit < 1 || query.Limit > MaxEventLimit ||
		(query.Source != "" && !scopeEventSources[query.Source]) || (query.Event != "" && !scopeEventKinds[query.Event]) ||
		(query.IP != "" && net.ParseIP(query.IP) == nil) {
		return ScopeEventPage{}, ErrInvalidInput
	}
	result := ScopeEventPage{SchemaVersion: 1, From: query.From.UTC(), To: query.To.UTC(), Page: query.Page, Limit: query.Limit,
		Items: make([]ScopeEvent, 0, query.Limit)}
	var nodeID *uuid.UUID
	if query.NodeID != uuid.Nil {
		nodeID = &query.NodeID
	}
	var ip *string
	if query.IP != "" {
		value := net.ParseIP(query.IP).String()
		ip = &value
	}
	const filter = `FROM node_serving_events e JOIN nodes n ON n.id=e.node_id
		WHERE n.scope_id=$1 AND e.occurred_at>=$2 AND e.occurred_at<=$3
		AND ($4::text IS NULL OR e.source=$4) AND ($5::text IS NULL OR e.event=$5)
		AND ($6::uuid IS NULL OR e.node_id=$6)
		AND ($7::text IS NULL OR host(n.ipv4)=$7 OR host(n.ipv6)=$7)`
	args := []any{scopeID, result.From, result.To, nullableText(query.Source), nullableText(query.Event), nodeID, ip}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ScopeEventPage{}, err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := tx.QueryRow(ctx, `SELECT count(*) `+filter, args...).Scan(&result.Total); err != nil {
		return ScopeEventPage{}, err
	}
	rows, err := tx.Query(ctx, `SELECT e.id,e.source,e.event,e.reason_code,e.hold_revision,e.detail,e.occurred_at,
		e.node_id,n.name,COALESCE(host(n.ipv4),''),COALESCE(host(n.ipv6),'') `+filter+`
		ORDER BY e.occurred_at DESC,e.id DESC LIMIT $8 OFFSET $9`, append(args, query.Limit, (query.Page-1)*query.Limit)...)
	if err != nil {
		return ScopeEventPage{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var event ScopeEvent
		var detail []byte
		if err := rows.Scan(&event.ID, &event.Source, &event.Event.Event, &event.ReasonCode, &event.HoldRevision, &detail,
			&event.OccurredAt, &event.NodeID, &event.NodeName, &event.IPv4, &event.IPv6); err != nil {
			return ScopeEventPage{}, err
		}
		if err := json.Unmarshal(detail, &event.Detail); err != nil {
			return ScopeEventPage{}, err
		}
		event.OccurredAt = event.OccurredAt.UTC()
		result.Items = append(result.Items, event)
	}
	if err := rows.Err(); err != nil {
		return ScopeEventPage{}, err
	}
	rows.Close()
	return result, tx.Commit(ctx)
}

func nullableText(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}
