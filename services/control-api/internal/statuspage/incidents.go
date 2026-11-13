package statuspage

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const maxMaintenanceWindow = 30 * 24 * time.Hour

// loadIncidents lists the incidents matching where (one $1 argument), newest
// first, with their updates newest first.
func loadIncidents(ctx context.Context, q queryer, where string, arg any) ([]Incident, error) {
	rows, err := q.Query(ctx, `SELECT id, kind, title, impact, status, component_ids, scheduled_start, scheduled_end,
		started_at, resolved_at FROM status_page_incidents WHERE `+where+` ORDER BY started_at DESC, id LIMIT 200`, arg)
	if err != nil {
		return nil, err
	}
	incidents, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Incident, error) {
		var item Incident
		err := row.Scan(&item.ID, &item.Kind, &item.Title, &item.Impact, &item.Status, &item.ComponentIDs,
			&item.ScheduledStart, &item.ScheduledEnd, &item.StartedAt, &item.ResolvedAt)
		item.Updates = []IncidentUpdate{}
		return item, err
	})
	if err != nil || len(incidents) == 0 {
		return incidents, err
	}
	index := make(map[uuid.UUID]int, len(incidents))
	ids := make([]uuid.UUID, len(incidents))
	for i, item := range incidents {
		index[item.ID], ids[i] = i, item.ID
	}
	rows, err = q.Query(ctx, `SELECT incident_id, id, status, message, created_at FROM status_page_incident_updates
		WHERE incident_id = ANY($1::uuid[]) ORDER BY created_at DESC, id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var incidentID uuid.UUID
		var update IncidentUpdate
		if err := rows.Scan(&incidentID, &update.ID, &update.Status, &update.Message, &update.CreatedAt); err != nil {
			return nil, err
		}
		incidents[index[incidentID]].Updates = append(incidents[index[incidentID]].Updates, update)
	}
	return incidents, rows.Err()
}

func validStatus(kind, status string) bool {
	if kind == KindMaintenance {
		return slices.Contains(maintenanceStatuses, status)
	}
	return kind == KindIncident && slices.Contains(incidentStatuses, status)
}

func terminal(status string) bool { return status == "resolved" || status == "completed" }

func (s *Service) CreateIncident(ctx context.Context, actor Actor, input IncidentInput) (Incident, error) {
	now := s.clock()
	if input.Status == "" {
		input.Status = map[string]string{KindIncident: "investigating", KindMaintenance: "scheduled"}[input.Kind]
	}
	if !validText(input.Title, 1, 120, false) || !validText(input.Message, 1, 2000, true) || !validStatus(input.Kind, input.Status) ||
		len(input.ComponentIDs) > MaxComponents {
		return Incident{}, ErrInvalidInput
	}
	startedAt := now
	switch input.Kind {
	case KindIncident:
		if input.Impact != StatusDegraded && input.Impact != StatusOutage || input.ScheduledStart != nil || input.ScheduledEnd != nil {
			return Incident{}, ErrInvalidInput
		}
	case KindMaintenance:
		input.Impact = StatusMaintenance
		if input.ScheduledStart == nil || input.ScheduledEnd == nil || !input.ScheduledEnd.After(*input.ScheduledStart) ||
			input.ScheduledEnd.Sub(*input.ScheduledStart) > maxMaintenanceWindow || !input.ScheduledEnd.After(now) {
			return Incident{}, ErrInvalidInput
		}
		startedAt = input.ScheduledStart.UTC()
	}
	slices.SortFunc(input.ComponentIDs, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	input.ComponentIDs = slices.Compact(input.ComponentIDs)
	id, err := uuid.NewV7()
	if err != nil {
		return Incident{}, err
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, PermissionManage); err != nil {
			return err
		}
		var known int
		if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM status_page_components WHERE id = ANY($1::uuid[]))
			+ (SELECT count(*) FROM status_page_groups WHERE id = ANY($1::uuid[]))`,
			input.ComponentIDs).Scan(&known); err != nil {
			return err
		}
		if known != len(input.ComponentIDs) {
			return ErrUnknownComponentRef
		}
		var resolvedAt *time.Time
		if terminal(input.Status) {
			resolvedAt = &now
		}
		if _, err := tx.Exec(ctx, `INSERT INTO status_page_incidents (id, kind, title, impact, status, component_ids,
			scheduled_start, scheduled_end, started_at, resolved_at, created_by_user_id, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)`, id, input.Kind, input.Title, input.Impact,
			input.Status, input.ComponentIDs, input.ScheduledStart, input.ScheduledEnd, startedAt, resolvedAt, actor.UserID, now); err != nil {
			return err
		}
		return s.appendUpdate(ctx, tx, actor, id, input.Status, input.Message, now, OperationIncidentCreate)
	})
	if err != nil {
		return Incident{}, err
	}
	return s.incident(ctx, id)
}

// AddUpdate posts a progress update and moves the incident to its status.
// A resolved incident or completed maintenance takes no further update.
func (s *Service) AddUpdate(ctx context.Context, actor Actor, id uuid.UUID, input UpdateInput) (Incident, error) {
	now := s.clock()
	if !validText(input.Message, 1, 2000, true) {
		return Incident{}, ErrInvalidInput
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, PermissionManage); err != nil {
			return err
		}
		var kind, status string
		err := tx.QueryRow(ctx, `SELECT kind, status FROM status_page_incidents WHERE id = $1 FOR UPDATE`, id).Scan(&kind, &status)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !validStatus(kind, input.Status) {
			return ErrInvalidInput
		}
		if terminal(status) {
			return ErrIncidentTransition
		}
		var resolvedAt *time.Time
		if terminal(input.Status) {
			resolvedAt = &now
		}
		// Maintenance started by hand before its window counts from now.
		if _, err := tx.Exec(ctx, `UPDATE status_page_incidents SET status = $2, resolved_at = $3, updated_at = $4,
			started_at = CASE WHEN kind = 'maintenance' AND $2 = 'in_progress' AND started_at > $4 THEN $4 ELSE started_at END,
			scheduled_start = CASE WHEN kind = 'maintenance' AND $2 = 'in_progress' AND scheduled_start > $4 THEN $4 ELSE scheduled_start END
			WHERE id = $1`, id, input.Status, resolvedAt, now); err != nil {
			return err
		}
		return s.appendUpdate(ctx, tx, actor, id, input.Status, input.Message, now, OperationIncidentUpdate)
	})
	if err != nil {
		return Incident{}, err
	}
	return s.incident(ctx, id)
}

func (s *Service) DeleteIncident(ctx context.Context, actor Actor, id uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorize(ctx, tx, actor, PermissionManage); err != nil {
			return err
		}
		var title string
		err := tx.QueryRow(ctx, `DELETE FROM status_page_incidents WHERE id = $1 RETURNING title`, id).Scan(&title)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID,
			Action: OperationIncidentDelete, ResourceType: "status_page_incident", ResourceID: id.String(),
			RequestID: actor.RequestID, Result: "success", Payload: map[string]any{"title": title}, OccurredAt: s.clock()})
	})
}

func (s *Service) appendUpdate(ctx context.Context, tx pgx.Tx, actor Actor, incidentID uuid.UUID, status, message string,
	now time.Time, operation string) error {
	updateID, err := uuid.NewV7()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO status_page_incident_updates (id, incident_id, status, message, created_by_user_id, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, updateID, incidentID, status, message, actor.UserID, now); err != nil {
		return err
	}
	return s.auditor.Append(ctx, tx, audit.Event{ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: operation,
		ResourceType: "status_page_incident", ResourceID: incidentID.String(), RequestID: actor.RequestID, Result: "success",
		Payload: map[string]any{"status": status}, OccurredAt: now})
}

func (s *Service) incident(ctx context.Context, id uuid.UUID) (Incident, error) {
	items, err := loadIncidents(ctx, s.pool, `id = $1`, id)
	if err != nil {
		return Incident{}, err
	}
	if len(items) != 1 {
		return Incident{}, ErrNotFound
	}
	return items[0], nil
}
