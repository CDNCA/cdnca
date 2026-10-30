package notificationcontrol

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const defaultDeliveryLogLimit = 50

var deliveryStates = map[string]struct{}{
	"pending": {}, "dispatching": {}, "retry_wait": {}, "accepted": {}, "unknown": {},
	"delivered": {}, "permanent_failed": {}, "exhausted": {}, "cancelled": {},
}

type normalizedDeliveryLogQuery struct {
	ScopeID *uuid.UUID
	Channel string
	State   string
	Limit   int
	Cursor  *uuid.UUID
}

func normalizeDeliveryLogQuery(raw DeliveryLogQuery) (normalizedDeliveryLogQuery, error) {
	if raw.Invalid {
		return normalizedDeliveryLogQuery{}, ErrInvalidInput
	}
	result := normalizedDeliveryLogQuery{Channel: raw.Channel, State: raw.State, Limit: defaultDeliveryLogLimit}
	if raw.ScopeID != "" {
		value, err := uuid.Parse(raw.ScopeID)
		if err != nil || value == uuid.Nil || value.String() != raw.ScopeID {
			return normalizedDeliveryLogQuery{}, ErrInvalidInput
		}
		result.ScopeID = &value
	}
	if raw.Channel != "" && raw.Channel != ChannelEmail && raw.Channel != ChannelSMS {
		return normalizedDeliveryLogQuery{}, ErrInvalidInput
	}
	if raw.State != "" {
		if _, ok := deliveryStates[raw.State]; !ok {
			return normalizedDeliveryLogQuery{}, ErrInvalidInput
		}
	}
	if raw.Limit != "" {
		value, err := strconv.Atoi(raw.Limit)
		if err != nil || value < 1 || value > 100 || strconv.Itoa(value) != raw.Limit {
			return normalizedDeliveryLogQuery{}, ErrInvalidInput
		}
		result.Limit = value
	}
	if raw.Cursor != "" {
		value, err := uuid.Parse(raw.Cursor)
		if err != nil || value == uuid.Nil || value.String() != raw.Cursor {
			return normalizedDeliveryLogQuery{}, ErrInvalidInput
		}
		result.Cursor = &value
	}
	return result, nil
}

func (s *Store) ListDeliveryLogs(ctx context.Context, actor Actor, raw DeliveryLogQuery) (DeliveryLogPage, error) {
	page := DeliveryLogPage{Items: []DeliveryLog{}}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRead(ctx, tx, actor, permissionRead, s.now()); err != nil {
			return err
		}
		query, err := normalizeDeliveryLogQuery(raw)
		if err != nil {
			return err
		}

		var cursorAt any
		var cursorID any
		if query.Cursor != nil {
			var createdAt time.Time
			var scopeID uuid.UUID
			var channel, state string
			err := tx.QueryRow(ctx, `SELECT outbox.created_at,outbox.scope_id,outbox.channel,
				COALESCE(settlement.state,'pending')
				FROM notification_outbox outbox
				LEFT JOIN notification_delivery_settlements_108 settlement ON settlement.outbox_id=outbox.id
				WHERE outbox.id=$1`, *query.Cursor).Scan(&createdAt, &scopeID, &channel, &state)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidInput
			}
			if err != nil {
				return err
			}
			if query.ScopeID != nil && *query.ScopeID != scopeID || query.Channel != "" && query.Channel != channel {
				return ErrInvalidInput
			}
			cursorAt, cursorID = createdAt, *query.Cursor
		}

		var scope any
		if query.ScopeID != nil {
			scope = *query.ScopeID
		}
		rows, err := tx.Query(ctx, `SELECT outbox.scope_id,outbox.id,event.event_type,outbox.channel,
			outbox.template_id,outbox.template_version,outbox.generation,
			COALESCE(settlement.state,'pending'),COALESCE(settlement.revision,0),outbox.attempt_count,
			settlement.provider,COALESCE(settlement.failure_code,outbox.last_failure_code),
			settlement.retry_at,settlement.accepted_at,settlement.completed_at,
			outbox.replay_of_outbox_id,outbox.created_at,COALESCE(settlement.updated_at,outbox.updated_at)
			FROM notification_outbox outbox
			JOIN notification_events event ON event.scope_id=outbox.scope_id AND event.id=outbox.event_id
			LEFT JOIN notification_delivery_settlements_108 settlement ON settlement.outbox_id=outbox.id
			WHERE ($1::uuid IS NULL OR outbox.scope_id=$1)
			  AND ($2::text='' OR outbox.channel=$2)
			  AND ($3::text='' OR COALESCE(settlement.state,'pending')=$3)
			  AND ($4::timestamptz IS NULL OR (outbox.created_at,outbox.id)<($4,$5::uuid))
			ORDER BY outbox.created_at DESC,outbox.id DESC LIMIT $6`,
			scope, query.Channel, query.State, cursorAt, cursorID, query.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item DeliveryLog
			if err := rows.Scan(&item.ScopeID, &item.OutboxID, &item.EventType, &item.Channel,
				&item.TemplateID, &item.TemplateVersion, &item.Generation, &item.State, &item.Revision,
				&item.AttemptCount, &item.Provider, &item.FailureCode, &item.RetryAt, &item.AcceptedAt,
				&item.CompletedAt, &item.ReplayOfOutboxID, &item.CreatedAt, &item.UpdatedAt); err != nil {
				return err
			}
			page.Items = append(page.Items, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Items) > query.Limit {
			page.Items = page.Items[:query.Limit]
			page.NextCursor = page.Items[len(page.Items)-1].OutboxID.String()
		}
		return nil
	})
	if err != nil {
		return DeliveryLogPage{}, fmt.Errorf("list notification delivery logs: %w", err)
	}
	return page, nil
}

func (s *Store) ListDeliveryAttempts(ctx context.Context, actor Actor, rawOutboxID string) (DeliveryAttemptPage, error) {
	result := DeliveryAttemptPage{Items: []DeliveryAttempt{}}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := authorizeRead(ctx, tx, actor, permissionRead, s.now()); err != nil {
			return err
		}
		outboxID, err := uuid.Parse(rawOutboxID)
		if err != nil || outboxID == uuid.Nil || outboxID.String() != rawOutboxID {
			return ErrInvalidInput
		}
		if err := tx.QueryRow(ctx, `SELECT id FROM notification_outbox WHERE id=$1`, outboxID).Scan(&result.OutboxID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		rows, err := tx.Query(ctx, `SELECT attempt_number,outcome,failure_code,next_attempt_at,
			lease_expires_at,claimed_at,completed_at FROM notification_attempts
			WHERE outbox_id=$1 ORDER BY attempt_number`, outboxID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item DeliveryAttempt
			if err := rows.Scan(&item.AttemptNumber, &item.Outcome, &item.FailureCode,
				&item.NextAttemptAt, &item.LeaseExpiresAt, &item.ClaimedAt, &item.CompletedAt); err != nil {
				return err
			}
			result.Items = append(result.Items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return DeliveryAttemptPage{}, fmt.Errorf("list notification delivery attempts: %w", err)
	}
	return result, nil
}
