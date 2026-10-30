package notificationcontrol

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type DeliveryHistoryQuery struct {
	ScopeID, Channel, State, EventType, UserID, MessageID string
	Result                                                string
	From, To, Limit, Cursor                               string
	Invalid                                               bool
}

type DeliveryHistoryFact struct {
	ID                     string     `json:"id"`
	ScopeID                uuid.UUID  `json:"scope_id"`
	OutboxID               uuid.UUID  `json:"outbox_id"`
	Sequence               int        `json:"sequence"`
	AttemptNumber          int        `json:"attempt_number"`
	FactKind               string     `json:"fact_kind"`
	State                  string     `json:"state"`
	FailureCode            *string    `json:"failure_code"`
	FailureCount           int64      `json:"failure_count"`
	ObservedAt             time.Time  `json:"observed_at"`
	MessageID              uuid.UUID  `json:"message_id"`
	EventType              string     `json:"event_type"`
	RecipientUserID        *uuid.UUID `json:"recipient_user_id"`
	RecipientUserDisplayID *string    `json:"recipient_user_display_id"`
	RecipientKind          string     `json:"recipient_kind"`
	Channel                string     `json:"channel"`
	Generation             int        `json:"generation"`
	ReplayOfOutboxID       *uuid.UUID `json:"replay_of_outbox_id"`
	RecipientAddress       *string    `json:"recipient_address"`
	RecipientAddressState  string     `json:"recipient_address_state"`
	ProviderCallStartedAt  *time.Time `json:"provider_call_started_at"`
}

type DeliveryHistoryPage struct {
	Schema     string                `json:"schema"`
	Items      []DeliveryHistoryFact `json:"items"`
	TotalCount int64                 `json:"total_count"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type normalizedDeliveryHistoryQuery struct {
	ScopeID, UserID, MessageID        *uuid.UUID
	UserDisplayID                     *int64
	Channel, State, EventType, Result string
	From, To                          *time.Time
	Limit                             int
	CursorOutboxID                    *uuid.UUID
	CursorSequence                    int
}

func normalizeDeliveryHistoryQuery(raw DeliveryHistoryQuery) (normalizedDeliveryHistoryQuery, error) {
	query := normalizedDeliveryHistoryQuery{Channel: raw.Channel, State: raw.State, EventType: raw.EventType, Result: raw.Result, Limit: defaultDeliveryLogLimit}
	if raw.Invalid {
		return query, ErrInvalidInput
	}
	for _, input := range []struct {
		value  string
		target **uuid.UUID
	}{{raw.ScopeID, &query.ScopeID}, {raw.MessageID, &query.MessageID}} {
		if input.value != "" {
			value, err := uuid.Parse(input.value)
			if err != nil || value == uuid.Nil || value.String() != input.value {
				return query, ErrInvalidInput
			}
			*input.target = &value
		}
	}
	if raw.UserID != "" {
		if value, err := strconv.ParseInt(raw.UserID, 10, 64); err == nil && value > 0 && strconv.FormatInt(value, 10) == raw.UserID {
			query.UserDisplayID = &value
		} else {
			value, err := uuid.Parse(raw.UserID)
			if err != nil || value == uuid.Nil || value.String() != raw.UserID {
				return query, ErrInvalidInput
			}
			query.UserID = &value
		}
	}
	if raw.Channel != "" && raw.Channel != ChannelEmail && raw.Channel != ChannelSMS ||
		raw.Result != "" && raw.Result != "success" && raw.Result != "failure" ||
		raw.EventType != "" && !messageTypePattern.MatchString(raw.EventType) {
		return query, ErrInvalidInput
	}
	if raw.State != "" {
		if _, ok := deliveryStates[raw.State]; !ok {
			return query, ErrInvalidInput
		}
	}
	if raw.To != "" {
		value, err := time.Parse(time.RFC3339Nano, raw.To)
		if err != nil {
			return query, ErrInvalidInput
		}
		value = value.UTC()
		query.To = &value
	}
	if raw.From != "" {
		value, err := time.Parse(time.RFC3339Nano, raw.From)
		if err != nil {
			return query, ErrInvalidInput
		}
		value = value.UTC()
		query.From = &value
	}
	if query.From != nil && query.To != nil && (!query.To.After(*query.From) || query.To.Sub(*query.From) > 31*24*time.Hour) {
		return query, ErrInvalidInput
	}
	if raw.Limit != "" {
		value, err := strconv.Atoi(raw.Limit)
		if err != nil || value < 1 || value > 300 || strconv.Itoa(value) != raw.Limit {
			return query, ErrInvalidInput
		}
		query.Limit = value
	}
	if raw.Cursor != "" {
		outbox, sequence, ok := strings.Cut(raw.Cursor, ":")
		id, err := uuid.Parse(outbox)
		if !ok || err != nil || id == uuid.Nil || id.String() != outbox {
			return query, ErrInvalidInput
		}
		value, err := strconv.ParseInt(sequence, 10, 32)
		if err != nil || value < 1 || strconv.FormatInt(value, 10) != sequence {
			return query, ErrInvalidInput
		}
		query.CursorOutboxID, query.CursorSequence = &id, int(value)
	}
	return query, nil
}

const deliveryHistoryCandidatesSQL = `WITH history AS (
	SELECT fact.scope_id,fact.outbox_id,fact.sequence,fact.attempt_number,fact.fact_kind,
	       fact.result_state,fact.failure_code,fact.observed_at,event.id AS message_id,
	       event.event_type,event.recipient_user_id,recipient.display_id::text AS recipient_user_display_id,
	       event.recipient_kind,outbox.channel,outbox.generation,outbox.replay_of_outbox_id
	FROM notification_delivery_facts_108 fact
	JOIN notification_outbox outbox ON outbox.scope_id=fact.scope_id AND outbox.id=fact.outbox_id
	JOIN notification_events event ON event.scope_id=outbox.scope_id AND event.id=outbox.event_id
	LEFT JOIN users recipient ON recipient.id=event.recipient_user_id
	WHERE ($1::uuid IS NULL OR fact.scope_id=$1)
	  AND ($2::text='' OR outbox.channel=$2)
	  AND ($3::text='' OR fact.result_state=$3)
	  AND ($4::text='' OR event.event_type=$4)
	  AND ($5::uuid IS NULL OR event.recipient_user_id=$5)
	  AND ($6::bigint IS NULL OR recipient.display_id=$6)
	  AND ($7::uuid IS NULL OR event.id=$7)
	  AND ($8::timestamptz IS NULL OR fact.observed_at >= $8)
	  AND ($9::timestamptz IS NULL OR fact.observed_at <= $9)
	  AND ($10::text='' OR ($10='success' AND fact.result_state='delivered')
	       OR ($10='failure' AND fact.result_state IN ('retry_wait','permanent_failed','exhausted')))
) `

// ListDeliveryHistory reads immutable facts, without mixing in current settlement
// state or recipient contacts. Failure counts include only confirmed failed
// attempts through each fact's sequence, even when later facts already exist.
func (s *Store) ListDeliveryHistory(ctx context.Context, actor Actor, raw DeliveryHistoryQuery) (DeliveryHistoryPage, error) {
	page := DeliveryHistoryPage{Schema: "cdnca.notification-delivery-history/v1", Items: []DeliveryHistoryFact{}}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if err := authorizeAny(ctx, tx, actor, deliveryHistoryReadPermissions, s.now(), identityLockRead); err != nil {
			return err
		}
		query, err := normalizeDeliveryHistoryQuery(raw)
		if err != nil {
			return err
		}
		arguments := []any{query.ScopeID, query.Channel, query.State, query.EventType, query.UserID,
			query.UserDisplayID, query.MessageID, query.From, query.To, query.Result}
		var cursorAt, cursorID, cursorSequence any
		if query.CursorOutboxID != nil {
			var observedAt time.Time
			if err := tx.QueryRow(ctx, deliveryHistoryCandidatesSQL+
				`SELECT observed_at FROM history WHERE outbox_id=$11 AND sequence=$12`,
				append(arguments, *query.CursorOutboxID, query.CursorSequence)...).Scan(&observedAt); errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidInput
			} else if err != nil {
				return err
			}
			cursorAt, cursorID, cursorSequence = observedAt, *query.CursorOutboxID, query.CursorSequence
		}
		if err := tx.QueryRow(ctx, deliveryHistoryCandidatesSQL+`SELECT count(*) FROM history`, arguments...).Scan(&page.TotalCount); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, deliveryHistoryCandidatesSQL+`SELECT history.*,
			(SELECT count(DISTINCT failure.attempt_number) FROM notification_delivery_facts_108 failure
			 WHERE failure.scope_id=history.scope_id AND failure.outbox_id=history.outbox_id
			   AND failure.sequence<=history.sequence AND failure.attempt_number>0
		   AND failure.result_state IN ('retry_wait','permanent_failed','exhausted')),
		observation.recipient_address_masked,observation.provider_call_started_at
			FROM history
			LEFT JOIN LATERAL (
				SELECT snapshot.recipient_address_masked,snapshot.provider_call_started_at
				FROM notification_delivery_facts_108 snapshot
				WHERE snapshot.scope_id=history.scope_id AND snapshot.outbox_id=history.outbox_id
				  AND snapshot.attempt_number=history.attempt_number AND snapshot.sequence<=history.sequence
				  AND snapshot.provider_call_started_at IS NOT NULL
				ORDER BY snapshot.sequence DESC LIMIT 1
			) observation ON true
			WHERE ($11::timestamptz IS NULL OR (observed_at,outbox_id,sequence)<($11,$12::uuid,$13::integer))
			ORDER BY observed_at DESC,outbox_id DESC,sequence DESC LIMIT $14`,
			append(arguments, cursorAt, cursorID, cursorSequence, query.Limit+1)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item DeliveryHistoryFact
			if err := rows.Scan(&item.ScopeID, &item.OutboxID, &item.Sequence, &item.AttemptNumber, &item.FactKind,
				&item.State, &item.FailureCode, &item.ObservedAt, &item.MessageID, &item.EventType,
				&item.RecipientUserID, &item.RecipientUserDisplayID, &item.RecipientKind, &item.Channel,
				&item.Generation, &item.ReplayOfOutboxID, &item.FailureCount, &item.RecipientAddress, &item.ProviderCallStartedAt); err != nil {
				return err
			}
			item.ID = item.OutboxID.String() + ":" + strconv.Itoa(item.Sequence)
			item.RecipientAddressState = "unavailable"
			if item.RecipientAddress != nil {
				item.RecipientAddressState = "masked"
			}
			page.Items = append(page.Items, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(page.Items) > query.Limit {
			page.Items = page.Items[:query.Limit]
			page.NextCursor = page.Items[len(page.Items)-1].ID
		}
		return nil
	})
	if err != nil {
		return DeliveryHistoryPage{}, fmt.Errorf("list notification delivery history: %w", err)
	}
	return page, nil
}
