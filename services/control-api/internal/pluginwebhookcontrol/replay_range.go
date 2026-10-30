package pluginwebhookcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
)

const (
	maxReplayRangeItems  = 100
	maxReplayRangeWindow = 31 * 24 * time.Hour
)

// ReplayRangeRequest re-sends the terminal deliveries of one subscription
// whose original delivery was created in [From, To). Statuses defaults to
// both terminal states; "dead_lettered" alone is the backfill of failures.
// It never sends events from before the subscription existed: only events
// already produced for this subscription can be replayed.
type ReplayRangeRequest struct {
	From           time.Time
	To             time.Time
	Statuses       []string
	EventTypes     []string
	Limit          int
	IdempotencyKey string
}

type ReplayRangeItem struct {
	ReplayOf uuid.UUID `json:"replay_of"`
	Delivery *Delivery `json:"delivery,omitempty"`
	// Outcome: replayed, already_replayed (same key retried), permission_denied
	// (installation lost the event permission or site), rate_limited.
	Outcome string `json:"outcome"`
}

type ReplayRangeResult struct {
	Items []ReplayRangeItem `json:"items"`
	// Remaining is true when more matching deliveries exist past Limit or a
	// rate limit stopped the batch; call again with the same key to continue.
	Remaining bool `json:"remaining"`
}

// ReplayRange replays each matching delivery through ReplayDelivery with a
// per-delivery idempotency key derived from the batch key, so a retried
// batch reuses the replays it already made and every replay keeps the
// single-delivery guarantees (new delivery ID, audit, rate, permission and
// site checks in the database).
func (store *Store) ReplayRange(ctx context.Context, actor Actor, subscription uuid.UUID, input ReplayRangeRequest) (ReplayRangeResult, error) {
	statuses, ok := replayRangeStatuses(input.Statuses)
	if actor.validate() != nil || subscription == uuid.Nil || !validIdempotencyKey(input.IdempotencyKey) || !ok ||
		input.From.IsZero() || !input.From.Before(input.To) || input.To.Sub(input.From) > maxReplayRangeWindow ||
		input.Limit < 1 || input.Limit > maxReplayRangeItems {
		return ReplayRangeResult{}, ErrInvalidInput
	}
	var eventTypes []string
	if len(input.EventTypes) > 0 {
		eventTypes, ok = NormalizeEventTypes(input.EventTypes)
		if !ok {
			return ReplayRangeResult{}, ErrInvalidInput
		}
	}
	candidates, remaining, err := store.replayRangeCandidates(ctx, actor, subscription, input, statuses, eventTypes)
	if err != nil {
		return ReplayRangeResult{}, err
	}
	result := ReplayRangeResult{Items: make([]ReplayRangeItem, 0, len(candidates)), Remaining: remaining}
	for _, original := range candidates {
		replayed, err := store.ReplayDelivery(ctx, actor, subscription, original, WriteRequest{
			IdempotencyKey: replayRangeKey(input.IdempotencyKey, original),
		})
		item := ReplayRangeItem{ReplayOf: original}
		var rate RateLimitError
		switch {
		case err == nil:
			delivery := replayed.Value.Delivery
			item.Delivery, item.Outcome = &delivery, "replayed"
			if replayed.Replayed {
				item.Outcome = "already_replayed"
			}
		case errors.Is(err, ErrPermissionDenied):
			item.Outcome = "permission_denied"
		case errors.As(err, &rate):
			item.Outcome = "rate_limited"
			result.Items = append(result.Items, item)
			result.Remaining = true
			return result, nil
		default:
			return result, err
		}
		result.Items = append(result.Items, item)
	}
	return result, nil
}

func (store *Store) replayRangeCandidates(ctx context.Context, actor Actor, subscription uuid.UUID,
	input ReplayRangeRequest, statuses, eventTypes []string) ([]uuid.UUID, bool, error) {
	tx, err := store.pool.Begin(ctx)
	if err != nil {
		return nil, false, mapStoreError(err)
	}
	defer tx.Rollback(ctx)
	if err = store.authorize(ctx, tx, actor, PermissionManage); err != nil {
		return nil, false, err
	}
	if _, err = getSubscriptionTx(ctx, tx, actor.TargetScopeID, subscription, false); err != nil {
		return nil, false, err
	}
	var typeFilter any
	if eventTypes != nil {
		typeFilter = eventTypes
	}
	rows, err := tx.Query(ctx, `SELECT delivery.id FROM plugin_webhook_deliveries delivery
		JOIN plugin_webhook_events event ON event.tenant_scope_id=delivery.tenant_scope_id
		 AND event.subscription_id=delivery.subscription_id AND event.id=delivery.event_id
		WHERE delivery.tenant_scope_id=$1 AND delivery.subscription_id=$2 AND delivery.replay_of IS NULL
		  AND delivery.created_at >= $3 AND delivery.created_at < $4 AND delivery.status = ANY($5)
		  AND ($6::text[] IS NULL OR event.event_type = ANY($6))
		ORDER BY delivery.created_at, delivery.id LIMIT $7`,
		actor.TargetScopeID, subscription, input.From.UTC(), input.To.UTC(), statuses, typeFilter, input.Limit+1)
	if err != nil {
		return nil, false, mapStoreError(err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, false, mapStoreError(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, false, mapStoreError(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, false, mapStoreError(err)
	}
	if len(ids) > input.Limit {
		return ids[:input.Limit], true, nil
	}
	return ids, false, nil
}

func replayRangeStatuses(values []string) ([]string, bool) {
	if len(values) == 0 {
		return []string{"dead_lettered", "delivered"}, true
	}
	seen := map[string]bool{}
	for _, value := range values {
		if (value != "delivered" && value != "dead_lettered") || seen[value] {
			return nil, false
		}
		seen[value] = true
	}
	return append([]string(nil), values...), true
}

// replayRangeKey derives a per-delivery idempotency key (69 bytes, inside
// the 128-byte limit) from the batch key, so retrying a batch replays each
// delivery at most once.
func replayRangeKey(batchKey string, original uuid.UUID) string {
	digest := sha256.Sum256([]byte("cdnca.plugin-webhook.replay-range/v1\x00" + batchKey + "\x00" + original.String()))
	return "range-" + hex.EncodeToString(digest[:]) + "-" + "v1"
}
