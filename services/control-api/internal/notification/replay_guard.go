package notification

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ReplayWithdrawnCode marks an automatically scheduled repeat that was not sent
// because its source condition no longer holds (renewed, recovered, removed).
const ReplayWithdrawnCode = "source_superseded"

var ErrInvalidReplayGuard = errors.New("invalid notification replay guard")

// ReplayCandidate is one automatically scheduled repeat (generation > 1) that
// has become due. The guard runs inside the claim transaction.
type ReplayCandidate struct {
	ScopeID       uuid.UUID
	EventID       uuid.UUID
	OutboxID      uuid.UUID
	EventType     string
	SourceEventID string
	Generation    int
}

// ReplayGuard reports whether the producer's source condition still holds.
// Returning false withdraws the repeat before it reaches a provider.
type ReplayGuard func(context.Context, pgx.Tx, ReplayCandidate) (bool, error)

// RegisterReplayGuard installs the producer-side recheck for one event type.
// It must be called before workers start; a type has at most one guard.
func (s *Store) RegisterReplayGuard(eventType string, guard ReplayGuard) error {
	if s == nil || guard == nil || !templateIDPattern.MatchString(eventType) {
		return ErrInvalidReplayGuard
	}
	s.guardsMu.Lock()
	defer s.guardsMu.Unlock()
	if s.replayGuards == nil {
		s.replayGuards = make(map[string]ReplayGuard)
	}
	if _, exists := s.replayGuards[eventType]; exists {
		return ErrInvalidReplayGuard
	}
	s.replayGuards[eventType] = guard
	return nil
}

func (s *Store) replayGuard(eventType string) ReplayGuard {
	s.guardsMu.RLock()
	defer s.guardsMu.RUnlock()
	return s.replayGuards[eventType]
}

// withdrawReplayTx cancels one pending repeat as a system fact (no actor).
func (s *Store) withdrawReplayTx(ctx context.Context, tx pgx.Tx, candidate ReplayCandidate, now time.Time) error {
	var revision, attempt int
	var state DeliveryState
	var replayOf *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT replay_of_outbox_id FROM notification_outbox
		WHERE scope_id=$1 AND id=$2 AND status='pending'`, candidate.ScopeID, candidate.OutboxID).Scan(&replayOf); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrClaimLost
		}
		return fmt.Errorf("lock withdrawn notification replay: %w", err)
	}
	err := tx.QueryRow(ctx, `SELECT revision,state,attempt_number FROM notification_delivery_settlements_108
		WHERE outbox_id=$1 FOR UPDATE`, candidate.OutboxID).Scan(&revision, &state, &attempt)
	if errors.Is(err, pgx.ErrNoRows) {
		revision, attempt = 0, 0
	} else if err != nil {
		return fmt.Errorf("lock withdrawn notification replay projection: %w", err)
	} else if state != DeliveryPending && state != DeliveryRetryWait {
		return ErrSettlementConflict
	}
	if _, err := tx.Exec(ctx, `UPDATE notification_outbox SET status='cancelled',last_failure_code=$3,
		completed_at=$4,updated_at=$4 WHERE scope_id=$1 AND id=$2`,
		candidate.ScopeID, candidate.OutboxID, ReplayWithdrawnCode, now); err != nil {
		return fmt.Errorf("withdraw notification replay: %w", err)
	}
	sequence := revision + 1
	if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery_facts_108(
		scope_id,outbox_id,sequence,attempt_number,fact_kind,result_state,failure_code,observed_at,created_at
	) VALUES($1,$2,$3,$4,'cancelled','cancelled',$5,$6,$6)`,
		candidate.ScopeID, candidate.OutboxID, sequence, attempt, ReplayWithdrawnCode, now); err != nil {
		return fmt.Errorf("insert withdrawn notification replay fact: %w", err)
	}
	if revision == 0 {
		_, err = tx.Exec(ctx, `INSERT INTO notification_delivery_settlements_108(
			scope_id,outbox_id,state,revision,attempt_number,failure_code,completed_at,replay_of_outbox_id,created_at,updated_at
		) VALUES($1,$2,'cancelled',1,0,'cancelled',$3,$4,$3,$3)`, candidate.ScopeID, candidate.OutboxID, now, replayOf)
	} else {
		_, err = tx.Exec(ctx, `UPDATE notification_delivery_settlements_108 SET state='cancelled',
			revision=$2,failure_code='cancelled',retry_at=NULL,completed_at=$3,updated_at=$3 WHERE outbox_id=$1`,
			candidate.OutboxID, sequence, now)
	}
	if err != nil {
		return fmt.Errorf("project withdrawn notification replay: %w", err)
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: candidate.ScopeID, Action: "notification.delivery.withdraw",
		ResourceType: "notification_outbox", ResourceID: candidate.OutboxID.String(),
		RequestID: "replay-guard:" + candidate.OutboxID.String(), Result: "success",
		Payload: map[string]any{
			"event_type": candidate.EventType, "generation": candidate.Generation,
			"reason": ReplayWithdrawnCode,
		},
	}); err != nil {
		return fmt.Errorf("audit withdrawn notification replay: %w", err)
	}
	return nil
}
