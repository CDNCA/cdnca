package notification

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const expiredLeaseFailureCode = "worker_lease_expired"

type claimResult struct {
	deliveries []claimedDelivery
	exhausted  int
	unknown    int
	withdrawn  int
}

type claimCandidate struct {
	delivery     claimedDelivery
	attemptCount int
	oldToken     *uuid.UUID
	generation   int
}

func (s *Store) claim(ctx context.Context, config WorkerConfig) (claimResult, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return claimResult{}, fmt.Errorf("begin notification claim: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return claimResult{}, fmt.Errorf("read notification claim time: %w", err)
	}
	now = storeTime(now)
	unknown, err := markExpiredDispatchUnknown(ctx, tx, now, 1)
	if err != nil {
		return claimResult{}, err
	}
	if unknown > 0 {
		if err := tx.Commit(ctx); err != nil {
			return claimResult{}, fmt.Errorf("commit unknown notification dispatch: %w", err)
		}
		return claimResult{unknown: unknown}, nil
	}

	exhausted, err := reapExpiredFinalLeases(ctx, tx, now, config.MaxAttempts, 1)
	if err != nil {
		return claimResult{}, err
	}
	if exhausted > 0 {
		if err := tx.Commit(ctx); err != nil {
			return claimResult{}, fmt.Errorf("commit exhausted notification lease: %w", err)
		}
		return claimResult{exhausted: exhausted}, nil
	}
	candidates, err := selectClaimCandidates(ctx, tx, now, config.MaxAttempts, 1)
	if err != nil {
		return claimResult{}, err
	}
	withdrawn, err := s.withdrawStaleReplays(ctx, tx, candidates, now)
	if err != nil {
		return claimResult{}, err
	}
	if withdrawn > 0 {
		if err := tx.Commit(ctx); err != nil {
			return claimResult{}, fmt.Errorf("commit withdrawn notification replay: %w", err)
		}
		return claimResult{withdrawn: withdrawn}, nil
	}
	deliveries := make([]claimedDelivery, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.oldToken != nil {
			result, err := tx.Exec(ctx, `
				UPDATE notification_attempts
				SET outcome = 'lease_expired', failure_code = $3,
					completed_at = $4
				WHERE outbox_id = $1 AND lease_token = $2 AND outcome = 'leased'`,
				candidate.delivery.OutboxID, *candidate.oldToken, expiredLeaseFailureCode, now)
			if err != nil {
				return claimResult{}, fmt.Errorf("expire notification attempt lease: %w", err)
			}
			if result.RowsAffected() != 1 {
				return claimResult{}, ErrClaimLost
			}
		}
		token, err := uuid.NewV7()
		if err != nil {
			return claimResult{}, fmt.Errorf("generate notification lease token: %w", err)
		}
		candidate.delivery.AttemptNumber = candidate.attemptCount + 1
		candidate.delivery.LeaseToken = token
		candidate.delivery.LeaseExpiresAt = now.Add(config.LeaseDuration)
		result, err := tx.Exec(ctx, `
			UPDATE notification_outbox
			SET status = 'leased', attempt_count = $2, lease_token = $3,
				lease_expires_at = $4, last_failure_code = NULL, updated_at = $5
			WHERE id = $1`,
			candidate.delivery.OutboxID, candidate.delivery.AttemptNumber, token,
			candidate.delivery.LeaseExpiresAt, now)
		if err != nil {
			return claimResult{}, fmt.Errorf("lease notification outbox: %w", err)
		}
		if result.RowsAffected() != 1 {
			return claimResult{}, ErrClaimLost
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO notification_attempts (
				outbox_id, scope_id, attempt_number, lease_token, lease_expires_at,
				outcome, claimed_at
			) VALUES ($1, $2, $3, $4, $5, 'leased', $6)`,
			candidate.delivery.OutboxID, candidate.delivery.ScopeID,
			candidate.delivery.AttemptNumber, token, candidate.delivery.LeaseExpiresAt, now)
		if err != nil {
			return claimResult{}, fmt.Errorf("insert notification attempt: %w", err)
		}
		deliveries = append(deliveries, candidate.delivery)
	}
	if err := tx.Commit(ctx); err != nil {
		return claimResult{}, fmt.Errorf("commit notification claim: %w", err)
	}
	return claimResult{deliveries: deliveries, exhausted: exhausted}, nil
}

func (s *Store) confirmLeaseFresh(
	ctx context.Context,
	delivery claimedDelivery,
	safetyMargin time.Duration,
) (time.Duration, error) {
	var leaseExpiresAt time.Time
	var databaseNow time.Time
	var attemptNumber int
	err := s.pool.QueryRow(ctx, `
		SELECT lease_expires_at, attempt_count, clock_timestamp()
		FROM notification_outbox
		WHERE id = $1 AND scope_id = $2 AND status = 'leased' AND lease_token = $3`,
		delivery.OutboxID, delivery.ScopeID, delivery.LeaseToken,
	).Scan(&leaseExpiresAt, &attemptNumber, &databaseNow)
	if err == pgx.ErrNoRows {
		return 0, ErrClaimLost
	}
	if err != nil {
		return 0, fmt.Errorf("confirm notification lease: %w", err)
	}
	if attemptNumber != delivery.AttemptNumber || !leaseExpiresAt.Equal(delivery.LeaseExpiresAt) {
		return 0, ErrClaimLost
	}
	remaining := leaseExpiresAt.Sub(storeTime(databaseNow))
	if remaining <= safetyMargin {
		return 0, ErrLeaseUnsafe
	}
	return remaining, nil
}

func reapExpiredFinalLeases(
	ctx context.Context,
	tx pgx.Tx,
	now time.Time,
	maxAttempts, limit int,
) (int, error) {
	rows, err := tx.Query(ctx, `
		SELECT id, lease_token
		FROM notification_outbox
		WHERE status = 'leased' AND lease_expires_at <= $1 AND attempt_count >= $2
		ORDER BY lease_expires_at, id
		FOR UPDATE SKIP LOCKED
		LIMIT $3`, now, maxAttempts, limit)
	if err != nil {
		return 0, fmt.Errorf("select exhausted notification leases: %w", err)
	}
	type expiredLease struct {
		outboxID uuid.UUID
		token    uuid.UUID
	}
	var expired []expiredLease
	for rows.Next() {
		var item expiredLease
		if err := rows.Scan(&item.outboxID, &item.token); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan exhausted notification lease: %w", err)
		}
		expired = append(expired, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("iterate exhausted notification leases: %w", err)
	}
	rows.Close()
	for _, item := range expired {
		attempt, err := tx.Exec(ctx, `
			UPDATE notification_attempts
			SET outcome = 'exhausted', failure_code = $3, completed_at = $4
			WHERE outbox_id = $1 AND lease_token = $2 AND outcome = 'leased'`,
			item.outboxID, item.token, expiredLeaseFailureCode, now)
		if err != nil {
			return 0, fmt.Errorf("exhaust expired notification attempt: %w", err)
		}
		if attempt.RowsAffected() != 1 {
			return 0, ErrClaimLost
		}
		outbox, err := tx.Exec(ctx, `
			UPDATE notification_outbox
			SET status = 'exhausted', lease_token = NULL, lease_expires_at = NULL,
				last_failure_code = $3, completed_at = $4, updated_at = $4
			WHERE id = $1 AND status = 'leased' AND lease_token = $2`,
			item.outboxID, item.token, expiredLeaseFailureCode, now)
		if err != nil {
			return 0, fmt.Errorf("exhaust expired notification outbox: %w", err)
		}
		if outbox.RowsAffected() != 1 {
			return 0, ErrClaimLost
		}
	}
	return len(expired), nil
}

func selectClaimCandidates(
	ctx context.Context,
	tx pgx.Tx,
	now time.Time,
	maxAttempts, limit int,
) ([]claimCandidate, error) {
	rows, err := tx.Query(ctx, `
			SELECT outbox.id, outbox.scope_id, outbox.event_id,
			       COALESCE(to_jsonb(event)->>'recipient_kind', 'member'),
			       event.recipient_user_id,
			       (to_jsonb(event)->>'anonymous_dispatch_reference')::uuid,
			       event.event_type, event.source_event_id,
			       outbox.channel, outbox.template_id, outbox.template_version,
		       outbox.subject, outbox.body, outbox.dedup_key,
		       outbox.attempt_count, outbox.lease_token, outbox.generation, outbox.template_params
		FROM notification_outbox outbox
		JOIN notification_events event
		  ON event.scope_id = outbox.scope_id AND event.id = outbox.event_id
		WHERE outbox.attempt_count < $2 AND (
			(outbox.status = 'pending' AND outbox.available_at <= $1) OR
			(outbox.status = 'leased' AND outbox.lease_expires_at <= $1)
		)
		ORDER BY outbox.available_at, outbox.id
			FOR UPDATE OF outbox SKIP LOCKED
			LIMIT $3`, now, maxAttempts, limit)
	if err != nil {
		return nil, fmt.Errorf("select notification outbox claims: %w", err)
	}
	defer rows.Close()
	candidates := make([]claimCandidate, 0, limit)
	for rows.Next() {
		var candidate claimCandidate
		var recipientKind string
		var memberID, anonymousReference *uuid.UUID
		if err := rows.Scan(
			&candidate.delivery.OutboxID, &candidate.delivery.ScopeID, &candidate.delivery.EventID,
			&recipientKind, &memberID, &anonymousReference,
			&candidate.delivery.EventType, &candidate.delivery.SourceEventID,
			&candidate.delivery.Channel, &candidate.delivery.Template.ID, &candidate.delivery.Template.Version,
			&candidate.delivery.Subject, &candidate.delivery.Body, &candidate.delivery.DedupKey,
			&candidate.attemptCount, &candidate.oldToken, &candidate.generation, &candidate.delivery.Params,
		); err != nil {
			return nil, fmt.Errorf("scan notification outbox claim: %w", err)
		}
		switch recipientKind {
		case "member":
			if memberID == nil || *memberID == uuid.Nil || anonymousReference != nil {
				return nil, ErrInvalidStore
			}
			candidate.delivery.Recipient = memberRecipient{userID: *memberID}
		case "anonymous":
			if memberID != nil || anonymousReference == nil || *anonymousReference == uuid.Nil ||
				!validAnonymousEventType(candidate.delivery.EventType) {
				return nil, ErrInvalidStore
			}
			candidate.delivery.Recipient = anonymousRecipient{reference: *anonymousReference}
		default:
			return nil, ErrInvalidStore
		}
		candidate.delivery.Template.Channel = candidate.delivery.Channel
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate notification outbox claims: %w", err)
	}
	return candidates, nil
}

// withdrawStaleReplays asks the producer guard whether a due automatic repeat
// is still current. Only never-leased pending repeats are eligible: a lease
// that expired may already have reached a provider and stays on its path.
func (s *Store) withdrawStaleReplays(
	ctx context.Context,
	tx pgx.Tx,
	candidates []claimCandidate,
	now time.Time,
) (int, error) {
	withdrawn := 0
	for _, candidate := range candidates {
		if candidate.generation < 2 || candidate.oldToken != nil {
			continue
		}
		guard := s.replayGuard(candidate.delivery.EventType)
		if guard == nil {
			continue
		}
		replay := ReplayCandidate{
			ScopeID: candidate.delivery.ScopeID, EventID: candidate.delivery.EventID,
			OutboxID: candidate.delivery.OutboxID, EventType: candidate.delivery.EventType,
			SourceEventID: candidate.delivery.SourceEventID, Generation: candidate.generation,
		}
		current, err := guard(ctx, tx, replay)
		if err != nil {
			return 0, fmt.Errorf("check notification replay source: %w", err)
		}
		if current {
			continue
		}
		if err := s.withdrawReplayTx(ctx, tx, replay, now); err != nil {
			return 0, err
		}
		withdrawn++
	}
	return withdrawn, nil
}
