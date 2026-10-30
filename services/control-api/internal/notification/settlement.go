package notification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type DeliveryState string

const (
	DeliveryPending         DeliveryState = "pending"
	DeliveryDispatching     DeliveryState = "dispatching"
	DeliveryRetryWait       DeliveryState = "retry_wait"
	DeliveryAccepted        DeliveryState = "accepted"
	DeliveryUnknown         DeliveryState = "unknown"
	DeliveryDelivered       DeliveryState = "delivered"
	DeliveryPermanentFailed DeliveryState = "permanent_failed"
	DeliveryExhausted       DeliveryState = "exhausted"
	DeliveryCancelled       DeliveryState = "cancelled"
)

type DeliverySettlement struct {
	ScopeID   uuid.UUID
	OutboxID  uuid.UUID
	State     DeliveryState
	Revision  int
	Attempt   int
	Replayed  bool
	UpdatedAt time.Time
}

type ProviderReceipt struct {
	ScopeID            uuid.UUID
	OutboxID           uuid.UUID
	Provider           string
	ProviderEventKey   string
	ProviderDeliveryID string
	State              DeliveryState
	FailureCode        string
	ObservedAt         time.Time
}

type SettlementActor struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	SessionID uuid.UUID
	ScopeKind string
}

type DeliveryCommand struct {
	ScopeID   uuid.UUID
	OutboxID  uuid.UUID
	RequestID string
}

type DeliveryReplayResult struct {
	SourceOutboxID uuid.UUID
	NewOutboxID    uuid.UUID
	State          DeliveryState
	Replayed       bool
}

func validProviderIdentity(value string) bool {
	if len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < ' ' || character == '\u007f' {
			return false
		}
	}
	return true
}

func (s *Store) beginDispatch(ctx context.Context, delivery claimedDelivery) error {
	if s == nil || s.pool == nil || ctx == nil {
		return ErrInvalidStore
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin notification dispatch fact: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	now, err := settlementDatabaseNow(ctx, tx)
	if err != nil {
		return err
	}
	var attempt int
	var expires time.Time
	var replayOf *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT attempt_count,lease_expires_at,replay_of_outbox_id FROM notification_outbox
		WHERE scope_id=$1 AND id=$2 AND status='leased' AND lease_token=$3 FOR UPDATE`,
		delivery.ScopeID, delivery.OutboxID, delivery.LeaseToken).Scan(&attempt, &expires, &replayOf); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrClaimLost
		}
		return fmt.Errorf("lock notification dispatch: %w", err)
	}
	if attempt != delivery.AttemptNumber || !expires.Equal(delivery.LeaseExpiresAt) || !expires.After(now) {
		return ErrClaimLost
	}
	var revision int
	var state DeliveryState
	err = tx.QueryRow(ctx, `SELECT revision,state FROM notification_delivery_settlements_108
		WHERE outbox_id=$1 FOR UPDATE`, delivery.OutboxID).Scan(&revision, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		revision = 0
	} else if err != nil {
		return fmt.Errorf("lock notification dispatch projection: %w", err)
	} else if state == DeliveryDispatching && attempt == delivery.AttemptNumber {
		return ErrSettlementConflict
	} else if state != DeliveryRetryWait && state != DeliveryPending {
		return ErrSettlementConflict
	}
	sequence := revision + 1
	if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery_facts_108(
		scope_id,outbox_id,sequence,attempt_number,fact_kind,result_state,observed_at,created_at
	) VALUES($1,$2,$3,$4,'dispatch_started','dispatching',$5,$5)`,
		delivery.ScopeID, delivery.OutboxID, sequence, delivery.AttemptNumber, now); err != nil {
		return fmt.Errorf("insert notification dispatch fact: %w", err)
	}
	if revision == 0 {
		_, err = tx.Exec(ctx, `INSERT INTO notification_delivery_settlements_108(
			scope_id,outbox_id,state,revision,attempt_number,replay_of_outbox_id,created_at,updated_at
		) VALUES($1,$2,'dispatching',1,$3,$4,$5,$5)`,
			delivery.ScopeID, delivery.OutboxID, delivery.AttemptNumber, replayOf, now)
	} else {
		_, err = tx.Exec(ctx, `UPDATE notification_delivery_settlements_108
			SET state='dispatching',revision=$2,attempt_number=$3,provider=NULL,
				provider_delivery_id=NULL,failure_code=NULL,retry_at=NULL,
				accepted_at=NULL,completed_at=NULL,updated_at=$4
			WHERE outbox_id=$1`, delivery.OutboxID, sequence, delivery.AttemptNumber, now)
	}
	if err != nil {
		return fmt.Errorf("project notification dispatch fact: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit notification dispatch fact: %w", err)
	}
	return nil
}

func (s *Store) settleSendResult(
	ctx context.Context,
	delivery claimedDelivery,
	result SendResult,
	action RetryAction,
	failureCode string,
	retryDelay time.Duration,
) error {
	if s == nil || s.pool == nil || ctx == nil {
		return ErrInvalidStore
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin notification provider settlement: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	now, err := settlementDatabaseNow(ctx, tx)
	if err != nil {
		return err
	}
	var leaseExpiresAt time.Time
	var attemptNumber int
	if err := tx.QueryRow(ctx, `SELECT lease_expires_at,attempt_count FROM notification_outbox
		WHERE scope_id=$1 AND id=$2 AND status='leased' AND lease_token=$3 FOR UPDATE`,
		delivery.ScopeID, delivery.OutboxID, delivery.LeaseToken).Scan(&leaseExpiresAt, &attemptNumber); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrClaimLost
		}
		return fmt.Errorf("lock notification provider settlement: %w", err)
	}
	if !leaseExpiresAt.After(now) || attemptNumber != delivery.AttemptNumber {
		return ErrClaimLost
	}
	var revision int
	var current DeliveryState
	if err := tx.QueryRow(ctx, `SELECT revision,state FROM notification_delivery_settlements_108
		WHERE outbox_id=$1 FOR UPDATE`, delivery.OutboxID).Scan(&revision, &current); err != nil {
		return fmt.Errorf("lock notification provider projection: %w", err)
	}
	if current != DeliveryDispatching {
		return ErrSettlementConflict
	}

	state, factKind, attemptOutcome, outboxStatus := DeliveryDelivered, "provider_delivered", "succeeded", OutboxSucceeded
	var storedFailure any
	var retryAt, acceptedAt, completedAt *time.Time
	completedAt = &now
	provider, providerDeliveryID := result.Provider, result.ProviderDeliveryID
	if result.Failure == nil {
		switch result.Disposition {
		case SendDelivered:
		case SendAccepted:
			state, factKind, attemptOutcome, outboxStatus = DeliveryAccepted, "provider_accepted", "accepted", OutboxAccepted
			acceptedAt, completedAt = &now, nil
		case SendUnknown:
			state, factKind, attemptOutcome, outboxStatus = DeliveryUnknown, "provider_unknown", "unknown", OutboxUnknown
			failureCode = "provider_outcome_unknown"
			storedFailure, completedAt = failureCode, nil
		default:
			return ErrInvalidFailure
		}
	} else {
		provider, providerDeliveryID = "", ""
		storedFailure = failureCode
		switch action {
		case RetryScheduled:
			if retryDelay <= 0 {
				return ErrInvalidFailure
			}
			state, factKind, attemptOutcome, outboxStatus = DeliveryRetryWait, "retry_scheduled", "temporary_failure", OutboxPending
			value := storeTime(now.Add(retryDelay))
			retryAt, completedAt = &value, nil
		case RetryStopped:
			state, factKind, attemptOutcome, outboxStatus = DeliveryPermanentFailed, "permanent_failed", "permanent_failure", OutboxPermanentFailed
		case RetryExhausted:
			state, factKind, attemptOutcome, outboxStatus = DeliveryExhausted, "exhausted", "exhausted", OutboxExhausted
		default:
			return ErrInvalidFailure
		}
	}
	if provider != "" && !validProviderIdentity(provider) || !validProviderIdentity(providerDeliveryID) {
		return ErrInvalidFailure
	}
	var nextAttempt any
	if retryAt != nil {
		nextAttempt = *retryAt
	}
	command, err := tx.Exec(ctx, `UPDATE notification_attempts
		SET outcome=$3,failure_code=$4,next_attempt_at=$5,completed_at=$6
		WHERE outbox_id=$1 AND lease_token=$2 AND outcome='leased'`,
		delivery.OutboxID, delivery.LeaseToken, attemptOutcome, storedFailure, nextAttempt, now)
	if err != nil || command.RowsAffected() != 1 {
		if err != nil {
			return fmt.Errorf("settle notification provider attempt: %w", err)
		}
		return ErrClaimLost
	}
	availableAt := now
	if retryAt != nil {
		availableAt = *retryAt
	}
	command, err = tx.Exec(ctx, `UPDATE notification_outbox
		SET status=$3,available_at=$4,lease_token=NULL,lease_expires_at=NULL,
			last_failure_code=$5,completed_at=$6,updated_at=$7
		WHERE id=$1 AND status='leased' AND lease_token=$2`,
		delivery.OutboxID, delivery.LeaseToken, outboxStatus, availableAt, storedFailure, completedAt, now)
	if err != nil || command.RowsAffected() != 1 {
		if err != nil {
			return fmt.Errorf("settle notification provider outbox: %w", err)
		}
		return ErrClaimLost
	}
	sequence := revision + 1
	factColumns := `scope_id,outbox_id,sequence,attempt_number,fact_kind,result_state,provider,
		provider_delivery_id,failure_code,retry_at,observed_at,created_at`
	factValues := `$1,$2,$3,$4,$5,$6,NULLIF($7,''),NULLIF($8,''),$9,$10,$11,$11`
	factArguments := []any{
		delivery.ScopeID, delivery.OutboxID, sequence, delivery.AttemptNumber, factKind, state,
		provider, providerDeliveryID, storedFailure, retryAt, now}
	if result.Observation != nil && !result.Observation.providerCallStartedAt.IsZero() {
		factColumns += `,recipient_address_masked,provider_call_started_at`
		factValues += `,NULLIF($12,''),$13`
		factArguments = append(factArguments, result.Observation.recipientAddressMasked, result.Observation.providerCallStartedAt)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery_facts_108(`+factColumns+`) VALUES(`+factValues+`)`, factArguments...); err != nil {
		return fmt.Errorf("insert notification provider settlement fact: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE notification_delivery_settlements_108
		SET state=$2,revision=$3,attempt_number=$4,provider=NULLIF($5,''),
			provider_delivery_id=NULLIF($6,''),failure_code=$7,retry_at=$8,
			accepted_at=$9,completed_at=$10,updated_at=$11
		WHERE outbox_id=$1`, delivery.OutboxID, state, sequence, delivery.AttemptNumber,
		provider, providerDeliveryID, storedFailure, retryAt, acceptedAt, completedAt, now); err != nil {
		return fmt.Errorf("project notification provider settlement: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit notification provider settlement: %w", err)
	}
	return nil
}

func markExpiredDispatchUnknown(ctx context.Context, tx pgx.Tx, now time.Time, limit int) (int, error) {
	var scopeID, outboxID, leaseToken uuid.UUID
	var attempt, revision int
	err := tx.QueryRow(ctx, `SELECT outbox.scope_id,outbox.id,outbox.lease_token,
		outbox.attempt_count,settlement.revision
		FROM notification_outbox outbox
		JOIN notification_delivery_settlements_108 settlement ON settlement.outbox_id=outbox.id
		WHERE outbox.status='leased' AND outbox.lease_expires_at<=$1 AND settlement.state='dispatching'
		ORDER BY outbox.lease_expires_at,outbox.id FOR UPDATE OF outbox,settlement SKIP LOCKED LIMIT $2`,
		now, limit).Scan(&scopeID, &outboxID, &leaseToken, &attempt, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("select expired notification dispatch: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE notification_attempts SET outcome='unknown',
		failure_code='provider_outcome_unknown',completed_at=$3
		WHERE outbox_id=$1 AND lease_token=$2 AND outcome='leased'`, outboxID, leaseToken, now); err != nil {
		return 0, fmt.Errorf("mark expired notification attempt unknown: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE notification_outbox SET status='unknown',lease_token=NULL,
		lease_expires_at=NULL,last_failure_code='provider_outcome_unknown',updated_at=$2
		WHERE id=$1`, outboxID, now); err != nil {
		return 0, fmt.Errorf("mark expired notification outbox unknown: %w", err)
	}
	sequence := revision + 1
	if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery_facts_108(
		scope_id,outbox_id,sequence,attempt_number,fact_kind,result_state,failure_code,observed_at,created_at
	) VALUES($1,$2,$3,$4,'lease_unknown','unknown','provider_outcome_unknown',$5,$5)`,
		scopeID, outboxID, sequence, attempt, now); err != nil {
		return 0, fmt.Errorf("insert expired notification dispatch fact: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE notification_delivery_settlements_108
		SET state='unknown',revision=$2,failure_code='provider_outcome_unknown',updated_at=$3
		WHERE outbox_id=$1`, outboxID, sequence, now); err != nil {
		return 0, fmt.Errorf("project expired notification dispatch: %w", err)
	}
	return 1, nil
}

func (s *Store) RecordProviderReceipt(ctx context.Context, input ProviderReceipt) (DeliverySettlement, error) {
	if s == nil || s.pool == nil || ctx == nil || input.ScopeID == uuid.Nil || input.OutboxID == uuid.Nil ||
		input.Provider == "" || input.ProviderEventKey == "" || !validProviderIdentity(input.Provider) ||
		!validProviderIdentity(input.ProviderEventKey) || !validProviderIdentity(input.ProviderDeliveryID) ||
		(input.State != DeliveryDelivered && input.State != DeliveryPermanentFailed) ||
		(input.State == DeliveryDelivered && input.FailureCode != "") ||
		(input.State == DeliveryPermanentFailed && !validFailureCode(input.FailureCode)) || input.ObservedAt.IsZero() {
		return DeliverySettlement{}, ErrInvalidFailure
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return DeliverySettlement{}, fmt.Errorf("begin provider receipt: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	var existingOutbox uuid.UUID
	var existingState DeliveryState
	err = tx.QueryRow(ctx, `SELECT outbox_id,result_state FROM notification_delivery_facts_108
		WHERE provider=$1 AND provider_event_key=$2`, input.Provider, input.ProviderEventKey).
		Scan(&existingOutbox, &existingState)
	if err == nil {
		if existingOutbox != input.OutboxID || existingState != input.State {
			return DeliverySettlement{}, ErrSettlementConflict
		}
		settlement, readErr := readSettlement(ctx, tx, input.OutboxID)
		if readErr != nil {
			return DeliverySettlement{}, readErr
		}
		settlement.Replayed = true
		return commitSettlementRead(ctx, tx, settlement)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return DeliverySettlement{}, fmt.Errorf("read provider receipt replay: %w", err)
	}
	settlement, err := readSettlementForUpdate(ctx, tx, input.ScopeID, input.OutboxID)
	if err != nil {
		return DeliverySettlement{}, err
	}
	if settlement.State != DeliveryAccepted && settlement.State != DeliveryUnknown {
		return DeliverySettlement{}, ErrSettlementConflict
	}
	now, err := settlementDatabaseNow(ctx, tx)
	if err != nil {
		return DeliverySettlement{}, err
	}
	failure := any(nil)
	outboxState := OutboxSucceeded
	if input.State == DeliveryPermanentFailed {
		failure, outboxState = input.FailureCode, OutboxPermanentFailed
	}
	if _, err := tx.Exec(ctx, `UPDATE notification_outbox SET status=$2,last_failure_code=$3,
		completed_at=$4,updated_at=$4 WHERE scope_id=$1 AND id=$5 AND status IN ('accepted','unknown')`,
		input.ScopeID, outboxState, failure, now, input.OutboxID); err != nil {
		return DeliverySettlement{}, fmt.Errorf("settle provider receipt outbox: %w", err)
	}
	sequence := settlement.Revision + 1
	if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery_facts_108(
		scope_id,outbox_id,sequence,attempt_number,fact_kind,result_state,provider,
		provider_event_key,provider_delivery_id,failure_code,observed_at,created_at
	) VALUES($1,$2,$3,$4,'provider_receipt',$5,$6,$7,NULLIF($8,''),$9,$10,$11)`,
		input.ScopeID, input.OutboxID, sequence, settlement.Attempt, input.State, input.Provider,
		input.ProviderEventKey, input.ProviderDeliveryID, failure, storeTime(input.ObservedAt), now); err != nil {
		return DeliverySettlement{}, fmt.Errorf("insert provider receipt fact: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE notification_delivery_settlements_108 SET
		state=$2,revision=$3,provider=$4,provider_delivery_id=NULLIF($5,''),failure_code=$6,
		completed_at=$7,updated_at=$7 WHERE outbox_id=$1`, input.OutboxID, input.State,
		sequence, input.Provider, input.ProviderDeliveryID, failure, now); err != nil {
		return DeliverySettlement{}, fmt.Errorf("project provider receipt: %w", err)
	}
	settlement.State, settlement.Revision, settlement.UpdatedAt = input.State, sequence, now
	return commitSettlementRead(ctx, tx, settlement)
}

func (s *Store) CancelDelivery(ctx context.Context, actor SettlementActor, command DeliveryCommand) (DeliverySettlement, error) {
	operation := "notification.delivery.cancel"
	result, _, replayed, err := s.deliveryCommand(ctx, actor, command, operation)
	if err != nil || replayed {
		result.Replayed = replayed
		return result, err
	}
	return result, nil
}

func (s *Store) ReplayDelivery(ctx context.Context, actor SettlementActor, command DeliveryCommand) (DeliveryReplayResult, error) {
	operation := "notification.delivery.replay"
	_, replayResult, replayed, err := s.deliveryCommand(ctx, actor, command, operation)
	replayResult.Replayed = replayed
	return replayResult, err
}

func (s *Store) deliveryCommand(
	ctx context.Context,
	actor SettlementActor,
	command DeliveryCommand,
	operation string,
) (DeliverySettlement, DeliveryReplayResult, bool, error) {
	if s == nil || s.pool == nil || ctx == nil || !validSettlementActor(actor) ||
		command.ScopeID == uuid.Nil || command.OutboxID == uuid.Nil || !validCommandRequestID(command.RequestID) {
		return DeliverySettlement{}, DeliveryReplayResult{}, false, ErrSettlementUnauthenticated
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return DeliverySettlement{}, DeliveryReplayResult{}, false, fmt.Errorf("begin notification delivery command: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	now, err := settlementDatabaseNow(ctx, tx)
	if err != nil {
		return DeliverySettlement{}, DeliveryReplayResult{}, false, err
	}
	if err := authorizeSettlementCommand(ctx, tx, actor, now); err != nil {
		if errors.Is(err, ErrSettlementUnauthenticated) {
			return DeliverySettlement{}, DeliveryReplayResult{}, false, err
		}
		if !errors.Is(err, ErrSettlementPermissionDenied) {
			return DeliverySettlement{}, DeliveryReplayResult{}, false, err
		}
		if auditErr := s.appendSettlementDeniedAudit(ctx, tx, actor, operation, command.RequestID); auditErr != nil {
			return DeliverySettlement{}, DeliveryReplayResult{}, false, auditErr
		}
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return DeliverySettlement{}, DeliveryReplayResult{}, false, commitErr
		}
		return DeliverySettlement{}, DeliveryReplayResult{}, false, ErrSettlementPermissionDenied
	}
	digest := deliveryCommandDigest(operation, command)
	receiptID, resultOutbox, resultState, replayed, err := claimDeliveryCommandReceipt(
		ctx, tx, actor, command, operation, digest, now,
	)
	if err != nil {
		return DeliverySettlement{}, DeliveryReplayResult{}, false, err
	}
	if replayed {
		if err := tx.Commit(ctx); err != nil {
			return DeliverySettlement{}, DeliveryReplayResult{}, false, err
		}
		if operation == "notification.delivery.cancel" {
			return DeliverySettlement{ScopeID: command.ScopeID, OutboxID: resultOutbox, State: DeliveryState(resultState), Replayed: true}, DeliveryReplayResult{}, true, nil
		}
		return DeliverySettlement{}, DeliveryReplayResult{SourceOutboxID: command.OutboxID, NewOutboxID: resultOutbox, State: DeliveryState(resultState), Replayed: true}, true, nil
	}
	if operation == "notification.delivery.cancel" {
		settlement, commandErr := s.cancelDeliveryTx(ctx, tx, actor, command, receiptID, digest, now)
		if commandErr != nil {
			return DeliverySettlement{}, DeliveryReplayResult{}, false, commandErr
		}
		if err := tx.Commit(ctx); err != nil {
			return DeliverySettlement{}, DeliveryReplayResult{}, false, err
		}
		return settlement, DeliveryReplayResult{}, false, nil
	}
	replay, commandErr := s.replayDeliveryTx(ctx, tx, actor, command, receiptID, digest, now)
	if commandErr != nil {
		return DeliverySettlement{}, DeliveryReplayResult{}, false, commandErr
	}
	if err := tx.Commit(ctx); err != nil {
		return DeliverySettlement{}, DeliveryReplayResult{}, false, err
	}
	return DeliverySettlement{}, replay, false, nil
}

func (s *Store) cancelDeliveryTx(
	ctx context.Context, tx pgx.Tx, actor SettlementActor, command DeliveryCommand,
	receiptID uuid.UUID, digest [sha256.Size]byte, now time.Time,
) (DeliverySettlement, error) {
	var status string
	var replayOf *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT status,replay_of_outbox_id FROM notification_outbox WHERE scope_id=$1 AND id=$2 FOR UPDATE`,
		command.ScopeID, command.OutboxID).Scan(&status, &replayOf); err != nil {
		return DeliverySettlement{}, ErrSettlementConflict
	}
	if status != OutboxPending {
		return DeliverySettlement{}, ErrSettlementConflict
	}
	var revision, attempt int
	var current DeliveryState
	err := tx.QueryRow(ctx, `SELECT revision,state,attempt_number FROM notification_delivery_settlements_108
		WHERE outbox_id=$1 FOR UPDATE`, command.OutboxID).Scan(&revision, &current, &attempt)
	if errors.Is(err, pgx.ErrNoRows) {
		revision, attempt = 0, 0
	} else if err != nil {
		return DeliverySettlement{}, err
	} else if current != DeliveryRetryWait && current != DeliveryPending {
		return DeliverySettlement{}, ErrSettlementConflict
	}
	if _, err := tx.Exec(ctx, `UPDATE notification_outbox SET status='cancelled',
		last_failure_code='cancelled',completed_at=$3,updated_at=$3 WHERE scope_id=$1 AND id=$2`,
		command.ScopeID, command.OutboxID, now); err != nil {
		return DeliverySettlement{}, err
	}
	auditID, err := s.appendSettlementSuccessAudit(ctx, tx, actor, "notification.delivery.cancel", command, now)
	if err != nil {
		return DeliverySettlement{}, err
	}
	sequence := revision + 1
	if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery_facts_108(
		scope_id,outbox_id,sequence,attempt_number,fact_kind,result_state,failure_code,
		actor_scope_id,actor_user_id,operation,request_id,request_digest,audit_event_id,observed_at,created_at
	) VALUES($1,$2,$3,$4,'cancelled','cancelled','cancelled',$5,$6,'notification.delivery.cancel',$7,$8,$9,$10,$10)`,
		command.ScopeID, command.OutboxID, sequence, attempt, actor.ScopeID, actor.UserID,
		command.RequestID, digest[:], auditID, now); err != nil {
		return DeliverySettlement{}, err
	}
	if revision == 0 {
		_, err = tx.Exec(ctx, `INSERT INTO notification_delivery_settlements_108(
			scope_id,outbox_id,state,revision,attempt_number,failure_code,completed_at,replay_of_outbox_id,created_at,updated_at
		) VALUES($1,$2,'cancelled',1,0,'cancelled',$3,$4,$3,$3)`, command.ScopeID, command.OutboxID, now, replayOf)
	} else {
		_, err = tx.Exec(ctx, `UPDATE notification_delivery_settlements_108 SET state='cancelled',
			revision=$2,failure_code='cancelled',retry_at=NULL,completed_at=$3,updated_at=$3 WHERE outbox_id=$1`,
			command.OutboxID, sequence, now)
	}
	if err != nil {
		return DeliverySettlement{}, err
	}
	if err := completeDeliveryCommandReceipt(ctx, tx, receiptID, digest, command.OutboxID, DeliveryCancelled, auditID, now); err != nil {
		return DeliverySettlement{}, err
	}
	return DeliverySettlement{ScopeID: command.ScopeID, OutboxID: command.OutboxID, State: DeliveryCancelled, Revision: sequence, Attempt: attempt, UpdatedAt: now}, nil
}

func (s *Store) replayDeliveryTx(
	ctx context.Context, tx pgx.Tx, actor SettlementActor, command DeliveryCommand,
	receiptID uuid.UUID, digest [sha256.Size]byte, now time.Time,
) (DeliveryReplayResult, error) {
	var eventID uuid.UUID
	var channel, templateID, subject, body, dedup, status string
	var templateVersion int64
	var params *string
	if err := tx.QueryRow(ctx, `SELECT event_id,channel,template_id,template_version,subject,body,dedup_key,status,template_params::text
		FROM notification_outbox WHERE scope_id=$1 AND id=$2 FOR UPDATE`, command.ScopeID, command.OutboxID).
		Scan(&eventID, &channel, &templateID, &templateVersion, &subject, &body, &dedup, &status, &params); err != nil {
		return DeliveryReplayResult{}, ErrSettlementConflict
	}
	if status != OutboxUnknown && status != OutboxPermanentFailed && status != OutboxExhausted && status != OutboxCancelled {
		return DeliveryReplayResult{}, ErrSettlementConflict
	}
	var generation int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(generation),0)+1 FROM notification_outbox
		WHERE event_id=$1 AND channel=$2`, eventID, channel).Scan(&generation); err != nil {
		return DeliveryReplayResult{}, err
	}
	newOutboxID, err := uuid.NewV7()
	if err != nil {
		return DeliveryReplayResult{}, err
	}
	newDedup := replayDedupKey(dedup, digest, generation)
	if _, err := tx.Exec(ctx, `INSERT INTO notification_outbox(
		id,scope_id,event_id,channel,template_id,template_version,subject,body,dedup_key,
		status,attempt_count,available_at,created_at,updated_at,generation,replay_of_outbox_id,template_params
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'pending',0,$10,$10,$10,$11,$12,$13::jsonb)`,
		newOutboxID, command.ScopeID, eventID, channel, templateID, templateVersion,
		subject, body, newDedup, now, generation, command.OutboxID, params); err != nil {
		return DeliveryReplayResult{}, err
	}
	auditID, err := s.appendSettlementSuccessAudit(ctx, tx, actor, "notification.delivery.replay", command, now)
	if err != nil {
		return DeliveryReplayResult{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery_facts_108(
		scope_id,outbox_id,sequence,attempt_number,fact_kind,result_state,
		actor_scope_id,actor_user_id,operation,request_id,request_digest,audit_event_id,
		replay_target_outbox_id,observed_at,created_at
	) VALUES($1,$2,1,0,'replay_created','pending',$3,$4,'notification.delivery.replay',$5,$6,$7,$8,$9,$9)`,
		command.ScopeID, newOutboxID, actor.ScopeID, actor.UserID, command.RequestID,
		digest[:], auditID, command.OutboxID, now); err != nil {
		return DeliveryReplayResult{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO notification_delivery_settlements_108(
		scope_id,outbox_id,state,revision,attempt_number,replay_of_outbox_id,created_at,updated_at
	) VALUES($1,$2,'pending',1,0,$3,$4,$4)`, command.ScopeID, newOutboxID, command.OutboxID, now); err != nil {
		return DeliveryReplayResult{}, err
	}
	if err := completeDeliveryCommandReceipt(ctx, tx, receiptID, digest, newOutboxID, DeliveryPending, auditID, now); err != nil {
		return DeliveryReplayResult{}, err
	}
	return DeliveryReplayResult{SourceOutboxID: command.OutboxID, NewOutboxID: newOutboxID, State: DeliveryPending}, nil
}

func authorizeSettlementCommand(ctx context.Context, tx pgx.Tx, actor SettlementActor, now time.Time) error {
	if err := protocol.AcquireShared(ctx, tx); err != nil {
		return err
	}
	if _, err := protocol.AcquireScopes(ctx, tx, []uuid.UUID{actor.ScopeID}); err != nil {
		return err
	}
	var scopeKind, accountStatus, membershipStatus string
	var tenantID *uuid.UUID
	var revokedAt *time.Time
	var expiresAt time.Time
	err := tx.QueryRow(ctx, `SELECT scope.kind,scope.tenant_id,account.status,membership.status,
		session.revoked_at,session.expires_at FROM auth_sessions session
		JOIN users account ON account.id=session.user_id
		JOIN memberships membership ON membership.scope_id=session.scope_id AND membership.user_id=session.user_id
		JOIN access_scopes scope ON scope.id=session.scope_id
		WHERE session.id=$1 AND session.user_id=$2 AND session.scope_id=$3
		FOR UPDATE OF session,account,membership,scope`, actor.SessionID, actor.UserID, actor.ScopeID).
		Scan(&scopeKind, &tenantID, &accountStatus, &membershipStatus, &revokedAt, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) || revokedAt != nil || !now.Before(expiresAt) || scopeKind != actor.ScopeKind {
		return ErrSettlementUnauthenticated
	}
	if err != nil {
		return err
	}
	if accountStatus != "active" || membershipStatus != "active" || scopeKind != "platform" || tenantID != nil {
		return ErrSettlementPermissionDenied
	}
	var granted bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM role_assignments assignment
		JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions permission ON permission.role_id=role.id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2
		AND permission.permission_name='system_configuration.manage')`, actor.ScopeID, actor.UserID).Scan(&granted); err != nil {
		return err
	}
	if !granted {
		return ErrSettlementPermissionDenied
	}
	return nil
}

func (s *Store) appendSettlementDeniedAudit(
	ctx context.Context, tx pgx.Tx, actor SettlementActor, operation, requestID string,
) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_events WHERE scope_id=$1
		AND actor_user_id=$2 AND action=$3 AND request_id=$4 AND result='denied')`,
		actor.ScopeID, actor.UserID, operation, requestID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	return s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: operation,
		ResourceType: "notification_delivery", ResourceID: operation,
		RequestID: requestID, Result: "denied",
		Payload: map[string]any{"reason_code": "permission_denied"},
	})
}

func (s *Store) appendSettlementSuccessAudit(
	ctx context.Context, tx pgx.Tx, actor SettlementActor, operation string,
	command DeliveryCommand, now time.Time,
) (uuid.UUID, error) {
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: operation,
		ResourceType: "notification_delivery", ResourceID: command.OutboxID.String(),
		RequestID: command.RequestID, Result: "success",
		Payload: map[string]any{"scope_id": command.ScopeID.String()},
	}); err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM audit_events WHERE scope_id=$1 AND actor_user_id=$2
		AND action=$3 AND request_id=$4 AND result='success'`, actor.ScopeID, actor.UserID,
		operation, command.RequestID).Scan(&id); err != nil {
		return uuid.Nil, err
	}
	return id, nil
}

func claimDeliveryCommandReceipt(
	ctx context.Context, tx pgx.Tx, actor SettlementActor, command DeliveryCommand,
	operation string, digest [sha256.Size]byte, now time.Time,
) (uuid.UUID, uuid.UUID, string, bool, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, uuid.Nil, "", false, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO notification_delivery_command_receipts_108(
		id,actor_scope_id,actor_user_id,operation,request_id,request_digest,
		source_scope_id,source_outbox_id,created_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
	ON CONFLICT(actor_scope_id,actor_user_id,operation,request_id) DO NOTHING RETURNING id`,
		id, actor.ScopeID, actor.UserID, operation, command.RequestID, digest[:],
		command.ScopeID, command.OutboxID, now).Scan(&id)
	if err == nil {
		return id, uuid.Nil, "", false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, "", false, err
	}
	var storedDigest []byte
	var resultOutbox *uuid.UUID
	var resultState *string
	var completedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT id,request_digest,result_outbox_id,result_state,completed_at
		FROM notification_delivery_command_receipts_108
		WHERE actor_scope_id=$1 AND actor_user_id=$2 AND operation=$3 AND request_id=$4 FOR UPDATE`,
		actor.ScopeID, actor.UserID, operation, command.RequestID).
		Scan(&id, &storedDigest, &resultOutbox, &resultState, &completedAt); err != nil {
		return uuid.Nil, uuid.Nil, "", false, err
	}
	if !bytes.Equal(storedDigest, digest[:]) || resultOutbox == nil || resultState == nil || completedAt == nil {
		return uuid.Nil, uuid.Nil, "", false, ErrSettlementConflict
	}
	return id, *resultOutbox, *resultState, true, nil
}

func completeDeliveryCommandReceipt(
	ctx context.Context, tx pgx.Tx, id uuid.UUID, digest [sha256.Size]byte,
	resultOutbox uuid.UUID, state DeliveryState, auditID uuid.UUID, now time.Time,
) error {
	command, err := tx.Exec(ctx, `UPDATE notification_delivery_command_receipts_108
		SET result_state=$3,result_outbox_id=$4,audit_event_id=$5,completed_at=$6
		WHERE id=$1 AND request_digest=$2 AND completed_at IS NULL`,
		id, digest[:], state, resultOutbox, auditID, now)
	if err != nil {
		return err
	}
	if command.RowsAffected() != 1 {
		return ErrSettlementConflict
	}
	return nil
}

func readSettlement(ctx context.Context, tx pgx.Tx, outboxID uuid.UUID) (DeliverySettlement, error) {
	var result DeliverySettlement
	result.OutboxID = outboxID
	if err := tx.QueryRow(ctx, `SELECT scope_id,state,revision,attempt_number,updated_at
		FROM notification_delivery_settlements_108 WHERE outbox_id=$1`, outboxID).
		Scan(&result.ScopeID, &result.State, &result.Revision, &result.Attempt, &result.UpdatedAt); err != nil {
		return DeliverySettlement{}, err
	}
	return result, nil
}

func readSettlementForUpdate(ctx context.Context, tx pgx.Tx, scopeID, outboxID uuid.UUID) (DeliverySettlement, error) {
	var result DeliverySettlement
	result.ScopeID, result.OutboxID = scopeID, outboxID
	if err := tx.QueryRow(ctx, `SELECT state,revision,attempt_number,updated_at
		FROM notification_delivery_settlements_108 WHERE scope_id=$1 AND outbox_id=$2 FOR UPDATE`,
		scopeID, outboxID).Scan(&result.State, &result.Revision, &result.Attempt, &result.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return DeliverySettlement{}, ErrSettlementConflict
		}
		return DeliverySettlement{}, err
	}
	return result, nil
}

func commitSettlementRead(ctx context.Context, tx pgx.Tx, result DeliverySettlement) (DeliverySettlement, error) {
	if err := tx.Commit(ctx); err != nil {
		return DeliverySettlement{}, err
	}
	return result, nil
}

func settlementDatabaseNow(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return time.Time{}, fmt.Errorf("read notification settlement time: %w", err)
	}
	return storeTime(now), nil
}

func validFailureCode(code string) bool {
	if code == "" || len(code) > 96 {
		return false
	}
	for index, character := range code {
		if index == 0 && (character < 'a' || character > 'z') {
			return false
		}
		if index > 0 && (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func validSettlementActor(actor SettlementActor) bool {
	return actor.UserID != uuid.Nil && actor.ScopeID != uuid.Nil && actor.SessionID != uuid.Nil &&
		(actor.ScopeKind == "platform" || actor.ScopeKind == "tenant")
}

func validCommandRequestID(value string) bool {
	return value != "" && len(value) <= 128 && validProviderIdentity(value)
}

func deliveryCommandDigest(operation string, command DeliveryCommand) [sha256.Size]byte {
	hash := sha256.New()
	for _, value := range []string{"cdnca-notification-delivery-command-v1", operation, command.ScopeID.String(), command.OutboxID.String()} {
		_ = binary.Write(hash, binary.BigEndian, uint32(len(value)))
		_, _ = hash.Write([]byte(value))
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func replayDedupKey(source string, digest [sha256.Size]byte, generation int) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("cdnca-notification-replay-v2"))
	_, _ = hash.Write([]byte(source))
	_, _ = hash.Write(digest[:])
	_ = binary.Write(hash, binary.BigEndian, uint64(generation))
	return fmt.Sprintf("notification-v2-%x", hash.Sum(nil))
}
