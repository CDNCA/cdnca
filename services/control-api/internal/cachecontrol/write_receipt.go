package cachecontrol

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// fix-cacheflow5: the receipt of a cache write by its Idempotency-Key, so a
// caller whose response was lost (network, timeout, 5xx) learns what the
// server did before it decides to send the write again.
//
// Accepted writes are read from the module's own idempotency records
// (cache_operations for a create/re-submit, completed cache_operation_commands
// for a retry/cancel). A definite refusal leaves no business row, so it is
// kept as a cache.write.reject audit event (result denied) carrying the key.
// Both are bound to the authenticated actor (scope, actor scope and user):
// another actor's key reads as never received.

type WriteAction string

const (
	WriteCreate   WriteAction = "create"
	WriteRetry    WriteAction = "retry"
	WriteCancel   WriteAction = "cancel"
	WriteResubmit WriteAction = "resubmit"
)

// writeRejectAction is outside cache.operation.%, whose audit triggers demand
// an operation row in a matching state.
const writeRejectAction = "cache.write.reject"

type WriteReceiptStatus string

const (
	WriteAccepted WriteReceiptStatus = "accepted"
	WriteRejected WriteReceiptStatus = "rejected"
)

// WriteReceiptRequest names one write: its action, the operation a
// retry/cancel/re-submit acts on (none for a create) and the key it was sent
// with (the batch key of a re-submit).
type WriteReceiptRequest struct {
	Action         WriteAction
	OperationID    uuid.UUID
	IdempotencyKey string
}

type WriteRejection struct {
	Code          string
	TargetOrdinal int
	TargetReason  string
}

// WriteReceipt: Operation is the accepted write's operation (the new one of a
// create/re-submit), Rejection the refusal. ErrNotFound: nothing recorded.
type WriteReceipt struct {
	Status    WriteReceiptStatus
	Operation Operation
	Rejection WriteRejection
	DecidedAt time.Time
}

func validWriteReceiptRequest(request WriteReceiptRequest) bool {
	switch request.Action {
	case WriteCreate:
		if request.OperationID != uuid.Nil {
			return false
		}
	case WriteRetry, WriteCancel, WriteResubmit:
		if request.OperationID == uuid.Nil {
			return false
		}
	default:
		return false
	}
	return validWriteMetadata(request.IdempotencyKey, "receipt")
}

func (store *Store) WriteReceipt(ctx context.Context, actor Actor, request WriteReceiptRequest) (WriteReceipt, error) {
	if ctx == nil || !validActor(actor) || !validWriteReceiptRequest(request) {
		return WriteReceipt{}, ErrInvalidInput
	}
	var result WriteReceipt
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if _, err := store.authorizeActor(ctx, tx, actor, "sites.read"); err != nil {
			return err
		}
		operationID, decidedAt, err := acceptedWrite(ctx, tx, actor, request)
		if err == nil {
			result.Status, result.DecidedAt = WriteAccepted, decidedAt
			result.Operation, err = loadOperation(ctx, tx, actor.ScopeID, operationID)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("read accepted cache write: %w", err)
		}
		var ordinal *string
		err = tx.QueryRow(ctx, `
			SELECT reason_code,payload->>'target_ordinal',COALESCE(payload->>'target_reason',''),occurred_at
			FROM audit_events
			WHERE scope_id=$1 AND actor_user_id=$2 AND action=$3 AND result='denied'
			  AND payload->>'actor_scope_id'=$4 AND payload->>'write'=$5
			  AND payload->>'idempotency_key'=$6 AND payload->>'operation_id'=$7
			ORDER BY stream_position DESC LIMIT 1`,
			actor.ScopeID, actor.UserID, writeRejectAction, actor.ActorScopeID.String(),
			string(request.Action), request.IdempotencyKey, operationText(request.OperationID)).Scan(
			&result.Rejection.Code, &ordinal, &result.Rejection.TargetReason, &result.DecidedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("read rejected cache write: %w", err)
		}
		if ordinal != nil {
			if result.Rejection.TargetOrdinal, err = strconv.Atoi(*ordinal); err != nil {
				return fmt.Errorf("rejected cache write has an invalid target ordinal")
			}
		}
		result.Status = WriteRejected
		return nil
	})
	if err != nil {
		return WriteReceipt{}, err
	}
	return result, nil
}

func acceptedWrite(ctx context.Context, tx pgx.Tx, actor Actor, request WriteReceiptRequest) (uuid.UUID, time.Time, error) {
	var operationID uuid.UUID
	var decidedAt time.Time
	var err error
	switch request.Action {
	case WriteCreate:
		err = tx.QueryRow(ctx, `SELECT id,created_at FROM cache_operations
			WHERE scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND idempotency_key=$4
			  AND parent_operation_id IS NULL AND idempotency_key NOT LIKE 'resubmit.%'`,
			actor.ScopeID, actor.ActorScopeID, actor.UserID, request.IdempotencyKey).Scan(&operationID, &decidedAt)
	case WriteResubmit:
		// A re-submit is a new top-level operation (parent_operation_id stays NULL;
		// parent only marks carrying-node follow-ups); its key embeds the source ID.
		err = tx.QueryRow(ctx, `SELECT id,created_at FROM cache_operations
			WHERE scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3 AND idempotency_key=$4
			  AND parent_operation_id IS NULL`,
			actor.ScopeID, actor.ActorScopeID, actor.UserID,
			resubmitKey(request.OperationID, request.IdempotencyKey)).Scan(&operationID, &decidedAt)
	default:
		err = tx.QueryRow(ctx, `SELECT operation_id,completed_at FROM cache_operation_commands
			WHERE scope_id=$1 AND actor_scope_id=$2 AND actor_user_id=$3
			  AND operation_id=$4 AND command=$5 AND idempotency_key=$6 AND completed_at IS NOT NULL`,
			actor.ScopeID, actor.ActorScopeID, actor.UserID, request.OperationID,
			string(request.Action), request.IdempotencyKey).Scan(&operationID, &decidedAt)
	}
	return operationID, decidedAt, err
}

func operationText(operationID uuid.UUID) string {
	if operationID == uuid.Nil {
		return ""
	}
	return operationID.String()
}

// writeRejectionCode is the stable code (the HTTP error code) of a definite
// refusal worth a receipt. Not found and permission refusals are not kept (the
// receipt answers them as never received, like another actor's key), nor an
// idempotency conflict (the key already names an accepted write), nor
// anything whose outcome is not a refusal.
func writeRejectionCode(err error) (WriteRejection, bool) {
	var target *TargetError
	switch {
	case errors.As(err, &target):
		return WriteRejection{Code: "invalid_request", TargetOrdinal: target.Ordinal, TargetReason: target.Reason}, true
	case errors.Is(err, ErrWildcardTargetHost):
		return WriteRejection{Code: "wildcard_target_host"}, true
	case errors.Is(err, ErrInvalidInput):
		return WriteRejection{Code: "invalid_request"}, true
	case errors.Is(err, ErrInvalidTransition):
		return WriteRejection{Code: "invalid_operation_transition"}, true
	case errors.Is(err, ErrRetriesExhausted):
		return WriteRejection{Code: "retries_exhausted"}, true
	case errors.Is(err, ErrEntitlementDenied):
		return WriteRejection{Code: "entitlement_denied"}, true
	case errors.Is(err, ErrSiteLocked):
		return WriteRejection{Code: "site_locked"}, true
	case errors.Is(err, ErrDailyLimitExceeded):
		return WriteRejection{Code: "daily_limit_exceeded"}, true
	case errors.Is(err, ErrNoCarryingNode):
		return WriteRejection{Code: "no_carrying_node"}, true
	case errors.Is(err, ErrTargetNodeUnavailable):
		return WriteRejection{Code: "target_node_unavailable"}, true
	case errors.Is(err, ErrWildcardPurgeUnsupported):
		return WriteRejection{Code: "wildcard_purge_unsupported"}, true
	default:
		return WriteRejection{}, false
	}
}

type rejectedWrite struct {
	action      WriteAction
	siteID      uuid.UUID
	operationID uuid.UUID
	key         string
	requestID   string
}

// withWriteRejection keeps the refusal cause as the write's receipt and
// returns cause (joined with the receipt failure, if any). It records nothing
// for an actor that may not read the scope, an invalid key or a cancelled
// request.
func (store *Store) withWriteRejection(ctx context.Context, actor Actor, write rejectedWrite, cause error) error {
	rejection, ok := writeRejectionCode(cause)
	if !ok || ctx == nil || ctx.Err() != nil || !validActor(actor) || !validWriteMetadata(write.key, write.requestID) {
		return cause
	}
	resourceType, resourceID := "cache_operation", write.operationID
	if write.action == WriteCreate {
		resourceType, resourceID = "site", write.siteID
	}
	payload := map[string]any{
		"write": string(write.action), "idempotency_key": write.key, "actor_scope_id": actor.ActorScopeID.String(),
		"operation_id": operationText(write.operationID), "reason_code": rejection.Code,
	}
	if rejection.TargetOrdinal > 0 {
		payload["target_ordinal"] = rejection.TargetOrdinal
		payload["target_reason"] = rejection.TargetReason
	}
	err := pgx.BeginFunc(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := store.authorizeActor(ctx, tx, actor, "sites.read"); err != nil {
			return errSkipWriteRejection
		}
		return store.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: writeRejectAction, ActorRef: auditActorRef(ctx),
			ResourceType: resourceType, ResourceID: resourceID.String(), RequestID: write.requestID,
			Result: "denied", ReasonCode: rejection.Code, Payload: payload,
		})
	})
	if err == nil || errors.Is(err, errSkipWriteRejection) {
		return cause
	}
	return errors.Join(cause, fmt.Errorf("record cache write refusal: %w", err))
}

var errSkipWriteRejection = errors.New("cache write refusal not recorded")
