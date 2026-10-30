package cachecontrol

import (
	"context"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
)

// CACHE-ADD-07: a cancel is delivered to every node that was running the
// operation (cache_operation_cancel_deliveries, migration 526). The
// operation itself is cancelled at once; this is only the node's
// confirmation.

// cacheCancelAPIVersion is the CACHE_CONTROL_CANCEL version a node needs to
// take a cancel.
const cacheCancelAPIVersion = 1

// CancelConfirmationWindow is how long a node has to answer a cancel before
// it is recorded as not responding.
const CancelConfirmationWindow = 5 * time.Minute

type CancelConfirmation string

const (
	CancelPending      CancelConfirmation = "pending"
	CancelConfirmed    CancelConfirmation = "cancelled"
	CancelCompleted    CancelConfirmation = "completed"
	CancelUnresponsive CancelConfirmation = "unresponsive"
	CancelUnsupported  CancelConfirmation = "unsupported"
)

// CancelDelivery is one node cancel to publish (pending, not yet published).
type CancelDelivery struct {
	ID          uuid.UUID
	ScopeID     uuid.UUID
	TenantID    uuid.UUID
	SiteID      uuid.UUID
	OperationID uuid.UUID
	NodeID      uuid.UUID
	Attempt     uint32
	LeaseID     uuid.UUID
	RequestedAt time.Time
}

// CancelReceipt is a node's answer to one cancel delivery.
type CancelReceipt struct {
	DeliveryID       uuid.UUID
	NodeID           uuid.UUID
	LeaseID          uuid.UUID
	Attempt          uint32
	EventID          uuid.UUID
	Outcome          CancelConfirmation
	SucceededTargets int
	FailedTargets    int
	CancelledTargets int
	SettledAt        time.Time
}

func declaresCacheCancel(snapshot []byte) bool {
	var capabilities agentv1.AgentCapabilities
	if len(snapshot) == 0 || proto.Unmarshal(snapshot, &capabilities) != nil {
		return false
	}
	for _, capability := range capabilities.GetFeatures() {
		if capability.GetName() == agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL_CANCEL &&
			capability.GetApiVersion() >= cacheCancelAPIVersion {
			return true
		}
	}
	return false
}

// recordCancelDeliveries writes one row per running attempt of the
// operation: pending for a node whose latest session declares
// CACHE_CONTROL_CANCEL, unsupported (settled now) for an older one.
func recordCancelDeliveries(ctx context.Context, tx pgx.Tx, scopeID, operationID, commandID uuid.UUID, now time.Time) error {
	rows, err := tx.Query(ctx, `
		SELECT attempt.node_id,attempt.attempt,attempt.lease_id,
		       (SELECT facts.capabilities_snapshot FROM node_session_capabilities facts
		        WHERE facts.node_id=attempt.node_id ORDER BY facts.session_epoch DESC LIMIT 1)
		FROM cache_operation_node_attempts attempt
		WHERE attempt.scope_id=$1 AND attempt.operation_id=$2 AND attempt.state='running'
		ORDER BY attempt.node_id,attempt.attempt FOR UPDATE OF attempt`, scopeID, operationID)
	if err != nil {
		return fmt.Errorf("read running cache attempts to cancel: %w", err)
	}
	type running struct {
		nodeID  uuid.UUID
		attempt int
		leaseID uuid.UUID
		capable bool
	}
	var attempts []running
	for rows.Next() {
		var item running
		var snapshot []byte
		if err := rows.Scan(&item.nodeID, &item.attempt, &item.leaseID, &snapshot); err != nil {
			rows.Close()
			return fmt.Errorf("scan running cache attempt: %w", err)
		}
		item.capable = declaresCacheCancel(snapshot)
		attempts = append(attempts, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range attempts {
		state, settled := CancelPending, any(nil)
		if !item.capable {
			state, settled = CancelUnsupported, now
		}
		if _, err := tx.Exec(ctx, `INSERT INTO cache_operation_cancel_deliveries (
			id,scope_id,operation_id,node_id,attempt,lease_id,command_id,state,requested_at,deadline_at,settled_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (scope_id,operation_id,node_id,attempt) DO NOTHING`,
			uuid.New(), scopeID, operationID, item.nodeID, item.attempt, item.leaseID, commandID, string(state),
			now, now.Add(CancelConfirmationWindow), settled); err != nil {
			return fmt.Errorf("record cache cancel delivery: %w", err)
		}
	}
	return nil
}

// PendingCancels lists cancels not yet published, oldest first.
func (store *Store) PendingCancels(ctx context.Context, limit int) ([]CancelDelivery, error) {
	if ctx == nil || limit < 1 || limit > 1000 {
		return nil, ErrInvalidInput
	}
	rows, err := store.pool.Query(ctx, `
		SELECT delivery.id,delivery.scope_id,operation.tenant_id,operation.site_id,delivery.operation_id,
		       delivery.node_id,delivery.attempt,delivery.lease_id,delivery.requested_at
		FROM cache_operation_cancel_deliveries delivery
		JOIN cache_operations operation ON operation.scope_id=delivery.scope_id AND operation.id=delivery.operation_id
		WHERE delivery.state='pending' AND delivery.published_at IS NULL
		ORDER BY delivery.requested_at,delivery.id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("read pending cache cancels: %w", err)
	}
	defer rows.Close()
	var result []CancelDelivery
	for rows.Next() {
		var item CancelDelivery
		var attempt int
		if err := rows.Scan(&item.ID, &item.ScopeID, &item.TenantID, &item.SiteID, &item.OperationID,
			&item.NodeID, &attempt, &item.LeaseID, &item.RequestedAt); err != nil {
			return nil, fmt.Errorf("scan pending cache cancel: %w", err)
		}
		item.Attempt = uint32(attempt)
		result = append(result, item)
	}
	return result, rows.Err()
}

// MarkCancelPublished records that the cancel is on the node's command subject.
func (store *Store) MarkCancelPublished(ctx context.Context, deliveryID uuid.UUID) error {
	if ctx == nil || deliveryID == uuid.Nil {
		return ErrInvalidInput
	}
	_, err := store.pool.Exec(ctx, `UPDATE cache_operation_cancel_deliveries SET published_at=$2
		WHERE id=$1 AND state='pending' AND published_at IS NULL`, deliveryID, store.timestamp())
	if err != nil {
		return fmt.Errorf("mark cache cancel published: %w", err)
	}
	return nil
}

// ExpireCancels records pending cancels past their window as not responding.
func (store *Store) ExpireCancels(ctx context.Context) (int, error) {
	if ctx == nil {
		return 0, ErrInvalidInput
	}
	now := store.timestamp()
	tag, err := store.pool.Exec(ctx, `UPDATE cache_operation_cancel_deliveries SET state='unresponsive',settled_at=$1
		WHERE state='pending' AND deadline_at <= $1`, now)
	if err != nil {
		return 0, fmt.Errorf("expire cache cancels: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// SettleCancel applies a node receipt. A receipt that arrives after the
// window (unresponsive) still replaces it: the node's answer is the fact.
// A redelivered receipt (same event) is a no-op.
func (store *Store) SettleCancel(ctx context.Context, receipt CancelReceipt) (bool, error) {
	if ctx == nil || receipt.DeliveryID == uuid.Nil || receipt.NodeID == uuid.Nil || receipt.LeaseID == uuid.Nil ||
		receipt.EventID == uuid.Nil || receipt.Attempt == 0 || receipt.SettledAt.IsZero() ||
		receipt.SucceededTargets < 0 || receipt.FailedTargets < 0 || receipt.CancelledTargets < 0 {
		return false, ErrInvalidInput
	}
	switch receipt.Outcome {
	case CancelConfirmed, CancelCompleted:
	case CancelUnresponsive:
		// NOT_RECEIVED: the node does not hold the task (it never got it or
		// already dropped it); recorded as not confirmed.
	default:
		return false, ErrInvalidInput
	}
	applied := false
	err := pgx.BeginTxFunc(ctx, store.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var scopeID, operationID uuid.UUID
		var row pgx.Row
		if receipt.Outcome == CancelUnresponsive {
			row = tx.QueryRow(ctx, `UPDATE cache_operation_cancel_deliveries SET state='unresponsive',settled_at=$5
				WHERE id=$1 AND node_id=$2 AND lease_id=$3 AND attempt=$4 AND state='pending'
				RETURNING scope_id,operation_id`,
				receipt.DeliveryID, receipt.NodeID, receipt.LeaseID, int(receipt.Attempt), receipt.SettledAt)
		} else {
			row = tx.QueryRow(ctx, `UPDATE cache_operation_cancel_deliveries SET state=$5,succeeded_targets=$6,
					failed_targets=$7,cancelled_targets=$8,settled_at=$9,receipt_event_id=$10
				WHERE id=$1 AND node_id=$2 AND lease_id=$3 AND attempt=$4 AND state IN ('pending','unresponsive')
				RETURNING scope_id,operation_id`,
				receipt.DeliveryID, receipt.NodeID, receipt.LeaseID, int(receipt.Attempt), string(receipt.Outcome),
				receipt.SucceededTargets, receipt.FailedTargets, receipt.CancelledTargets, receipt.SettledAt, receipt.EventID)
		}
		if err := row.Scan(&scopeID, &operationID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil // settled already or unknown delivery: no new fact, no audit
			}
			return fmt.Errorf("settle cache cancel: %w", err)
		}
		if err := store.auditor.Append(ctx, tx, cancelReceiptAuditEvent(scopeID, operationID, receipt)); err != nil {
			return fmt.Errorf("audit cache cancel receipt: %w", err)
		}
		applied = true
		return nil
	})
	if err != nil {
		return false, err
	}
	return applied, nil
}

// cancelReceiptAuditEvent is the cache.cancel.receipt audit fact written with
// the settled delivery row: the node (no user) answered the cancel of one
// cache operation attempt. The request ID is the receipt event so a
// redelivered receipt cannot be confused with a later one.
func cancelReceiptAuditEvent(scopeID, operationID uuid.UUID, receipt CancelReceipt) audit.Event {
	return audit.Event{
		ScopeID: scopeID, Action: "cache.cancel.receipt",
		ResourceType: "cache_operation", ResourceID: operationID.String(),
		RequestID: "cache-cancel-receipt:" + receipt.EventID.String(), Result: "success",
		Payload: map[string]any{
			"settled_at": receipt.SettledAt.UTC().Format(time.RFC3339Nano),
			"cancel_id": receipt.DeliveryID.String(), "node_id": receipt.NodeID.String(),
			"lease_id": receipt.LeaseID.String(), "attempt": receipt.Attempt,
			"outcome":           string(receipt.Outcome),
			"succeeded_targets": receipt.SucceededTargets, "failed_targets": receipt.FailedTargets,
			"cancelled_targets": receipt.CancelledTargets,
		},
	}
}
