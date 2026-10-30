package cachecontrolruntime

import (
	"context"
	"errors"
	"fmt"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	commonv1 "github.com/cdnca/cdnca/proto/gen/go/common/v1"
	"github.com/cdnca/cdnca/services/control-api/internal/cachecontrol"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CACHE-ADD-07: the cache runtime publishes the node cancels Cancel queued
// (cache_operation_cancel_deliveries) and settles the receipts the gateway
// puts on the cache status subject.
const (
	// cacheMessageKindHeader / cancelKind / cancelReceiptKind are the values
	// agent-gateway uses (nats_cache_commands.go CacheMessageKind*).
	cacheMessageKindHeader = "CDNCA-Cache-Message"
	cancelKind             = "cancel"
	cancelReceiptKind      = "cancel-receipt"
	cancelPublishBatch     = 64
)

type cancelStore interface {
	PendingCancels(context.Context, int) ([]cachecontrol.CancelDelivery, error)
	MarkCancelPublished(context.Context, uuid.UUID) error
	ExpireCancels(context.Context) (int, error)
	SettleCancel(context.Context, cachecontrol.CancelReceipt) (bool, error)
}

func buildCancel(delivery cachecontrol.CancelDelivery) *agentv1.CacheControlCancel {
	claim := cachecontrol.Claim{OperationID: delivery.OperationID, NodeID: delivery.NodeID, Attempt: delivery.Attempt}
	taskID := taskID(claim)
	return &agentv1.CacheControlCancel{
		Event: &commonv1.EventMetadata{
			EventId: stableUUID("cancel-event:" + delivery.ID.String()).String(), RequestId: stableUUID("cancel-request:" + delivery.ID.String()).String(),
			OccurredTime: timestamppb.New(delivery.RequestedAt), CorrelationId: delivery.OperationID.String(), TaskId: stringPointer(taskID),
		},
		CancelId: delivery.ID.String(), TaskId: taskID, ScopeId: delivery.ScopeID.String(), TenantId: delivery.TenantID.String(),
		SiteId: delivery.SiteID.String(), NodeId: delivery.NodeID.String(), ControlOperationId: delivery.OperationID.String(),
		LeaseId: delivery.LeaseID.String(), Attempt: delivery.Attempt, RequestedTime: timestamppb.New(delivery.RequestedAt),
	}
}

// publishCancels publishes queued cancels (Nats-Msg-Id dedupes a republish
// after a crash between publish and mark) and settles overdue ones.
func (runtime *Runtime) publishCancels(ctx context.Context) error {
	if runtime.cancels == nil {
		return nil
	}
	if _, err := runtime.cancels.ExpireCancels(ctx); err != nil {
		return err
	}
	pending, err := runtime.cancels.PendingCancels(ctx, cancelPublishBatch)
	if err != nil {
		return err
	}
	for _, delivery := range pending {
		if err := runtime.bus.PublishCancel(ctx, delivery.NodeID.String(), buildCancel(delivery)); err != nil {
			return fmt.Errorf("publish cache cancel %s: %w", delivery.ID, err)
		}
		if err := runtime.cancels.MarkCancelPublished(ctx, delivery.ID); err != nil {
			return err
		}
	}
	return nil
}

func cancelOutcome(outcome agentv1.CacheControlCancelOutcome) (cachecontrol.CancelConfirmation, bool) {
	switch outcome {
	case agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_CANCELLED:
		return cachecontrol.CancelConfirmed, true
	case agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_ALREADY_COMPLETED:
		return cachecontrol.CancelCompleted, true
	case agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_NOT_RECEIVED:
		return cachecontrol.CancelUnresponsive, true
	default:
		return "", false
	}
}

func (runtime *Runtime) processCancelReceipt(ctx context.Context, source delivery) (string, error) {
	if runtime.cancels == nil {
		return runtime.quarantine(ctx, source, "cancel_unsupported")
	}
	if len(source.Data()) == 0 || len(source.Data()) > runtime.config.MaxPayloadBytes {
		return runtime.quarantine(ctx, source, "payload_size")
	}
	receipt := new(agentv1.CacheControlCancelReceipt)
	if err := (proto.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(source.Data(), receipt); err != nil ||
		hasUnknownFields(receipt.ProtoReflect()) || receipt.Event == nil || receipt.SettledTime == nil ||
		receipt.SettledTime.CheckValid() != nil {
		return runtime.quarantine(ctx, source, "protobuf_invalid")
	}
	nodeID, nodeOK := canonicalUUID(receipt.NodeId)
	if !nodeOK || source.Subject() != runtime.config.StatusSubjectPrefix+"."+nodeID.String() {
		return runtime.quarantine(ctx, source, "subject_mismatch")
	}
	deliveryID, deliveryOK := canonicalUUID(receipt.CancelId)
	leaseID, leaseOK := canonicalUUID(receipt.LeaseId)
	eventID, eventOK := canonicalUUID(receipt.Event.EventId)
	outcome, outcomeOK := cancelOutcome(receipt.Outcome)
	if !deliveryOK || !leaseOK || !eventOK || !outcomeOK || receipt.Attempt == 0 ||
		receipt.SucceededTargets > 1000 || receipt.FailedTargets > 1000 || receipt.CancelledTargets > 1000 {
		return runtime.quarantine(ctx, source, "receipt_invalid")
	}
	_, err := runtime.cancels.SettleCancel(ctx, cachecontrol.CancelReceipt{
		DeliveryID: deliveryID, NodeID: nodeID, LeaseID: leaseID, Attempt: receipt.Attempt, EventID: eventID,
		Outcome: outcome, SucceededTargets: int(receipt.SucceededTargets), FailedTargets: int(receipt.FailedTargets),
		CancelledTargets: int(receipt.CancelledTargets), SettledAt: receipt.SettledTime.AsTime().UTC(),
	})
	if err != nil {
		if errors.Is(err, cachecontrol.ErrInvalidInput) {
			return runtime.quarantine(ctx, source, "receipt_invalid")
		}
		return runtime.nak(ctx, source, err)
	}
	// A receipt for a settled or unknown delivery (redelivery) is consumed.
	return runtime.ack(ctx, source)
}
