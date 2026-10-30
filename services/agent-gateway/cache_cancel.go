package gateway

import (
	"context"
	"fmt"
	"strconv"
	"time"

	agentv1 "github.com/cdnca/cdnca/proto/gen/go/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// cacheControlCancelAPIVersion is CACHE_CONTROL_CANCEL v1 (fz-x3,
// CACHE-ADD-07): the gateway forwards a cache cancel from the node's cache
// command subject and publishes the node's receipt on the cache status
// subject before it acknowledges the cancel.
const cacheControlCancelAPIVersion = 1

func cacheControlCancelCapabilityFromFeatures(features []*agentv1.Capability) (bool, error) {
	seen := false
	for _, capability := range features {
		if capability == nil || capability.Name != agentv1.CapabilityName_CAPABILITY_NAME_CACHE_CONTROL_CANCEL {
			continue
		}
		if seen || capability.ApiVersion != cacheControlCancelAPIVersion {
			return false, fmt.Errorf("cache cancel capability is duplicated or unsupported")
		}
		seen = true
	}
	return seen, nil
}

func (g *Gateway) validateCacheControlCancel(cancel *agentv1.CacheControlCancel, nodeID string) error {
	if cancel == nil || cacheControlMessageHasUnknown(cancel.ProtoReflect()) {
		return fmt.Errorf("cache cancel is missing or contains unknown fields")
	}
	if err := g.validateEventMetadata(cancel.Event); err != nil || cancel.Event.OccurredTime == nil ||
		cancel.Event.OccurredTime.CheckValid() != nil {
		return fmt.Errorf("cache cancel event is invalid")
	}
	for name, value := range map[string]string{
		"cancel_id": cancel.CancelId, "scope_id": cancel.ScopeId, "tenant_id": cancel.TenantId, "site_id": cancel.SiteId,
		"node_id": cancel.NodeId, "control_operation_id": cancel.ControlOperationId, "lease_id": cancel.LeaseId,
	} {
		if err := g.validateUUID("cache_cancel."+name, value); err != nil {
			return err
		}
	}
	wantTaskID := "cc-" + cancel.ControlOperationId + "-" + cancel.NodeId + "-" + strconv.FormatUint(uint64(cancel.Attempt), 10)
	if cancel.NodeId != nodeID || cancel.Attempt == 0 || cancel.TaskId != wantTaskID ||
		cancel.RequestedTime == nil || cancel.RequestedTime.CheckValid() != nil {
		return fmt.Errorf("cache cancel identity is invalid")
	}
	return nil
}

func (g *Gateway) validateCacheControlCancelReceipt(receipt *agentv1.CacheControlCancelReceipt, cancel *agentv1.CacheControlCancel) error {
	if receipt == nil || cacheControlMessageHasUnknown(receipt.ProtoReflect()) {
		return fmt.Errorf("cache cancel receipt is missing or contains unknown fields")
	}
	if err := g.validateEventMetadata(receipt.Event); err != nil || receipt.Event.CausationId == nil ||
		receipt.Event.GetCausationId() != cancel.Event.EventId {
		return fmt.Errorf("cache cancel receipt event is invalid")
	}
	if receipt.CancelId != cancel.CancelId || receipt.TaskId != cancel.TaskId || receipt.NodeId != cancel.NodeId ||
		receipt.LeaseId != cancel.LeaseId || receipt.Attempt != cancel.Attempt ||
		receipt.SettledTime == nil || receipt.SettledTime.CheckValid() != nil {
		return fmt.Errorf("cache cancel receipt does not match the cancel")
	}
	switch receipt.Outcome {
	case agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_CANCELLED,
		agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_ALREADY_COMPLETED,
		agentv1.CacheControlCancelOutcome_CACHE_CONTROL_CANCEL_OUTCOME_NOT_RECEIVED:
	default:
		return fmt.Errorf("cache cancel receipt outcome is invalid")
	}
	return nil
}

// pendingCacheCancels are cancels sent on this session and not yet answered,
// by cancel_id; each keeps every delivery of it to acknowledge together.
type pendingCacheCancel struct {
	cancel     *agentv1.CacheControlCancel
	deliveries []CacheCommandDelivery
}

type pendingCacheCancelSet map[string]*pendingCacheCancel

// settleCacheCancelReceipt publishes the receipt on the cache status subject
// and then acknowledges the cancel deliveries it answers.
func (g *Gateway) settleCacheCancelReceipt(ctx context.Context, nodeID string, receipt *agentv1.CacheControlCancelReceipt, pending pendingCacheCancelSet) error {
	entry := pending[receipt.GetCancelId()]
	if entry == nil {
		return status.Error(codes.FailedPrecondition, "cache cancel receipt has no pending cancel")
	}
	if err := g.validateCacheControlCancelReceipt(receipt, entry.cancel); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	operationCtx, cancel := context.WithTimeout(ctx, g.config.CommandOperationTimeout)
	err := g.cache.PublishCacheCancelReceipt(operationCtx, nodeID, receipt)
	cancel()
	if err != nil {
		return status.Error(codes.Unavailable, "cache cancel receipt could not be persisted")
	}
	for len(entry.deliveries) > 0 {
		operationCtx, cancel = context.WithTimeout(ctx, g.config.CommandOperationTimeout)
		err = entry.deliveries[0].Ack(operationCtx)
		cancel()
		if err != nil {
			return status.Error(codes.Unavailable, "cache cancel could not be acknowledged")
		}
		entry.deliveries = entry.deliveries[1:]
	}
	delete(pending, receipt.CancelId)
	return nil
}

// nakPendingCacheCancels returns unanswered cancels to the queue when the
// session ends; the next session delivers them again.
func nakPendingCacheCancels(pending pendingCacheCancelSet, timeout time.Duration) {
	for id, entry := range pending {
		for _, delivery := range entry.deliveries {
			nakCacheCommand(delivery, timeout)
		}
		delete(pending, id)
	}
}
