package securitypolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/cdnca/cdnca/services/control-api/internal/packageaddon"
	"github.com/google/uuid"
)

// SEC-ACCOUNT-04: batch enable / disable / delete of WAF rule libraries the
// actor can manage. Each item is its own CAS write (id + version) under an
// item idempotency key derived from the batch key, so retrying the same batch
// replays items already written. System (licensed) libraries are refused.
// The batch key itself is bound to the request digest (action + items in
// order, migration 637): the same key with another body is ErrIdempotencyConflict
// before any item is written, and a completed batch replays its stored results.

const (
	BatchEnable  = "enable"
	BatchDisable = "disable"
	BatchDelete  = "delete"

	maxBatchItems = 100
)

type BatchItem struct {
	ID      uuid.UUID `json:"id"`
	Version int64     `json:"version"`
}

type BatchRequest struct {
	Action         string
	Items          []BatchItem
	IdempotencyKey string
	RequestID      string
}

// BatchItemResult status: ok, unchanged, version_conflict, system_protected,
// not_found, forbidden, in_use, unsupported_kind, idempotency_conflict,
// rejected (validation or package feature), error (the batch stopped here),
// not_attempted (after an error).
type BatchItemResult struct {
	ID       uuid.UUID `json:"id"`
	Status   string    `json:"status"`
	Version  int64     `json:"version,omitempty"`
	Replayed bool      `json:"replayed,omitempty"`
}

func validBatch(actor Actor, request BatchRequest) bool {
	if !validActor(actor) || !validWriteMetadata(request.IdempotencyKey, request.RequestID) ||
		(request.Action != BatchEnable && request.Action != BatchDisable && request.Action != BatchDelete) ||
		len(request.Items) < 1 || len(request.Items) > maxBatchItems {
		return false
	}
	seen := make(map[uuid.UUID]bool, len(request.Items))
	for _, item := range request.Items {
		if item.ID == uuid.Nil || item.Version < 1 || seen[item.ID] {
			return false
		}
		seen[item.ID] = true
	}
	return true
}

func batchItemKey(batchKey string, id uuid.UUID) string {
	sum := sha256.Sum256([]byte(batchKey + ":" + id.String()))
	return "batch-" + hex.EncodeToString(sum[:20])
}

func (s *Service) Batch(ctx context.Context, actor Actor, request BatchRequest) ([]BatchItemResult, error) {
	if !validBatch(actor, request) {
		return nil, ErrInvalidInput
	}
	digest := batchDigest(request)
	stored, replayed, err := s.store.claimBatch(ctx, actor, request.IdempotencyKey, digest)
	if err != nil {
		return nil, err
	}
	if replayed {
		return stored, nil
	}
	results := make([]BatchItemResult, len(request.Items))
	stopped := false
	for index, item := range request.Items {
		results[index] = BatchItemResult{ID: item.ID, Status: "not_attempted"}
		if stopped {
			continue
		}
		result, err := s.batchItem(ctx, actor, request, item)
		if err != nil {
			results[index].Status = "error"
			stopped = true
			continue
		}
		results[index] = result
	}
	// A batch stopped by a store error stays open so the same request can finish it.
	if !stopped {
		if err := s.store.completeBatch(ctx, actor, request.IdempotencyKey, digest, results); err != nil {
			return nil, err
		}
	}
	return results, nil
}

func batchDigest(request BatchRequest) [32]byte {
	var canonical strings.Builder
	canonical.WriteString("security_policy.batch\n" + request.Action)
	for _, item := range request.Items {
		canonical.WriteString("\n" + item.ID.String() + ":" + strconv.FormatInt(item.Version, 10))
	}
	return sha256.Sum256([]byte(canonical.String()))
}

// batchItem returns an error only for failures that stop the batch (store or
// context errors); refusals of this item are its status.
func (s *Service) batchItem(ctx context.Context, actor Actor, request BatchRequest, item BatchItem) (BatchItemResult, error) {
	result := BatchItemResult{ID: item.ID}
	key := batchItemKey(request.IdempotencyKey, item.ID)
	if request.Action == BatchDelete {
		current, err := s.store.Get(ctx, actor, item.ID)
		if err == nil && current.Kind != KindWAF {
			result.Status = "unsupported_kind"
			return result, nil
		}
		if err == nil {
			if _, protected := licensedWAFMetadata(current); protected {
				result.Status = "system_protected"
				return result, nil
			}
		}
		// A deleted policy is not found by Get; the store replays a delete
		// this batch already made before it checks for deletion.
		if err != nil && !errors.Is(err, ErrNotFound) {
			return result, err
		}
		deleted, err := s.delete(ctx, actor, DeleteRequest{
			ID: item.ID, ExpectedRevision: item.Version, IdempotencyKey: key, RequestID: request.RequestID,
		})
		if err != nil {
			return batchRefusal(result, err)
		}
		result.Status, result.Replayed = "ok", deleted.Replayed
		return result, nil
	}
	current, err := s.store.Get(ctx, actor, item.ID)
	if err != nil {
		return batchRefusal(result, err)
	}
	if current.Kind != KindWAF {
		result.Status = "unsupported_kind"
		return result, nil
	}
	if _, protected := licensedWAFMetadata(current); protected {
		result.Status = "system_protected"
		return result, nil
	}
	enabled := request.Action == BatchEnable
	if current.Revision == item.Version && current.Enabled == enabled {
		result.Status, result.Version = "unchanged", current.Revision
		return result, nil
	}
	fields := PolicyFields{
		Kind: current.Kind, Name: current.Name, Description: current.Description, Enabled: enabled,
		DefaultAction: current.DefaultAction, Rules: cloneRules(current.Rules),
		CCSettings: cloneCCSettings(current.CCSettings), WAFSettings: cloneWAFSettings(current.WAFSettings),
	}
	written, err := s.update(ctx, actor, UpdateRequest{
		ID: item.ID, ExpectedRevision: item.Version, Fields: fields, IdempotencyKey: key, RequestID: request.RequestID,
	})
	if err != nil {
		return batchRefusal(result, err)
	}
	result.Status, result.Version, result.Replayed = "ok", written.Policy.Revision, written.Replayed
	return result, nil
}

func batchRefusal(result BatchItemResult, err error) (BatchItemResult, error) {
	switch {
	case errors.Is(err, ErrRevisionConflict):
		result.Status = "version_conflict"
	case errors.Is(err, ErrNotFound):
		result.Status = "not_found"
	case errors.Is(err, ErrPermissionDenied):
		result.Status = "forbidden"
	case errors.Is(err, ErrInUse):
		result.Status = "in_use"
	case errors.Is(err, ErrIdempotencyConflict):
		result.Status = "idempotency_conflict"
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrConflict), errors.Is(err, ErrIPListUnavailable), errors.Is(err, ErrStringSetUnavailable),
		errors.Is(err, ErrStringSetTargetMismatch),
		errors.Is(err, ErrQuickBlockUnsupported), errors.Is(err, packageaddon.ErrFeatureDenied):
		result.Status = "rejected"
	default:
		return result, err
	}
	return result, nil
}
