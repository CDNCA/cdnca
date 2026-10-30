package jobstate

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
)

const (
	maxAttempts      = maxRetries + 1
	maxClaimBatch    = 100
	minLeaseDuration = time.Second
	maxLeaseDuration = time.Hour
)

func validateCreate(input CreateInput) error {
	if input.TenantID == uuid.Nil || !validStableIdentifier(input.Kind) ||
		!validSafeText(input.Subject, maxSubjectRunes, false) ||
		!validIdempotencyKey(input.IdempotencyKey) || len(input.Payload) > maxPayloadBytes ||
		len(input.Items) == 0 || len(input.Items) > maxItems ||
		input.MaxAttempts == 0 || input.MaxAttempts > maxAttempts ||
		!validSafeText(input.RequestID, maxRequestIDRunes, false) ||
		!validSafeText(input.TraceID, maxTraceIDRunes, true) {
		return ErrInvalidRequest
	}
	seen := make(map[string]struct{}, len(input.Items))
	for _, item := range input.Items {
		if !validSafeText(item.ItemID, maxItemIDRunes, false) ||
			(item.NodeID != nil && *item.NodeID == uuid.Nil) {
			return ErrInvalidRequest
		}
		if _, exists := seen[item.ItemID]; exists {
			return ErrInvalidRequest
		}
		seen[item.ItemID] = struct{}{}
	}
	return nil
}

func digestCreate(input CreateInput) (RequestDigest, error) {
	type digestItem struct {
		ItemID string `json:"item_id"`
		NodeID string `json:"node_id,omitempty"`
	}
	items := make([]digestItem, len(input.Items))
	for index, item := range input.Items {
		items[index].ItemID = item.ItemID
		if item.NodeID != nil {
			items[index].NodeID = item.NodeID.String()
		}
	}
	encoded, err := json.Marshal(struct {
		Version     uint8        `json:"version"`
		Kind        string       `json:"kind"`
		Subject     string       `json:"subject"`
		Payload     []byte       `json:"payload"`
		Items       []digestItem `json:"items"`
		MaxAttempts uint32       `json:"max_attempts"`
	}{1, input.Kind, input.Subject, input.Payload, items, input.MaxAttempts})
	if err != nil {
		return RequestDigest{}, fmt.Errorf("%w: encode create digest", ErrInvalidRequest)
	}
	return sha256.Sum256(encoded), nil
}

func validateClaim(input ClaimInput) error {
	return validateLeaseFields(input.TenantID, input.Kind, input.WorkerID, input.Limit, input.LeaseDuration)
}

func validateHeartbeat(input HeartbeatInput) error {
	if input.JobID == uuid.Nil || input.Attempt == 0 || input.LeaseID == uuid.Nil {
		return ErrInvalidRequest
	}
	return validateLeaseFields(input.TenantID, "heartbeat", input.WorkerID, 1, input.LeaseDuration)
}

func validateLeaseFields(tenantID uuid.UUID, kind, workerID string, limit int, duration time.Duration) error {
	if tenantID == uuid.Nil || !validStableIdentifier(kind) ||
		!validSafeText(workerID, maxRequestIDRunes, false) || limit < 1 || limit > maxClaimBatch ||
		duration < minLeaseDuration || duration > maxLeaseDuration {
		return ErrInvalidRequest
	}
	return nil
}

func validateStoreReport(input ReportInput) error {
	if input.TenantID == uuid.Nil || input.JobID == uuid.Nil || input.LeaseID == uuid.Nil ||
		!validSafeText(input.WorkerID, maxRequestIDRunes, false) ||
		input.Report.Sequence > math.MaxInt64 {
		return ErrInvalidReport
	}
	return validateReport(input.Report)
}
