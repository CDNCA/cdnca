package analyticsconnectionshttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
	"github.com/google/uuid"
)

type DLQService struct {
	store DeadLetterStore
}

type deadLetterPagedStore interface {
	ListDeadLettersPage(context.Context, analyticsconnections.DeadLetterQuery) ([]analyticsconnections.DeadLetterReceiptView, uint64, error)
}

func NewDLQService(store DeadLetterStore) (*DLQService, error) {
	if nilDependency(store) {
		return nil, ErrDeadLetterInvalidRequest
	}
	return &DLQService{store: store}, nil
}

func (service *DLQService) List(ctx context.Context, request DeadLetterListRequest) (DeadLetterPage, error) {
	if service == nil || nilDependency(service.store) || ctx == nil {
		return DeadLetterPage{}, ErrDeadLetterInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return DeadLetterPage{}, err
	}
	if request.TenantID != "" && !canonicalDeadLetterUUID(request.TenantID) || request.Limit < 1 || request.Limit > maximumDeadLetterLimit {
		return DeadLetterPage{}, ErrDeadLetterInvalidRequest
	}
	query := analyticsconnections.DeadLetterQuery{
		TenantID: request.TenantID, AfterSequence: request.AfterSequence, Limit: request.Limit,
	}
	var rows []analyticsconnections.DeadLetterReceiptView
	var nextAfterSequence uint64
	var err error
	if pagedStore, ok := service.store.(deadLetterPagedStore); ok {
		rows, nextAfterSequence, err = pagedStore.ListDeadLettersPage(ctx, query)
	} else {
		query.Limit++
		rows, err = service.store.ListDeadLetters(ctx, query)
	}
	if err != nil {
		return DeadLetterPage{}, normalizeDeadLetterStoreError(ctx, err)
	}
	page, err := buildDeadLetterPage(rows, request, nextAfterSequence)
	if err != nil {
		return DeadLetterPage{}, err
	}
	return page, nil
}

func (service *DLQService) Get(ctx context.Context, tenantID, deadLetterID string) (DeadLetterItem, error) {
	if service == nil || nilDependency(service.store) || ctx == nil {
		return DeadLetterItem{}, ErrDeadLetterInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return DeadLetterItem{}, err
	}
	if (tenantID != "" && !canonicalDeadLetterUUID(tenantID)) || !canonicalDeadLetterDigest(deadLetterID) {
		return DeadLetterItem{}, ErrDeadLetterInvalidRequest
	}
	receipt, err := service.store.GetDeadLetter(ctx, deadLetterID)
	if err != nil {
		return DeadLetterItem{}, normalizeDeadLetterStoreError(ctx, err)
	}
	if !validDeadLetterReceipt(receipt) {
		return DeadLetterItem{}, ErrDeadLetterInvalidResponse
	}
	if tenantID != "" && receipt.TenantID != tenantID {
		return DeadLetterItem{}, ErrDeadLetterPermission
	}
	return deadLetterItem(receipt), nil
}

func buildDeadLetterPage(rows []analyticsconnections.DeadLetterReceiptView, request DeadLetterListRequest, nextAfterSequence uint64) (DeadLetterPage, error) {
	maximumRows := request.Limit
	if nextAfterSequence == 0 {
		maximumRows++
	}
	if len(rows) > maximumRows {
		return DeadLetterPage{}, ErrDeadLetterTooLarge
	}
	hasExtraRow := nextAfterSequence == 0 && len(rows) > request.Limit
	if hasExtraRow {
		rows = rows[:request.Limit]
	}
	items := make([]DeadLetterItem, 0, len(rows))
	var previous uint64
	for _, receipt := range rows {
		if !validDeadLetterReceipt(receipt) || request.TenantID != "" && receipt.TenantID != request.TenantID ||
			receipt.DeadLetterSequence <= request.AfterSequence ||
			previous != 0 && receipt.DeadLetterSequence <= previous {
			return DeadLetterPage{}, ErrDeadLetterInvalidResponse
		}
		items = append(items, deadLetterItem(receipt))
		previous = receipt.DeadLetterSequence
	}
	page := DeadLetterPage{Items: items}
	if nextAfterSequence != 0 {
		if nextAfterSequence <= request.AfterSequence || previous != 0 && nextAfterSequence < previous {
			return DeadLetterPage{}, ErrDeadLetterInvalidResponse
		}
		page.NextAfterSequence = nextAfterSequence
	} else if hasExtraRow && len(items) != 0 {
		page.NextAfterSequence = items[len(items)-1].DeadLetterSequence
	}
	return page, nil
}

func deadLetterItem(receipt analyticsconnections.DeadLetterReceiptView) DeadLetterItem {
	return DeadLetterItem{
		DeadLetterID: receipt.DeadLetterID, BatchID: receipt.BatchID, ReceiptID: receipt.ReceiptID,
		EventID: receipt.EventID, TenantID: receipt.TenantID, Reason: string(receipt.FailureReason),
		Attempt: receipt.Attempt, MaxDeliver: receipt.MaxDeliver, SourceStream: receipt.SourceStream,
		SourceSequence: receipt.SourceStreamSequence, ConsumerSequence: receipt.ConsumerSequence,
		DeadLetterStream: receipt.DeadLetterStream, DeadLetterSequence: receipt.DeadLetterSequence,
		CreatedAt: receipt.CreatedAt.UTC(), SettledAt: utcTimePointer(receipt.SettledAt),
		PayloadDigest: receipt.PayloadSHA256,
	}
}

func validDeadLetterReceipt(receipt analyticsconnections.DeadLetterReceiptView) bool {
	base := receipt.MetadataVersion == analyticsconnections.DeliveryMetadataVersion &&
		canonicalDeadLetterDigest(receipt.DeadLetterID) && canonicalDeadLetterDigest(receipt.EnvelopeSHA256) &&
		validDeadLetterID(receipt.SourceStream) && validDeadLetterID(receipt.Durable) &&
		receipt.SourceStreamSequence != 0 && receipt.ConsumerSequence != 0 && receipt.Attempt != 0 &&
		receipt.MaxDeliver != 0 && receipt.Attempt <= receipt.MaxDeliver && validDeadLetterReason(receipt.FailureReason) &&
		canonicalDeadLetterDigest(receipt.PayloadSHA256) && validDeadLetterID(receipt.DeadLetterStream) &&
		receipt.DeadLetterSequence != 0 && !receipt.CreatedAt.IsZero() && receipt.CreatedAt.Location() == time.UTC &&
		!receipt.SettledAt.IsZero() && receipt.SettledAt.Location() == time.UTC
	if !base {
		return false
	}
	if receipt.Poison {
		return receipt.TenantID == "" && receipt.BatchID == "" && receipt.ReceiptID == "" && receipt.EventID == "" &&
			receipt.CanonicalEventSHA256 == "" && receipt.EvidenceSHA256 == ""
	}
	return canonicalDeadLetterUUID(receipt.TenantID) && validDeadLetterID(receipt.BatchID) &&
		validDeadLetterID(receipt.ReceiptID) && validDeadLetterID(receipt.EventID) &&
		canonicalDeadLetterDigest(receipt.CanonicalEventSHA256) && canonicalDeadLetterDigest(receipt.EvidenceSHA256)
}

func validDeadLetterReason(reason analyticsconnections.DeliveryFailureReason) bool {
	switch reason {
	case analyticsconnections.DeliveryFailureInvalid, analyticsconnections.DeliveryFailureReceiptConflict,
		analyticsconnections.DeliveryFailureClickHouseUnavailable, analyticsconnections.DeliveryFailureOutcomeUnknown,
		analyticsconnections.DeliveryFailureMaxDeliver:
		return true
	default:
		return false
	}
}

func normalizeDeadLetterStoreError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, ErrDeadLetterNotFound) || errors.Is(err, analyticsconnections.ErrDeadLetterReceiptNotFound) {
		return ErrDeadLetterNotFound
	}
	if errors.Is(err, analyticsconnections.ErrDeadLetterReceiptInvalidRequest) {
		return ErrDeadLetterInvalidRequest
	}
	if errors.Is(err, analyticsconnections.ErrDeadLetterReceiptInvalid) || errors.Is(err, analyticsconnections.ErrDeadLetterReceiptConflict) {
		return ErrDeadLetterInvalidResponse
	}
	if errors.Is(err, analyticsconnections.ErrDeadLetterReceiptUnavailable) {
		return ErrDeadLetterUnavailable
	}
	return ErrDeadLetterUnavailable
}

func canonicalDeadLetterUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func canonicalDeadLetterDigest(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	for _, item := range decoded {
		if item != 0 {
			return true
		}
	}
	return false
}

func validDeadLetterID(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, char := range value {
		if unicode.IsSpace(char) || unicode.IsControl(char) || char == '/' {
			return false
		}
	}
	return true
}

func utcTimePointer(value time.Time) *time.Time {
	result := value.UTC()
	return &result
}
