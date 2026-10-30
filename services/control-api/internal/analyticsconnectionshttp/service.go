package analyticsconnectionshttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticsconnections"
	"github.com/google/uuid"
)

type Service struct{ store RetentionStore }

func NewService(store RetentionStore) (*Service, error) {
	if nilDependency(store) {
		return nil, ErrInvalidRequest
	}
	return &Service{store: store}, nil
}

func (service *Service) Query(ctx context.Context, request RetentionRequest) (RetentionPage, error) {
	if service == nil || nilDependency(service.store) || ctx == nil {
		return RetentionPage{}, ErrInvalidRequest
	}
	if err := ctx.Err(); err != nil {
		return RetentionPage{}, err
	}
	if !canonicalUUIDText(request.TenantID) || !canonicalUUIDText(request.SubscriptionID) ||
		request.From.IsZero() || request.To.IsZero() || request.From.Location() != time.UTC ||
		request.To.Location() != time.UTC || !request.From.Before(request.To) ||
		request.To.Sub(request.From) > maximumRetentionWindow || request.Limit < 1 || request.Limit > maximumRetentionLimit {
		return RetentionPage{}, ErrInvalidRequest
	}
	rows, err := service.store.QueryRetention(ctx, RetentionStoreQuery{
		RetentionQuery: analyticsconnections.RetentionQuery{
			TenantID: request.TenantID, SubscriptionID: request.SubscriptionID, From: request.From, To: request.To,
		},
		Limit: request.Limit + 1,
	})
	if err != nil {
		return RetentionPage{}, normalizeStoreError(ctx, err)
	}
	if len(rows) > request.Limit {
		return RetentionPage{}, ErrResponseTooLarge
	}
	page := RetentionPage{Items: make([]RetentionItem, 0, len(rows))}
	var previous *analyticsconnections.RetentionRow
	for _, row := range rows {
		if !validRetentionRow(row, request, previous) {
			return RetentionPage{}, ErrInvalidResponse
		}
		page.Items = append(page.Items, RetentionItem{
			Metric: row.Metric, TenantID: row.TenantID, SubscriptionID: row.SubscriptionID,
			PeriodStart: row.PeriodStart, PeriodEnd: row.PeriodEnd, Value: row.Value,
			FinalizedThrough: row.FinalizedThrough, SourceWatermark: row.SourceWatermark,
			EvidenceDigest: hex.EncodeToString(row.EvidenceDigest[:]), RetentionUntil: row.RetentionUntil,
		})
		copyRow := row
		previous = &copyRow
	}
	return page, nil
}

func validRetentionRow(row analyticsconnections.RetentionRow, request RetentionRequest, previous *analyticsconnections.RetentionRow) bool {
	if row.Metric != "connections" || row.TenantID != request.TenantID || row.SubscriptionID != request.SubscriptionID ||
		row.Value == 0 || row.SourceWatermark == 0 || row.PeriodStart.IsZero() || row.PeriodEnd.IsZero() ||
		row.PeriodStart.Location() != time.UTC || row.PeriodEnd.Location() != time.UTC ||
		row.FinalizedThrough.Location() != time.UTC || row.RetentionUntil.Location() != time.UTC ||
		!row.PeriodStart.Before(row.PeriodEnd) || row.PeriodStart.Before(request.From) || row.PeriodEnd.After(request.To) ||
		!row.FinalizedThrough.Equal(row.PeriodEnd) ||
		!row.RetentionUntil.Equal(row.PeriodEnd.Add(analyticsconnections.DefaultRetentionTTL)) ||
		row.EvidenceDigest == ([sha256.Size]byte{}) {
		return false
	}
	if previous == nil {
		return true
	}
	return row.PeriodStart.After(previous.PeriodStart) ||
		row.PeriodStart.Equal(previous.PeriodStart) && row.PeriodEnd.After(previous.PeriodEnd)
}

func normalizeStoreError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case errors.Is(err, analyticsconnections.ErrRetentionResponseTooLarge):
		return ErrResponseTooLarge
	case errors.Is(err, analyticsconnections.ErrRetentionInvalidResponse),
		errors.Is(err, analyticsconnections.ErrRetentionScopeMismatch),
		errors.Is(err, analyticsconnections.ErrRetentionOrder),
		errors.Is(err, analyticsconnections.ErrRetentionDuplicate),
		errors.Is(err, analyticsconnections.ErrRetentionExpired):
		return ErrInvalidResponse
	default:
		return ErrUnavailable
	}
}

func canonicalUUIDText(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
