package qualitydiagnostics

import (
	"context"
	"errors"
	"reflect"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/google/uuid"
)

type ProductionAccessAuthority struct {
	source analyticslog.FinalizedAccessReader
}

func NewProductionAccessAuthority(source analyticslog.FinalizedAccessReader) (*ProductionAccessAuthority, error) {
	if source == nil || reflect.ValueOf(source).Kind() == reflect.Ptr && reflect.ValueOf(source).IsNil() {
		return nil, ErrInvalidConfiguration
	}
	return &ProductionAccessAuthority{source: source}, nil
}

func (authority *ProductionAccessAuthority) ReadFinalizedAccess(
	ctx context.Context,
	request ReadRequest,
) (ReadPage, error) {
	if authority == nil || authority.source == nil || ctx == nil {
		return ReadPage{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return ReadPage{}, err
	}
	sourceRequest := analyticslog.FinalizedAccessRequest{
		TenantID: request.Scope.TenantID.String(), From: request.Filter.From, To: request.Filter.To,
		Category: string(request.Filter.Category), Limit: request.Limit, Cursor: request.SourceCursor,
	}
	if request.Filter.SiteID != uuid.Nil {
		sourceRequest.SiteID = request.Filter.SiteID.String()
	}
	if request.Filter.NodeID != uuid.Nil {
		sourceRequest.NodeID = request.Filter.NodeID.String()
	}
	if request.Snapshot != nil {
		snapshot := *request.Snapshot
		sourceRequest.Snapshot = &snapshot
	}
	sourcePage, err := authority.source.ReadFinalizedAccess(ctx, sourceRequest)
	if operationErr := operationError(ctx, err); operationErr != nil {
		return ReadPage{}, operationErr
	}
	if err != nil {
		return ReadPage{}, productionAuthorityError(err)
	}
	page := ReadPage{
		Facts:            make([]ScopedAccessFact, 0, len(sourcePage.Facts)),
		NextSourceCursor: sourcePage.NextCursor, Snapshot: sourcePage.Snapshot,
	}
	for _, fact := range sourcePage.Facts {
		tenantID, parseErr := uuid.Parse(fact.TenantID)
		if parseErr != nil || tenantID == uuid.Nil || tenantID.String() != fact.TenantID || tenantID != request.Scope.TenantID {
			return ReadPage{}, ErrInvalidResponse
		}
		page.Facts = append(page.Facts, ScopedAccessFact{TenantID: tenantID, Log: fact.Log})
	}
	return page, nil
}

func productionAuthorityError(err error) error {
	switch {
	case errors.Is(err, analyticslog.ErrInvalidInput):
		return ErrInvalidRequest
	case errors.Is(err, analyticslog.ErrInvalidResponse):
		return ErrInvalidResponse
	default:
		return ErrUnavailable
	}
}

var _ FinalizedLatestStateAuthority = (*ProductionAccessAuthority)(nil)
