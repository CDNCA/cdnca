package analyticsdiagnostic

import (
	"context"
	"errors"
	"reflect"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
)

type AnalyticsLogReader interface {
	ListAccess(context.Context, analyticslog.Actor, analyticslog.QueryRequest) (analyticslog.AccessPage, error)
}

type AnalyticsLogAdapter struct {
	reader AnalyticsLogReader
}

func NewAnalyticsLogAdapter(reader AnalyticsLogReader) (*AnalyticsLogAdapter, error) {
	if reader == nil || reflect.ValueOf(reader).Kind() == reflect.Ptr && reflect.ValueOf(reader).IsNil() {
		return nil, ErrInvalidConfiguration
	}
	return &AnalyticsLogAdapter{reader: reader}, nil
}

func (adapter *AnalyticsLogAdapter) ReadAccess(ctx context.Context, actor Actor, request QueryRequest) (analyticslog.AccessPage, error) {
	if adapter == nil || adapter.reader == nil {
		return analyticslog.AccessPage{}, ErrInvalidConfiguration
	}
	page, err := adapter.reader.ListAccess(ctx, actor, analyticslog.QueryRequest{
		Audience: request.Audience,
		TenantID: request.TenantID,
		Filter: analyticslog.Filter{
			From: request.From, To: request.To, SiteID: request.SiteID, NodeID: request.NodeID,
		},
		Limit: request.Limit, Cursor: request.Cursor,
	})
	if err == nil {
		return page, nil
	}
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return analyticslog.AccessPage{}, err
	case errors.Is(err, analyticslog.ErrInvalidInput):
		return analyticslog.AccessPage{}, ErrInvalidInput
	case errors.Is(err, analyticslog.ErrPermissionDenied):
		return analyticslog.AccessPage{}, ErrPermissionDenied
	case errors.Is(err, analyticslog.ErrScopeForbidden):
		return analyticslog.AccessPage{}, ErrScopeForbidden
	case errors.Is(err, analyticslog.ErrInvalidResponse):
		return analyticslog.AccessPage{}, ErrInvalidResponse
	default:
		return analyticslog.AccessPage{}, ErrEvidenceUnavailable
	}
}
