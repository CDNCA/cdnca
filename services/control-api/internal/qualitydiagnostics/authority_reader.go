package qualitydiagnostics

import (
	"context"
	"errors"
	"reflect"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/analyticsrealtime"
)

// FinalizedLatestStateAuthority reads a diagnostics page and its finalized
// analytics snapshot in one authority operation.
type FinalizedLatestStateAuthority interface {
	ReadFinalizedAccess(context.Context, ReadRequest) (ReadPage, error)
}

type AuthorityReaderAdapter struct {
	authority FinalizedLatestStateAuthority
}

func NewAuthorityReaderAdapter(authority FinalizedLatestStateAuthority) (*AuthorityReaderAdapter, error) {
	if authority == nil || reflect.ValueOf(authority).Kind() == reflect.Ptr && reflect.ValueOf(authority).IsNil() {
		return nil, ErrInvalidConfiguration
	}
	return &AuthorityReaderAdapter{authority: authority}, nil
}

func (adapter *AuthorityReaderAdapter) ReadFinalizedLatest(ctx context.Context, request ReadRequest) (ReadPage, error) {
	if adapter == nil || adapter.authority == nil || ctx == nil {
		return ReadPage{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return ReadPage{}, err
	}
	var expected *analyticsrealtime.Snapshot
	if request.Snapshot != nil {
		value := *request.Snapshot
		exact := value
		expected = &value
		request.Snapshot = &exact
	}
	page, err := adapter.authority.ReadFinalizedAccess(ctx, request)
	if operationErr := operationError(ctx, err); operationErr != nil {
		return ReadPage{}, operationErr
	}
	if err != nil {
		return ReadPage{}, stableAuthorityError(err)
	}
	if expected != nil && !sameSnapshot(*expected, page.Snapshot) {
		return ReadPage{}, ErrInvalidSnapshot
	}
	return page, nil
}

func stableAuthorityError(err error) error {
	for _, stable := range []error{
		ErrInvalidRequest, ErrInvalidCursor, ErrInvalidSnapshot, ErrInvalidResponse,
		ErrPermissionDenied, ErrScopeForbidden, ErrUnavailable,
	} {
		if errors.Is(err, stable) {
			return stable
		}
	}
	switch {
	case errors.Is(err, analyticslog.ErrInvalidInput), errors.Is(err, analyticsrealtime.ErrInvalidRequest):
		return ErrInvalidRequest
	case errors.Is(err, analyticslog.ErrInvalidResponse), errors.Is(err, analyticsrealtime.ErrInvalidResponse):
		return ErrInvalidResponse
	case errors.Is(err, analyticsrealtime.ErrInvalidSnapshot):
		return ErrInvalidSnapshot
	default:
		return ErrUnavailable
	}
}
