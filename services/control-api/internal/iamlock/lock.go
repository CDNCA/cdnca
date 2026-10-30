package iamlock

import (
	"context"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/iamlock/protocol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidInput      = protocol.ErrInvalidInput
	ErrProtocolRequired  = protocol.ErrProtocolRequired
	ErrLockOrder         = protocol.ErrLockOrder
	ErrUpgradeForbidden  = protocol.ErrUpgradeForbidden
	ErrPermissionDenied  = protocol.ErrPermissionDenied
	ErrInvalidCredential = fmt.Errorf("%w: invalid IAM credential", ErrPermissionDenied)
	ErrUnavailable       = protocol.ErrUnavailable
)

func AcquireShared(ctx context.Context, tx pgx.Tx) error {
	return protocol.AcquireShared(ctx, tx)
}

func AcquireExclusive(ctx context.Context, tx pgx.Tx) error {
	return protocol.AcquireExclusive(ctx, tx)
}

func AcquireScopes(ctx context.Context, tx pgx.Tx, scopes []uuid.UUID) ([]uuid.UUID, error) {
	return protocol.AcquireScopes(ctx, tx, scopes)
}
