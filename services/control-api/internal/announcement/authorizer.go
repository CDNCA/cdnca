package announcement

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type denyAuthorizer struct{}

func (denyAuthorizer) Authorize(context.Context, pgx.Tx, Actor, string) error {
	return ErrPermissionDenied
}
