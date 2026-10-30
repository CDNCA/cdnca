package identityverification

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// AuthorizeProviderWrite applies the same live session, account, membership,
// tenant and RBAC lock protocol as the existing case write path.
func (s *Service) AuthorizeProviderWrite(ctx context.Context, tx pgx.Tx, actor Actor) error {
	if tx == nil || !validActor(actor) {
		return ErrPermissionDenied
	}
	return s.authorizeWrite(ctx, tx, actor, actor.ScopeID, permissionSelfManage)
}
