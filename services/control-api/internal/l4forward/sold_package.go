package l4forward

import (
	"context"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/cnameallocation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// DeleteSoldPackageTx keeps the normal immutable stream intent and audit facts;
// the caller publishes the resulting tenant configuration before commit.
func (s *Store) DeleteSoldPackageTx(ctx context.Context, tx pgx.Tx, actor Actor, scopeID, subscriptionID uuid.UUID, requestID string) (int, error) {
	if tx == nil || actor.ScopeKind != "platform" || actor.UserID == uuid.Nil {
		return 0, ErrPermissionDenied
	}
	rows, err := tx.Query(ctx, `SELECT id FROM l4_forwards WHERE scope_id=$1 AND package_subscription_id=$2 AND deleted_at IS NULL ORDER BY id FOR UPDATE`, scopeID, subscriptionID)
	if err != nil {
		return 0, err
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		item, deleted, err := s.lockForward(ctx, tx, actor, id)
		if err != nil {
			return 0, err
		}
		if deleted {
			return 0, ErrNotFound
		}
		now := s.now().UTC()
		if _, err = tx.Exec(ctx, `UPDATE l4_forwards SET deleted_at=$2,updated_at=$2,updated_by_user_id=$3,revision=revision+1 WHERE id=$1 AND deleted_at IS NULL`, id, now, actor.UserID); err != nil {
			return 0, err
		}
		if err = cnameallocation.RetireStreamOwnersTx(ctx, tx, scopeID, id, cnameallocation.RetireStreamDeleted, now); err != nil {
			return 0, err
		}
		item.Revision++
		item.UpdatedAt = now
		intent, err := s.appendPublishIntent(ctx, tx, actor.UserID, item, "delete")
		if err != nil {
			return 0, err
		}
		if err = s.auditor.Append(ctx, tx, audit.Event{ScopeID: scopeID, ActorUserID: &actor.UserID, Action: "stream.package.delete", ResourceType: "stream", ResourceID: id.String(), RequestID: requestID, Result: "success", Payload: map[string]any{"package_subscription_id": subscriptionID.String(), "revision": item.Revision, "publish_intent_id": intent.ID.String()}}); err != nil {
			return 0, err
		}
	}
	return len(ids), nil
}
