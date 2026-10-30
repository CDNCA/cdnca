package l4forward

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SetTrafficStatusTx is the package traffic enforcement's stop and restore of
// one forward (L4 traffic over the monthly limit is handled
// like HTTP): admin_status normal <-> traffic_exceeded only, with the next
// revision and its versioned intent (desired_state disabled / enabled), so
// the next publication withdraws or restores the forward on its nodes. A
// forward in any other state (locked, package_expired, deleted) is left
// alone and reported unchanged. The caller holds the subscription's
// enforcement head and the configuration scope; the row lock is SKIP LOCKED
// so a forward a tenant is editing converges on the next tick.
func (s *Store) SetTrafficStatusTx(ctx context.Context, tx pgx.Tx, streamID uuid.UUID, from, to string) (Forward, bool, error) {
	if tx == nil || streamID == uuid.Nil ||
		!(from == AdminStatusNormal && to == AdminStatusTrafficExceeded || from == AdminStatusTrafficExceeded && to == AdminStatusNormal) {
		return Forward{}, false, ErrInvalidInput
	}
	var locked uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM l4_forwards WHERE id=$1 AND admin_status=$2 AND deleted_at IS NULL
		FOR UPDATE SKIP LOCKED`, streamID, from).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return Forward{}, false, nil
	}
	if err != nil {
		return Forward{}, false, err
	}
	// The forward's own owner is the intent's author: the system has no user.
	item, err := scanForwardWithoutIntent(tx.QueryRow(ctx, `
		UPDATE l4_forwards SET admin_status=$3, revision=revision+1, updated_at=$4
		WHERE id=$1 AND admin_status=$2 AND deleted_at IS NULL
		RETURNING `+forwardColumns("l4_forwards")+`,
		          (SELECT display_name FROM users WHERE id = l4_forwards.owner_user_id)`,
		streamID, from, to, s.now().UTC()))
	if errors.Is(err, pgx.ErrNoRows) {
		return Forward{}, false, nil
	}
	if err != nil {
		return Forward{}, false, err
	}
	if err := loadAdditionalListeners(ctx, tx, &item); err != nil {
		return Forward{}, false, err
	}
	intent, err := s.appendPublishIntent(ctx, tx, item.ownerUserID, item, "update")
	if err != nil {
		return Forward{}, false, err
	}
	item.PublishIntent = intent
	return item, true, nil
}
