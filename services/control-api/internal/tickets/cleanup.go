package tickets

import (
	"context"
	"errors"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CleanupPendingAttachments deletes up to limit uploads that were never bound
// to a message within PendingUploadWindow. Each one is handled in its own
// transaction holding the row lock (SKIP LOCKED, so replicas and a racing
// bind do not collide): the object goes first and only then the row, so a
// store failure leaves the row for the next run instead of a dangling object.
func (service *Service) CleanupPendingAttachments(ctx context.Context, limit int) (int, error) {
	if service.objects == nil || limit < 1 {
		return 0, nil
	}
	removed := 0
	for removed < limit {
		done, err := service.cleanupOne(ctx)
		if err != nil {
			return removed, err
		}
		if !done {
			return removed, nil
		}
		removed++
	}
	return removed, nil
}

// cleanupOne returns false when nothing (deletable) is left.
func (service *Service) cleanupOne(ctx context.Context) (bool, error) {
	cutoff := service.clock().Add(-PendingUploadWindow)
	found := false
	err := pgx.BeginTxFunc(ctx, service.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		var id, scopeID, ownerID uuid.UUID
		var key string
		var size int64
		err := tx.QueryRow(ctx, `SELECT id,owner_scope_id,owner_user_id,object_key,size_bytes FROM ticket_attachments
			WHERE message_id IS NULL AND created_at < $1 ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, cutoff).
			Scan(&id, &scopeID, &ownerID, &key, &size)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := service.objects.Delete(ctx, scopeID, key); err != nil {
			service.logf("ticket attachment %s cleanup: object delete failed: %v", id, err)
			return errCleanupDeferred
		}
		if _, err := tx.Exec(ctx, `DELETE FROM ticket_attachments WHERE id=$1 AND message_id IS NULL`, id); err != nil {
			return err
		}
		found = true
		return service.auditor.Append(ctx, tx, audit.Event{ScopeID: scopeID, Action: "ticket.attachment.expire",
			ResourceType: "ticket_attachment", ResourceID: id.String(), RequestID: "ticket-attachment-cleanup",
			Result: "success", Payload: map[string]any{"owner_user_id": ownerID.String(), "size_bytes": size}})
	})
	if errors.Is(err, errCleanupDeferred) {
		return false, nil
	}
	return found, err
}

var errCleanupDeferred = errors.New("ticket attachment cleanup deferred")

// RunCleanup removes expired pending uploads every interval until ctx ends.
func (service *Service) RunCleanup(ctx context.Context, interval time.Duration) {
	if service.objects == nil || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if removed, err := service.CleanupPendingAttachments(ctx, 500); err != nil && ctx.Err() == nil {
			service.logf("ticket attachment cleanup: %v", err)
		} else if removed > 0 {
			service.logf("ticket attachment cleanup removed %d expired uploads", removed)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
