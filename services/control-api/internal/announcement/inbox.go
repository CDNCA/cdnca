package announcement

import (
	"context"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) ListInbox(ctx context.Context, actor Actor, request ListRequest) (InboxPage, error) {
	if request.Limit == 0 {
		request.Limit = DefaultPageSize
	}
	if request.Limit < 1 || request.Limit > MaxPageSize {
		return InboxPage{}, ErrInvalidInput
	}
	if request.ReadFilter != "" && request.ReadFilter != "unread" && request.ReadFilter != "read" && request.ReadFilter != "popup" {
		return InboxPage{}, ErrInvalidInput
	}
	if request.Offset < 0 || request.Offset > MaxInboxOffset || (request.Offset > 0 && request.Cursor != "") {
		return InboxPage{}, ErrInvalidInput
	}
	var cursor *pageCursor
	if request.Cursor != "" {
		decoded, err := decodeCursor(s.cursorKeys, request.Cursor)
		if err != nil {
			return InboxPage{}, err
		}
		if decoded.ScopeID != actor.ScopeID || decoded.UserID != actor.UserID || decoded.Filter != normalizeReadFilter(request.ReadFilter) {
			return InboxPage{}, ErrInvalidCursor
		}
		cursor = &decoded
	}
	var result InboxPage
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if err := s.authorizeSelf(ctx, tx, actor); err != nil {
			return err
		}
		watermark := int64(0)
		if cursor != nil {
			watermark = cursor.Watermark
		} else {
			var err error
			watermark, err = announcementStateWatermark(ctx, tx, actor.ScopeID)
			if err != nil {
				return err
			}
		}
		var err error
		result, err = s.listInboxSnapshot(ctx, tx, actor, request, cursor, watermark)
		return err
	})
	if err != nil {
		return InboxPage{}, fmt.Errorf("list announcement inbox: %w", err)
	}
	return result, nil
}

func (s *Store) MarkDelivered(ctx context.Context, actor Actor, request StateRequest) (InboxState, error) {
	return s.markState(ctx, actor, request, false)
}

func (s *Store) MarkRead(ctx context.Context, actor Actor, request StateRequest) (InboxState, error) {
	return s.markState(ctx, actor, request, true)
}

func (s *Store) markState(ctx context.Context, actor Actor, request StateRequest, markRead bool) (InboxState, error) {
	if request.EventID == uuid.Nil || request.ExpectedRevision < 1 || !validMeta(request.IdempotencyKey, request.RequestID) {
		return InboxState{}, ErrInvalidInput
	}
	operation := operationDeliver
	if markRead {
		operation = operationRead
	}
	digest, err := requestDigest(request)
	if err != nil {
		return InboxState{}, err
	}
	var result InboxState
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := s.authorizeSelf(ctx, tx, actor); err != nil {
			return err
		}
		replay, found, err := s.claimWrite(ctx, tx, actor, operation, request.IdempotencyKey, digest)
		if err != nil {
			return err
		}
		if found {
			return decodeReplay(replay, &result)
		}
		err = tx.QueryRow(ctx, `SELECT event_id,delivered_at,read_at,revision
			FROM announcement_inbox_states WHERE tenant_scope_id=$1 AND event_id=$2 AND user_id=$3
			FOR UPDATE`, actor.ScopeID, request.EventID, actor.UserID).
			Scan(&result.EventID, &result.DeliveredAt, &result.ReadAt, &result.Revision)
		if errors.Is(err, pgx.ErrNoRows) {
			err = tx.QueryRow(ctx, `SELECT event_id,delivered_at,read_at,revision
				FROM platform_announcement_recipients_141
				WHERE tenant_scope_id=$1 AND event_id=$2 AND user_id=$3 FOR UPDATE`,
				actor.ScopeID, request.EventID, actor.UserID).
				Scan(&result.EventID, &result.DeliveredAt, &result.ReadAt, &result.Revision)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
			return s.markGlobalInboxState(ctx, tx, actor, request, markRead, &result, operation)
		}
		if err != nil {
			return err
		}
		if result.Revision != request.ExpectedRevision {
			return ErrRevisionConflict
		}
		alreadyApplied := (!markRead && result.DeliveredAt != nil) || (markRead && result.ReadAt != nil)
		if !alreadyApplied {
			now := storeTime(s.now())
			if markRead {
				command, err := tx.Exec(ctx, `UPDATE announcement_inbox_states SET
					delivered_at=COALESCE(delivered_at,$4),read_at=$4,revision=revision+1,updated_at=$4
					WHERE tenant_scope_id=$1 AND event_id=$2 AND user_id=$3 AND revision=$5`,
					actor.ScopeID, request.EventID, actor.UserID, now, request.ExpectedRevision)
				if err != nil {
					return err
				}
				if command.RowsAffected() != 1 {
					return ErrRevisionConflict
				}
			} else {
				command, err := tx.Exec(ctx, `UPDATE announcement_inbox_states SET
					delivered_at=$4,revision=revision+1,updated_at=$4
					WHERE tenant_scope_id=$1 AND event_id=$2 AND user_id=$3 AND revision=$5 AND delivered_at IS NULL`,
					actor.ScopeID, request.EventID, actor.UserID, now, request.ExpectedRevision)
				if err != nil {
					return err
				}
				if command.RowsAffected() != 1 {
					return ErrRevisionConflict
				}
			}
			if err := tx.QueryRow(ctx, `SELECT event_id,delivered_at,read_at,revision
				FROM announcement_inbox_states WHERE tenant_scope_id=$1 AND event_id=$2 AND user_id=$3`,
				actor.ScopeID, request.EventID, actor.UserID).
				Scan(&result.EventID, &result.DeliveredAt, &result.ReadAt, &result.Revision); err != nil {
				return err
			}
		}
		if err := s.auditor.Append(ctx, tx, audit.Event{
			ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: operation,
			ResourceType: "announcement_inbox_event", ResourceID: request.EventID.String(),
			RequestID: request.RequestID, Result: "success",
			Payload: map[string]any{"revision": result.Revision, "changed": !alreadyApplied},
		}); err != nil {
			return fmt.Errorf("audit announcement inbox state: %w", err)
		}
		return s.completeWrite(ctx, tx, actor, operation, request.IdempotencyKey, result)
	})
	if err != nil {
		return InboxState{}, fmt.Errorf("mark announcement inbox state: %w", err)
	}
	return result, nil
}

func (s *Store) markGlobalInboxState(
	ctx context.Context,
	tx pgx.Tx,
	actor Actor,
	request StateRequest,
	markRead bool,
	result *InboxState,
	operation string,
) error {
	if result.Revision != request.ExpectedRevision {
		return ErrRevisionConflict
	}
	alreadyApplied := !markRead && result.DeliveredAt != nil || markRead && result.ReadAt != nil
	if !alreadyApplied {
		now := storeTime(s.now())
		query := `UPDATE platform_announcement_recipients_141 SET
			delivered_at=$4,revision=revision+1,updated_at=$4
			WHERE tenant_scope_id=$1 AND event_id=$2 AND user_id=$3 AND revision=$5 AND delivered_at IS NULL`
		if markRead {
			query = `UPDATE platform_announcement_recipients_141 SET
				delivered_at=COALESCE(delivered_at,$4),read_at=$4,revision=revision+1,updated_at=$4
				WHERE tenant_scope_id=$1 AND event_id=$2 AND user_id=$3 AND revision=$5`
		}
		command, err := tx.Exec(ctx, query, actor.ScopeID, request.EventID, actor.UserID, now, request.ExpectedRevision)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrRevisionConflict
		}
		if err := tx.QueryRow(ctx, `SELECT event_id,delivered_at,read_at,revision
			FROM platform_announcement_recipients_141 WHERE tenant_scope_id=$1 AND event_id=$2 AND user_id=$3`,
			actor.ScopeID, request.EventID, actor.UserID).
			Scan(&result.EventID, &result.DeliveredAt, &result.ReadAt, &result.Revision); err != nil {
			return err
		}
	}
	if err := s.auditor.Append(ctx, tx, audit.Event{
		ScopeID: actor.ScopeID, ActorUserID: &actor.UserID, Action: operation,
		ResourceType: "platform_announcement_inbox_event", ResourceID: request.EventID.String(),
		RequestID: request.RequestID, Result: "success",
		Payload: map[string]any{"revision": result.Revision, "changed": !alreadyApplied},
	}); err != nil {
		return fmt.Errorf("audit global announcement inbox state: %w", err)
	}
	return s.completeWrite(ctx, tx, actor, operation, request.IdempotencyKey, *result)
}
