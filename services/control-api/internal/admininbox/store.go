// Package admininbox is the platform administrator message center:
// operations events
// (notification.PlatformEventType) copied for each platform recipient at
// enqueue time, with unread counts, mark-read and mark-all-read.
package admininbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	MaxPageSize   = 100
	retentionDays = 180
)

var (
	ErrNotFound     = errors.New("admin inbox message not found")
	ErrInvalidInput = errors.New("admin inbox request invalid")
)

type Message struct {
	ID        uuid.UUID         `json:"id"`
	EventType string            `json:"event_type"`
	Params    map[string]string `json:"params"`
	CreatedAt time.Time         `json:"created_at"`
	ReadAt    *time.Time        `json:"read_at"`
}

type Page struct {
	Items      []Message `json:"items"`
	Unread     int       `json:"unread"`
	Total      int       `json:"total"`
	NextCursor *string   `json:"next_cursor"`
	UnreadOnly bool      `json:"unread_only"`
	PageSize   int       `json:"page_size"`
}

type Store struct {
	pool    *pgxpool.Pool
	auditor *audit.Log
	now     func() time.Time
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool, auditor: audit.New(pool), now: time.Now}
}

// Recipient is an authenticated user in the scope of the session: platform
// members read the operations events, tenant members their in-app notices
// (notification.InboxEventType, N23). Each reads only its scope's messages.
type Recipient struct {
	UserID    uuid.UUID
	ScopeID   uuid.UUID
	RequestID string
}

// UnreadCount backs the header badge.
func (s *Store) UnreadCount(ctx context.Context, recipient Recipient) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM admin_inbox_messages WHERE recipient_user_id=$1 AND scope_id=$2 AND read_at IS NULL`,
		recipient.UserID, recipient.ScopeID).Scan(&count)
	return count, err
}

// List returns the newest messages first. cursor is the created_at|id of the
// last item of the previous page.
func (s *Store) List(ctx context.Context, recipient Recipient, unreadOnly bool, pageSize int, cursor string) (Page, error) {
	if pageSize < 1 || pageSize > MaxPageSize {
		return Page{}, ErrInvalidInput
	}
	var afterTime *time.Time
	var afterID *uuid.UUID
	if cursor != "" {
		createdAt, id, err := decodeCursor(cursor)
		if err != nil {
			return Page{}, ErrInvalidInput
		}
		afterTime, afterID = &createdAt, &id
	}
	page := Page{Items: []Message{}, UnreadOnly: unreadOnly, PageSize: pageSize}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE read_at IS NULL), count(*) FROM admin_inbox_messages
		WHERE recipient_user_id=$1 AND scope_id=$2`, recipient.UserID, recipient.ScopeID).Scan(&page.Unread, &page.Total); err != nil {
		return Page{}, err
	}
	rows, err := s.pool.Query(ctx, `SELECT id,event_type,params,created_at,read_at FROM admin_inbox_messages
		WHERE recipient_user_id=$1 AND scope_id=$6 AND (NOT $2 OR read_at IS NULL)
		  AND ($3::timestamptz IS NULL OR (created_at,id) < ($3,$4::uuid))
		ORDER BY created_at DESC,id DESC LIMIT $5`, recipient.UserID, unreadOnly, afterTime, afterID, pageSize+1, recipient.ScopeID)
	if err != nil {
		return Page{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var message Message
		var raw []byte
		if err := rows.Scan(&message.ID, &message.EventType, &raw, &message.CreatedAt, &message.ReadAt); err != nil {
			return Page{}, err
		}
		if err := json.Unmarshal(raw, &message.Params); err != nil {
			return Page{}, fmt.Errorf("decode admin inbox params: %w", err)
		}
		page.Items = append(page.Items, message)
	}
	if err := rows.Err(); err != nil {
		return Page{}, err
	}
	if len(page.Items) > pageSize {
		page.Items = page.Items[:pageSize]
		last := page.Items[pageSize-1]
		next := encodeCursor(last.CreatedAt, last.ID)
		page.NextCursor = &next
	}
	return page, nil
}

// MarkRead marks one message read; reading a read message is a no-op.
func (s *Store) MarkRead(ctx context.Context, recipient Recipient, id uuid.UUID) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE admin_inbox_messages SET read_at=COALESCE(read_at,$3) WHERE id=$1 AND recipient_user_id=$2 AND scope_id=$4`,
			id, recipient.UserID, s.now().UTC(), recipient.ScopeID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		return nil
	})
}

// MarkAllRead marks every unread message read, prunes old read ones and
// audits the action.
func (s *Store) MarkAllRead(ctx context.Context, recipient Recipient) (int64, error) {
	var changed int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		now := s.now().UTC()
		tag, err := tx.Exec(ctx, `UPDATE admin_inbox_messages SET read_at=$2 WHERE recipient_user_id=$1 AND scope_id=$3 AND read_at IS NULL`,
			recipient.UserID, now, recipient.ScopeID)
		if err != nil {
			return err
		}
		changed = tag.RowsAffected()
		if _, err := tx.Exec(ctx, `DELETE FROM admin_inbox_messages WHERE recipient_user_id=$1 AND scope_id=$3 AND read_at < $2`,
			recipient.UserID, now.AddDate(0, 0, -retentionDays), recipient.ScopeID); err != nil {
			return err
		}
		return s.auditor.Append(ctx, tx, audit.Event{ScopeID: recipient.ScopeID, ActorUserID: &recipient.UserID,
			Action: "admin.inbox.read_all", ResourceType: "admin_inbox", ResourceID: recipient.UserID.String(),
			RequestID: recipient.RequestID, Result: "success", Payload: map[string]any{"marked": changed}})
	})
	return changed, err
}

func encodeCursor(createdAt time.Time, id uuid.UUID) string {
	return createdAt.UTC().Format(time.RFC3339Nano) + "|" + id.String()
}

func decodeCursor(raw string) (time.Time, uuid.UUID, error) {
	for index := len(raw) - 1; index >= 0; index-- {
		if raw[index] == '|' {
			createdAt, err := time.Parse(time.RFC3339Nano, raw[:index])
			if err != nil {
				return time.Time{}, uuid.Nil, err
			}
			id, err := uuid.Parse(raw[index+1:])
			return createdAt, id, err
		}
	}
	return time.Time{}, uuid.Nil, ErrInvalidInput
}
