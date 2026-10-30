package announcement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	snapshotResponseBytes     = 1 << 20
	maxSnapshotCursorBytes    = 512
	snapshotItemsEnvelopeSize = len(`{"items":[]}`) + 1
	snapshotCursorFieldSize   = len(`,"next_cursor":`)
)

var errSnapshotResponseInvariant = errors.New("announcement snapshot response invariant violated")

func announcementStateWatermark(ctx context.Context, tx pgx.Tx, scopeID uuid.UUID) (int64, error) {
	var watermark int64
	err := tx.QueryRow(ctx, `SELECT current_watermark FROM announcement_state_watermarks WHERE tenant_scope_id=$1`, scopeID).Scan(&watermark)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	return watermark, err
}

func boundedSnapshotItems[T any](candidates []T, limit int, cursorFor func(T) string) ([]T, string, error) {
	if limit < 1 {
		return nil, "", errSnapshotResponseInvariant
	}
	capacity := len(candidates)
	if capacity > limit {
		capacity = limit
	}
	items := make([]T, 0, capacity)
	itemSizes := make([]int, 0, capacity)
	used := snapshotItemsEnvelopeSize
	for _, item := range candidates {
		if len(items) == limit {
			break
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, "", fmt.Errorf("%w: marshal item: %v", errSnapshotResponseInvariant, err)
		}
		delta := len(encoded)
		if len(items) > 0 {
			delta++
		}
		if used+delta > snapshotResponseBytes {
			break
		}
		items = append(items, item)
		itemSizes = append(itemSizes, len(encoded))
		used += delta
	}
	if len(items) == len(candidates) {
		return items, "", nil
	}
	if len(items) == 0 {
		return nil, "", fmt.Errorf("%w: item exceeds byte budget", errSnapshotResponseInvariant)
	}
	if cursorFor == nil {
		return nil, "", fmt.Errorf("%w: cursor callback is required", errSnapshotResponseInvariant)
	}
	for len(items) > 0 {
		nextCursor := cursorFor(items[len(items)-1])
		if nextCursor == "" || len(nextCursor) > maxSnapshotCursorBytes {
			return nil, "", fmt.Errorf("%w: cursor exceeds byte budget", errSnapshotResponseInvariant)
		}
		encodedCursor, err := json.Marshal(nextCursor)
		if err != nil {
			return nil, "", fmt.Errorf("%w: marshal cursor: %v", errSnapshotResponseInvariant, err)
		}
		if used+snapshotCursorFieldSize+len(encodedCursor) <= snapshotResponseBytes {
			return items, nextCursor, nil
		}
		used -= itemSizes[len(itemSizes)-1]
		if len(items) > 1 {
			used--
		}
		items = items[:len(items)-1]
		itemSizes = itemSizes[:len(itemSizes)-1]
	}
	return nil, "", fmt.Errorf("%w: item and cursor exceed byte budget", errSnapshotResponseInvariant)
}

func (s *Store) listAnnouncementSnapshot(ctx context.Context, tx pgx.Tx, actor Actor, request AnnouncementListRequest, cursor *announcementCursor, watermark int64) (AnnouncementPage, error) {
	query := `WITH version_facts AS (
        SELECT DISTINCT ON (announcement_id,announcement_version) payload
          FROM announcement_state_facts
         WHERE tenant_scope_id=$1 AND fact_type='version' AND watermark <= $2
         ORDER BY announcement_id,announcement_version,watermark DESC
    ), heads AS (
        SELECT DISTINCT ON (payload->>'id') payload
          FROM version_facts
         ORDER BY payload->>'id',(payload->>'version')::bigint DESC
    ), lifecycle AS (
        SELECT DISTINCT ON (announcement_id) announcement_id,state,revision,occurred_at
          FROM announcement_lifecycle_facts_254
         WHERE tenant_scope_id=$1 AND watermark <= $2
         ORDER BY announcement_id,revision DESC
    )
    SELECT (payload->>'id')::uuid,(payload->>'scope_id')::uuid,
           (payload->>'version')::bigint,(payload->>'version')::bigint,
           (payload->>'revision')::bigint,payload->>'status',payload->>'title',payload->>'body',
           COALESCE(payload->>'content_format','content'),NULLIF(payload->>'link_url',''),
           COALESCE((payload->>'sort_order')::bigint,100),COALESCE((payload->>'is_visible')::boolean,true),
           COALESCE((payload->>'is_popup')::boolean,false),COALESCE((payload->>'style_red')::boolean,false),COALESCE((payload->>'style_bold')::boolean,false),
           payload->>'audience_mode',payload->>'withdrawal_visibility',
           NULLIF(payload->>'scheduled_at','')::timestamptz,
           NULLIF(payload->>'published_at','')::timestamptz,
           NULLIF(payload->>'withdrawn_at','')::timestamptz,
           (payload->>'root_created_at')::timestamptz,(payload->>'state_changed_at')::timestamptz,
           COALESCE(archive.state='archived',false),COALESCE(archive.revision,1),
           CASE WHEN archive.state='archived' THEN archive.occurred_at END,
           payload->'audience_user_ids',payload->'audience_group_ids'
      FROM heads
      LEFT JOIN lifecycle archive ON archive.announcement_id=(payload->>'id')::uuid
     WHERE 1=1`
	args := []any{actor.ScopeID, watermark}
	if request.Status == "archived" {
		query += ` AND archive.state='archived'`
	} else {
		query += ` AND COALESCE(archive.state,'active')='active'`
		if request.Status != "" {
			query += fmt.Sprintf(` AND payload->>'status'=$%d`, len(args)+1)
			args = append(args, normalizeStatusFilter(request.Status))
		}
	}
	if cursor != nil {
		position := len(args) + 1
		query += fmt.Sprintf(` AND ((payload->>'root_created_at')::timestamptz,(payload->>'id')::uuid) < ($%d,$%d)`, position, position+1)
		args = append(args, cursor.CreatedAt, cursor.ID)
	}
	limitPosition := len(args) + 1
	query += fmt.Sprintf(` ORDER BY (payload->>'root_created_at')::timestamptz DESC,(payload->>'id')::uuid DESC LIMIT $%d`, limitPosition)
	args = append(args, request.Limit+1)
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return AnnouncementPage{}, err
	}
	defer rows.Close()
	result := AnnouncementPage{}
	for rows.Next() {
		item, err := scanAnnouncementSnapshot(rows)
		if err != nil {
			return AnnouncementPage{}, err
		}
		result.Items = append(result.Items, item)
	}
	if err := rows.Err(); err != nil {
		return AnnouncementPage{}, err
	}
	result.Items, result.NextCursor, err = boundedSnapshotItems(result.Items, request.Limit, func(last Announcement) string {
		return encodeAnnouncementCursor(s.cursorKeys, announcementCursor{
			ScopeID: actor.ScopeID, UserID: actor.UserID, Filter: normalizeStatusFilter(request.Status), Watermark: watermark,
			CreatedAt: last.CreatedAt, ID: last.ID,
		})
	})
	if err != nil {
		return AnnouncementPage{}, err
	}
	return result, nil
}

func scanAnnouncementSnapshot(row interface{ Scan(...any) error }) (Announcement, error) {
	var item Announcement
	var mode string
	var linkURL *string
	var userIDsJSON, groupIDsJSON []byte
	if err := row.Scan(&item.ID, &item.ScopeID, &item.Version, &item.HeadVersion,
		&item.Revision, &item.Status, &item.Title, &item.Body, &item.Format, &linkURL, &item.SortOrder,
		&item.Visible, &item.Popup, &item.Red, &item.Bold, &mode,
		&item.WithdrawalVisibility, &item.ScheduledAt, &item.PublishedAt,
		&item.WithdrawnAt, &item.CreatedAt, &item.StateChangedAt,
		&item.Archived, &item.LifecycleRevision, &item.ArchivedAt,
		&userIDsJSON, &groupIDsJSON); err != nil {
		return Announcement{}, err
	}
	if linkURL != nil {
		item.LinkURL = *linkURL
	}
	item.Audience.All = mode == "all"
	if len(userIDsJSON) > 0 {
		if err := json.Unmarshal(userIDsJSON, &item.Audience.UserIDs); err != nil {
			return Announcement{}, err
		}
	}
	if len(groupIDsJSON) > 0 {
		if err := json.Unmarshal(groupIDsJSON, &item.Audience.GroupIDs); err != nil {
			return Announcement{}, err
		}
	}
	return item, nil
}

func (s *Store) listInboxSnapshot(ctx context.Context, tx pgx.Tx, actor Actor, request ListRequest, cursor *pageCursor, watermark int64) (InboxPage, error) {
	query := `WITH version_facts AS (
        SELECT DISTINCT ON (announcement_id,announcement_version) payload
          FROM announcement_state_facts
         WHERE tenant_scope_id=$1 AND fact_type='version' AND watermark <= $2
         ORDER BY announcement_id,announcement_version,watermark DESC
    ), event_facts AS (
        SELECT DISTINCT ON (event_id) payload
          FROM announcement_state_facts
         WHERE tenant_scope_id=$1 AND fact_type='inbox_event' AND watermark <= $2
         ORDER BY event_id,watermark DESC
    ), state_facts AS (
        SELECT DISTINCT ON (event_id) payload
          FROM announcement_state_facts
         WHERE tenant_scope_id=$1 AND fact_type='inbox_state' AND watermark <= $2
         ORDER BY event_id,watermark DESC
    )
    SELECT (event.payload->>'id')::uuid,(event.payload->>'announcement_id')::uuid,
           (event.payload->>'announcement_version')::bigint,event.payload->>'title',event.payload->>'body',
           COALESCE(version_row.payload->>'content_format','content'),COALESCE(version_row.payload->>'link_url',''),
           COALESCE((version_row.payload->>'sort_order')::bigint,100),COALESCE((version_row.payload->>'is_visible')::boolean,true),
           COALESCE((version_row.payload->>'is_popup')::boolean,false),COALESCE((version_row.payload->>'style_red')::boolean,false),COALESCE((version_row.payload->>'style_bold')::boolean,false),
           (event.payload->>'published_at')::timestamptz,
           NULLIF(state.payload->>'delivered_at','')::timestamptz,
           NULLIF(state.payload->>'read_at','')::timestamptz,
           (state.payload->>'revision')::bigint,
           count(*) OVER()
      FROM event_facts event
      JOIN state_facts state ON (state.payload->>'event_id')::uuid=(event.payload->>'id')::uuid
      JOIN version_facts version_row
        ON (version_row.payload->>'id')::uuid=(event.payload->>'announcement_id')::uuid
       AND (version_row.payload->>'version')::bigint=(event.payload->>'announcement_version')::bigint
     WHERE (event.payload->>'recipient_user_id')::uuid=$3
       AND COALESCE((version_row.payload->>'is_visible')::boolean,true)
       AND ((version_row.payload->>'status') <> 'withdrawn' OR version_row.payload->>'withdrawal_visibility' = 'retain')`
	args := []any{actor.ScopeID, watermark, actor.UserID}
	if request.ReadFilter == "unread" {
		query += ` AND state.payload->>'read_at' IS NULL`
	} else if request.ReadFilter == "read" {
		query += ` AND state.payload->>'read_at' IS NOT NULL`
	} else if request.ReadFilter == "popup" {
		// 登录弹窗：未读且开了弹窗的公告，直接在库里筛（未读多于一页时也不漏）。
		query += ` AND state.payload->>'read_at' IS NULL AND COALESCE((version_row.payload->>'is_popup')::boolean,false)`
	}
	if cursor != nil {
		position := len(args) + 1
		sortOrder := int64(100)
		if cursor.SortOrder != nil {
			sortOrder = *cursor.SortOrder
		}
		query += fmt.Sprintf(` AND (-COALESCE((version_row.payload->>'sort_order')::bigint,100),(event.payload->>'published_at')::timestamptz,(event.payload->>'id')::uuid) < (-$%d::bigint,$%d,$%d)`, position, position+1, position+2)
		args = append(args, sortOrder, cursor.PublishedAt, cursor.ID)
	}
	limitPosition := len(args) + 1
	query += fmt.Sprintf(` ORDER BY COALESCE((version_row.payload->>'sort_order')::bigint,100),(event.payload->>'published_at')::timestamptz DESC,(event.payload->>'id')::uuid DESC LIMIT $%d OFFSET $%d`, limitPosition, limitPosition+1)
	args = append(args, request.Limit+1, request.Offset)
	result, total, err := scanInboxSnapshot(ctx, tx, query, args)
	if err != nil {
		return InboxPage{}, err
	}
	// tp-b7: the count window runs before LIMIT/OFFSET, so it is the filtered
	// total of this snapshot. A cursor page filters by position and has no
	// total; an offset past the end returns no row, so count from the start.
	if cursor == nil {
		if len(result.Items) == 0 && request.Offset > 0 {
			args[len(args)-1] = 0
			if _, total, err = scanInboxSnapshot(ctx, tx, query, args); err != nil {
				return InboxPage{}, err
			}
		}
		result.Total = &total
	}
	result.Items, result.NextCursor, err = boundedSnapshotItems(result.Items, request.Limit, func(last InboxMessage) string {
		return encodeCursor(s.cursorKeys, pageCursor{
			ScopeID: actor.ScopeID, UserID: actor.UserID, Filter: normalizeReadFilter(request.ReadFilter), Watermark: watermark,
			PublishedAt: last.PublishedAt, ID: last.ID, SortOrder: &last.SortOrder,
		})
	})
	if err != nil {
		return InboxPage{}, err
	}
	return result, nil
}

func scanInboxSnapshot(ctx context.Context, tx pgx.Tx, query string, args []any) (InboxPage, int, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return InboxPage{}, 0, err
	}
	defer rows.Close()
	result := InboxPage{}
	total := 0
	for rows.Next() {
		var item InboxMessage
		var count int64
		if err := rows.Scan(&item.ID, &item.AnnouncementID, &item.AnnouncementVersion,
			&item.Title, &item.Body, &item.Format, &item.LinkURL, &item.SortOrder, &item.Visible, &item.Popup, &item.Red, &item.Bold,
			&item.PublishedAt, &item.DeliveredAt, &item.ReadAt, &item.StateRevision, &count); err != nil {
			return InboxPage{}, 0, err
		}
		total = int(count)
		result.Items = append(result.Items, item)
	}
	return result, total, rows.Err()
}
