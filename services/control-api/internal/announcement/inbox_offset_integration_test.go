package announcement

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

// tp-b7：消息查询"共 N 条 + 页码"。首页和 offset 页带本快照、本筛选下的总数，
// offset 跳页和游标页内容一致，越界页返回空列表和真实总数，游标页不带总数。
func TestInboxOffsetPagesCarryFilteredTotal(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	tenant := seedAnnouncementFixture(t, pool)
	platform := seedGlobalPlatformActor(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	ctx := context.Background()
	for index := range 3 {
		key := fmt.Sprintf("offset-%d", index)
		item, err := store.CreateGlobalDraft(ctx, platform, CreateGlobalDraftRequest{
			Content: Content{Title: key, Body: "正文"}, Presentation: Presentation{Format: FormatContent, SortOrder: int64(100 - index), Visible: true},
			Audience: GlobalAudience{AllTenants: true}, WithdrawalVisibility: VisibilityHide, IdempotencyKey: key, RequestID: key,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PublishGlobal(ctx, platform, GlobalTransitionRequest{AnnouncementID: item.ID, ExpectedRevision: item.Revision, IdempotencyKey: "publish-" + key, RequestID: key}); err != nil {
			t.Fatal(err)
		}
	}
	reader := tenant.adminFor(tenant.userA)
	first, err := store.ListInbox(ctx, reader, ListRequest{Limit: 2})
	if err != nil || len(first.Items) != 2 || first.Total == nil || *first.Total != 3 || first.NextCursor == "" {
		t.Fatalf("first page: %+v %v", first, err)
	}
	cursorPage, err := store.ListInbox(ctx, reader, ListRequest{Limit: 2, Cursor: first.NextCursor})
	if err != nil || len(cursorPage.Items) != 1 || cursorPage.Total != nil {
		t.Fatalf("cursor page: %+v %v", cursorPage, err)
	}
	offsetPage, err := store.ListInbox(ctx, reader, ListRequest{Limit: 2, Offset: 2})
	if err != nil || len(offsetPage.Items) != 1 || offsetPage.Total == nil || *offsetPage.Total != 3 || offsetPage.NextCursor != "" ||
		offsetPage.Items[0].ID != cursorPage.Items[0].ID {
		t.Fatalf("offset page: %+v %v", offsetPage, err)
	}
	beyond, err := store.ListInbox(ctx, reader, ListRequest{Limit: 2, Offset: 20})
	if err != nil || len(beyond.Items) != 0 || beyond.Total == nil || *beyond.Total != 3 {
		t.Fatalf("page beyond the end: %+v %v", beyond, err)
	}
	if _, err := store.MarkRead(ctx, reader, StateRequest{EventID: first.Items[0].ID, ExpectedRevision: first.Items[0].StateRevision, IdempotencyKey: "read-offset", RequestID: "read-offset"}); err != nil {
		t.Fatal(err)
	}
	unread, err := store.ListInbox(ctx, reader, ListRequest{Limit: 2, ReadFilter: "unread"})
	if err != nil || unread.Total == nil || *unread.Total != 2 {
		t.Fatalf("unread total: %+v %v", unread, err)
	}
	if _, err := store.ListInbox(ctx, reader, ListRequest{Limit: 2, Offset: 2, Cursor: first.NextCursor}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("offset with cursor: %v", err)
	}
	other, err := store.ListInbox(ctx, tenant.adminFor(tenant.userB), ListRequest{Limit: 2})
	if err != nil || other.Total == nil || *other.Total != 3 {
		t.Fatalf("second member total: %+v %v", other, err)
	}
}

// 登录弹窗只取“未读且需弹窗”的公告，未读普通公告再多也不会把它挤出第一页。
func TestInboxPopupFilterFindsPopupBeyondUnreadPage(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	tenant := seedAnnouncementFixture(t, pool)
	platform := seedGlobalPlatformActor(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	ctx := context.Background()
	publish := func(key string, popup bool, sortOrder int64) {
		item, err := store.CreateGlobalDraft(ctx, platform, CreateGlobalDraftRequest{
			Content: Content{Title: key, Body: "正文"}, Presentation: Presentation{Format: FormatContent, SortOrder: sortOrder, Visible: true, Popup: popup},
			Audience: GlobalAudience{AllTenants: true}, WithdrawalVisibility: VisibilityHide, IdempotencyKey: key, RequestID: key,
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.PublishGlobal(ctx, platform, GlobalTransitionRequest{AnnouncementID: item.ID, ExpectedRevision: item.Revision, IdempotencyKey: "publish-" + key, RequestID: key}); err != nil {
			t.Fatal(err)
		}
	}
	for index := range 3 {
		publish(fmt.Sprintf("plain-%d", index), false, 1)
	}
	publish("popup", true, 900) // 排在所有普通公告之后
	reader := tenant.adminFor(tenant.userA)
	unread, err := store.ListInbox(ctx, reader, ListRequest{Limit: 2, ReadFilter: "unread"})
	if err != nil || len(unread.Items) != 2 || unread.Items[0].Popup || unread.Items[1].Popup {
		t.Fatalf("unread first page: %+v %v", unread, err)
	}
	popup, err := store.ListInbox(ctx, reader, ListRequest{Limit: 1, ReadFilter: "popup"})
	if err != nil || len(popup.Items) != 1 || popup.Items[0].Title != "popup" || popup.Total == nil || *popup.Total != 1 {
		t.Fatalf("popup page: %+v %v", popup, err)
	}
	if _, err := store.MarkRead(ctx, reader, StateRequest{EventID: popup.Items[0].ID, ExpectedRevision: popup.Items[0].StateRevision, IdempotencyKey: "read-popup", RequestID: "read-popup"}); err != nil {
		t.Fatal(err)
	}
	if again, err := store.ListInbox(ctx, reader, ListRequest{Limit: 1, ReadFilter: "popup"}); err != nil || len(again.Items) != 0 {
		t.Fatalf("read popup still listed: %+v %v", again, err)
	}
}
