package announcement

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/migrations"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var fixedNow = time.Date(2026, 7, 22, 2, 0, 0, 123456000, time.FixedZone("CST", 8*60*60))

func TestAnnouncementLifecycleSnapshotRevisionWithdrawalAndPagination(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	clock := &testClock{now: fixedNow}
	store := newTestStore(t, pool, audit.New(pool), clock.Now)

	created, err := store.CreateDraft(context.Background(), fixture.admin, CreateDraftRequest{
		Content:              Content{Title: "维护通知", Body: "## 第一版\n\n预计 15 分钟。"},
		Audience:             Audience{UserIDs: []uuid.UUID{fixture.userA}, GroupIDs: []uuid.UUID{fixture.groupID}},
		WithdrawalVisibility: VisibilityRetain,
		IdempotencyKey:       "create-1", RequestID: "req-create-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Status != StatusDraft || created.Version != 1 || created.Revision != 1 {
		t.Fatalf("created = %+v", created)
	}

	scheduledAt := fixedNow.UTC().Add(time.Hour)
	scheduled, err := store.Schedule(context.Background(), fixture.admin, ScheduleRequest{
		AnnouncementID: created.ID, Version: 1, ExpectedRevision: 1,
		PublishAt: scheduledAt, IdempotencyKey: "schedule-1", RequestID: "req-schedule-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if scheduled.Status != StatusScheduled || scheduled.ScheduledAt == nil || !scheduled.ScheduledAt.Equal(scheduledAt) {
		t.Fatalf("scheduled = %+v", scheduled)
	}

	clock.Set(scheduledAt.Add(-time.Microsecond))
	if published, err := store.PublishDue(context.Background(), 10); err != nil || len(published) != 0 {
		t.Fatalf("early publish = %+v, %v", published, err)
	}
	clock.Set(scheduledAt)
	published, err := store.PublishDue(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(published) != 1 || published[0].Status != StatusPublished || !published[0].PublishedAt.Equal(scheduledAt) {
		t.Fatalf("published = %+v", published)
	}

	assertRecipients(t, pool, fixture.scopeID, created.ID, 1, fixture.userA, fixture.userB)
	if _, err := pool.Exec(context.Background(), `
		UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, fixture.scopeID, fixture.userB); err != nil {
		t.Fatal(err)
	}
	assertRecipients(t, pool, fixture.scopeID, created.ID, 1, fixture.userA, fixture.userB)

	page, err := store.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].Title != "维护通知" || page.Items[0].ReadAt != nil {
		t.Fatalf("page = %+v", page)
	}

	revised, err := store.Revise(context.Background(), fixture.admin, ReviseRequest{
		AnnouncementID: created.ID, ExpectedHeadVersion: 1,
		Content:              Content{Title: "维护通知（修订）", Body: "## 第二版\n\n窗口缩短。"},
		Audience:             Audience{UserIDs: []uuid.UUID{fixture.userA}},
		WithdrawalVisibility: VisibilityHide,
		IdempotencyKey:       "revise-1", RequestID: "req-revise-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if revised.Version != 2 || revised.Status != StatusDraft {
		t.Fatalf("revised = %+v", revised)
	}
	assertVersionContent(t, pool, created.ID, 1, "维护通知", "## 第一版\n\n预计 15 分钟。")

	clock.Set(scheduledAt.Add(time.Minute))
	second, err := store.Publish(context.Background(), fixture.admin, PublishRequest{
		AnnouncementID: created.ID, Version: 2, ExpectedRevision: 1,
		IdempotencyKey: "publish-2", RequestID: "req-publish-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if second.Status != StatusPublished || second.Version != 2 {
		t.Fatalf("second publish = %+v", second)
	}

	firstPage, err := store.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 1})
	if err != nil || len(firstPage.Items) != 1 || firstPage.NextCursor == "" {
		t.Fatalf("first page = %+v, %v", firstPage, err)
	}
	if firstPage.Items[0].AnnouncementVersion != 2 {
		t.Fatalf("first page version = %d", firstPage.Items[0].AnnouncementVersion)
	}
	secondPage, err := store.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 1, Cursor: firstPage.NextCursor})
	if err != nil || len(secondPage.Items) != 1 || secondPage.Items[0].AnnouncementVersion != 1 {
		t.Fatalf("second page = %+v, %v", secondPage, err)
	}

	withdrawn, err := store.Withdraw(context.Background(), fixture.admin, WithdrawRequest{
		AnnouncementID: created.ID, Version: 2, ExpectedRevision: second.Revision,
		IdempotencyKey: "withdraw-2", RequestID: "req-withdraw-2",
	})
	if err != nil || withdrawn.Status != StatusWithdrawn {
		t.Fatalf("withdraw = %+v, %v", withdrawn, err)
	}
	var currentPublished *int64
	if err := pool.QueryRow(context.Background(), `SELECT current_published_version FROM announcements WHERE id=$1`, created.ID).Scan(&currentPublished); err != nil {
		t.Fatal(err)
	}
	if currentPublished == nil || *currentPublished != 1 {
		t.Fatalf("current published after withdrawing v2 = %v, want v1", currentPublished)
	}
	visible, err := store.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 10})
	if err != nil || len(visible.Items) != 1 || visible.Items[0].AnnouncementVersion != 1 {
		t.Fatalf("visible after hide withdrawal = %+v, %v", visible, err)
	}
	assertCount(t, pool, `SELECT count(*) FROM announcement_inbox_events WHERE announcement_id=$1`, 3, created.ID)
	assertAuditActions(t, pool, fixture.scopeID,
		"announcement.create", "announcement.schedule", "announcement.publish",
		"announcement.revise", "announcement.publish", "announcement.withdraw")
}

func TestCreateDraftRejectsRawDuplicateAudienceOverLimit(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	duplicateUserID := uuid.New()
	duplicateUsers := make([]uuid.UUID, MaxAudienceTargets+1)
	for index := range duplicateUsers {
		duplicateUsers[index] = duplicateUserID
	}
	_, err := store.CreateDraft(context.Background(), fixture.admin, CreateDraftRequest{
		Content: Content{Title: "重复受众", Body: "不得去重后绕过上限"}, Audience: Audience{UserIDs: duplicateUsers},
		WithdrawalVisibility: VisibilityRetain, IdempotencyKey: "duplicate-limit", RequestID: "req-duplicate-limit",
	})
	if !errors.Is(err, ErrInvalidAudience) {
		t.Fatalf("duplicate raw audience limit = %v", err)
	}
	assertCount(t, pool, `SELECT count(*) FROM announcements`, 0)
	assertCount(t, pool, `SELECT count(*) FROM announcement_write_requests`, 0)
}

func TestAnnouncementTenantIsolationAndIdempotencyConflict(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	other := seedAdditionalTenant(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	_, err := store.CreateDraft(context.Background(), fixture.adminFor(fixture.userA), CreateDraftRequest{
		Content: Content{Title: "越权", Body: "不得创建"}, Audience: Audience{All: true},
		WithdrawalVisibility: VisibilityRetain, IdempotencyKey: "permission-denied", RequestID: "req-permission-denied",
	})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("unprivileged create = %v", err)
	}

	_, err = store.CreateDraft(context.Background(), fixture.admin, CreateDraftRequest{
		Content: Content{Title: "定向", Body: "正文"}, Audience: Audience{UserIDs: []uuid.UUID{other.userID}},
		WithdrawalVisibility: VisibilityRetain, IdempotencyKey: "tenant-leak", RequestID: "req-leak",
	})
	if !errors.Is(err, ErrAudienceScopeDenied) {
		t.Fatalf("cross-tenant user = %v", err)
	}
	_, err = store.CreateDraft(context.Background(), fixture.admin, CreateDraftRequest{
		Content: Content{Title: "定向", Body: "正文"}, Audience: Audience{GroupIDs: []uuid.UUID{other.groupID}},
		WithdrawalVisibility: VisibilityRetain, IdempotencyKey: "group-leak", RequestID: "req-group-leak",
	})
	if !errors.Is(err, ErrAudienceScopeDenied) {
		t.Fatalf("cross-tenant group = %v", err)
	}

	request := CreateDraftRequest{
		Content: Content{Title: "幂等", Body: "相同请求"}, Audience: Audience{All: true},
		WithdrawalVisibility: VisibilityRetain, IdempotencyKey: "same-key", RequestID: "req-same",
	}
	first, err := store.CreateDraft(context.Background(), fixture.admin, request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := store.CreateDraft(context.Background(), fixture.admin, request)
	if err != nil || !replay.Replayed || replay.ID != first.ID {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	request.Content.Body = "冲突请求"
	if _, err := store.CreateDraft(context.Background(), fixture.admin, request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflicting replay = %v", err)
	}

	if _, err := store.ListInbox(context.Background(), Actor{ScopeID: other.scopeID, UserID: fixture.userA, SessionID: uuid.New()}, ListRequest{Limit: 10}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-tenant inbox = %v", err)
	}
}

func TestDraftUpdateUsesCASAndScheduleSealsContent(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	item := mustCreateDraft(t, store, fixture.admin, "draft-cas", Audience{UserIDs: []uuid.UUID{fixture.userA}})

	request := UpdateDraftRequest{
		AnnouncementID: item.ID, Version: item.Version, ExpectedRevision: item.Revision,
		Content:              Content{Title: "更新后的草稿", Body: "## 新正文\n\n已核对。"},
		Audience:             Audience{UserIDs: []uuid.UUID{fixture.userA, fixture.userB}},
		WithdrawalVisibility: VisibilityRetain,
		IdempotencyKey:       "update-draft", RequestID: "req-update-draft",
	}
	updated, err := store.UpdateDraft(context.Background(), fixture.admin, request)
	if err != nil || updated.Revision != item.Revision+1 || len(updated.Audience.UserIDs) != 2 {
		t.Fatalf("updated = %+v, %v", updated, err)
	}
	stale := request
	stale.IdempotencyKey = "update-stale"
	stale.RequestID = "req-update-stale"
	if _, err := store.UpdateDraft(context.Background(), fixture.admin, stale); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale update = %v", err)
	}

	scheduled, err := store.Schedule(context.Background(), fixture.admin, ScheduleRequest{
		AnnouncementID: item.ID, Version: item.Version, ExpectedRevision: updated.Revision,
		PublishAt: fixedNow.Add(time.Minute), IdempotencyKey: "schedule-seal", RequestID: "req-schedule-seal",
	})
	if err != nil || scheduled.Status != StatusScheduled {
		t.Fatalf("scheduled = %+v, %v", scheduled, err)
	}
	afterSchedule := request
	afterSchedule.ExpectedRevision = scheduled.Revision
	afterSchedule.IdempotencyKey = "update-after-schedule"
	afterSchedule.RequestID = "req-update-after-schedule"
	if _, err := store.UpdateDraft(context.Background(), fixture.admin, afterSchedule); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("update after schedule = %v", err)
	}
	withdrawn, err := store.Withdraw(context.Background(), fixture.admin, WithdrawRequest{
		AnnouncementID: item.ID, Version: item.Version, ExpectedRevision: scheduled.Revision,
		IdempotencyKey: "withdraw-scheduled", RequestID: "req-withdraw-scheduled",
	})
	if err != nil || withdrawn.Status != StatusWithdrawn || withdrawn.PublishedAt != nil {
		t.Fatalf("withdraw scheduled = %+v, %v", withdrawn, err)
	}
}

func TestConcurrentPublishAndReadHaveSingleCASWinner(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	item := mustCreateDraft(t, store, fixture.admin, "concurrent", Audience{UserIDs: []uuid.UUID{fixture.userA}})

	var publishSuccess atomic.Int32
	var publishConflict atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := store.Publish(context.Background(), fixture.admin, PublishRequest{
				AnnouncementID: item.ID, Version: 1, ExpectedRevision: 1,
				IdempotencyKey: fmt.Sprintf("publish-%d", i), RequestID: fmt.Sprintf("req-publish-%d", i),
			})
			switch {
			case err == nil:
				publishSuccess.Add(1)
			case errors.Is(err, ErrRevisionConflict), errors.Is(err, ErrInvalidTransition):
				publishConflict.Add(1)
			default:
				t.Errorf("publish %d: %v", i, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if publishSuccess.Load() != 1 || publishConflict.Load() != 1 {
		t.Fatalf("publish winners/conflicts = %d/%d", publishSuccess.Load(), publishConflict.Load())
	}
	assertCount(t, pool, `SELECT count(*) FROM announcement_inbox_events WHERE announcement_id=$1`, 1, item.ID)

	page, err := store.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 10})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("inbox = %+v, %v", page, err)
	}
	eventID := page.Items[0].ID
	var readSuccess atomic.Int32
	var readConflict atomic.Int32
	start = make(chan struct{})
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := store.MarkRead(context.Background(), fixture.adminFor(fixture.userA), StateRequest{
				EventID: eventID, ExpectedRevision: 1,
				IdempotencyKey: fmt.Sprintf("read-%d", i), RequestID: fmt.Sprintf("req-read-%d", i),
			})
			switch {
			case err == nil:
				readSuccess.Add(1)
			case errors.Is(err, ErrRevisionConflict):
				readConflict.Add(1)
			default:
				t.Errorf("read %d: %v", i, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if readSuccess.Load() != 1 || readConflict.Load() != 1 {
		t.Fatalf("read winners/conflicts = %d/%d", readSuccess.Load(), readConflict.Load())
	}
	state, err := store.MarkDelivered(context.Background(), fixture.adminFor(fixture.userA), StateRequest{
		EventID: eventID, ExpectedRevision: 2, IdempotencyKey: "delivered-after-read", RequestID: "req-delivered-after-read",
	})
	if err != nil || state.DeliveredAt == nil || state.ReadAt == nil || state.Revision != 2 {
		t.Fatalf("delivered after read = %+v, %v", state, err)
	}
}

func TestAuditFailureRollsBackMutation(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	store := newTestStore(t, pool, failingAuditor{}, func() time.Time { return fixedNow })
	_, err := store.CreateDraft(context.Background(), fixture.admin, CreateDraftRequest{
		Content: Content{Title: "审计失败", Body: "不得提交"}, Audience: Audience{All: true},
		WithdrawalVisibility: VisibilityRetain, IdempotencyKey: "audit-fail", RequestID: "req-audit-fail",
	})
	if err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("create error = %v", err)
	}
	assertCount(t, pool, `SELECT count(*) FROM announcements`, 0)
	assertCount(t, pool, `SELECT count(*) FROM announcement_write_requests`, 0)
}

func TestPublicationOutboxFailureRollsBackSnapshotAndState(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	item := mustCreateDraft(t, store, fixture.admin, "outbox-fail", Audience{UserIDs: []uuid.UUID{fixture.userA}})
	failing, err := NewStoreWithDependencies(pool, audit.New(pool), failingPublicationOutbox{}, func() time.Time { return fixedNow }, testCursorKeyring("test", 0x5a), testAnnouncementAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = failing.Publish(context.Background(), fixture.admin, PublishRequest{
		AnnouncementID: item.ID, Version: item.Version, ExpectedRevision: item.Revision,
		IdempotencyKey: "publish-outbox-fail", RequestID: "req-publish-outbox-fail",
	})
	if err == nil || !strings.Contains(err.Error(), "outbox") {
		t.Fatalf("publish error = %v", err)
	}
	assertCount(t, pool, `SELECT count(*) FROM announcement_recipient_snapshots WHERE announcement_id=$1`, 0, item.ID)
	assertCount(t, pool, `SELECT count(*) FROM announcement_inbox_events WHERE announcement_id=$1`, 0, item.ID)
	assertCount(t, pool, `SELECT count(*) FROM announcement_inbox_states state
		JOIN announcement_inbox_events event ON event.tenant_scope_id=state.tenant_scope_id AND event.id=state.event_id
		WHERE event.announcement_id=$1`, 0, item.ID)
	assertCount(t, pool, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action='announcement.publish'`, 0, fixture.scopeID)
	assertCount(t, pool, `SELECT count(*) FROM announcement_write_requests
		WHERE tenant_scope_id=$1 AND operation='announcement.publish' AND idempotency_key='publish-outbox-fail'`, 0, fixture.scopeID)
	var status string
	if err := pool.QueryRow(context.Background(), `SELECT status FROM announcement_versions WHERE announcement_id=$1 AND version=1`, item.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != StatusDraft {
		t.Fatalf("status after outbox failure = %s", status)
	}
}

func TestDatabaseGuardsRejectForgeryRegressionDeleteAndTruncate(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	item := mustCreateDraft(t, store, fixture.admin, "sql-guard", Audience{UserIDs: []uuid.UUID{fixture.userA}})

	assertSQLRejected(t, pool, `UPDATE announcement_versions SET status='published',sealed_at=now(),published_at=now(),revision=revision+1 WHERE announcement_id=$1 AND version=1`, item.ID)
	published, err := store.Publish(context.Background(), fixture.admin, PublishRequest{
		AnnouncementID: item.ID, Version: 1, ExpectedRevision: 1,
		IdempotencyKey: "guard-publish", RequestID: "req-guard-publish",
	})
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 10})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("guard inbox = %+v, %v", page, err)
	}
	state, err := store.MarkRead(context.Background(), fixture.adminFor(fixture.userA), StateRequest{
		EventID: page.Items[0].ID, ExpectedRevision: 1,
		IdempotencyKey: "guard-read", RequestID: "req-guard-read",
	})
	if err != nil || state.ReadAt == nil {
		t.Fatalf("guard read = %+v, %v", state, err)
	}
	assertSQLRejected(t, pool, `UPDATE announcement_inbox_states SET read_at=NULL,revision=revision+1 WHERE event_id=$1`, page.Items[0].ID)
	assertSQLRejected(t, pool, `UPDATE announcement_inbox_states SET delivered_at=delivered_at-interval '1 day',read_at=read_at-interval '1 day',revision=revision+1 WHERE event_id=$1`, page.Items[0].ID)
	assertSQLRejected(t, pool, `UPDATE announcement_versions SET body='篡改' WHERE announcement_id=$1 AND version=1`, item.ID)
	withdrawn, err := store.Withdraw(context.Background(), fixture.admin, WithdrawRequest{
		AnnouncementID: item.ID, Version: 1, ExpectedRevision: published.Revision,
		IdempotencyKey: "guard-withdraw", RequestID: "req-guard-withdraw",
	})
	if err != nil {
		t.Fatal(err)
	}
	if withdrawn.Status != StatusWithdrawn {
		t.Fatalf("withdrawn = %+v", withdrawn)
	}
	assertSQLRejected(t, pool, `UPDATE announcement_versions SET status='published',withdrawn_at=NULL,revision=revision+1 WHERE announcement_id=$1 AND version=1`, item.ID)
	assertSQLRejected(t, pool, `DELETE FROM announcements WHERE id=$1`, item.ID)
	assertSQLRejected(t, pool, `DELETE FROM announcement_inbox_events WHERE announcement_id=$1`, item.ID)
	assertSQLRejected(t, pool, `DELETE FROM announcement_recipient_snapshots WHERE announcement_id=$1`, item.ID)
	assertSQLRejected(t, pool, `TRUNCATE announcements CASCADE`)
}

func TestCursorRejectsTamperingAndKeepsBoundaryStable(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	clock := &testClock{now: fixedNow}
	store := newTestStore(t, pool, audit.New(pool), clock.Now)
	first := mustCreateDraft(t, store, fixture.admin, "page-a", Audience{UserIDs: []uuid.UUID{fixture.userA}})
	mustPublish(t, store, fixture.admin, first)
	clock.Set(fixedNow.Add(time.Second))
	second := mustCreateDraft(t, store, fixture.admin, "page-b", Audience{UserIDs: []uuid.UUID{fixture.userA}})
	mustPublish(t, store, fixture.admin, second)

	page, err := store.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 1})
	if err != nil || page.NextCursor == "" {
		t.Fatalf("page = %+v, %v", page, err)
	}
	clock.Set(fixedNow.Add(2 * time.Second))
	third := mustCreateDraft(t, store, fixture.admin, "page-c", Audience{UserIDs: []uuid.UUID{fixture.userA}})
	mustPublish(t, store, fixture.admin, third)
	next, err := store.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 10, Cursor: page.NextCursor})
	if err != nil || len(next.Items) != 1 || next.Items[0].AnnouncementID != first.ID {
		t.Fatalf("stable next page = %+v, %v", next, err)
	}
	if _, err := store.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 10, Cursor: page.NextCursor + "x"}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("tampered cursor = %v", err)
	}
	if _, err := store.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 10, ReadFilter: "read", Cursor: page.NextCursor}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cursor filter swap = %v", err)
	}
}

func TestWithdrawOnlyPublishedVersionClearsCurrentPointer(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	item := mustCreateDraft(t, store, fixture.admin, "withdraw-only", Audience{UserIDs: []uuid.UUID{fixture.userA}})
	published := mustPublish(t, store, fixture.admin, item)
	if _, err := store.Withdraw(context.Background(), fixture.admin, WithdrawRequest{
		AnnouncementID: item.ID, Version: item.Version, ExpectedRevision: published.Revision,
		IdempotencyKey: "withdraw-only", RequestID: "req-withdraw-only",
	}); err != nil {
		t.Fatal(err)
	}
	var currentPublished *int64
	if err := pool.QueryRow(context.Background(), `SELECT current_published_version FROM announcements WHERE id=$1`, item.ID).Scan(&currentPublished); err != nil {
		t.Fatal(err)
	}
	if currentPublished != nil {
		t.Fatalf("current published after only-version withdrawal = %v, want NULL", *currentPublished)
	}
}

func TestCursorBindsActorDomainAndStableRotatingKeyring(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	clock := &testClock{now: fixedNow}
	oldRing := testCursorKeyring("old", 0x11)
	oldStore := newTestStoreWithKeyring(t, pool, audit.New(pool), clock.Now, oldRing)
	first := mustCreateDraft(t, oldStore, fixture.admin, "cursor-one", Audience{UserIDs: []uuid.UUID{fixture.userA}})
	mustPublish(t, oldStore, fixture.admin, first)
	clock.Set(fixedNow.Add(time.Second))
	second := mustCreateDraft(t, oldStore, fixture.admin, "cursor-two", Audience{UserIDs: []uuid.UUID{fixture.userA}})
	mustPublish(t, oldStore, fixture.admin, second)

	inbox, err := oldStore.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 1})
	if err != nil || inbox.NextCursor == "" {
		t.Fatalf("inbox cursor = %+v, %v", inbox, err)
	}
	admin, err := oldStore.ListAnnouncements(context.Background(), fixture.admin, AnnouncementListRequest{Limit: 1})
	if err != nil || admin.NextCursor == "" {
		t.Fatalf("admin cursor = %+v, %v", admin, err)
	}
	sameKeyStore := newTestStoreWithKeyring(t, pool, audit.New(pool), clock.Now, testCursorKeyring("old", 0x11))
	if _, err := sameKeyStore.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 10, Cursor: inbox.NextCursor}); err != nil {
		t.Fatalf("same keyring on another Store rejected cursor: %v", err)
	}
	if _, err := oldStore.ListInbox(context.Background(), fixture.adminFor(fixture.userB), ListRequest{Limit: 10, Cursor: inbox.NextCursor}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-user cursor = %v", err)
	}
	crossScope := fixture.adminFor(fixture.userA)
	crossScope.ScopeID = uuid.New()
	if _, err := oldStore.ListInbox(context.Background(), crossScope, ListRequest{Limit: 10, Cursor: inbox.NextCursor}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-scope cursor = %v", err)
	}
	if _, err := oldStore.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 10, Cursor: admin.NextCursor}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("admin cursor used for inbox = %v", err)
	}
	if _, err := oldStore.ListAnnouncements(context.Background(), fixture.admin, AnnouncementListRequest{Limit: 10, Cursor: inbox.NextCursor}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("inbox cursor used for admin = %v", err)
	}

	rotatedRing := CursorKeyring{ActiveKID: "new", Keys: map[string][]byte{
		"old": bytes.Repeat([]byte{0x11}, 32),
		"new": bytes.Repeat([]byte{0x22}, 32),
	}}
	rotatedStore := newTestStoreWithKeyring(t, pool, audit.New(pool), clock.Now, rotatedRing)
	if _, err := rotatedStore.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 10, Cursor: inbox.NextCursor}); err != nil {
		t.Fatalf("rotated keyring rejected old cursor: %v", err)
	}
	newPage, err := rotatedStore.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 1})
	if err != nil || newPage.NextCursor == "" {
		t.Fatalf("rotated cursor page = %+v, %v", newPage, err)
	}
	newOnly := newTestStoreWithKeyring(t, pool, audit.New(pool), clock.Now, testCursorKeyring("new", 0x22))
	if _, err := newOnly.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 10, Cursor: newPage.NextCursor}); err != nil {
		t.Fatalf("new active key cursor rejected after restart: %v", err)
	}
	if _, err := newOnly.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 10, Cursor: inbox.NextCursor}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("removed old key accepted old cursor: %v", err)
	}
}

func TestCursorWatermarkFreezesWithdrawAndReadAcrossPages(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	clock := &testClock{now: fixedNow}
	store := newTestStore(t, pool, audit.New(pool), clock.Now)
	older := mustCreateDraftVisibility(t, store, fixture.admin, "snapshot-old", VisibilityHide, Audience{UserIDs: []uuid.UUID{fixture.userA}})
	older = mustPublish(t, store, fixture.admin, older)
	clock.Set(fixedNow.Add(time.Second))
	newer := mustCreateDraftVisibility(t, store, fixture.admin, "snapshot-new", VisibilityHide, Audience{UserIDs: []uuid.UUID{fixture.userA}})
	mustPublish(t, store, fixture.admin, newer)

	firstPage, err := store.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{Limit: 1, ReadFilter: "unread"})
	if err != nil || len(firstPage.Items) != 1 || firstPage.NextCursor == "" || firstPage.Items[0].AnnouncementID != newer.ID {
		t.Fatalf("first snapshot page = %+v, %v", firstPage, err)
	}
	var olderEventID uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT id FROM announcement_inbox_events WHERE announcement_id=$1 AND recipient_user_id=$2`, older.ID, fixture.userA).Scan(&olderEventID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkRead(context.Background(), fixture.adminFor(fixture.userA), StateRequest{
		EventID: olderEventID, ExpectedRevision: 1, IdempotencyKey: "snapshot-read", RequestID: "req-snapshot-read",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Withdraw(context.Background(), fixture.admin, WithdrawRequest{
		AnnouncementID: older.ID, Version: older.Version, ExpectedRevision: older.Revision,
		IdempotencyKey: "snapshot-withdraw", RequestID: "req-snapshot-withdraw",
	}); err != nil {
		t.Fatal(err)
	}
	secondPage, err := store.ListInbox(context.Background(), fixture.adminFor(fixture.userA), ListRequest{
		Limit: 10, ReadFilter: "unread", Cursor: firstPage.NextCursor,
	})
	if err != nil || len(secondPage.Items) != 1 || secondPage.Items[0].AnnouncementID != older.ID || secondPage.Items[0].ReadAt != nil {
		t.Fatalf("frozen second page = %+v, %v", secondPage, err)
	}
}

func TestStoreRequiresInjectedCursorKeyring(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	if _, err := NewStore(pool); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("NewStore without keyring = %v", err)
	}
	for _, ring := range []CursorKeyring{
		{},
		{ActiveKID: "missing", Keys: map[string][]byte{"other": bytes.Repeat([]byte{1}, 32)}},
		{ActiveKID: "bad kid", Keys: map[string][]byte{"bad kid": bytes.Repeat([]byte{1}, 32)}},
		{ActiveKID: "short", Keys: map[string][]byte{"short": bytes.Repeat([]byte{1}, 31)}},
	} {
		if _, err := NewStoreWithDependencies(pool, audit.New(pool), NoopPublicationOutbox{}, time.Now, ring, testAnnouncementAuthorizer{}); !errors.Is(err, ErrInvalidStore) {
			t.Fatalf("invalid keyring %+v = %v", ring, err)
		}
	}
}

type fixture struct {
	scopeID      uuid.UUID
	admin        Actor
	userA        uuid.UUID
	userB        uuid.UUID
	groupID      uuid.UUID
	adminSession uuid.UUID
	userASession uuid.UUID
	userBSession uuid.UUID
}

func (f fixture) adminFor(userID uuid.UUID) Actor {
	sessionID := f.adminSession
	if userID == f.userA {
		sessionID = f.userASession
	} else if userID == f.userB {
		sessionID = f.userBSession
	}
	return Actor{ScopeID: f.scopeID, UserID: userID, SessionID: sessionID}
}

type otherFixture struct{ scopeID, userID, groupID uuid.UUID }

func seedAnnouncementFixture(t *testing.T, pool *pgxpool.Pool) fixture {
	t.Helper()
	ctx := context.Background()
	tenantID, scopeID := uuid.New(), uuid.New()
	adminID, userA, userB, groupID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seedTenant(t, pool, tenantID, scopeID, "tenant-main", adminID, userA, userB)
	adminSession := seedAnnouncementSession(t, pool, scopeID, adminID)
	userASession := seedAnnouncementSession(t, pool, scopeID, userA)
	userBSession := seedAnnouncementSession(t, pool, scopeID, userB)
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'ops-group','',true)`, groupID, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scopeID, userB, groupID); err != nil {
		t.Fatal(err)
	}
	adminRole := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'announcement-admin','',true)`, adminRole, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'announcements.manage'),($1,'announcements.read')`, adminRole); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scopeID, adminID, adminRole); err != nil {
		t.Fatal(err)
	}
	readerRole := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'announcement-reader','',true)`, readerRole, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'announcements.read')`, readerRole); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3),($1,$4,$3)`, scopeID, userA, readerRole, userB); err != nil {
		t.Fatal(err)
	}
	return fixture{scopeID: scopeID, admin: Actor{ScopeID: scopeID, UserID: adminID, SessionID: adminSession}, userA: userA, userB: userB, groupID: groupID,
		adminSession: adminSession, userASession: userASession, userBSession: userBSession}
}

func seedAdditionalTenant(t *testing.T, pool *pgxpool.Pool) otherFixture {
	t.Helper()
	tenantID, scopeID, userID, groupID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	seedTenant(t, pool, tenantID, scopeID, "tenant-other", userID)
	if _, err := pool.Exec(context.Background(), `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'other-group','',true)`, groupID, scopeID); err != nil {
		t.Fatal(err)
	}
	return otherFixture{scopeID: scopeID, userID: userID, groupID: groupID}
}

func seedTenant(t *testing.T, pool *pgxpool.Pool, tenantID, scopeID uuid.UUID, name string, users ...uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, name); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID); err != nil {
		t.Fatal(err)
	}
	for index, userID := range users {
		if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'hash')`, userID, fmt.Sprintf("%s-user-%d", name, index)); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
			t.Fatal(err)
		}
	}
}

func newTestStore(t *testing.T, pool *pgxpool.Pool, auditor AuditAppender, now Clock) *Store {
	t.Helper()
	return newTestStoreWithKeyring(t, pool, auditor, now, testCursorKeyring("test", 0x5a))
}

func newTestStoreWithKeyring(t *testing.T, pool *pgxpool.Pool, auditor AuditAppender, now Clock, keyring CursorKeyring) *Store {
	t.Helper()
	store, err := NewStoreWithDependencies(pool, auditor, NoopPublicationOutbox{}, now, keyring, testAnnouncementAuthorizer{})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func testCursorKeyring(kid string, value byte) CursorKeyring {
	return CursorKeyring{ActiveKID: kid, Keys: map[string][]byte{kid: bytes.Repeat([]byte{value}, 32)}}
}

func seedAnnouncementSession(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID) uuid.UUID {
	t.Helper()
	sessionID := uuid.New()
	familyID := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO auth_sessions(
		id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at
	) VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, familyID, userID, scopeID,
		hashSessionFixture(sessionID), fixedNow.UTC(), fixedNow.UTC().Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	return sessionID
}

func hashSessionFixture(id uuid.UUID) []byte {
	digest := sha256.Sum256(id[:])
	return digest[:]
}

type testAnnouncementAuthorizer struct{}

func (testAnnouncementAuthorizer) Authorize(ctx context.Context, tx pgx.Tx, actor Actor, permission string) error {
	if actor.ScopeID == uuid.Nil || actor.UserID == uuid.Nil || actor.SessionID == uuid.Nil {
		return ErrPermissionDenied
	}
	var kind string
	var tenantID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT kind,tenant_id FROM access_scopes WHERE id=$1 FOR SHARE`, actor.ScopeID).Scan(&kind, &tenantID); err != nil || kind != "tenant" || tenantID == nil {
		return ErrPermissionDenied
	}
	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM tenants WHERE id=$1 FOR UPDATE`, *tenantID).Scan(&status); err != nil || status != "active" {
		return ErrPermissionDenied
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM users WHERE id=$1 FOR UPDATE`, actor.UserID).Scan(&status); err != nil || status != "active" {
		return ErrPermissionDenied
	}
	if err := tx.QueryRow(ctx, `SELECT status FROM memberships WHERE scope_id=$1 AND user_id=$2 FOR UPDATE`, actor.ScopeID, actor.UserID).Scan(&status); err != nil || status != "active" {
		return ErrPermissionDenied
	}
	var revokedAt *time.Time
	var expiresAt time.Time
	if err := tx.QueryRow(ctx, `SELECT revoked_at,expires_at FROM auth_sessions WHERE id=$1 AND user_id=$2 AND scope_id=$3 FOR UPDATE`, actor.SessionID, actor.UserID, actor.ScopeID).Scan(&revokedAt, &expiresAt); err != nil || revokedAt != nil || !fixedNow.UTC().Before(expiresAt) {
		return ErrPermissionDenied
	}
	var granted string
	err := tx.QueryRow(ctx, `SELECT permission.permission_name
		FROM role_assignments assignment
		JOIN roles role ON role.id=assignment.role_id AND role.scope_id=assignment.scope_id
		JOIN role_permissions permission ON permission.role_id=role.id
		WHERE assignment.scope_id=$1 AND assignment.user_id=$2 AND permission.permission_name=$3
		ORDER BY role.id LIMIT 1 FOR SHARE OF assignment,role,permission`, actor.ScopeID, actor.UserID, permission).Scan(&granted)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPermissionDenied
	}
	return err
}

func mustCreateDraft(t *testing.T, store *Store, actor Actor, key string, audience Audience) Announcement {
	return mustCreateDraftVisibility(t, store, actor, key, VisibilityRetain, audience)
}

func mustCreateDraftVisibility(t *testing.T, store *Store, actor Actor, key, visibility string, audience Audience) Announcement {
	t.Helper()
	item, err := store.CreateDraft(context.Background(), actor, CreateDraftRequest{
		Content: Content{Title: key, Body: "正文"}, Audience: audience,
		WithdrawalVisibility: visibility, IdempotencyKey: "create-" + key, RequestID: "req-create-" + key,
	})
	if err != nil {
		t.Fatal(err)
	}
	return item
}

func mustPublish(t *testing.T, store *Store, actor Actor, item Announcement) Announcement {
	t.Helper()
	result, err := store.Publish(context.Background(), actor, PublishRequest{
		AnnouncementID: item.ID, Version: item.Version, ExpectedRevision: item.Revision,
		IdempotencyKey: "publish-" + item.ID.String(), RequestID: "req-publish-" + item.ID.String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertRecipients(t *testing.T, pool *pgxpool.Pool, scopeID, announcementID uuid.UUID, version int64, want ...uuid.UUID) {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT user_id FROM announcement_recipient_snapshots WHERE tenant_scope_id=$1 AND announcement_id=$2 AND announcement_version=$3 ORDER BY user_id`, scopeID, announcementID, version)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := make(map[uuid.UUID]bool)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		got[id] = true
	}
	if len(got) != len(want) {
		t.Fatalf("recipients = %v, want %v", got, want)
	}
	for _, id := range want {
		if !got[id] {
			t.Fatalf("missing recipient %s from %v", id, got)
		}
	}
}

func assertVersionContent(t *testing.T, pool *pgxpool.Pool, announcementID uuid.UUID, version int64, title, body string) {
	t.Helper()
	var gotTitle, gotBody string
	if err := pool.QueryRow(context.Background(), `SELECT title,body FROM announcement_versions WHERE announcement_id=$1 AND version=$2`, announcementID, version).Scan(&gotTitle, &gotBody); err != nil {
		t.Fatal(err)
	}
	if gotTitle != title || gotBody != body {
		t.Fatalf("content = %q/%q, want %q/%q", gotTitle, gotBody, title, body)
	}
}

func assertAuditActions(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, want ...string) {
	t.Helper()
	rows, err := pool.Query(context.Background(), `SELECT action FROM audit_events WHERE scope_id=$1 AND action LIKE 'announcement.%' ORDER BY stream_position`, scopeID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err != nil {
			t.Fatal(err)
		}
		got = append(got, action)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("audit actions = %v, want %v", got, want)
	}
}

func assertCount(t *testing.T, pool *pgxpool.Pool, query string, want int, args ...any) {
	t.Helper()
	var got int
	if err := pool.QueryRow(context.Background(), query, args...).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("count = %d, want %d", got, want)
	}
}

func assertSQLRejected(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), query, args...); err == nil {
		t.Fatalf("SQL unexpectedly succeeded: %s", query)
	}
}

type failingAuditor struct{}

// discardAuditor accepts every event without writing it: for migration round
// trips on a schema below 361, whose audit_events lacks the unified-log
// columns audit.Append writes. Announcement facts do not reference audit rows.
type discardAuditor struct{}

func (discardAuditor) Append(context.Context, pgx.Tx, audit.Event) error { return nil }

func (failingAuditor) Append(context.Context, pgx.Tx, audit.Event) error {
	return errors.New("forced audit failure")
}

type failingPublicationOutbox struct{}

func (failingPublicationOutbox) EnqueuePublication(context.Context, pgx.Tx, PublicationNotice) error {
	return errors.New("forced outbox failure")
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

func isolatedAnnouncementPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if os.Getenv("ANNOUNCEMENT_MIGRATION_TARGET") == "" {
		if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
			return pool
		}
	}
	return isolatedAnnouncementSchema(t, true)
}

// isolatedAnnouncementSchema returns a fresh schema, migrated (to the head or
// ANNOUNCEMENT_MIGRATION_TARGET) when migrate is set.
func isolatedAnnouncementSchema(t *testing.T, migrate bool) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	// A full migration from scratch takes minutes on a loaded machine.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "announcement_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	admin.Close()

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if migrate {
		if err := migrateAnnouncementTestSchema(ctx, pool); err != nil {
			pool.Close()
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, cleanupErr := pgxpool.New(context.Background(), databaseURL)
		if cleanupErr == nil {
			_, _ = cleanup.Exec(context.Background(), `DROP SCHEMA `+pgx.Identifier{schema}.Sanitize()+` CASCADE`)
			cleanup.Close()
		}
	})
	return pool
}

func migrateAnnouncementTestSchema(ctx context.Context, pool *pgxpool.Pool) error {
	targetText := os.Getenv("ANNOUNCEMENT_MIGRATION_TARGET")
	if targetText == "" {
		return database.Migrate(ctx, pool, "up")
	}
	target, err := strconv.Atoi(targetText)
	if err != nil || target < 1 {
		return fmt.Errorf("invalid announcement migration target %q", targetText)
	}
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return err
	}
	expected := 1
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		separator := strings.IndexByte(name, '_')
		if separator < 1 {
			continue
		}
		version, err := strconv.Atoi(name[:separator])
		if err != nil {
			return err
		}
		if version > target {
			continue
		}
		if version != expected {
			return fmt.Errorf("migration target gap: expected %d, found %d", expected, version)
		}
		script, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, string(script)); err != nil {
			return fmt.Errorf("apply %s: %w", name, err)
		}
		expected++
	}
	if expected != target+1 {
		return fmt.Errorf("migration target incomplete: applied through %d, want %d", expected-1, target)
	}
	return nil
}
