package announcement

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
)

func TestAnnouncementArchiveCreationReplayAndRestore(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	request := CreateDraftRequest{
		Content: Content{Title: "归档生命周期", Body: "创建后可以归档和恢复"}, Audience: Audience{All: true},
		WithdrawalVisibility: VisibilityRetain, IdempotencyKey: "archive-create", RequestID: "req-archive-create",
	}
	created, err := store.CreateDraft(t.Context(), fixture.admin, request)
	if err != nil {
		t.Fatal(err)
	}
	if created.Archived || created.LifecycleRevision != 1 || created.ArchivedAt != nil {
		t.Fatalf("initial lifecycle = %+v", created)
	}
	assertCount(t, pool, `SELECT count(*) FROM announcement_archive_254 WHERE announcement_id=$1 AND NOT archived AND revision=1`, 1, created.ID)
	assertCount(t, pool, `SELECT count(*) FROM announcement_lifecycle_facts_254 WHERE announcement_id=$1 AND state='active' AND revision=1 AND watermark>0`, 1, created.ID)
	if replay, err := store.CreateDraft(t.Context(), fixture.admin, request); err != nil || !replay.Replayed || replay.ID != created.ID || replay.LifecycleRevision != 1 {
		t.Fatalf("create replay = %+v, %v", replay, err)
	}
	assertCount(t, pool, `SELECT count(*) FROM announcement_lifecycle_facts_254 WHERE announcement_id=$1`, 1, created.ID)
	loaded, err := store.GetAnnouncement(t.Context(), fixture.admin, created.ID)
	if err != nil || loaded.ID != created.ID || loaded.LifecycleRevision != 1 {
		t.Fatalf("created detail = %+v, %v", loaded, err)
	}

	archiveRequest := ArchiveRequest{AnnouncementID: created.ID, ExpectedLifecycleRevision: 1, IdempotencyKey: "archive", RequestID: "req-archive"}
	if _, err := store.Archive(t.Context(), fixture.adminFor(fixture.userA), archiveRequest); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("reader archive = %v", err)
	}
	archived, err := store.Archive(t.Context(), fixture.admin, archiveRequest)
	if err != nil || !archived.Archived || archived.LifecycleRevision != 2 || archived.ArchivedAt == nil {
		t.Fatalf("archive = %+v, %v", archived, err)
	}
	archiveRequest.RequestID = "req-archive-retry"
	if replay, err := store.Archive(t.Context(), fixture.admin, archiveRequest); err != nil || !replay.Replayed || replay.LifecycleRevision != 2 {
		t.Fatalf("archive replay = %+v, %v", replay, err)
	}
	archiveRequest.ExpectedLifecycleRevision = 2
	if _, err := store.Archive(t.Context(), fixture.admin, archiveRequest); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed archive replay = %v", err)
	}
	archiveRequest.ExpectedLifecycleRevision, archiveRequest.IdempotencyKey = 1, "archive-stale"
	if _, err := store.Archive(t.Context(), fixture.admin, archiveRequest); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale archive = %v", err)
	}
	assertCount(t, pool, `SELECT count(*) FROM announcement_lifecycle_facts_254 WHERE announcement_id=$1`, 2, created.ID)
	page, err := store.ListAnnouncements(t.Context(), fixture.admin, AnnouncementListRequest{})
	if err != nil || len(page.Items) != 0 {
		t.Fatalf("active list after archive = %+v, %v", page, err)
	}
	page, err = store.ListAnnouncements(t.Context(), fixture.admin, AnnouncementListRequest{Status: StatusArchived})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != created.ID || !page.Items[0].Archived {
		t.Fatalf("archived list = %+v, %v", page, err)
	}

	restoreRequest := RestoreRequest{AnnouncementID: created.ID, ExpectedLifecycleRevision: 2, IdempotencyKey: "restore", RequestID: "req-restore"}
	if _, err := store.Restore(t.Context(), fixture.adminFor(fixture.userA), restoreRequest); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("reader restore = %v", err)
	}
	restored, err := store.Restore(t.Context(), fixture.admin, restoreRequest)
	if err != nil || restored.Archived || restored.LifecycleRevision != 3 || restored.ArchivedAt != nil {
		t.Fatalf("restore = %+v, %v", restored, err)
	}
	if replay, err := store.Restore(t.Context(), fixture.admin, restoreRequest); err != nil || !replay.Replayed || replay.LifecycleRevision != 3 {
		t.Fatalf("restore replay = %+v, %v", replay, err)
	}
	page, err = store.ListAnnouncements(t.Context(), fixture.admin, AnnouncementListRequest{})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != created.ID || page.Items[0].Archived || page.Items[0].LifecycleRevision != 3 {
		t.Fatalf("restored active list = %+v, %v", page, err)
	}
	assertCount(t, pool, `SELECT count(*) FROM announcement_lifecycle_facts_254 WHERE announcement_id=$1`, 3, created.ID)
	assertAuditActions(t, pool, fixture.scopeID, operationCreate, operationArchive, operationRestore)
	assertSQLRejected(t, pool, `UPDATE announcement_lifecycle_facts_254 SET state='active' WHERE announcement_id=$1 AND revision=2`, created.ID)
}

func TestAnnouncementArchiveAuditFailureRollsBackLifecycle(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	failing := newTestStore(t, pool, failingAuditor{}, func() time.Time { return fixedNow })
	_, err := failing.CreateDraft(t.Context(), fixture.admin, CreateDraftRequest{
		Content: Content{Title: "审计失败", Body: "不得遗留生命周期"}, Audience: Audience{All: true},
		WithdrawalVisibility: VisibilityRetain, IdempotencyKey: "failed-create", RequestID: "req-failed-create",
	})
	if err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("create audit failure = %v", err)
	}
	for _, table := range []string{"announcements", "announcement_archive_254", "announcement_lifecycle_facts_254", "announcement_write_requests"} {
		assertCount(t, pool, "SELECT count(*) FROM "+table, 0)
	}
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	created := mustCreateDraft(t, store, fixture.admin, "audit-archive", Audience{All: true})
	_, err = failing.Archive(t.Context(), fixture.admin, ArchiveRequest{
		AnnouncementID: created.ID, ExpectedLifecycleRevision: 1, IdempotencyKey: "failed-archive", RequestID: "req-failed-archive",
	})
	if err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("archive audit failure = %v", err)
	}
	assertCount(t, pool, `SELECT count(*) FROM announcement_archive_254 WHERE announcement_id=$1 AND NOT archived AND revision=1`, 1, created.ID)
	assertCount(t, pool, `SELECT count(*) FROM announcement_lifecycle_facts_254 WHERE announcement_id=$1`, 1, created.ID)
	assertCount(t, pool, `SELECT count(*) FROM announcement_write_requests WHERE operation='announcement.archive'`, 0)
	archived, err := store.Archive(t.Context(), fixture.admin, ArchiveRequest{
		AnnouncementID: created.ID, ExpectedLifecycleRevision: 1, IdempotencyKey: "archive-after-failure", RequestID: "req-archive-after-failure",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = failing.Restore(t.Context(), fixture.admin, RestoreRequest{
		AnnouncementID: created.ID, ExpectedLifecycleRevision: archived.LifecycleRevision, IdempotencyKey: "failed-restore", RequestID: "req-failed-restore",
	})
	if err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("restore audit failure = %v", err)
	}
	assertCount(t, pool, `SELECT count(*) FROM announcement_archive_254 WHERE announcement_id=$1 AND archived AND revision=2`, 1, created.ID)
	assertCount(t, pool, `SELECT count(*) FROM announcement_lifecycle_facts_254 WHERE announcement_id=$1`, 2, created.ID)
	assertCount(t, pool, `SELECT count(*) FROM announcement_write_requests WHERE operation='announcement.restore'`, 0)
	assertAuditActions(t, pool, fixture.scopeID, operationCreate, operationArchive)
}

func TestAnnouncementArchiveCASAllowsSingleWinner(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	created := mustCreateDraft(t, store, fixture.admin, "archive-cas", Audience{All: true})
	errorsByRequest := make(chan error, 2)
	for index := range 2 {
		go func() {
			_, err := store.Archive(t.Context(), fixture.admin, ArchiveRequest{
				AnnouncementID: created.ID, ExpectedLifecycleRevision: 1,
				IdempotencyKey: fmt.Sprintf("archive-cas-%d", index), RequestID: fmt.Sprintf("req-archive-cas-%d", index),
			})
			errorsByRequest <- err
		}()
	}
	winners, conflicts := 0, 0
	for range 2 {
		err := <-errorsByRequest
		if err == nil {
			winners++
		} else if errors.Is(err, ErrRevisionConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("CAS winners=%d conflicts=%d", winners, conflicts)
	}
	assertCount(t, pool, `SELECT count(*) FROM announcement_lifecycle_facts_254 WHERE announcement_id=$1`, 2, created.ID)
	assertAuditActions(t, pool, fixture.scopeID, operationCreate, operationArchive)
}

func TestAnnouncementArchiveCursorFreezesLifecycleAcrossPages(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	clock := &testClock{now: fixedNow}
	store := newTestStore(t, pool, audit.New(pool), clock.Now)
	older := mustCreateDraft(t, store, fixture.admin, "archive-old", Audience{All: true})
	clock.Set(fixedNow.Add(time.Second))
	newer := mustCreateDraft(t, store, fixture.admin, "archive-new", Audience{All: true})
	first, err := store.ListAnnouncements(t.Context(), fixture.admin, AnnouncementListRequest{Limit: 1})
	if err != nil || len(first.Items) != 1 || first.Items[0].ID != newer.ID || first.NextCursor == "" {
		t.Fatalf("active first page = %+v, %v", first, err)
	}
	for _, item := range []Announcement{older, newer} {
		if _, err := store.Archive(t.Context(), fixture.admin, ArchiveRequest{
			AnnouncementID: item.ID, ExpectedLifecycleRevision: 1, IdempotencyKey: "archive-" + item.ID.String(), RequestID: "req-archive-" + item.ID.String(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	second, err := store.ListAnnouncements(t.Context(), fixture.admin, AnnouncementListRequest{Limit: 1, Cursor: first.NextCursor})
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != older.ID || second.Items[0].Archived || second.Items[0].LifecycleRevision != 1 {
		t.Fatalf("frozen active second page = %+v, %v", second, err)
	}
	first, err = store.ListAnnouncements(t.Context(), fixture.admin, AnnouncementListRequest{Limit: 1, Status: StatusArchived})
	if err != nil || len(first.Items) != 1 || first.Items[0].ID != newer.ID || first.NextCursor == "" {
		t.Fatalf("archived first page = %+v, %v", first, err)
	}
	if _, err := store.Restore(t.Context(), fixture.admin, RestoreRequest{
		AnnouncementID: older.ID, ExpectedLifecycleRevision: 2, IdempotencyKey: "restore-old", RequestID: "req-restore-old",
	}); err != nil {
		t.Fatal(err)
	}
	second, err = store.ListAnnouncements(t.Context(), fixture.admin, AnnouncementListRequest{Limit: 1, Status: StatusArchived, Cursor: first.NextCursor})
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != older.ID || !second.Items[0].Archived || second.Items[0].LifecycleRevision != 2 || second.Items[0].ArchivedAt == nil {
		t.Fatalf("frozen archived second page = %+v, %v", second, err)
	}
	current, err := store.ListAnnouncements(t.Context(), fixture.admin, AnnouncementListRequest{Status: StatusArchived})
	if err != nil || len(current.Items) != 1 || current.Items[0].ID != newer.ID {
		t.Fatalf("fresh archived page = %+v, %v", current, err)
	}
}
