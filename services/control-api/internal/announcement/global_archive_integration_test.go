package announcement

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestGlobalArchiveLegacyReplayLifecycle(t *testing.T) {
	legacy := `{"id":"2caa83ca-e1d9-4415-a551-996db7138507","platform_scope_id":"d22a2d05-d08b-4964-a68c-708c8b56e589","version":1,"revision":3,"status":"published","title":"historical title"}`
	for _, test := range []struct {
		name, extra string
		invalid     bool
		archived    bool
		revision    int64
	}{
		{name: "legacy", revision: 1},
		{name: "current", extra: `,"archived":false,"lifecycle_revision":3`, revision: 3},
		{name: "archived", extra: `,"archived":true,"lifecycle_revision":2,"archived_at":"2026-09-28T00:00:00Z"`, archived: true, revision: 2},
		{name: "explicit zero", extra: `,"archived":false,"lifecycle_revision":0`, invalid: true},
		{name: "missing revision", extra: `,"archived":false`, invalid: true},
		{name: "missing archived", extra: `,"lifecycle_revision":1`, invalid: true},
		{name: "null archived", extra: `,"archived":null,"lifecycle_revision":1`, invalid: true},
		{name: "null revision", extra: `,"archived":false,"lifecycle_revision":null`, invalid: true},
		{name: "bad revision", extra: `,"archived":false,"lifecycle_revision":"1"`, invalid: true},
		{name: "missing archive timestamp", extra: `,"archived":true,"lifecycle_revision":2`, invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var result GlobalAnnouncement
			err := decodeGlobalReplay([]byte(strings.TrimSuffix(legacy, "}")+test.extra+"}"), &result)
			if test.invalid {
				if err == nil {
					t.Fatal("invalid stored replay was silently repaired")
				}
				return
			}
			if err != nil || !result.Replayed || result.LifecycleRevision != test.revision || result.Archived != test.archived || result.Title != "historical title" || result.Revision != 3 {
				t.Fatalf("replay: %+v %v", result, err)
			}
		})
	}
	var invalid GlobalAnnouncement
	if err := decodeGlobalReplay([]byte(`{}`), &invalid); err == nil {
		t.Fatal("empty stored replay was treated as legacy")
	}
}

func TestGlobalArchiveInitialLifecycle(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	platform := seedGlobalPlatformActor(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	item, err := store.CreateGlobalDraft(t.Context(), platform, CreateGlobalDraftRequest{
		Content: Content{Title: "全局归档", Body: "保留发布历史"}, Audience: GlobalAudience{AllTenants: true},
		WithdrawalVisibility: VisibilityRetain, IdempotencyKey: "global-archive-initial", RequestID: "global-archive-initial",
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	var resource map[string]any
	if err := json.Unmarshal(encoded, &resource); err != nil {
		t.Fatal(err)
	}
	if resource["archived"] != false || resource["lifecycle_revision"] != float64(1) {
		t.Fatalf("missing initial lifecycle: %s", encoded)
	}
	page, err := store.ListGlobalAnnouncements(t.Context(), platform, AnnouncementListRequest{})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != item.ID || page.Items[0].Title != item.Title {
		t.Fatalf("initial snapshot: %+v %v", page, err)
	}
}

func TestGlobalArchiveConcurrentPublishRechecksLifecycle(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	seedAnnouncementFixture(t, pool)
	platform := seedGlobalPlatformActor(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	draft := mustGlobalArchiveDraft(t, store, platform, "concurrent-publish")
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := loadGlobalAnnouncement(t.Context(), tx, platform.ScopeID, draft.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE platform_announcement_archive_255 SET archived=true,revision=2,
		changed_at=$3,changed_by_user_id=$4,archived_at=$3,archived_by_user_id=$4
		WHERE platform_scope_id=$1 AND announcement_id=$2`, platform.ScopeID, draft.ID, fixedNow, platform.UserID); err != nil {
		t.Fatal(err)
	}
	published := make(chan error, 1)
	go func() {
		_, err := store.PublishGlobal(t.Context(), platform, GlobalTransitionRequest{AnnouncementID: draft.ID,
			ExpectedRevision: 1, IdempotencyKey: "publish-waiting", RequestID: "publish-waiting"})
		published <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var blocked bool
		if err := pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity
			WHERE $1::integer=ANY(pg_blocking_pids(pid)))`, tx.Conn().PgConn().PID()).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("publish did not wait for the concurrent archive")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-published; !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("publish after waiting on archive: %v", err)
	}
	assertCount(t, pool, `SELECT count(*) FROM platform_announcement_recipients_141 WHERE announcement_id=$1`, 0, draft.ID)
	assertCount(t, pool, `SELECT count(*) FROM platform_announcements_141 WHERE id=$1 AND status='draft'`, 1, draft.ID)
}

func TestGlobalArchivePreservesPublicationAndRestores(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	tenant := seedAnnouncementFixture(t, pool)
	platform := seedGlobalPlatformActor(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	draft := mustGlobalArchiveDraft(t, store, platform, "published")
	published, err := store.PublishGlobal(t.Context(), platform, GlobalTransitionRequest{AnnouncementID: draft.ID, ExpectedRevision: 1, IdempotencyKey: "publish", RequestID: "publish"})
	if err != nil {
		t.Fatal(err)
	}
	inbox, err := store.ListInbox(t.Context(), tenant.adminFor(tenant.userA), ListRequest{})
	if err != nil || len(inbox.Items) != 1 {
		t.Fatalf("published inbox: %+v %v", inbox, err)
	}
	read, err := store.MarkRead(t.Context(), tenant.adminFor(tenant.userA), StateRequest{EventID: inbox.Items[0].ID, ExpectedRevision: 1, IdempotencyKey: "read", RequestID: "read"})
	if err != nil {
		t.Fatal(err)
	}
	request := ArchiveRequest{AnnouncementID: draft.ID, ExpectedLifecycleRevision: 1, IdempotencyKey: "archive", RequestID: "archive"}
	if _, err := store.ArchiveGlobal(t.Context(), tenant.admin, request); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant archive: %v", err)
	}
	missing := request
	missing.AnnouncementID = uuid.New()
	if _, err := store.ArchiveGlobal(t.Context(), platform, missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown announcement archive: %v", err)
	}
	invalid := request
	invalid.ExpectedLifecycleRevision = 0
	if _, err := store.ArchiveGlobal(t.Context(), platform, invalid); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid archive: %v", err)
	}
	archived, err := store.ArchiveGlobal(t.Context(), platform, request)
	if err != nil || !archived.Archived || archived.LifecycleRevision != 2 || archived.ArchivedAt == nil || archived.Revision != published.Revision || archived.Status != StatusPublished {
		t.Fatalf("archive: %+v %v", archived, err)
	}
	request.RequestID = "archive-retry"
	if replay, err := store.ArchiveGlobal(t.Context(), platform, request); err != nil || !replay.Replayed || replay.LifecycleRevision != 2 {
		t.Fatalf("archive replay: %+v %v", replay, err)
	}
	request.ExpectedLifecycleRevision = 2
	if _, err := store.ArchiveGlobal(t.Context(), platform, request); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay: %v", err)
	}
	request.ExpectedLifecycleRevision, request.IdempotencyKey = 1, "stale"
	if _, err := store.ArchiveGlobal(t.Context(), platform, request); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale archive: %v", err)
	}
	active, err := store.ListGlobalAnnouncements(t.Context(), platform, AnnouncementListRequest{})
	if err != nil || len(active.Items) != 0 {
		t.Fatalf("active after archive: %+v %v", active, err)
	}
	inbox, err = store.ListInbox(t.Context(), tenant.adminFor(tenant.userA), ListRequest{})
	if err != nil || len(inbox.Items) != 1 || inbox.Items[0].ReadAt == nil || !inbox.Items[0].ReadAt.Equal(*read.ReadAt) {
		t.Fatalf("archive changed published history: %+v %v", inbox, err)
	}
	assertCount(t, pool, `SELECT count(*) FROM platform_announcement_recipients_141 WHERE announcement_id=$1`, int(published.RecipientCount), draft.ID)
	restore := RestoreRequest{AnnouncementID: draft.ID, ExpectedLifecycleRevision: 2, IdempotencyKey: "restore", RequestID: "restore"}
	restored, err := store.RestoreGlobal(t.Context(), platform, restore)
	if err != nil || restored.Archived || restored.LifecycleRevision != 3 || restored.ArchivedAt != nil || restored.Status != StatusPublished || restored.Revision != published.Revision {
		t.Fatalf("restore: %+v %v", restored, err)
	}
	if replay, err := store.RestoreGlobal(t.Context(), platform, restore); err != nil || !replay.Replayed || replay.LifecycleRevision != 3 {
		t.Fatalf("restore replay: %+v %v", replay, err)
	}
	assertAuditActions(t, pool, platform.ScopeID, operationGlobalCreate, operationGlobalPublish, operationGlobalArchive, operationGlobalRestore)
	assertSQLRejected(t, pool, `DELETE FROM platform_announcement_archive_255 WHERE announcement_id=$1`, draft.ID)
	assertSQLRejected(t, pool, `UPDATE platform_announcement_snapshots_255 SET payload='{}' WHERE announcement_id=$1`, draft.ID)
	assertSQLRejected(t, pool, `INSERT INTO platform_announcement_snapshots_255(platform_scope_id,announcement_id,payload) VALUES($1,$2,'{}')`, platform.ScopeID, draft.ID)
	if _, err := pool.Exec(t.Context(), `UPDATE auth_sessions SET revoked_at=$2,revocation_reason='test-revoke' WHERE id=$1`, platform.SessionID, fixedNow); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestoreGlobal(t.Context(), platform, restore); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("revoked replay: %v", err)
	}
}

func TestGlobalArchiveAuditFailureAndConcurrentCAS(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	platform := seedGlobalPlatformActor(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	failing := newTestStore(t, pool, failingAuditor{}, func() time.Time { return fixedNow })
	_, err := failing.CreateGlobalDraft(t.Context(), platform, CreateGlobalDraftRequest{Content: Content{Title: "回滚", Body: "回滚"}, Audience: GlobalAudience{AllTenants: true}, WithdrawalVisibility: VisibilityRetain, IdempotencyKey: "fail-create", RequestID: "fail-create"})
	if err == nil {
		t.Fatal("create audit failure accepted")
	}
	for _, table := range []string{"platform_announcements_141", "platform_announcement_archive_255", "platform_announcement_snapshots_255", "announcement_write_requests"} {
		assertCount(t, pool, "SELECT count(*) FROM "+table, 0)
	}
	draft := mustGlobalArchiveDraft(t, store, platform, "audit")
	request := ArchiveRequest{AnnouncementID: draft.ID, ExpectedLifecycleRevision: 1, IdempotencyKey: "fail-archive", RequestID: "fail-archive"}
	if _, err := failing.ArchiveGlobal(t.Context(), platform, request); err == nil {
		t.Fatal("archive audit failure accepted")
	}
	assertCount(t, pool, `SELECT count(*) FROM platform_announcement_snapshots_255`, 1)
	assertCount(t, pool, `SELECT count(*) FROM platform_announcement_archive_255 WHERE NOT archived AND revision=1`, 1)
	errorsByRequest := make(chan error, 2)
	for index := range 2 {
		go func() {
			_, err := store.ArchiveGlobal(t.Context(), platform, ArchiveRequest{AnnouncementID: draft.ID, ExpectedLifecycleRevision: 1, IdempotencyKey: fmt.Sprintf("cas-%d", index), RequestID: "cas"})
			errorsByRequest <- err
		}()
	}
	winners, conflicts := 0, 0
	for range 2 {
		if err := <-errorsByRequest; err == nil {
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
	restore := RestoreRequest{AnnouncementID: draft.ID, ExpectedLifecycleRevision: 2, IdempotencyKey: "fail-restore", RequestID: "fail-restore"}
	if _, err := failing.RestoreGlobal(t.Context(), platform, restore); err == nil {
		t.Fatal("restore audit failure accepted")
	}
	assertCount(t, pool, `SELECT count(*) FROM platform_announcement_snapshots_255`, 2)
	assertCount(t, pool, `SELECT count(*) FROM platform_announcement_archive_255 WHERE archived AND revision=2`, 1)
	assertCount(t, pool, `SELECT count(*) FROM announcement_write_requests WHERE operation=$1`, 0, operationGlobalRestore)
	if _, err := store.PublishGlobal(t.Context(), platform, GlobalTransitionRequest{AnnouncementID: draft.ID, ExpectedRevision: 1, IdempotencyKey: "publish-archived", RequestID: "publish-archived"}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("publish archived: %v", err)
	}
	if _, err := store.UpdateGlobalDraft(t.Context(), platform, UpdateGlobalDraftRequest{AnnouncementID: draft.ID, ExpectedRevision: 1, Content: Content{Title: "禁止编辑", Body: "禁止编辑"}, Audience: draft.Audience, WithdrawalVisibility: draft.WithdrawalVisibility, IdempotencyKey: "edit-archived", RequestID: "edit-archived"}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("edit archived: %v", err)
	}
	assertSQLRejected(t, pool, `UPDATE platform_announcements_141 SET title='edited',revision=revision+1 WHERE id=$1`, draft.ID)
}

func TestGlobalArchiveSnapshotsFreezeContentStatusAndLifecycle(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	seedAnnouncementFixture(t, pool)
	platform := seedGlobalPlatformActor(t, pool)
	clock := &testClock{now: fixedNow}
	store := newTestStore(t, pool, audit.New(pool), clock.Now)
	older := mustGlobalArchiveDraft(t, store, platform, "old")
	clock.Set(fixedNow.Add(time.Second))
	newer := mustGlobalArchiveDraft(t, store, platform, "new")
	first, err := store.ListGlobalAnnouncements(t.Context(), platform, AnnouncementListRequest{Limit: 1})
	if err != nil || len(first.Items) != 1 || first.Items[0].ID != newer.ID || first.NextCursor == "" {
		t.Fatalf("first: %+v %v", first, err)
	}
	updated, err := store.UpdateGlobalDraft(t.Context(), platform, UpdateGlobalDraftRequest{AnnouncementID: older.ID, ExpectedRevision: 1, Content: Content{Title: "changed", Body: older.Body}, Audience: older.Audience, WithdrawalVisibility: older.WithdrawalVisibility, IdempotencyKey: "update-old", RequestID: "update-old"})
	if err != nil {
		t.Fatal(err)
	}
	published, err := store.PublishGlobal(t.Context(), platform, GlobalTransitionRequest{AnnouncementID: older.ID, ExpectedRevision: updated.Revision, IdempotencyKey: "publish-old", RequestID: "publish-old"})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []GlobalAnnouncement{older, newer} {
		if _, err := store.ArchiveGlobal(t.Context(), platform, ArchiveRequest{AnnouncementID: item.ID, ExpectedLifecycleRevision: 1, IdempotencyKey: "archive-" + item.ID.String(), RequestID: "archive"}); err != nil {
			t.Fatal(err)
		}
	}
	second, err := store.ListGlobalAnnouncements(t.Context(), platform, AnnouncementListRequest{Limit: 1, Cursor: first.NextCursor})
	if err != nil || len(second.Items) != 1 || second.Items[0].ID != older.ID || second.Items[0].Title != older.Title || second.Items[0].Status != StatusDraft || second.Items[0].Archived {
		t.Fatalf("frozen active: %+v %v", second, err)
	}
	if _, err := store.ListGlobalAnnouncements(t.Context(), platform, AnnouncementListRequest{Status: StatusArchived, Cursor: first.NextCursor}); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-filter cursor: %v", err)
	}
	first, err = store.ListGlobalAnnouncements(t.Context(), platform, AnnouncementListRequest{Limit: 1, Status: StatusArchived})
	if err != nil || first.NextCursor == "" {
		t.Fatalf("archived first: %+v %v", first, err)
	}
	if _, err := store.RestoreGlobal(t.Context(), platform, RestoreRequest{AnnouncementID: older.ID, ExpectedLifecycleRevision: 2, IdempotencyKey: "restore-old", RequestID: "restore-old"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WithdrawGlobal(t.Context(), platform, GlobalTransitionRequest{AnnouncementID: older.ID, ExpectedRevision: published.Revision, IdempotencyKey: "withdraw-old", RequestID: "withdraw-old"}); err != nil {
		t.Fatal(err)
	}
	second, err = store.ListGlobalAnnouncements(t.Context(), platform, AnnouncementListRequest{Limit: 1, Status: StatusArchived, Cursor: first.NextCursor})
	if err != nil || len(second.Items) != 1 || !second.Items[0].Archived || second.Items[0].LifecycleRevision != 2 || second.Items[0].Status != StatusPublished || second.Items[0].Title != "changed" {
		t.Fatalf("frozen archive: %+v %v", second, err)
	}
	current, err := store.ListGlobalAnnouncements(t.Context(), platform, AnnouncementListRequest{})
	if err != nil || len(current.Items) != 1 || current.Items[0].Status != StatusWithdrawn || current.Items[0].Archived {
		t.Fatalf("current snapshot: %+v %v", current, err)
	}
}

func TestGlobalArchiveMigrationBackfillAndRollback(t *testing.T) {
	// Migration 268's down is a deliberate one-way gate (P2682) and later
	// migrations sit on top of 255; pin the schema head to 255 for this test.
	pool := isolatedAnnouncementSchema(t, false)
	if err := databasetest.MigrateThrough(t.Context(), pool, "up", 255); err != nil {
		t.Fatal(err)
	}
	if err := databasetest.MigrateThrough(t.Context(), pool, "down", 255); err != nil {
		t.Fatal(err)
	}
	platform := seedGlobalPlatformActor(t, pool)
	id := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO platform_announcements_141(id,platform_scope_id,status,title,body,audience,withdrawal_visibility,created_by_user_id,created_at,updated_at)
		VALUES($1,$2,'draft','历史公告','保留正文','{"all_tenants":true,"tenant_scope_ids":[],"role_targets":[],"user_targets":[]}','retain',$3,$4,$4)`, id, platform.ScopeID, platform.UserID, fixedNow); err != nil {
		t.Fatal(err)
	}
	if err := databasetest.MigrateThrough(t.Context(), pool, "up", 255); err != nil {
		t.Fatal(err)
	}
	store := newTestStore(t, pool, discardAuditor{}, func() time.Time { return fixedNow })
	page, err := store.ListGlobalAnnouncements(t.Context(), platform, AnnouncementListRequest{})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != id || page.Items[0].LifecycleRevision != 1 || page.Items[0].Archived {
		t.Fatalf("backfill: %+v %v", page, err)
	}
	if err := databasetest.MigrateThrough(t.Context(), pool, "down", 255); err != nil {
		t.Fatal(err)
	}
	if err := databasetest.MigrateThrough(t.Context(), pool, "up", 255); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ArchiveGlobal(t.Context(), platform, ArchiveRequest{AnnouncementID: id, ExpectedLifecycleRevision: 1, IdempotencyKey: "archive-baseline", RequestID: "archive-baseline"}); err != nil {
		t.Fatal(err)
	}
	var rejection *pgconn.PgError
	if err := databasetest.MigrateThrough(t.Context(), pool, "down", 255); !errors.As(err, &rejection) || rejection.Code != "P2553" || !strings.Contains(err.Error(), "history") {
		t.Fatalf("rollback discarded history: %v", err)
	}
	assertCount(t, pool, `SELECT count(*) FROM schema_migrations WHERE version=255`, 1)
}

func mustGlobalArchiveDraft(t *testing.T, store *Store, actor Actor, key string) GlobalAnnouncement {
	t.Helper()
	item, err := store.CreateGlobalDraft(t.Context(), actor, CreateGlobalDraftRequest{Content: Content{Title: key, Body: "归档测试"}, Audience: GlobalAudience{AllTenants: true}, WithdrawalVisibility: VisibilityRetain, IdempotencyKey: key, RequestID: key})
	if err != nil {
		t.Fatal(err)
	}
	return item
}
