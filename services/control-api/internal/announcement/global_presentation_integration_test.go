package announcement

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGlobalPresentationRoundTripVisibilityOrderingAndRollback(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	tenant := seedAnnouncementFixture(t, pool)
	platform := seedGlobalPlatformActor(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })
	ctx := context.Background()
	create := func(key string, presentation Presentation, body string) GlobalAnnouncement {
		t.Helper()
		item, err := store.CreateGlobalDraft(ctx, platform, CreateGlobalDraftRequest{
			Content: Content{Title: key, Body: body}, Presentation: presentation,
			Audience: GlobalAudience{AllTenants: true}, WithdrawalVisibility: VisibilityHide,
			IdempotencyKey: key, RequestID: key,
		})
		if err != nil {
			t.Fatal(err)
		}
		return item
	}
	link := create("link", Presentation{Format: FormatLink, LinkURL: "https://example.com/notice", SortOrder: 0, Visible: true, Popup: true, Red: true, Bold: true}, "")
	update := UpdateGlobalDraftRequest{AnnouncementID: link.ID, ExpectedRevision: link.Revision,
		Content: Content{Title: "updated-link"}, Presentation: Presentation{Format: FormatLink, LinkURL: "https://example.com/updated", SortOrder: 0, Visible: true, Popup: true, Red: true, Bold: true},
		Audience: link.Audience, WithdrawalVisibility: VisibilityHide, IdempotencyKey: "update-link", RequestID: "update-link"}
	updated, err := store.UpdateGlobalDraft(ctx, platform, update)
	if err != nil || updated.LinkURL != update.LinkURL || updated.SortOrder != 0 {
		t.Fatalf("update: %+v %v", updated, err)
	}
	replay, err := store.UpdateGlobalDraft(ctx, platform, update)
	if err != nil || !replay.Replayed || replay.Revision != updated.Revision {
		t.Fatalf("replay: %+v %v", replay, err)
	}
	update.IdempotencyKey = "stale-update"
	if _, err := store.UpdateGlobalDraft(ctx, platform, update); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale update: %v", err)
	}
	link = updated
	html := create("html", Presentation{Format: FormatContent, SortOrder: 50, Visible: true}, "<h2>维护公告</h2><p>正文</p>")
	hidden := create("hidden", Presentation{Format: FormatContent, SortOrder: 1, Visible: false, Popup: true}, "隐藏正文")
	for _, item := range []GlobalAnnouncement{link, html, hidden} {
		published, err := store.PublishGlobal(ctx, platform, GlobalTransitionRequest{AnnouncementID: item.ID, ExpectedRevision: item.Revision, IdempotencyKey: "publish-" + item.Title, RequestID: "publish"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `UPDATE platform_announcements_141 SET is_popup=NOT is_popup,revision=revision+1 WHERE id=$1`, published.ID); err == nil {
			t.Fatal("sealed presentation changed")
		}
	}
	page, err := store.ListInbox(ctx, tenant.adminFor(tenant.userA), ListRequest{Limit: 1})
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("first page: %+v %v", page, err)
	}
	first := page.Items[0]
	if first.AnnouncementID != link.ID || first.LinkURL != update.LinkURL || first.SortOrder != 0 || !first.Popup || !first.Red || !first.Bold {
		t.Fatalf("first: %+v", first)
	}
	page, err = store.ListInbox(ctx, tenant.adminFor(tenant.userA), ListRequest{Limit: 1, Cursor: page.NextCursor})
	if err != nil || len(page.Items) != 1 || page.Items[0].AnnouncementID != html.ID || page.NextCursor != "" {
		t.Fatalf("second page: %+v %v", page, err)
	}
	rollbackPool := globalPresentationMigrationPool(t)
	rollbackActor := seedGlobalPlatformActor(t, rollbackPool)
	if _, err := rollbackPool.Exec(ctx, `INSERT INTO platform_announcements_141(
		id,platform_scope_id,status,title,body,content_format,link_url,audience,withdrawal_visibility,created_by_user_id,created_at,updated_at
	) VALUES(gen_random_uuid(),$1,'draft','保留链接','','link',$2,'{"all_tenants":true,"tenant_scope_ids":[],"role_targets":[],"user_targets":[]}','retain',$3,$4,$4)`, rollbackActor.ScopeID, update.LinkURL, rollbackActor.UserID, fixedNow); err != nil {
		t.Fatal(err)
	}
	var rollbackError *pgconn.PgError
	if err := databasetest.MigrateThrough(ctx, rollbackPool, "down", globalPresentationMigration); !errors.As(err, &rollbackError) || rollbackError.Code != "P2454" {
		t.Fatalf("presentation rollback must reject stored settings: %v", err)
	}
	assertCount(t, rollbackPool, `SELECT count(*) FROM schema_migrations WHERE version=245`, 1)
	assertCount(t, rollbackPool, `SELECT count(*) FROM platform_announcements_141 WHERE content_format='link' AND link_url=$1`, 1, update.LinkURL)
}

func TestGlobalPresentationRejectsInvalidInput(t *testing.T) {
	for _, content := range []Content{{Title: "", Body: ""}, {Title: "title\n", Body: ""}} {
		if err := validateGlobalDraftInput(content, Presentation{Format: FormatLink, LinkURL: "https://example.com"}, GlobalAudience{AllTenants: true}, VisibilityHide, "invalid", "invalid"); err == nil {
			t.Fatal("invalid link title accepted")
		}
	}
}

func TestGlobalPresentationEmptyMigrationRollsBackAndReapplies(t *testing.T) {
	pool := globalPresentationMigrationPool(t)
	if err := databasetest.MigrateThrough(t.Context(), pool, "down", globalPresentationMigration); err != nil {
		t.Fatal(err)
	}
	assertCount(t, pool, `SELECT count(*) FROM schema_migrations WHERE version=245`, 0)
	if err := databasetest.MigrateThrough(t.Context(), pool, "up", globalPresentationMigration); err != nil {
		t.Fatal(err)
	}
	assertCount(t, pool, `SELECT count(*) FROM schema_migrations WHERE version=245`, 1)
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatalf("roll forward to release head: %v", err)
	}
}

// globalPresentationMigrationPool returns a schema whose head is 245. Migration
// 268's down is a deliberate one-way gate (P2682), so only 1..245 are loaded.
func globalPresentationMigrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := isolatedAnnouncementSchema(t, false)
	if err := databasetest.MigrateThrough(t.Context(), pool, "up", globalPresentationMigration); err != nil {
		t.Fatalf("migrate through %d: %v", globalPresentationMigration, err)
	}
	return pool
}

const globalPresentationMigration = 245
