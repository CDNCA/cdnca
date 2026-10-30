package announcement

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FX16: a user who joins a tenant after an audience "all" announcement was
// published sees it in the inbox; selected audiences stay frozen and the
// withdrawal semantics are unchanged.
func TestAudienceAllAnnouncementReachesLateMembers(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	fixture := seedAnnouncementFixture(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })

	everyone := mustPublish(t, store, fixture.admin, mustCreateDraft(t, store, fixture.admin, "late-all", Audience{All: true}))
	selected := mustPublish(t, store, fixture.admin, mustCreateDraft(t, store, fixture.admin, "late-selected", Audience{UserIDs: []uuid.UUID{fixture.userA}}))
	hidden := mustPublish(t, store, fixture.admin, mustCreateDraftVisibility(t, store, fixture.admin, "late-hidden", VisibilityHide, Audience{All: true}))
	if _, err := store.Withdraw(context.Background(), fixture.admin, WithdrawRequest{
		AnnouncementID: hidden.ID, Version: hidden.Version, ExpectedRevision: hidden.Revision,
		IdempotencyKey: "withdraw-late-hidden", RequestID: "req-withdraw-late-hidden",
	}); err != nil {
		t.Fatal(err)
	}

	late := joinTenantAsReader(t, pool, fixture.scopeID, "late-member")
	page, err := store.ListInbox(context.Background(), late, ListRequest{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].AnnouncementID != everyone.ID || page.Items[0].ReadAt != nil ||
		!page.Items[0].PublishedAt.Equal(*everyone.PublishedAt) {
		t.Fatalf("late member inbox = %+v", page.Items)
	}
	assertCount(t, pool, `SELECT count(*) FROM announcement_recipient_snapshots WHERE announcement_id=$1 AND user_id=$2`, 0, selected.ID, late.UserID)
	assertCount(t, pool, `SELECT count(*) FROM announcement_inbox_events WHERE announcement_id=$1 AND recipient_user_id=$2`, 0, hidden.ID, late.UserID)

	read, err := store.MarkRead(context.Background(), late, StateRequest{
		EventID: page.Items[0].ID, ExpectedRevision: page.Items[0].StateRevision,
		IdempotencyKey: "late-read", RequestID: "req-late-read",
	})
	if err != nil || read.ReadAt == nil {
		t.Fatalf("late member read = %+v, %v", read, err)
	}

	// Suspending and reactivating the member neither duplicates nor resets it.
	for _, status := range []string{"suspended", "active"} {
		if _, err := pool.Exec(context.Background(), `UPDATE memberships SET status=$3 WHERE scope_id=$1 AND user_id=$2`,
			fixture.scopeID, late.UserID, status); err != nil {
			t.Fatal(err)
		}
	}
	assertCount(t, pool, `SELECT count(*) FROM announcement_inbox_events WHERE announcement_id=$1 AND recipient_user_id=$2`, 1, everyone.ID, late.UserID)

	// Withdrawing with "hide" removes it from the late member as well.
	current, err := store.GetAnnouncement(context.Background(), fixture.admin, everyone.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Withdraw(context.Background(), fixture.admin, WithdrawRequest{
		AnnouncementID: everyone.ID, Version: everyone.Version, ExpectedRevision: current.Revision,
		IdempotencyKey: "withdraw-late-all", RequestID: "req-withdraw-late-all",
	}); err != nil {
		t.Fatal(err)
	}
	after, err := store.ListInbox(context.Background(), late, ListRequest{Limit: 10})
	if err != nil || len(after.Items) != 1 {
		t.Fatalf("retained withdrawal = %+v, %v", after, err)
	}

	// A late recipient cannot be forged outside the membership trigger.
	assertSQLRejected(t, pool, `INSERT INTO announcement_recipient_snapshots(tenant_scope_id,announcement_id,announcement_version,user_id,resolved_at)
		VALUES($1,$2,$3,$4,now())`, fixture.scopeID, selected.ID, selected.Version, late.UserID)
}

func TestGlobalAnnouncementReachesMembersOfLaterTenants(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	mainTenant := seedAnnouncementFixture(t, pool)
	platform := seedGlobalPlatformActor(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })

	publishGlobal := func(key string, audience GlobalAudience, visibility string) GlobalAnnouncement {
		t.Helper()
		draft, err := store.CreateGlobalDraft(context.Background(), platform, CreateGlobalDraftRequest{
			Content: Content{Title: key, Body: "正文"}, Audience: audience,
			Presentation:         Presentation{Format: FormatContent, SortOrder: 100, Visible: true, Popup: true},
			WithdrawalVisibility: visibility, IdempotencyKey: "create-" + key, RequestID: "req-create-" + key,
		})
		if err != nil {
			t.Fatal(err)
		}
		published, err := store.PublishGlobal(context.Background(), platform, GlobalTransitionRequest{
			AnnouncementID: draft.ID, ExpectedRevision: draft.Revision,
			IdempotencyKey: "publish-" + key, RequestID: "req-publish-" + key,
		})
		if err != nil {
			t.Fatal(err)
		}
		return published
	}
	allTenants := publishGlobal("global-late-all", GlobalAudience{AllTenants: true}, VisibilityHide)
	mainOnly := publishGlobal("global-late-main", GlobalAudience{TenantScopeIDs: []uuid.UUID{mainTenant.scopeID}}, VisibilityRetain)
	roleOnly := publishGlobal("global-late-role", GlobalAudience{RoleTargets: []GlobalRoleTarget{{ScopeID: mainTenant.scopeID, RoleID: mainTenant.groupID}}}, VisibilityRetain)

	// A tenant registered after publication.
	newTenant := seedAdditionalTenant(t, pool)
	grantGlobalInboxRead(t, pool, newTenant.scopeID, newTenant.userID)
	newActor := Actor{ScopeID: newTenant.scopeID, UserID: newTenant.userID, SessionID: seedAnnouncementSession(t, pool, newTenant.scopeID, newTenant.userID)}
	page, err := store.ListInbox(context.Background(), newActor, ListRequest{Limit: 10})
	if err != nil || len(page.Items) != 1 || page.Items[0].AnnouncementID != allTenants.ID || !page.Items[0].Popup {
		t.Fatalf("new tenant inbox = %+v, %v", page, err)
	}

	// A member who joins the targeted tenant later.
	late := joinTenantAsReader(t, pool, mainTenant.scopeID, "global-late-member")
	mainPage, err := store.ListInbox(context.Background(), late, ListRequest{Limit: 10})
	if err != nil || len(mainPage.Items) != 2 {
		t.Fatalf("late main member inbox = %+v, %v", mainPage, err)
	}
	assertCount(t, pool, `SELECT count(*) FROM platform_announcement_recipients_141 WHERE announcement_id=$1 AND user_id=$2`, 0, roleOnly.ID, late.UserID)

	read, err := store.MarkRead(context.Background(), newActor, StateRequest{
		EventID: page.Items[0].ID, ExpectedRevision: page.Items[0].StateRevision,
		IdempotencyKey: "global-late-read", RequestID: "req-global-late-read",
	})
	if err != nil || read.ReadAt == nil {
		t.Fatalf("late global read = %+v, %v", read, err)
	}
	withdrawn, err := store.WithdrawGlobal(context.Background(), platform, GlobalTransitionRequest{
		AnnouncementID: allTenants.ID, ExpectedRevision: allTenants.Revision,
		IdempotencyKey: "withdraw-global-late-all", RequestID: "req-withdraw-global-late-all",
	})
	if err != nil || withdrawn.Status != StatusWithdrawn {
		t.Fatalf("withdraw = %+v, %v", withdrawn, err)
	}
	if page, err := store.ListInbox(context.Background(), newActor, ListRequest{Limit: 10}); err != nil || len(page.Items) != 0 {
		t.Fatalf("withdrawn hide inbox = %+v, %v", page, err)
	}
	// Members joining after the withdrawal do not receive it.
	other := joinTenantAsReader(t, pool, newTenant.scopeID, "global-after-withdraw")
	assertCount(t, pool, `SELECT count(*) FROM platform_announcement_recipients_141 WHERE user_id=$1`, 0, other.UserID)
	_ = mainOnly
}

func TestLateJoinMigrationRollsBackAndReapplies(t *testing.T) {
	// 304's own round trip: the schema stops at 304 (MigrateThrough down only
	// rolls back the current head, so a release-head schema cannot do it).
	pool := databasetest.MigratedThroughPool(t, "announcement_late_join", lateJoinMigrationVersion)
	fixture := seedAnnouncementFixture(t, pool)
	store := newTestStore(t, pool, discardAuditor{}, func() time.Time { return fixedNow })
	everyone := mustPublish(t, store, fixture.admin, mustCreateDraft(t, store, fixture.admin, "rollback-all", Audience{All: true}))
	joinTenantAsReader(t, pool, fixture.scopeID, "rollback-before")

	ctx := context.Background()
	if err := databasetest.MigrateThrough(ctx, pool, "down", lateJoinMigrationVersion); err != nil {
		t.Fatal(err)
	}
	// Without 304 the late joiner gets nothing and publication still works.
	without := joinTenantAsReader(t, pool, fixture.scopeID, "rollback-without")
	assertCount(t, pool, `SELECT count(*) FROM announcement_inbox_events WHERE announcement_id=$1 AND recipient_user_id=$2`, 0, everyone.ID, without.UserID)
	mustPublish(t, store, fixture.admin, mustCreateDraft(t, store, fixture.admin, "rollback-down-publish", Audience{All: true}))
	if err := databasetest.MigrateThrough(ctx, pool, "up", lateJoinMigrationVersion); err != nil {
		t.Fatal(err)
	}
	with := joinTenantAsReader(t, pool, fixture.scopeID, "rollback-with")
	assertCount(t, pool, `SELECT count(*) FROM announcement_inbox_events WHERE recipient_user_id=$1`, 2, with.UserID)
}

// lateJoinMigrationVersion is the placeholder number of the FX16 migration.
const lateJoinMigrationVersion = 304

// joinTenantAsReader adds a new active user to an existing tenant scope with
// announcements.read, the way an admin-created or registered user joins.
func joinTenantAsReader(t *testing.T, pool *pgxpool.Pool, scopeID uuid.UUID, name string) Actor {
	t.Helper()
	ctx := context.Background()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'hash')`, userID, name); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	grantGlobalInboxRead(t, pool, scopeID, userID)
	return Actor{ScopeID: scopeID, UserID: userID, SessionID: seedAnnouncementSession(t, pool, scopeID, userID)}
}
