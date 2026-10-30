package announcement

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGlobalAnnouncementTargetsInboxIsolationIdempotencyAndWithdrawal(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	mainTenant := seedAnnouncementFixture(t, pool)
	otherTenant := seedAdditionalTenant(t, pool)
	grantGlobalInboxRead(t, pool, otherTenant.scopeID, otherTenant.userID)
	platform := seedGlobalPlatformActor(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })

	request := CreateGlobalDraftRequest{
		Content:      Content{Title: "全平台维护", Body: "跨租户维护窗口"},
		Presentation: Presentation{Format: FormatContent, SortOrder: 7, Visible: true, Popup: true, Red: true, Bold: true},
		Audience: GlobalAudience{
			TenantScopeIDs: []uuid.UUID{mainTenant.scopeID},
			RoleTargets:    []GlobalRoleTarget{{ScopeID: mainTenant.scopeID, RoleID: mainTenant.groupID}},
			UserTargets:    []GlobalUserTarget{{ScopeID: otherTenant.scopeID, UserID: otherTenant.userID}},
		},
		WithdrawalVisibility: VisibilityHide,
		IdempotencyKey:       "global-create-1", RequestID: "req-global-create-1",
	}
	draft, err := store.CreateGlobalDraft(context.Background(), platform, request)
	if err != nil {
		t.Fatal(err)
	}
	if draft.Format != FormatContent || draft.SortOrder != 7 || !draft.Visible || !draft.Popup || !draft.Red || !draft.Bold {
		t.Fatalf("global presentation = %+v", draft)
	}
	loaded, err := store.GetGlobalAnnouncement(context.Background(), platform, draft.ID)
	if err != nil || loaded.SortOrder != 7 || !loaded.Visible || !loaded.Popup || !loaded.Red || !loaded.Bold {
		t.Fatalf("loaded global presentation = %+v, %v", loaded, err)
	}
	replay, err := store.CreateGlobalDraft(context.Background(), platform, request)
	if err != nil || !replay.Replayed || replay.ID != draft.ID {
		t.Fatalf("global replay = %+v, %v", replay, err)
	}

	published, err := store.PublishGlobal(context.Background(), platform, GlobalTransitionRequest{
		AnnouncementID: draft.ID, ExpectedRevision: draft.Revision,
		IdempotencyKey: "global-publish-1", RequestID: "req-global-publish-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if published.Status != StatusPublished || published.RecipientCount != 4 {
		t.Fatalf("published global = %+v", published)
	}
	assertCount(t, pool, `SELECT count(*) FROM platform_announcement_recipients_141 WHERE announcement_id=$1`, 4, draft.ID)

	mainInbox, err := store.ListInbox(context.Background(), mainTenant.adminFor(mainTenant.userA), ListRequest{Limit: 10})
	if err != nil || len(mainInbox.Items) != 1 || mainInbox.Items[0].AnnouncementID != draft.ID {
		t.Fatalf("main tenant inbox = %+v, %v", mainInbox, err)
	}
	otherSession := seedAnnouncementSession(t, pool, otherTenant.scopeID, otherTenant.userID)
	otherActor := Actor{ScopeID: otherTenant.scopeID, UserID: otherTenant.userID, SessionID: otherSession}
	otherInbox, err := store.ListInbox(context.Background(), otherActor, ListRequest{Limit: 10})
	if err != nil || len(otherInbox.Items) != 1 || otherInbox.Items[0].AnnouncementID != draft.ID {
		t.Fatalf("other tenant inbox = %+v, %v", otherInbox, err)
	}

	read, err := store.MarkRead(context.Background(), otherActor, StateRequest{
		EventID: otherInbox.Items[0].ID, ExpectedRevision: 1,
		IdempotencyKey: "global-read-1", RequestID: "req-global-read-1",
	})
	if err != nil || read.Revision != 2 || read.DeliveredAt == nil || read.ReadAt == nil {
		t.Fatalf("global inbox read = %+v, %v", read, err)
	}

	withdrawn, err := store.WithdrawGlobal(context.Background(), platform, GlobalTransitionRequest{
		AnnouncementID: draft.ID, ExpectedRevision: published.Revision,
		IdempotencyKey: "global-withdraw-1", RequestID: "req-global-withdraw-1",
	})
	if err != nil || withdrawn.Status != StatusWithdrawn {
		t.Fatalf("global withdraw = %+v, %v", withdrawn, err)
	}
	hidden, err := store.ListInbox(context.Background(), otherActor, ListRequest{Limit: 10})
	if err != nil || len(hidden.Items) != 0 {
		t.Fatalf("hidden global inbox = %+v, %v", hidden, err)
	}
	if _, err := store.ListGlobalAnnouncements(context.Background(), mainTenant.admin, AnnouncementListRequest{}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("tenant global list = %v, want permission denied", err)
	}
}

func TestGlobalAnnouncementAllTenantsFreezesOnlyActiveTenantMembers(t *testing.T) {
	pool := isolatedAnnouncementPool(t)
	mainTenant := seedAnnouncementFixture(t, pool)
	otherTenant := seedAdditionalTenant(t, pool)
	platform := seedGlobalPlatformActor(t, pool)
	store := newTestStore(t, pool, audit.New(pool), func() time.Time { return fixedNow })

	draft, err := store.CreateGlobalDraft(context.Background(), platform, CreateGlobalDraftRequest{
		Content: Content{Title: "全租户公告", Body: "全部活跃用户"}, Audience: GlobalAudience{AllTenants: true},
		WithdrawalVisibility: VisibilityRetain, IdempotencyKey: "global-all-create", RequestID: "req-global-all-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	published, err := store.PublishGlobal(context.Background(), platform, GlobalTransitionRequest{
		AnnouncementID: draft.ID, ExpectedRevision: draft.Revision,
		IdempotencyKey: "global-all-publish", RequestID: "req-global-all-publish",
	})
	if err != nil || published.RecipientCount != 4 {
		t.Fatalf("all tenant publish = %+v, %v", published, err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE memberships SET status='suspended' WHERE scope_id=$1 AND user_id=$2`, mainTenant.scopeID, mainTenant.userB); err != nil {
		t.Fatal(err)
	}
	assertCount(t, pool, `SELECT count(*) FROM platform_announcement_recipients_141 WHERE announcement_id=$1`, 4, draft.ID)
	assertCount(t, pool, `SELECT count(*) FROM platform_announcement_recipients_141 WHERE announcement_id=$1 AND tenant_scope_id=$2 AND user_id=$3`, 1, draft.ID, otherTenant.scopeID, otherTenant.userID)
}

func seedGlobalPlatformActor(t *testing.T, pool *pgxpool.Pool) Actor {
	t.Helper()
	ctx := context.Background()
	scopeID, userID, roleID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'hash')`, userID, fmt.Sprintf("global-admin-%s", userID.String()[:8])); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'platform_admin','',true)`, roleID, scopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'platform.admin')`, roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scopeID, userID, roleID); err != nil {
		t.Fatal(err)
	}
	return Actor{ScopeID: scopeID, UserID: userID, SessionID: seedAnnouncementSession(t, pool, scopeID, userID)}
}

func grantGlobalInboxRead(t *testing.T, pool *pgxpool.Pool, scopeID, userID uuid.UUID) {
	t.Helper()
	roleID := uuid.New()
	if _, err := pool.Exec(context.Background(), `INSERT INTO roles(id,scope_id,name,description,system_role)
		VALUES($1,$2,$3,'',true)`, roleID, scopeID, "global-inbox-reader-"+roleID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'announcements.read')`, roleID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, scopeID, userID, roleID); err != nil {
		t.Fatal(err)
	}
}
