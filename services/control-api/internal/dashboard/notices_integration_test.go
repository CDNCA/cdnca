package dashboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/announcement"
	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FX16: the home page lists platform (global) announcements next to tenant
// ones, including for a user who registered after publication, and keeps
// the withdrawal visibility rules.
func TestReadNoticesIncludesGlobalAnnouncementsForLateRegistrations(t *testing.T) {
	pool := noticesPool(t)
	ctx := context.Background()
	publishedAt := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	platformScope, platformUser := uuid.New(), uuid.New()
	noticeExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope)
	noticeExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'notice-platform','p','x')`, platformUser)
	noticeExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platformScope, platformUser)
	early := seedNoticeTenant(t, pool, "notice-early")

	publish := func(title, visibility string) uuid.UUID {
		id := uuid.New()
		noticeExec(t, pool, `INSERT INTO platform_announcements_141(id,platform_scope_id,status,title,body,audience,withdrawal_visibility,created_by_user_id,created_at,updated_at)
			VALUES($1,$2,'draft',$3,'正文','{"all_tenants":true,"tenant_scope_ids":[],"role_targets":[],"user_targets":[]}',$4,$5,$6,$6)`,
			id, platformScope, title, visibility, platformUser, publishedAt)
		noticeExec(t, pool, `INSERT INTO platform_announcement_recipients_141(announcement_id,tenant_scope_id,user_id,event_id,revision,published_at,updated_at)
			VALUES($1,$2,$3,$4,1,$5,$5)`, id, early.scopeID, early.userID, uuid.New(), publishedAt)
		noticeExec(t, pool, `UPDATE platform_announcements_141 SET status='published',published_at=$2,revision=revision+1,updated_at=$2 WHERE id=$1`, id, publishedAt)
		return id
	}
	kept := publish("全员公告", "retain")
	gone := publish("撤回隐藏", "hide")
	noticeExec(t, pool, `UPDATE platform_announcements_141 SET status='withdrawn',withdrawn_at=$2,revision=revision+1,updated_at=$2 WHERE id=$1`, gone, publishedAt.Add(time.Minute))

	late := seedNoticeTenant(t, pool, "notice-late")
	for _, member := range []noticeTenant{early, late} {
		var stats NoticeStats
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var err error
			stats, err = readNotices(ctx, tx, member.scopeID, member.userID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if stats.Unread != 1 || len(stats.Items) != 1 || stats.Items[0].Title != "全员公告" {
			t.Fatalf("%s notices = %+v (want only %s)", member.name, stats, kept)
		}
	}
}

// fix-overview：管理员经真实发布流程（announcement.Store CreateGlobalDraft→PublishGlobal，
// 全部租户）发一条全局公告后，用户概览的系统公告能读到它。
func TestAdminPublishedGlobalAnnouncementReachesTenantOverview(t *testing.T) {
	pool := noticesPool(t)
	ctx := context.Background()
	member := seedNoticeTenant(t, pool, "notice-publish-flow")
	platformScope, platformUser, roleID, sessionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	noticeExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platformScope)
	noticeExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'notice-publisher','p','x')`, platformUser)
	noticeExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platformScope, platformUser)
	noticeExec(t, pool, `INSERT INTO roles(id,scope_id,name,description,system_role) VALUES($1,$2,'notice_platform_admin','',true)`, roleID, platformScope)
	noticeExec(t, pool, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'platform.admin')`, roleID)
	noticeExec(t, pool, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, platformScope, platformUser, roleID)
	tokenHash := sha256.Sum256(sessionID[:])
	now := time.Now().UTC()
	noticeExec(t, pool, `INSERT INTO auth_sessions(id,family_id,user_id,scope_id,refresh_token_hash,created_at,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7)`, sessionID, uuid.New(), platformUser, platformScope, tokenHash[:], now, now.Add(time.Hour))

	store, err := announcement.NewStoreWithDependencies(pool, audit.New(pool), announcement.NoopPublicationOutbox{}, time.Now,
		announcement.CursorKeyring{ActiveKID: "t", Keys: map[string][]byte{"t": bytes.Repeat([]byte{0x5a}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	actor := announcement.Actor{ScopeID: platformScope, UserID: platformUser, SessionID: sessionID}
	draft, err := store.CreateGlobalDraft(ctx, actor, announcement.CreateGlobalDraftRequest{
		Content:              announcement.Content{Title: "概览可见的全局公告", Body: "正文"},
		Audience:             announcement.GlobalAudience{AllTenants: true},
		WithdrawalVisibility: announcement.VisibilityHide,
		IdempotencyKey:       "fix-overview-create", RequestID: "req-fix-overview-create",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishGlobal(ctx, actor, announcement.GlobalTransitionRequest{
		AnnouncementID: draft.ID, ExpectedRevision: draft.Revision,
		IdempotencyKey: "fix-overview-publish", RequestID: "req-fix-overview-publish",
	}); err != nil {
		t.Fatal(err)
	}

	var stats NoticeStats
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		var err error
		stats, err = readNotices(ctx, tx, member.scopeID, member.userID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if stats.Unread != 1 || len(stats.Items) != 1 || stats.Items[0].Title != "概览可见的全局公告" {
		t.Fatalf("tenant overview notices = %+v, want the published global announcement", stats)
	}
}

type noticeTenant struct {
	name            string
	scopeID, userID uuid.UUID
}

func seedNoticeTenant(t *testing.T, pool *pgxpool.Pool, name string) noticeTenant {
	t.Helper()
	tenantID, scopeID, userID := uuid.New(), uuid.New(), uuid.New()
	noticeExec(t, pool, `INSERT INTO tenants(id,display_name) VALUES($1,$2)`, tenantID, name)
	noticeExec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)`, scopeID, tenantID)
	noticeExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,$2,'x')`, userID, name)
	noticeExec(t, pool, `INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, scopeID, userID)
	return noticeTenant{name: name, scopeID: scopeID, userID: userID}
}

func noticeExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", strings.Fields(sql)[0:3], err)
	}
}

func noticesPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("TEST_DATABASE_URL") == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	if pool := databasetest.ClonedMigratedPool(t, nil); pool != nil {
		return pool
	}
	fixture, cleanup := newDashboardFixture(t)
	t.Cleanup(cleanup)
	return fixture.pool
}
