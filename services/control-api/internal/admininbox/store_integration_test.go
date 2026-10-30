//go:build integration

package admininbox_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/admininbox"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func inboxPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	admin, err := pgxpool.New(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	schema := "admin_inbox_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		admin.Close()
	})
	if err := database.Migrate(t.Context(), pool, "up"); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestAdminInboxListReadAndReadAll(t *testing.T) {
	pool := inboxPool(t)
	ctx := t.Context()
	scopeID, userID, otherID := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL)`, []any{scopeID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'inbox-a','A','x'),($2,'inbox-b','B','x')`, []any{userID, otherID}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($1,$3)`, []any{scopeID, userID, otherID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Now().UTC().Add(-time.Hour)
	for index := range 5 {
		if _, err := pool.Exec(ctx, `INSERT INTO admin_inbox_messages(id,scope_id,recipient_user_id,event_type,source_event_id,params,created_at)
			VALUES($1,$2,$3,'node.availability.offline',$4,'{"node_name":"n"}',$5)`, uuid.New(), scopeID, userID,
			"src-"+string(rune('a'+index)), base.Add(time.Duration(index)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO admin_inbox_messages(id,scope_id,recipient_user_id,event_type,source_event_id,params,created_at)
		VALUES($1,$2,$3,'node.availability.offline','other','{}',now())`, uuid.New(), scopeID, otherID); err != nil {
		t.Fatal(err)
	}
	store := admininbox.NewStore(pool)
	me := admininbox.Recipient{UserID: userID, ScopeID: scopeID, RequestID: "inbox-test"}
	if count, err := store.UnreadCount(ctx, me); err != nil || count != 5 {
		t.Fatalf("unread=%d err=%v", count, err)
	}
	first, err := store.List(ctx, me, false, 3, "")
	if err != nil || len(first.Items) != 3 || first.NextCursor == nil || first.Total != 5 || first.Items[0].Params["node_name"] != "n" {
		t.Fatalf("first page: %+v %v", first, err)
	}
	second, err := store.List(ctx, me, false, 3, *first.NextCursor)
	if err != nil || len(second.Items) != 2 || second.NextCursor != nil || !second.Items[0].CreatedAt.Before(first.Items[2].CreatedAt) {
		t.Fatalf("second page: %+v %v", second, err)
	}
	if err := store.MarkRead(ctx, me, first.Items[0].ID); err != nil {
		t.Fatal(err)
	}
	unread, err := store.List(ctx, me, true, 10, "")
	if err != nil || len(unread.Items) != 4 || unread.Unread != 4 {
		t.Fatalf("unread page: %+v %v", unread, err)
	}
	// Someone else's message is not mine.
	var foreign uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM admin_inbox_messages WHERE recipient_user_id=$1`, otherID).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkRead(ctx, me, foreign); err != admininbox.ErrNotFound {
		t.Fatalf("foreign mark read: %v", err)
	}
	if marked, err := store.MarkAllRead(ctx, me); err != nil || marked != 4 {
		t.Fatalf("read all: %d %v", marked, err)
	}
	if count, _ := store.UnreadCount(ctx, admininbox.Recipient{UserID: otherID, ScopeID: scopeID}); count != 1 {
		t.Fatalf("other recipient unread=%d", count)
	}
	var audited int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action='admin.inbox.read_all' AND resource_id=$1`, userID.String()).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("audit=%d err=%v", audited, err)
	}
}

// A platform operations event reaches the message center even when every
// delivery channel is switched off; tenant-scope events never do.
func TestAdminInboxReceivesPlatformEventsWithChannelsOff(t *testing.T) {
	pool := inboxPool(t)
	ctx := t.Context()
	platformScope, tenantScope, tenantID, admin, member := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,display_name) VALUES($1,'Inbox Tenant')`, []any{tenantID}},
		{`INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'platform',NULL),($2,'tenant',$3)`, []any{platformScope, tenantScope, tenantID}},
		{`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'inbox-admin','A','x'),($2,'inbox-member','M','x')`, []any{admin, member}},
		{`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($3,$4)`, []any{platformScope, admin, tenantScope, member}},
		{`UPDATE notification_channel_settings SET sms_enabled=false,email_enabled=false WHERE singleton`, nil},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	notifications, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	values := notification.TemplateContext{"node_name": notification.PublicValue("edge-9"), "node_ip": notification.PublicValue("192.0.2.9"),
		"reason": notification.PublicValue("probe_failed"), "occurred_at": notification.PublicValue("2026-10-18T00:00:00Z")}
	templates := map[notification.Channel]notification.TemplateRef{
		notification.ChannelSMS:   {ID: notification.EventTypeNodeOffline + ".zh-cn", Version: 1, Channel: notification.ChannelSMS},
		notification.ChannelEmail: {ID: notification.EventTypeNodeOffline + ".zh-cn", Version: 1, Channel: notification.ChannelEmail},
	}
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		result, err := notifications.EnqueueTx(ctx, tx, notification.EnqueueRequest{
			ScopeID: platformScope, RecipientID: admin, SourceEventID: "node-availability/x/1", EventType: notification.EventTypeNodeOffline,
			Policy: notification.DeliverySystemRequired, Templates: templates,
			Contexts:       map[notification.Channel]notification.TemplateContext{notification.ChannelSMS: values, notification.ChannelEmail: values},
			AuditRequestID: "inbox-channels-off",
		})
		if err == nil && len(result.Deliveries) != 0 {
			t.Errorf("deliveries with channels off = %d", len(result.Deliveries))
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	store := admininbox.NewStore(pool)
	page, err := store.List(ctx, admininbox.Recipient{UserID: admin, ScopeID: platformScope}, false, 10, "")
	if err != nil || len(page.Items) != 1 || page.Items[0].Params["node_name"] != "edge-9" {
		t.Fatalf("platform inbox: %+v %v", page, err)
	}
	if count, _ := store.UnreadCount(ctx, admininbox.Recipient{UserID: member, ScopeID: tenantScope}); count != 0 {
		t.Fatalf("tenant member inbox=%d", count)
	}
}
