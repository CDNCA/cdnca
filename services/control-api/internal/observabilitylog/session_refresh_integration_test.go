//go:build integration

package observabilitylog

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// hide_session_refresh 在存储层去掉成功的 auth.refresh，
// 续期失败与业务变更保留；总数与翻页按同一条件计算；不带条件时仍是全部记录。
func TestOperationLogHidesSuccessfulSessionRefreshPostgreSQL(t *testing.T) {
	pool := anonymousNotificationPool(t)
	ctx := t.Context()
	scope, user := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants(id,display_name) VALUES($1,'Refresh A');
		INSERT INTO access_scopes(id,kind,tenant_id) VALUES($2,'tenant',$1);
		INSERT INTO users(id,username,display_name,password_hash) VALUES($3,'refresh-a','Refresh A','unused');
		INSERT INTO memberships(scope_id,user_id) VALUES($2,$3)`, pgx.QueryExecModeSimpleProtocol, uuid.New(), scope, user); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	appendEvent := func(action, result string, at time.Time) {
		t.Helper()
		if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			_, err := audit.AppendTx(ctx, tx, audit.Event{ScopeID: scope, ActorUserID: &user, Action: action,
				ResourceType: "user", ResourceID: user.String(), RequestID: "req-" + uuid.NewString()[:8],
				Result: result, OccurredAt: at, Payload: map[string]any{}})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	appendEvent("site.update", "success", now.Add(-10*time.Minute))
	for minute := 9; minute >= 3; minute-- {
		appendEvent("auth.refresh", "success", now.Add(-time.Duration(minute)*time.Minute))
	}
	appendEvent("auth.refresh", "failure", now.Add(-2*time.Minute))
	appendEvent("dns.update", "success", now.Add(-time.Minute))

	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, []byte("0123456789abcdef0123456789abcdef"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	actor := Actor{UserID: user, ScopeID: scope, SessionID: uuid.New(), ScopeKind: ScopeTenant, Permissions: []string{"identity.self.read"}}
	window := Query{Kinds: []Kind{KindOperation}, From: now.Add(-time.Hour), To: now.Add(time.Second)}

	all := window
	all.Limit = 50
	page, err := service.List(ctx, actor, all)
	if err != nil || page.TotalCount != 10 {
		t.Fatalf("all rows total=%d err=%v", page.TotalCount, err)
	}

	hidden := window
	hidden.HideSessionRefresh, hidden.Limit = true, 2
	page, err = service.List(ctx, actor, hidden)
	if err != nil || page.TotalCount != 3 || len(page.Items) != 2 || page.NextCursor == "" ||
		page.Items[0].Action != "dns.update" || page.Items[1].Action != "auth.refresh" || page.Items[1].ResultCode != "failure" {
		t.Fatalf("first hidden page=%+v err=%v", page, err)
	}
	hidden.Cursor = page.NextCursor
	page, err = service.List(ctx, actor, hidden)
	if err != nil || len(page.Items) != 1 || page.Items[0].Action != "site.update" || page.NextCursor != "" {
		t.Fatalf("second hidden page=%+v err=%v", page, err)
	}
}
