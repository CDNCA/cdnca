//go:build integration

package auditlog

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/audit"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The log center reads the unified columns, filters by category / scope /
// actor / IP, resolves display names, renders plain language and pages.
func TestStoreListsRenderedEventsByCategory(t *testing.T) {
	pool := migratedPool(t)
	ctx := context.Background()
	tenantID, platformScope, tenantScope := uuid.New(), uuid.New(), uuid.New()
	adminID, memberID := uuid.New(), uuid.New()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO tenants(id,display_name) VALUES($1,'Log Center')", []any{tenantID}},
		{"INSERT INTO access_scopes(id,kind) VALUES($1,'platform')", []any{platformScope}},
		{"INSERT INTO access_scopes(id,kind,tenant_id) VALUES($1,'tenant',$2)", []any{tenantScope, tenantID}},
		{"INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'root-admin','Root','unused')", []any{adminID}},
		{"INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'member-a','Member','unused')", []any{memberID}},
		{"INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)", []any{platformScope, adminID}},
		{"INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)", []any{tenantScope, memberID}},
	} {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Date(2026, 10, 18, 1, 0, 0, 0, time.UTC)
	fromIP := audit.WithSourceIP(ctx, netip.MustParseAddr("203.0.113.7"))
	events := []audit.Event{
		{ScopeID: tenantScope, ActorUserID: &adminID, Action: "identity.user.update", ResourceType: "user",
			ResourceID: memberID.String(), RequestID: "l1", Result: "success", OccurredAt: base,
			Changes: []audit.Change{{Field: "email", Before: "old@example.com", After: "new@example.com"}}},
		{ScopeID: tenantScope, ActorUserID: &memberID, Action: "auth.login", ResourceType: "user",
			ResourceID: memberID.String(), RequestID: "l2", Result: "denied", OccurredAt: base.Add(time.Minute),
			Payload: map[string]any{"reason_code": "invalid_credentials"}},
		{ScopeID: tenantScope, ActorUserID: &memberID, Action: "auth.login", ResourceType: "user",
			ResourceID: memberID.String(), RequestID: "l3", Result: "success", OccurredAt: base.Add(2 * time.Minute)},
	}
	log := audit.New(pool)
	if err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, event := range events {
			if err := log.Append(fromIP, tx, event); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool)
	shanghai, _ := time.LoadLocation("Asia/Shanghai")

	page, err := store.List(ctx, Filter{ScopeIDs: []uuid.UUID{tenantScope}, Category: "admin"}, audit.LocaleZH, shanghai)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("admin category: %+v %v", page, err)
	}
	item := page.Items[0]
	want := "管理员 root-admin 于 2026-10-18 09:00:00 从 203.0.113.7 修改用户 member-a 的资料"
	if item.Summary != want || item.Category != "admin" || item.Resource != "member-a" {
		t.Fatalf("summary = %q (resource %q), want %q", item.Summary, item.Resource, want)
	}
	if len(item.Changes) != 1 || item.Changes[0].Before != "o***@example.com" || item.Changes[0].After != "n***@example.com" {
		t.Fatalf("masked changes = %+v", item.Changes)
	}

	// Paging the auth category: newest first, one per page.
	first, err := store.List(ctx, Filter{Category: "auth", Limit: 1}, audit.LocaleEN, time.UTC)
	if err != nil || len(first.Items) != 1 || first.NextCursor == "" || first.Items[0].Result != "success" {
		t.Fatalf("first auth page: %+v %v", first, err)
	}
	second, err := store.List(ctx, Filter{Category: "auth", Limit: 1, Cursor: first.NextCursor}, audit.LocaleEN, time.UTC)
	if err != nil || len(second.Items) != 1 || second.NextCursor != "" || second.Items[0].ReasonCode != "invalid_credentials" ||
		!strings.Contains(second.Items[0].Summary, "User member-a from 203.0.113.7 at 2026-10-18 01:01:00 signed in — denied") {
		t.Fatalf("second auth page: %+v %v", second, err)
	}

	for name, filter := range map[string]Filter{
		"actor name":   {ActorName: "Member-A"},
		"actor id":     {ActorUserID: &memberID},
		"source ip":    {SourceIP: "203.0.113.7", Result: "success", Category: "auth"},
		"other scope":  {ScopeIDs: []uuid.UUID{platformScope}},
		"time window":  {Since: base.Add(30 * time.Second), Until: base.Add(90 * time.Second)},
		"action exact": {Action: "auth.login", Result: "denied"},
	} {
		page, err := store.List(ctx, filter, audit.LocaleZH, time.UTC)
		wantRows := map[string]int{"actor name": 2, "actor id": 2, "source ip": 1, "other scope": 0, "time window": 1, "action exact": 1}[name]
		if err != nil || len(page.Items) != wantRows {
			t.Errorf("%s: %d rows (%v), want %d", name, len(page.Items), err, wantRows)
		}
	}

	var out bytes.Buffer
	rows, err := store.Export(ctx, Filter{ScopeIDs: []uuid.UUID{tenantScope}}, audit.LocaleZH, time.UTC, &out)
	if err != nil || rows != 3 || !strings.HasPrefix(out.String(), "时间,分类,操作人") || strings.Count(out.String(), "\n") != 4 {
		t.Fatalf("export rows=%d err=%v\n%s", rows, err, out.String())
	}
}

func migratedPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "auditlog_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err == nil {
		err = database.Migrate(ctx, pool, "up")
	}
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		cleanupCtx, cleanupCancel := databasetest.CleanupContext()
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		admin.Close()
	})
	if err != nil {
		t.Fatal(err)
	}
	return pool
}
