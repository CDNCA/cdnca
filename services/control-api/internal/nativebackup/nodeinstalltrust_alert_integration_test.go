//go:build integration

package nativebackup

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/entitlement"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fix-btenv5 on real PostgreSQL: one notification per failure streak to the
// nodes.manage platform members (not to other members), the same streak is
// merged across calls (restarts, replicas), and a republication is audited.
func TestNodeInstallTrustAlertsOnPostgres(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	t.Cleanup(cancel)
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "node_install_trust_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, done := databasetest.CleanupContext()
		defer done()
		_, _ = admin.Exec(cleanup, "DROP SCHEMA "+identifier+" CASCADE")
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := database.Migrate(ctx, pool, "up"); err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	platform, manager, viewer, role := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'trust-manager','Manager','test-only'),($2,'trust-viewer','Viewer','test-only')`, manager, viewer)
	exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($1,$3)`, platform, manager, viewer)
	exec(`INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'platform_owner',true)`, role, platform)
	exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'nodes.manage')`, role)
	exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, platform, manager, role)
	exec(`UPDATE notification_channel_settings SET sms_enabled=true,email_enabled=true WHERE singleton`)
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, 10, 28, 5, 0, 0, 0, time.UTC)
	alert := NodeInstallTrustAlert{Since: since, At: since.Add(20 * time.Minute), Failures: 3, Host: "cdnca.com", Port: 19445,
		Reason: "cannot resolve cdnca.com for node upgrade downloads: no such host"}
	events := func() []uuid.UUID {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT recipient_user_id FROM notification_events WHERE event_type=$1 ORDER BY created_at`, EventTypeNodeInstallTrustFailed)
		if err != nil {
			t.Fatal(err)
		}
		recipients, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			t.Fatal(err)
		}
		return recipients
	}
	for range 2 { // a restart of the same streak, or a second replica
		if err := AlertNodeInstallTrustFailed(ctx, pool, store, alert); err != nil {
			t.Fatal(err)
		}
	}
	if got := events(); len(got) != 1 || got[0] != manager {
		t.Fatalf("one streak notified %v, want only the nodes.manage member once", got)
	}
	var inbox int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM admin_inbox_messages WHERE recipient_user_id=$1 AND event_type=$2`,
		manager, EventTypeNodeInstallTrustFailed).Scan(&inbox); err != nil || inbox != 1 {
		t.Fatalf("admin inbox copies = %d, %v", inbox, err)
	}
	alert.Since, alert.At = since.Add(2*time.Hour), since.Add(150*time.Minute)
	if err := AlertNodeInstallTrustFailed(ctx, pool, store, alert); err != nil {
		t.Fatal(err)
	}
	if got := events(); len(got) != 2 {
		t.Fatalf("a new streak notified %d times in total, want 2", len(got))
	}
	change := NodeInstallTrustChange{
		Before:         &entitlement.UpgradeDownloadPolicy{Host: "cdnca.com", Port: 443, Addresses: []string{"198.51.100.7"}, RootCA: "system"},
		After:          entitlement.UpgradeDownloadPolicy{Host: "cdnca.com", Port: 19445, Addresses: []string{"203.0.113.20"}, RootCA: "system"},
		PreviousSHA256: strings.Repeat("11", 32), SHA256: strings.Repeat("ab", 32)}
	if err := AuditNodeInstallTrustRepublish(ctx, pool, change); err != nil {
		t.Fatal(err)
	}
	var audited int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE scope_id=$1 AND action=$2`, platform,
		ActionNodeInstallTrustRepublish).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("republish audit events = %d, %v", audited, err)
	}
}
