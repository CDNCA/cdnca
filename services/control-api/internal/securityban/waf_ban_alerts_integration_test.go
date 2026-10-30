//go:build integration

package securityban_test

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"github.com/google/uuid"
)

// J1: a folded WAF automatic ban reaches the notification
// center (nodes.manage holders of the platform, admin inbox copy), merged per
// (site, client, hour) like the node kernel bans; CC bans, duplicates and
// skipped events send nothing.
func TestSecurityBanSyncAlertsWAFBans(t *testing.T) {
	pool := newPool(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Hour).Add(30 * time.Minute)
	name := "sbw-" + uuid.NewString()[:6]
	a, domainOf := seedTenant(t, pool, name), name+".example.com"
	platform := platformActor(t, pool).ScopeID
	manager, viewer, role := uuid.New(), uuid.New(), uuid.New()
	for _, user := range []uuid.UUID{manager, viewer} {
		exec(t, pool, `INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
			VALUES($1,$2,'sbw','not-used','active',now(),now())`, user, "sbw-"+user.String()[:12])
		exec(t, pool, `INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($1,$2,'active',now())`, platform, user)
	}
	// The platform owner system role (seeded by an earlier test or here).
	if err := pool.QueryRow(ctx, `SELECT id FROM roles WHERE scope_id=$1 AND name='platform_owner'`, platform).Scan(&role); err != nil {
		exec(t, pool, `INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'platform_owner',true)`, role, platform)
	}
	exec(t, pool, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'nodes.manage') ON CONFLICT DO NOTHING`, role)
	exec(t, pool, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, platform, manager, role)
	exec(t, pool, `UPDATE notification_channel_settings SET sms_enabled=true,email_enabled=true WHERE singleton`)
	// The cursor is one row per database (another test may have advanced it).
	exec(t, pool, `DELETE FROM security_ban_sync_cursor`)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM security_ban_sync_cursor`) })

	ingested := now.Add(-time.Minute)
	event := func(id, kind, client string, occurred time.Time) analyticslog.TemporaryBanEvent {
		ingested = ingested.Add(time.Millisecond)
		return analyticslog.TemporaryBanEvent{EventID: id, TenantID: a.tenant.String(), SiteID: a.site.String(), EventType: kind,
			ClientIP: client, RuleID: uuid.NewString(), OccurredAt: occurred, IngestedAt: ingested}
	}
	source := &events{items: []analyticslog.TemporaryBanEvent{
		event("w1", "waf", "198.51.100.30", now.Add(-2*time.Minute)),
		event("w1", "waf", "198.51.100.30", now.Add(-2*time.Minute)), // redelivery: skipped
		event("w2", "waf", "198.51.100.30", now.Add(-time.Minute)),   // extension within the hour: merged
		event("c1", "cc", "198.51.100.31", now.Add(-time.Minute)),    // CC ban: not a WAF alert
		event("w3", "waf", "2001:db8::30", now.Add(-time.Minute)),    // another client: new message
		event("w4", "waf", "198.51.100.32", now.Add(-3*time.Hour)),   // over: skipped
	}}
	syncer, err := securityban.NewSyncer(pool, source, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	notifications, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	syncer.EnableWAFBanAlerts(notifications)
	if result, err := syncer.RunOnce(ctx); err != nil || result.Added != 3 || result.Extended != 1 || result.Skipped != 2 {
		t.Fatalf("sync = %+v, %v", result, err)
	}
	var events, outbox, inbox int
	site := "waf-ban/" + a.site.String() + "/%"
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM notification_events WHERE event_type=$1 AND source_event_id LIKE $3),
		(SELECT count(*) FROM notification_outbox outbox JOIN notification_events event ON event.id=outbox.event_id
			WHERE event.event_type=$1 AND event.source_event_id LIKE $3),
		(SELECT count(*) FROM admin_inbox_messages WHERE event_type=$1 AND recipient_user_id=$2)`,
		securityban.EventTypeWAFBan, manager, site).Scan(&events, &outbox, &inbox); err != nil {
		t.Fatal(err)
	}
	// Only the nodes.manage holder; system required, both channels on.
	if events != 2 || outbox != 4 || inbox != 2 {
		t.Fatalf("events=%d outbox=%d inbox=%d (want 2/4/2)", events, outbox, inbox)
	}
	// evt-site: each alert records the banned site (502).
	var subjects int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM notification_events WHERE event_type=$1 AND source_event_id LIKE $2
		AND subject_site_id=$3`, securityban.EventTypeWAFBan, site, a.site).Scan(&subjects); err != nil || subjects != 2 {
		t.Fatalf("WAF ban subject_site_id rows=%d, %v (want 2)", subjects, err)
	}
	var domain, duration string
	if err := pool.QueryRow(ctx, `SELECT params->>'site_domain',params->>'duration_seconds' FROM admin_inbox_messages
		WHERE event_type=$1 AND params->>'client_ip'='198.51.100.30'`, securityban.EventTypeWAFBan).Scan(&domain, &duration); err != nil ||
		domain != domainOf || duration != "3600" {
		t.Fatalf("inbox params domain=%q duration=%q err=%v", domain, duration, err)
	}
	var source1 string
	if err := pool.QueryRow(ctx, `SELECT source_event_id FROM notification_events WHERE event_type=$1 AND source_event_id LIKE '%2001:db8::30%'`,
		securityban.EventTypeWAFBan).Scan(&source1); err != nil ||
		source1 != securityban.WAFBanSourceEventID(a.site, "2001:db8::30", now.Add(-time.Minute)) {
		t.Fatalf("IPv6 client merge key %q, %v", source1, err)
	}
}
