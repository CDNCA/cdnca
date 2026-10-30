//go:build integration

package securityban_test

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	contract "github.com/cdnca/cdnca/libs/edgeconfig/securityban"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/securityban"
	"github.com/google/uuid"
)

// A node one entry over contract.MaxEntries gets a list
// cut by exactly one ban (the one ending soonest), every release kept, signed
// and published as usual; the state says warning_code=list_truncated with the
// count; the nodes.manage holders get one alert per node and hour, not one
// per run.
func TestSecurityBanDistributorTruncatesOverLimitList(t *testing.T) {
	pool := newPool(t)
	ctx := t.Context()
	now := time.Now().UTC().Truncate(time.Hour).Add(10 * time.Minute)
	fixture := seedTenant(t, pool, "sbl-"+uuid.NewString()[:6])
	node := seedNode(t, pool, fixture)
	platform := platformActor(t, pool).ScopeID
	manager, role := uuid.New(), uuid.New()
	exec(t, pool, `INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
		VALUES($1,$2,'sbl','not-used','active',now(),now())`, manager, "sbl-"+manager.String()[:12])
	exec(t, pool, `INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($1,$2,'active',now())`, platform, manager)
	if err := pool.QueryRow(ctx, `SELECT id FROM roles WHERE scope_id=$1 AND name='platform_owner'`, platform).Scan(&role); err != nil {
		exec(t, pool, `INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'platform_owner',true)`, role, platform)
	}
	exec(t, pool, `INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'nodes.manage') ON CONFLICT DO NOTHING`, role)
	exec(t, pool, `INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3)`, platform, manager, role)
	exec(t, pool, `UPDATE notification_channel_settings SET sms_enabled=true,email_enabled=true WHERE singleton`)
	alerts, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	public, private, _ := ed25519.GenerateKey(nil)
	carrier := &transport{}
	clock := now
	distributor, err := securityban.NewDistributor(securityban.DistributorConfig{Pool: pool, Transport: carrier, KeyID: "test-key",
		Sign:     func(_ context.Context, payload []byte) ([]byte, error) { return ed25519.Sign(private, payload), nil },
		Interval: time.Minute, Now: func() time.Time { return clock }, Alerts: alerts})
	if err != nil {
		t.Fatal(err)
	}
	const releases = 3
	// releases: three released bans; bans: MaxEntries-releases running an hour,
	// plus one running only ten minutes (+1 over the limit).
	exec(t, pool, `INSERT INTO security_ban_entries(id,tenant_scope_id,site_id,client_ip,source,banned_at,banned_until,released_at)
		SELECT gen_random_uuid(),$1,$2,('10.1.0.0'::inet + n)::inet,'manual',$3::timestamptz - interval '1 minute',
		       $3::timestamptz + interval '1 hour',$3::timestamptz - interval '30 seconds'
		FROM generate_series(1,$4::int) n`, fixture.scope, fixture.site, now, releases)
	exec(t, pool, `INSERT INTO security_ban_entries(id,tenant_scope_id,site_id,client_ip,source,banned_at,banned_until)
		SELECT gen_random_uuid(),$1,$2,('10.0.0.0'::inet + n)::inet,'manual',$3::timestamptz,$3::timestamptz + interval '1 hour'
		FROM generate_series(1,$4::int) n`, fixture.scope, fixture.site, now, contract.MaxEntries-releases)
	exec(t, pool, `INSERT INTO security_ban_entries(id,tenant_scope_id,site_id,client_ip,source,banned_at,banned_until)
		VALUES(gen_random_uuid(),$1,$2,'192.0.2.250','manual',$3,$3::timestamptz + interval '10 minutes')`, fixture.scope, fixture.site, now)

	if err := distributor.PublishOnce(ctx); err != nil || len(carrier.published) != 1 {
		t.Fatalf("over the limit: published %d %v", len(carrier.published), err)
	}
	list, err := contract.Open(carrier.published[0].encoded, node.String(), func(string) (ed25519.PublicKey, bool) { return public, true })
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Releases) != releases || len(list.Bans)+len(list.Releases) != contract.MaxEntries {
		t.Fatalf("list bans=%d releases=%d", len(list.Bans), len(list.Releases))
	}
	for _, ban := range list.Bans {
		if ban.Client == "192.0.2.250" {
			t.Fatal("the ban ending soonest was kept")
		}
	}
	var warning string
	var truncated int
	if err := pool.QueryRow(ctx, `SELECT warning_code,truncated_entries FROM security_ban_node_state WHERE node_id=$1`, node).
		Scan(&warning, &truncated); err != nil || warning != securityban.WarningListTruncated || truncated != 1 {
		t.Fatalf("state = %q %d %v", warning, truncated, err)
	}
	// A later run in the same hour with a changed list (cut again): no new alert.
	clock = now.Add(5 * time.Minute)
	exec(t, pool, `INSERT INTO security_ban_entries(id,tenant_scope_id,site_id,client_ip,source,banned_at,banned_until)
		VALUES(gen_random_uuid(),$1,$2,'192.0.2.251','manual',$3,$3::timestamptz + interval '2 hours')`, fixture.scope, fixture.site, clock)
	if err := distributor.PublishOnce(ctx); err != nil || len(carrier.published) != 2 {
		t.Fatalf("second run: published %d %v", len(carrier.published), err)
	}
	var events, inbox int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM notification_events WHERE event_type=$1 AND source_event_id LIKE $3),
		(SELECT count(*) FROM admin_inbox_messages WHERE event_type=$1 AND recipient_user_id=$2)`,
		securityban.EventTypeListTruncated, manager, "list-truncated/v1/security_ban/"+node.String()+"/%").Scan(&events, &inbox); err != nil {
		t.Fatal(err)
	}
	if events != 1 || inbox != 1 {
		t.Fatalf("alerts events=%d inbox=%d (want one)", events, inbox)
	}
	// Back under the limit (MaxEntries-1): the warning clears.
	// (A release still counts within the release window, so delete.)
	exec(t, pool, `DELETE FROM security_ban_entries WHERE site_id=$1 AND client_ip IN ('192.0.2.250','192.0.2.251','10.0.0.1')`,
		fixture.site)
	if err := distributor.PublishOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT warning_code,truncated_entries FROM security_ban_node_state WHERE node_id=$1`, node).
		Scan(&warning, &truncated); err != nil || warning != "" || truncated != 0 {
		t.Fatalf("state after recovery = %q %d %v", warning, truncated, err)
	}
}
