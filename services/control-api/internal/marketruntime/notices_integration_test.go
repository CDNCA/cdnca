//go:build integration

package marketruntime

import (
	"context"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/marketproto/notice"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/marketclient"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
)

// ADR 0012 ML-10: a relayed market notice becomes one notification center
// event per platform member holding the role's permission; members can turn
// channels off per event (tenant_subscribed); a redelivered notice is
// enqueued once.
func TestMarketNoticeReachesNotificationCenter(t *testing.T) {
	pool := databasetest.ClonedMigratedPool(t, nil)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	var platform uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM access_scopes WHERE kind='platform' AND tenant_id IS NULL`).Scan(&platform); err != nil {
		platform = uuid.New()
		exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	}
	buyerRole, sellerRole := uuid.New(), uuid.New()
	// System roles (custom roles need RBAC facts); permissions as in 296.
	exec(`INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$2,'platform_owner',true),($3,$2,'platform_admin',true)`, buyerRole, platform, sellerRole)
	exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'marketplace.purchase'),($2,'marketplace.sell')`, buyerRole, sellerRole)
	buyer, seller, quiet := uuid.New(), uuid.New(), uuid.New()
	for i, user := range []uuid.UUID{buyer, seller, quiet} {
		exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,$2,'ml10','unused')`, user, "ml10-"+string(rune('a'+i)))
		exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2)`, platform, user)
	}
	exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3),($1,$4,$5),($1,$6,$3)`,
		platform, buyer, buyerRole, seller, sellerRole, quiet)
	// quiet opts out of every channel for this event.
	exec(`INSERT INTO notification_subscriptions(scope_id,user_id,event_type,sms_enabled,email_enabled,created_at,updated_at)
		VALUES($1,$2,'market.limit.reached',false,false,now(),now())`, platform, quiet)
	exec(`UPDATE notification_channel_settings SET email_enabled=true, sms_enabled=true WHERE singleton`)

	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	r := New(Config{}, pool, nil, nil, nil).WithNotices(store)
	sub := uuid.New()
	n := notice.Notice{Schema: notice.SchemaV1, ID: uuid.New(), MemberID: uuid.New(), SubscriptionID: &sub, Role: notice.RoleBuyer,
		Kind: notice.KindLimitReached, Stage: "qps", PeriodKey: "hold-1", CreatedAt: time.Now().Unix(),
		Values: map[string]string{notice.ValueOffer: "华东 BGP", notice.ValueSubscription: sub.String(), notice.ValueMetric: "qps",
			notice.ValueObserved: "1000", notice.ValueCap: "1000", notice.ValueAction: "pause"}}
	for range 2 { // redelivery
		if err := r.answer(ctx, marketclient.Identity{}, marketclient.Inbound{Seq: 1, Notice: &n}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(user uuid.UUID, table string) int {
		t.Helper()
		var n int
		query := `SELECT count(*) FROM notification_events WHERE recipient_user_id=$1 AND event_type='market.limit.reached'`
		if table == "outbox" {
			query = `SELECT count(*) FROM notification_outbox o JOIN notification_events e ON e.id=o.event_id
				WHERE e.recipient_user_id=$1 AND e.event_type='market.limit.reached' AND o.channel='email'`
		}
		if table == "inbox" {
			query = `SELECT count(*) FROM admin_inbox_messages WHERE recipient_user_id=$1 AND event_type='market.limit.reached'`
		}
		if err := pool.QueryRow(ctx, query, user).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count(buyer, "events") != 1 || count(buyer, "outbox") != 1 || count(buyer, "inbox") != 1 {
		t.Fatalf("buyer: events %d email %d inbox %d", count(buyer, "events"), count(buyer, "outbox"), count(buyer, "inbox"))
	}
	if count(seller, "events") != 0 {
		t.Fatal("a buyer notice is not for marketplace.sell holders")
	}
	if count(quiet, "events") != 1 || count(quiet, "outbox") != 0 {
		t.Fatalf("opted-out member: events %d email %d", count(quiet, "events"), count(quiet, "outbox"))
	}
	var body string
	if err := pool.QueryRow(ctx, `SELECT o.body FROM notification_outbox o JOIN notification_events e ON e.id=o.event_id
		WHERE e.recipient_user_id=$1 AND o.channel='email'`, buyer).Scan(&body); err != nil || body == "" {
		t.Fatalf("email body %q %v", body, err)
	}

	// Every kind has templates whose variables match NoticeContext.
	for _, kind := range notice.Kinds {
		k := notice.Notice{Schema: notice.SchemaV1, ID: uuid.New(), MemberID: n.MemberID, Role: notice.RoleSeller, Kind: kind,
			PeriodKey: "p", CreatedAt: time.Now().Unix()}
		if err := r.answer(ctx, marketclient.Identity{}, marketclient.Inbound{Seq: 2, Notice: &k}); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	var kinds int
	if err := pool.QueryRow(ctx, `SELECT count(DISTINCT event_type) FROM notification_events WHERE recipient_user_id=$1`, seller).Scan(&kinds); err != nil ||
		kinds != len(notice.Kinds) {
		t.Fatalf("seller kinds %d of %d: %v", kinds, len(notice.Kinds), err)
	}
}
