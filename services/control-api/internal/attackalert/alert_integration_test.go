//go:build integration

package attackalert_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/analyticslog"
	"github.com/cdnca/cdnca/services/control-api/internal/attackalert"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/cdnca/cdnca/services/control-api/internal/securityanalytics"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// summaries stands for the ClickHouse aggregation: windows -> sites.
type summaries struct {
	byWindow map[time.Time][]analyticslog.AttackSiteSummary
	calls    []time.Time
}

func (source *summaries) ListAttackSummaries(_ context.Context, from, to time.Time, minimum uint64, _ uint16,
) ([]analyticslog.AttackSiteSummary, error) {
	source.calls = append(source.calls, from)
	// minimum 1 when market summaries are merged in (WithMarket).
	if (minimum != attackalert.Threshold && minimum != 1) || to.Sub(from) != attackalert.Window {
		return nil, context.Canceled
	}
	var out []analyticslog.AttackSiteSummary
	for _, s := range source.byWindow[from] {
		if s.Events >= minimum {
			out = append(out, s)
		}
	}
	return out, nil
}

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")) == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	pool := databasetest.ClonedMigratedPool(t, nil)
	if pool == nil {
		var err error
		if pool, err = pgxpool.New(t.Context(), os.Getenv("TEST_DATABASE_URL")); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		if err := database.Migrate(t.Context(), pool, "up"); err != nil {
			t.Fatal(err)
		}
	}
	return pool
}

func exec(t *testing.T, pool *pgxpool.Pool, query string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(t.Context(), query, args...); err != nil {
		t.Fatalf("%s: %v", strings.Join(strings.Fields(query)[:3], " "), err)
	}
}

// tenant seeds a tenant with an owner and one site; returns tenant, scope, owner, site.
func tenant(t *testing.T, pool *pgxpool.Pool, name string) (uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	tenantID, scope, owner, site := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(t, pool, `INSERT INTO tenants(id,display_name,status,created_at,updated_at) VALUES($1,$2,'active',now(),now())`, tenantID, name)
	exec(t, pool, `INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($1,'tenant',$2,now())`, scope, tenantID)
	exec(t, pool, `INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
		VALUES($1,$2,$3,'not-used','active',now(),now())`, owner, "aa-"+strings.ReplaceAll(owner.String(), "-", "")[:20], name)
	exec(t, pool, `INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($1,$2,'active',now())`, scope, owner)
	if err := pgx.BeginFunc(t.Context(), pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(t.Context(), `INSERT INTO sites(id,scope_id,owner_user_id,domain,origins,origin_hosts,
			created_by_user_id,updated_by_user_id,display_id)
			VALUES($1,$2,$3,$4,ARRAY['origin.example.test:80'],ARRAY['origin.example.test'],$3,$3,1)`,
			site, scope, owner, name+".example.com"); err != nil {
			return err
		}
		if _, err := tx.Exec(t.Context(), `INSERT INTO site_origin_pools(site_id) VALUES($1)`, site); err != nil {
			return err
		}
		_, err := tx.Exec(t.Context(), `INSERT INTO site_origins(site_id,position,host,port) VALUES($1,1,'origin.example.test',80)`, site)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return tenantID, scope, owner, site
}

type notice struct{ source, channel, body string }

func notices(t *testing.T, pool *pgxpool.Pool, scope, owner uuid.UUID) []notice {
	t.Helper()
	rows, err := pool.Query(t.Context(), `SELECT event.source_event_id, outbox.channel, outbox.body
		FROM notification_events event JOIN notification_outbox outbox ON outbox.event_id=event.id
		WHERE event.scope_id=$1 AND event.recipient_user_id=$2 AND event.event_type=$3
		ORDER BY event.source_event_id, outbox.channel`, scope, owner, attackalert.EventType)
	if err != nil {
		t.Fatal(err)
	}
	result, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (notice, error) {
		var item notice
		return item, row.Scan(&item.source, &item.channel, &item.body)
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// TestAttackAlertsAggregateCooldownAndOwnership: one notice per site and
// window at threshold, none during the cooldown, a new one after it; a row
// naming another tenant's site is dropped; the cursor does not re-evaluate.
func TestAttackAlertsAggregateCooldownAndOwnership(t *testing.T) {
	pool := newPool(t)
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{SMS: true, Email: true}); err != nil {
		t.Fatal(err)
	}
	tenantA, scopeA, ownerA, siteA := tenant(t, pool, "aa-victim")
	_, scopeB, ownerB, siteB := tenant(t, pool, "aa-other")
	now := time.Date(2026, 10, 18, 12, 3, 0, 0, time.UTC)
	window := func(offset time.Duration) time.Time {
		return now.Add(-attackalert.Settle).Truncate(attackalert.Window).Add(offset)
	}
	first := window(-attackalert.Window)
	summary := func(site uuid.UUID, start time.Time, events uint64) analyticslog.AttackSiteSummary {
		return analyticslog.AttackSiteSummary{TenantID: tenantA.String(), SiteID: site.String(), Host: "aa-victim.example.com",
			Events: events, Blocked: events - 100, Challenged: 60, Banned: 40, Clients: 37, TopDetector: "sqli",
			TopClientIP: "203.0.113.9", FirstEventAt: start, LastEventAt: start.Add(time.Minute)}
	}
	source := &summaries{byWindow: map[time.Time][]analyticslog.AttackSiteSummary{
		// siteB belongs to tenant B: a row claiming tenant A for it is dropped.
		first: {summary(siteA, first, 1500), summary(siteB, first, 2000)},
	}}
	clock := now
	worker, err := attackalert.NewWorker(pool, source, store, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	result, err := worker.RunOnce(t.Context())
	if err != nil || result.Windows != 1 || result.Notified != 1 || result.Rejected != 1 {
		t.Fatalf("first run = %+v, %v", result, err)
	}
	got := notices(t, pool, scopeA, ownerA)
	// fix-notifsub: a member who never chose gets both channels (ordered email, sms).
	if len(got) != 2 || got[0].source != "attack-alert/"+siteA.String()+"/1" || got[0].channel != "email" ||
		got[1].channel != "sms" ||
		!strings.Contains(got[0].body, "aa-victim.example.com") || !strings.Contains(got[0].body, "1500") ||
		!strings.Contains(got[0].body, "sqli") || !strings.Contains(got[0].body, "203.0.113.9") {
		t.Fatalf("notices = %+v", got)
	}
	if other := notices(t, pool, scopeB, ownerB); len(other) != 0 {
		t.Fatalf("cross-tenant notice = %+v", other)
	}
	// Same time again: the cursor already covers the window.
	if result, err = worker.RunOnce(t.Context()); err != nil || result.Windows != 0 {
		t.Fatalf("rerun = %+v, %v", result, err)
	}
	// 10 minutes later the site is still attacked: cooling down.
	clock = now.Add(10 * time.Minute)
	for _, offset := range []time.Duration{0, attackalert.Window} {
		start := window(offset)
		source.byWindow[start] = []analyticslog.AttackSiteSummary{summary(siteA, start, 5000)}
	}
	if result, err = worker.RunOnce(t.Context()); err != nil || result.Windows != 2 || result.Cooling != 2 || result.Notified != 0 {
		t.Fatalf("cooling run = %+v, %v", result, err)
	}
	// After the cooldown a new notice, the next sequence.
	clock = now.Add(attackalert.Cooldown + 5*time.Minute)
	start := clock.Add(-attackalert.Settle).Truncate(attackalert.Window).Add(-attackalert.Window)
	source.byWindow[start] = []analyticslog.AttackSiteSummary{summary(siteA, start, 1200)}
	if result, err = worker.RunOnce(t.Context()); err != nil || result.Notified != 1 {
		t.Fatalf("after cooldown = %+v, %v", result, err)
	}
	if got = notices(t, pool, scopeA, ownerA); len(got) != 4 || got[3].source != "attack-alert/"+siteA.String()+"/2" {
		t.Fatalf("notices after cooldown = %+v", got)
	}
	// Delivery switched off: windows are skipped (no aggregation), the
	// cursor still advances.
	exec(t, pool, `UPDATE notification_event_policies SET enabled=false WHERE event_type=$1`, attackalert.EventType)
	calls := len(source.calls)
	clock = clock.Add(20 * time.Minute)
	if result, err = worker.RunOnce(t.Context()); err != nil || result.Windows == 0 || len(source.calls) != calls {
		t.Fatalf("disabled run = %+v, %v, calls %d -> %d", result, err, calls, len(source.calls))
	}
}

// market stands for the relayed market digests (securityanalytics.ClickHouse).
type market struct {
	byWindow map[time.Time][]securityanalytics.MarketAttackSummary
}

func (source *market) MarketAttackSummaries(_ context.Context, from, to time.Time, _ int) ([]securityanalytics.MarketAttackSummary, error) {
	if to.Sub(from) != attackalert.Window {
		return nil, context.Canceled
	}
	return source.byWindow[from], nil
}

// TestAttackAlertsMergeMarketSupply (ADR 0012 ML-21): attacks a leaf relayed
// for a market-supplied site count with the local ones of the same window
// (neither alone reaches the threshold here) and share the cooldown; a market
// row naming another tenant's site is dropped like a local one.
func TestAttackAlertsMergeMarketSupply(t *testing.T) {
	pool := newPool(t)
	store, err := notification.NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetChannelSwitches(t.Context(), notification.ChannelSwitches{SMS: true, Email: true}); err != nil {
		t.Fatal(err)
	}
	tenantA, scopeA, ownerA, siteA := tenant(t, pool, "aa-supplied")
	_, _, _, siteB := tenant(t, pool, "aa-elsewhere")
	now := time.Date(2026, 10, 21, 12, 3, 0, 0, time.UTC)
	start := now.Add(-attackalert.Settle).Truncate(attackalert.Window).Add(-attackalert.Window)
	local := &summaries{byWindow: map[time.Time][]analyticslog.AttackSiteSummary{start: {{TenantID: tenantA.String(),
		SiteID: siteA.String(), Host: "aa-supplied.example.com", Events: 600, Blocked: 600, Clients: 3, TopDetector: "xss",
		TopClientIP: "198.51.100.1", FirstEventAt: start, LastEventAt: start.Add(time.Minute)}}}}
	relayed := &market{byWindow: map[time.Time][]securityanalytics.MarketAttackSummary{start: {
		{TenantID: tenantA.String(), SiteID: siteA.String(), Events: 700, Blocked: 650, Challenged: 50, Clients: 9,
			TopDetector: "sqli", TopClientIP: "203.0.113.7", FirstEventAt: start.Add(-5 * time.Minute), LastEventAt: start},
		{TenantID: tenantA.String(), SiteID: siteB.String(), Events: 5000, Blocked: 5000},
	}}}
	clock := now
	worker, err := attackalert.NewWorker(pool, local, store, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	worker.WithMarket(relayed)
	result, err := worker.RunOnce(t.Context())
	if err != nil || result.Notified != 1 || result.Rejected != 1 {
		t.Fatalf("run = %+v, %v", result, err)
	}
	got := notices(t, pool, scopeA, ownerA)
	if len(got) != 2 || !strings.Contains(got[0].body, "1300") || !strings.Contains(got[0].body, "sqli") ||
		!strings.Contains(got[0].body, "203.0.113.7") {
		t.Fatalf("notices = %+v", got)
	}
	// Market alone over the threshold in the next window: cooling (shared).
	clock = now.Add(attackalert.Window)
	next := start.Add(attackalert.Window)
	relayed.byWindow[next] = []securityanalytics.MarketAttackSummary{{TenantID: tenantA.String(), SiteID: siteA.String(), Events: 4000,
		Blocked: 4000, FirstEventAt: start, LastEventAt: next}}
	if result, err = worker.RunOnce(t.Context()); err != nil || result.Cooling != 1 || result.Notified != 0 {
		t.Fatalf("cooling = %+v, %v", result, err)
	}
}
