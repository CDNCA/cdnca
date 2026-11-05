//go:build integration

package poolmon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/cdnca/cdnca/libs/dbpoolmon"
	"github.com/cdnca/cdnca/services/control-api/internal/database"
	"github.com/cdnca/cdnca/services/control-api/internal/database/databasetest"
	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/cdnca/cdnca/services/control-api/internal/notification"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// On real PostgreSQL: a 3-connection pool held full, a fourth
// request waiting until its deadline. The monitor alerts in that cycle
// (canceled_acquire under pressure), writing through its own connection
// while the pool is still full; the control.upgrades.read and platform.admin
// members get the notification and an admin inbox copy, nodes.manage does
// not; the admin route answers from memory. Three clean cycles send the
// recovery, a re-entry within 15 minutes sends nothing, and a new process
// closes an alert its predecessor left open.
func TestPoolMonitorNotifiesOnAFullPool(t *testing.T) {
	admin := databasetest.MigratedPool(t, nil)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	t.Cleanup(cancel)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := admin.Exec(ctx, query, args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	platform, reader, owner, operator := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	readRole, adminRole, nodeRole := uuid.New(), uuid.New(), uuid.New()
	// control.upgrades.* may only be granted to platform_owner, and a new
	// platform_owner gets them by trigger (migration 096).
	exec(`INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
	exec(`INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'pool-reader','Reader','test-only'),
		($2,'pool-owner','Owner','test-only'),($3,'pool-operator','Operator','test-only')`, reader, owner, operator)
	exec(`INSERT INTO memberships(scope_id,user_id) VALUES($1,$2),($1,$3),($1,$4)`, platform, reader, owner, operator)
	exec(`INSERT INTO roles(id,scope_id,name,system_role) VALUES($1,$4,'platform_owner',true),($2,$4,'pool_admin',true),
		($3,$4,'node_operator',true)`, readRole, adminRole, nodeRole, platform)
	exec(`INSERT INTO role_permissions(role_id,permission_name) VALUES($1,'control.upgrades.read'),($2,'platform.admin'),($3,'nodes.manage')
		ON CONFLICT DO NOTHING`,
		readRole, adminRole, nodeRole)
	exec(`INSERT INTO role_assignments(scope_id,user_id,role_id) VALUES($1,$2,$3),($1,$4,$5),($1,$6,$7)`,
		platform, reader, readRole, owner, adminRole, operator, nodeRole)
	exec(`UPDATE notification_channel_settings SET sms_enabled=true,email_enabled=true WHERE singleton`)

	// The pool under watch: same database, three connections.
	config := admin.Config().Copy()
	config.MaxConns, config.MinConns = 3, 0
	small, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(small.Close)
	store, err := notification.NewStore(admin)
	if err != nil {
		t.Fatal(err)
	}
	notifier := NewPGNotifier(small.Config().ConnConfig, store)
	release := database.HoldResident("poolmon_integration_listen", true)
	t.Cleanup(release)
	monitor := New("ctl-int", dbpoolmon.FromPool(small), database.Residents, notifier, nil)
	monitor.Prime()

	held := make([]*pgxpool.Conn, 0, 3)
	for range 3 {
		conn, err := small.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	waiting, stop := context.WithTimeout(ctx, 300*time.Millisecond)
	_, err = small.Acquire(waiting)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("fourth acquire on a full pool = %v, want its deadline", err)
	}
	at := time.Now().UTC()
	monitor.Tick(ctx, at) // the pool is still full: the write must not need it
	snap := monitor.Snapshot()
	if !snap.Firing || !snap.Notified || snap.PendingNotifications != 0 || snap.Current == nil ||
		snap.Current.InUse != 3 || snap.Current.MaxConns != 3 || snap.Current.ResidentConns < 1 ||
		!slices.Contains(snap.Current.Reasons, dbpoolmon.ReasonSaturated) || !slices.Contains(snap.Current.Reasons, dbpoolmon.ReasonCanceled) {
		t.Fatalf("snapshot on a full pool = %+v (current %+v)", snap, snap.Current)
	}
	recipients := func(eventType string) []uuid.UUID {
		t.Helper()
		rows, err := admin.Query(ctx, `SELECT recipient_user_id FROM notification_events WHERE event_type=$1 ORDER BY recipient_user_id`, eventType)
		if err != nil {
			t.Fatal(err)
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	want := []uuid.UUID{reader, owner}
	slices.SortFunc(want, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	if got := recipients(EventTypeSaturated); !slices.Equal(got, want) {
		t.Fatalf("saturated recipients = %v, want the control.upgrades.read and platform.admin members %v", got, want)
	}
	var inbox, outbox int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM admin_inbox_messages WHERE event_type=$1 AND params->>'instance'='ctl-int'
		AND params->>'in_use'='3' AND params->>'max_conns'='3'`, EventTypeSaturated).Scan(&inbox); err != nil || inbox != 2 {
		t.Fatalf("admin inbox copies = %d, %v", inbox, err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM notification_outbox WHERE template_id=$1 AND channel IN ('sms','email')`,
		saturatedTemplate).Scan(&outbox); err != nil || outbox != 4 {
		t.Fatalf("saturated outbox rows = %d, %v (two members × sms+email)", outbox, err)
	}
	var subject string
	if err := admin.QueryRow(ctx, `SELECT subject FROM notification_outbox WHERE template_id=$1 AND channel='email' LIMIT 1`,
		saturatedTemplate).Scan(&subject); err != nil || subject != "主控数据库连接池满载：ctl-int" {
		t.Fatalf("email subject = %q, %v", subject, err)
	}

	// The admin route answers from memory while the pool is full.
	route := NewHandler(monitor, func(*http.Request, string) (identity.AuthenticatedSession, error) {
		return identity.AuthenticatedSession{SessionID: uuid.New(), Principal: identity.Principal{UserID: reader, ScopeID: platform,
			ScopeKind: "platform", Permissions: []string{"control.upgrades.read"}}}, nil
	})
	request := httptest.NewRequest(http.MethodGet, Route, nil)
	request.Header.Set("Authorization", "Bearer reader")
	response := httptest.NewRecorder()
	route.ServeHTTP(response, request)
	var body Snapshot
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusOK || !body.Firing ||
		body.Instance != "ctl-int" || body.Current == nil || body.Current.InUse != 3 || len(body.Series) != 1 ||
		!slices.ContainsFunc(body.Residents, func(r database.Resident) bool { return r.Name == "poolmon_integration_listen" }) {
		t.Fatalf("admin route = %d %s", response.Code, response.Body)
	}

	for _, conn := range held {
		conn.Release()
	}
	for i := range dbpoolmon.RecoverCycles {
		monitor.Tick(ctx, at.Add(time.Duration(i+1)*dbpoolmon.SampleInterval))
	}
	if monitor.Snapshot().Firing {
		t.Fatal("three clean cycles must recover")
	}
	if got := recipients(EventTypeRecovered); !slices.Equal(got, want) {
		t.Fatalf("recovered recipients = %v", got)
	}
	var cause string
	if err := admin.QueryRow(ctx, `SELECT params->>'cause' FROM admin_inbox_messages WHERE event_type=$1 LIMIT 1`, EventTypeRecovered).
		Scan(&cause); err != nil || cause != CauseRecovered {
		t.Fatalf("recovery cause = %q, %v", cause, err)
	}

	// Re-entry 2 minutes later, within the dedup window: nothing new.
	for i := range dbpoolmon.EnterCycles + dbpoolmon.RecoverCycles {
		inUse := []int{3, 3, 3, 0, 0, 0}[i]
		conns := make([]*pgxpool.Conn, 0, inUse)
		for range inUse {
			conn, err := small.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			conns = append(conns, conn)
		}
		monitor.Tick(ctx, at.Add(2*time.Minute+time.Duration(i)*dbpoolmon.SampleInterval))
		for _, conn := range conns {
			conn.Release()
		}
	}
	if n := len(recipients(EventTypeSaturated)) + len(recipients(EventTypeRecovered)); n != 4 {
		t.Fatalf("a re-entry within the window sent notifications: %d events", n)
	}

	// A process that sent a saturation and died: the next one recovers it once.
	since := at.Add(-time.Hour)
	if err := notifier.Saturated(ctx, "ctl-int", since, Sample{At: since, MaxConns: 3, InUse: 3, Reasons: []string{dbpoolmon.ReasonSaturated}}); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := notifier.CloseStale(ctx, "ctl-int", at); err != nil {
			t.Fatal(err)
		}
	}
	if err := notifier.CloseStale(ctx, "ctl-other", at); err != nil {
		t.Fatal(err)
	}
	var restarted int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM admin_inbox_messages WHERE event_type=$1 AND source_event_id=$2
		AND params->>'cause'=$3`, EventTypeRecovered, SourceEventID("ctl-int", since), CauseInstanceRestarted).Scan(&restarted); err != nil || restarted != 2 {
		t.Fatalf("restart recoveries = %d, %v (one per recipient, once)", restarted, err)
	}
	if got := len(recipients(EventTypeRecovered)); got != 4 {
		t.Fatalf("recovered events = %d, want 4 (2 recovered + 2 restarted)", got)
	}
}
