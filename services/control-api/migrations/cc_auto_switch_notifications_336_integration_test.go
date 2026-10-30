//go:build integration

package migrations_test

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestCCAutoSwitchNotifications336RollbackAndReapply checks the event is
// supported with templates at 336, that a clean rollback restores the 335
// state (trigger re-enabled) and re-applies, and that rollback refuses once
// notification history exists.
func TestCCAutoSwitchNotifications336RollbackAndReapply(t *testing.T) {
	pool := migrationPoolAt(t, 336)
	ctx := t.Context()
	state := func() (supported, defaultEmail bool, templates int, table bool) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT supported AND enabled AND sms_enabled AND email_enabled,
			default_email OR enabled OR sms_enabled OR email_enabled,
			(SELECT count(*) FROM notification_templates WHERE template_id='package.monitor.cc_rule_auto_switch.zh-cn'),
			to_regclass('cc_auto_switch_notification_windows') IS NOT NULL
			FROM notification_event_policies WHERE event_type='package.monitor.cc_rule_auto_switch'`).
			Scan(&supported, &defaultEmail, &templates, &table); err != nil {
			t.Fatal(err)
		}
		return supported, defaultEmail, templates, table
	}
	// At 336 the event is supported, enabled on both channels, email by default.
	if supported, defaultEmail, templates, table := state(); !supported || !defaultEmail || templates != 2 || !table {
		t.Fatalf("at 336 supported=%v default_email=%v templates=%d table=%v", supported, defaultEmail, templates, table)
	}

	if err := migrateVersionIsolated(ctx, pool, "down", 336); err != nil {
		t.Fatalf("down 336: %v", err)
	}
	// Back at 335: unsupported and switched off as 201 left it.
	if supported, switchedOn, templates, table := state(); supported || switchedOn || templates != 0 || table {
		t.Fatalf("after rollback supported=%v switched_on=%v templates=%d table=%v", supported, switchedOn, templates, table)
	}
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT tgenabled='O' FROM pg_trigger
		WHERE tgrelid='notification_templates'::regclass AND tgname='notification_templates_immutable'`).Scan(&enabled); err != nil || !enabled {
		t.Fatalf("notification_templates_immutable enabled=%v err=%v", enabled, err)
	}
	if err := migrateVersionIsolated(ctx, pool, "up", 336); err != nil {
		t.Fatalf("up 336: %v", err)
	}
	if supported, _, templates, table := state(); !supported || templates != 2 || !table {
		t.Fatalf("after re-apply supported=%v templates=%d table=%v", supported, templates, table)
	}
	// notification_events is append-only: once an engagement was notified,
	// 336 can no longer be rolled back.
	scope, tenant, user := uuid.New(), uuid.New(), uuid.New()
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO tenants(id,display_name,status,created_at,updated_at) VALUES($1,'cc336','active',now(),now())`, []any{tenant}},
		{`INSERT INTO access_scopes(id,kind,tenant_id,created_at) VALUES($1,'tenant',$2,now())`, []any{scope, tenant}},
		{`INSERT INTO users(id,username,display_name,password_hash,status,created_at,updated_at)
			VALUES($1,'cc336-owner','cc336','not-used','active',now(),now())`, []any{user}},
		{`INSERT INTO memberships(scope_id,user_id,status,created_at) VALUES($1,$2,'active',now())`, []any{scope, user}},
		{`INSERT INTO notification_events(id,scope_id,recipient_user_id,source_event_id,event_type,delivery_policy,request_digest,created_at)
			VALUES($1,$2,$3,'cc-auto-switch/x/1','package.monitor.cc_rule_auto_switch','tenant_subscribed',$4,now())`,
			[]any{uuid.New(), scope, user, make([]byte, 32)}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	var postgresError *pgconn.PgError
	if err := migrateVersionIsolated(ctx, pool, "down", 336); !errors.As(err, &postgresError) || postgresError.Code != "P3362" {
		t.Fatalf("rollback with notification history err=%v", err)
	}
}
