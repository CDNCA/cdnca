//go:build integration

package identity_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/identity"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fix-migrollback: the frozen console's password check reads only. A held
// control plane must not diverge from the copy on the new host.
func TestVerifyPlatformPasswordWritesNothing(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	ctx := t.Context()
	// Login failures are audit events; the throttle has its own table.
	count := func() (sessions, throttle, audits int) {
		t.Helper()
		if err := fixture.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM auth_sessions),
			(SELECT count(*) FROM identity_login_attempts), (SELECT count(*) FROM audit_events)`).Scan(&sessions, &throttle, &audits); err != nil {
			t.Fatal(err)
		}
		return
	}
	s0, t0, a0 := count()
	if _, err := fixture.service.VerifyPlatformPassword(ctx, fixture.username, "wrong", "203.0.113.4"); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if _, err := fixture.service.VerifyPlatformPassword(ctx, "nobody-"+fixture.username, fixture.password, "203.0.113.4"); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
	principal, err := fixture.service.VerifyPlatformPassword(ctx, " "+fixture.username+" ", fixture.password, "203.0.113.4")
	if err != nil || principal.ScopeKind != "platform" || principal.Username != fixture.username {
		t.Fatalf("verify = %+v %v", principal, err)
	}
	if s1, t1, a1 := count(); s1 != s0 || t1 != t0 || a1 != a0 {
		t.Fatalf("writes: sessions %d→%d throttle %d→%d audits %d→%d", s0, s1, t0, t1, a0, a1)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE users SET status='disabled' WHERE username=$1`, fixture.username); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.VerifyPlatformPassword(ctx, fixture.username, fixture.password, "203.0.113.4"); !errors.Is(err, identity.ErrAccountDisabled) {
		t.Fatalf("disabled: %v", err)
	}
}

// The check also runs on a pool that refuses writes (default_transaction_read_only).
func TestVerifyPlatformPasswordOnReadOnlyTransaction(t *testing.T) {
	fixture := seedThrottleFixture(t, 30, 30)
	ctx := t.Context()
	// Same as the frozen console (native_backup.go): the read-only default is a
	// connection parameter of its own pool. Never ALTER ROLE here: the role is
	// shared by every test on this server and a failed reset leaves it read-only.
	config := fixture.pool.Config().Copy()
	config.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	readOnly, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer readOnly.Close()
	if _, err := readOnly.Exec(ctx, `CREATE TEMP TABLE frozen_console_probe(x int)`); err == nil {
		t.Fatal("read-only pool accepted a write")
	}
	tokens, err := identity.NewTokenManager(strings.Repeat("f", 32), 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(identity.NewStore(readOnly), tokens, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.VerifyPlatformPassword(ctx, fixture.username, fixture.password, "203.0.113.4"); err != nil {
		t.Fatalf("read-only verify: %v", err)
	}
}
