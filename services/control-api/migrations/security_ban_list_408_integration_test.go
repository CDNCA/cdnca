//go:build integration

package migrations_test

import (
	"io/fs"
	"strconv"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// securityBanListVersion resolves the ban list migration's number (a
// placeholder until the merge renumbers it).
func securityBanListVersion(t *testing.T) int64 {
	t.Helper()
	matches, err := fs.Glob(controlmigrations.FS, "*_security_ban_list.up.sql")
	if err != nil || len(matches) != 1 {
		t.Fatalf("security ban list migration: %v %v", matches, err)
	}
	version, err := strconv.ParseInt(strings.SplitN(matches[0], "_", 2)[0], 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

// TestSecurityBanList408: the tables come and go with the migration; one
// row per ban, no network, at most 30 days, manual rows have no event; down
// refuses once the list holds a ban.
func TestSecurityBanList408(t *testing.T) {
	version := securityBanListVersion(t)
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	for _, step := range []string{"up", "down", "up"} {
		if err := migrateVersionIsolated(ctx, pool, step, version); err != nil {
			t.Fatalf("%s %d: %v", step, version, err)
		}
	}
	mustExec(t, pool, `ALTER TABLE security_ban_entries DISABLE TRIGGER ALL`)
	insert := `INSERT INTO security_ban_entries(id,tenant_scope_id,site_id,client_ip,source,banned_at,banned_until,source_event_id)
		VALUES(gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),$1,$2,now(),now()+$3::interval,$4)`
	for _, bad := range []struct {
		client, source, duration string
		event                    *string
	}{
		{"198.51.100.0/24", "manual", "1 hour", nil},
		{"198.51.100.1", "manual", "31 days", nil},
		{"198.51.100.1", "waf", "1 hour", nil},
		{"198.51.100.1", "manual", "1 hour", ptr("event-1")},
		{"198.51.100.1", "other", "1 hour", nil},
	} {
		if _, err := pool.Exec(ctx, insert, bad.client, bad.source, bad.duration, bad.event); sqlState(err) != "23514" {
			t.Fatalf("%+v: %v, want 23514", bad, err)
		}
	}
	mustExec(t, pool, insert, "2001:db8::1", "cc", "1 hour", "event-2")
	if _, err := pool.Exec(ctx, insert, "2001:db8::2", "waf", "1 hour", "event-2"); sqlState(err) != "23505" {
		t.Fatalf("duplicate event: %v, want 23505", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO security_ban_sync_cursor(singleton,ingested_until_ms,updated_at) VALUES(false,0,now())`); sqlState(err) != "23514" {
		t.Fatalf("second cursor row: %v, want 23514", err)
	}
	if err := migrateVersionIsolated(ctx, pool, "down", version); sqlState(err) != "P4082" {
		t.Fatalf("down with bans: %v, want P4082", err)
	}
}

func ptr(value string) *string { return &value }
