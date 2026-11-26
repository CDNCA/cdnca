//go:build integration

package migrations_test

import (
	"testing"

	"github.com/google/uuid"
)

// TestRegistrationUsernameRequired682: at 681 a stored false
// and an absent username_required both read true after 682, with revision,
// updated_at and the other settings unchanged; a false saved after 682 stays
// false (the administrator's choice), and down writes nothing back.
func TestRegistrationUsernameRequired682(t *testing.T) {
	const version = 682
	for _, item := range []struct {
		name, settings, before string
	}{
		{"saved false", `{"username_required":false,"qq_required":true}`, "false"},
		{"absent", `{"qq_required":true}`, "absent"},
	} {
		t.Run(item.name, func(t *testing.T) {
			pool := migrationPoolAt(t, version-1)
			ctx := t.Context()
			scope := uuid.New()
			mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, scope)
			mustExec(t, pool, `INSERT INTO platform_system_user_settings(platform_scope_id,revision,settings,updated_at)
				VALUES($1,3,$2,'2026-11-01T00:00:00Z')`, scope, item.settings)
			read := func() (string, string, int64, string) {
				t.Helper()
				var value, qq, updated string
				var revision int64
				if err := pool.QueryRow(ctx, `SELECT COALESCE(settings->>'username_required','absent'),settings->>'qq_required',
					revision,updated_at::text FROM platform_system_user_settings WHERE platform_scope_id=$1`, scope).
					Scan(&value, &qq, &revision, &updated); err != nil {
					t.Fatal(err)
				}
				return value, qq, revision, updated
			}
			value, _, revision, updated := read()
			if value != item.before {
				t.Fatalf("seeded username_required=%s", value)
			}
			if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
				t.Fatalf("up %d: %v", version, err)
			}
			if after, qq, afterRevision, afterUpdated := read(); after != "true" || qq != "true" ||
				afterRevision != revision || afterUpdated != updated {
				t.Fatalf("after 682: username_required=%s qq=%s rev=%d updated=%s", after, qq, afterRevision, afterUpdated)
			}
			// a false saved after 682 is the administrator's and stays, down included
			mustExec(t, pool, `UPDATE platform_system_user_settings SET settings=jsonb_set(settings,'{username_required}','false'::jsonb),
				revision=revision+1 WHERE platform_scope_id=$1`, scope)
			if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
				t.Fatalf("down %d: %v", version, err)
			}
			if value, _, _, _ := read(); value != "false" {
				t.Fatalf("down changed a saved false: %s", value)
			}
		})
	}
}
