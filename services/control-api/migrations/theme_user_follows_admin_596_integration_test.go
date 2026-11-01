//go:build integration

package migrations_test

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestThemeUserFollowsAdmin596Backfill: a user row equal to the admin
// package (or the default before any admin activation) becomes "follows"; a
// different one stays the user console's own; an 'all' row already follows.
// Follow rows are user-only, and down pins them to the admin package then.
func TestThemeUserFollowsAdmin596Backfill(t *testing.T) {
	// Keep equal to migration596Version / migration596PreviousVersion.
	const version, previous = 596, 595
	type activation struct {
		pkg  string
		slot string
	}
	for _, tc := range []struct {
		name    string
		history []activation
		follows bool
	}{
		{"user equals admin", []activation{{"official.slate", "admin"}, {"official.slate", "user"}}, true},
		{"user equals default, no admin row", []activation{{"default", "user"}}, true},
		{"user differs from admin", []activation{{"official.slate", "admin"}, {"official.tech", "user"}}, false},
		{"user differs from default, no admin row", []activation{{"official.tech", "user"}}, false},
		{"admin changed after user cleared", []activation{{"default", "all"}, {"default", "user"}, {"official.slate", "admin"}}, false},
		{"all row", []activation{{"official.tech", "all"}}, true},
		{"no activation", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := migrationPoolAt(t, previous)
			ctx := t.Context()
			now := time.Now().UTC()
			platform, user := uuid.New(), uuid.New()
			mustExec(t, pool, `INSERT INTO users(id,username,display_name,password_hash) VALUES($1,'theme-596','Theme 596','unused')`, user)
			mustExec(t, pool, `INSERT INTO access_scopes(id,kind) VALUES($1,'platform')`, platform)
			mustExec(t, pool, `INSERT INTO memberships(scope_id,user_id,status) VALUES($1,$2,'active')`, platform, user)
			packages := map[string][]byte{}
			for _, id := range []string{"default", "official.slate", "official.tech"} {
				raw := []byte(id + "-596")
				digest := sha256.Sum256(raw)
				packages[id] = digest[:]
				mustExec(t, pool, `INSERT INTO theme_packages(package_sha256,theme_id,version,source,package_body,css_sha256,css_body,json_sha256,json_body,downloaded_by_user_id,downloaded_at)
					VALUES($1,$2,'1.0.0','builtin',$3,sha256('c'::bytea),'c'::bytea,sha256('j'::bytea),'j'::bytea,$4,now())`, digest[:], id, raw, user)
			}
			for index, row := range tc.history {
				mustExec(t, pool, `INSERT INTO theme_activations(revision,platform_scope_id,package_sha256,activated_by_user_id,request_id,activated_at,slot)
					VALUES($1,$2,$3,$4,'r',$5,$6)`, index+1, platform, packages[row.pkg], user, now, row.slot)
			}
			if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
				t.Fatalf("up: %v", err)
			}
			// Same rule as theme.userPinnedSQL.
			var pinned []byte
			var rows int
			if err := pool.QueryRow(ctx, `SELECT (SELECT CASE WHEN slot='user' THEN package_sha256 END FROM theme_activations
				WHERE slot IN ('user','all') ORDER BY revision DESC LIMIT 1),(SELECT count(*) FROM theme_activations)`).Scan(&pinned, &rows); err != nil {
				t.Fatal(err)
			}
			if (pinned == nil) != tc.follows {
				t.Fatalf("follows = %v, want %v", pinned == nil, tc.follows)
			}
			added := tc.follows && len(tc.history) > 0 && tc.history[len(tc.history)-1].slot == "user"
			if want := len(tc.history) + map[bool]int{true: 1}[added]; rows != want {
				t.Fatalf("activation rows = %d, want %d (existing rows are not rewritten)", rows, want)
			}
			// A follow row is user-only.
			next := rows + 1
			if _, err := pool.Exec(ctx, `INSERT INTO theme_activations(revision,platform_scope_id,package_sha256,activated_by_user_id,request_id,activated_at,slot)
				VALUES($1,$2,NULL,$3,'r',$4,'admin')`, next, platform, user, now); sqlState(err) != "23514" {
				t.Fatalf("admin row without package: %v, want 23514", err)
			}
			mustExec(t, pool, `INSERT INTO theme_activations(revision,platform_scope_id,package_sha256,activated_by_user_id,request_id,activated_at,slot)
				VALUES($1,$2,NULL,$3,'r',$4,'user')`, next, platform, user, now)
			// The admin package stays protected although the latest row has none.
			adminRow := false
			for _, row := range tc.history {
				adminRow = adminRow || row.slot != "user"
			}
			if adminRow {
				if _, err := pool.Exec(ctx, `UPDATE theme_packages SET removed_at=now(),removed_by_user_id=$1 WHERE package_sha256=
					(SELECT package_sha256 FROM theme_activations WHERE slot IN ('admin','all') ORDER BY revision DESC LIMIT 1)`, user); sqlState(err) != "P3602" {
					t.Fatalf("remove the admin console package: %v, want P3602", err)
				}
			}
			if err := migrateVersionIsolated(ctx, pool, "down", version); err != nil {
				t.Fatalf("down: %v", err)
			}
			var nulls int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM theme_activations WHERE package_sha256 IS NULL`).Scan(&nulls); err != nil || nulls != 0 {
				t.Fatalf("follow rows after down = %d %v", nulls, err)
			}
			if err := migrateVersionIsolated(ctx, pool, "up", version); err != nil {
				t.Fatalf("up again: %v", err)
			}
		})
	}
}
