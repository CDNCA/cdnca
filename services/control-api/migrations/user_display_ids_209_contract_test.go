package migrations

import (
	"strings"
	"testing"
)

func TestUserDisplayIDs209Contract(t *testing.T) {
	up, err := FS.ReadFile("209_user_display_ids.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := FS.ReadFile("209_user_display_ids.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"users_display_id_seq",
		"ADD COLUMN display_id bigint",
		"row_number() OVER (ORDER BY created_at, id)",
		"ALTER COLUMN display_id SET NOT NULL",
		"UNIQUE (display_id)",
		"CHECK (display_id > 0)",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("up migration missing %q", required)
		}
	}
	for _, required := range []string{
		"DROP COLUMN display_id",
		"DROP SEQUENCE IF EXISTS users_display_id_seq",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("down migration missing %q", required)
		}
	}
}
