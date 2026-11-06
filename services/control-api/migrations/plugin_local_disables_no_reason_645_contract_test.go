package migrations

import (
	"strings"
	"testing"
)

// Migration 645 (predecessor 644_plugin_local_disables): the
// local plugin stop asks for no reason any more, so up drops
// plugin_local_disables.reason and nothing else; down puts the column back with
// 644's NOT NULL and 1..500 CHECK (rows still stopped then read「未填写」).
func TestPluginLocalDisablesNoReason645Contract(t *testing.T) {
	read := func(direction string) string {
		body, err := FS.ReadFile("645_plugin_local_disables_no_reason." + direction + ".sql")
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	up, down := read("up"), read("down")
	for _, fragment := range []string{
		"ERRCODE='P6450'", "(SELECT count(*) FROM schema_migrations) <> 644",
		"(SELECT max(version) FROM schema_migrations) <> 644",
		"migration_id='644_plugin_local_disables'",
		"ALTER TABLE plugin_local_disables DROP COLUMN reason;",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("645 up missing %q", fragment)
		}
	}
	for _, fragment := range []string{
		"ERRCODE='P6451'", "migration_id='645_plugin_local_disables_no_reason'",
		"ADD COLUMN reason text NOT NULL DEFAULT '未填写'", "CHECK (char_length(reason) BETWEEN 1 AND 500)",
		"ALTER COLUMN reason DROP DEFAULT",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("645 down missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"DELETE FROM", "UPDATE ", "DROP TABLE", "CREATE TABLE"} {
		if strings.Contains(up, forbidden) {
			t.Errorf("645 up must not contain %q", forbidden)
		}
	}
}
