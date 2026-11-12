//go:build integration

package migrations_test

import (
	"strings"
	"testing"
)

// TestCNAMECustomLabel658UpDownUp rolls the CNAME name column and settings table
// up, down and up on the 657 head, checks the shape checks, and that a down with
// a value set is refused.
func TestCNAMECustomLabel658UpDownUp(t *testing.T) {
	const version = 658
	pool := migrationPoolAt(t, version-1)
	ctx := t.Context()
	columns := func() int {
		t.Helper()
		var count int
		if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='sites' AND column_name='cname_custom_label'
			  AND is_nullable='YES' AND data_type='text')
			+ (SELECT count(*) FROM information_schema.tables
			WHERE table_schema=current_schema() AND table_name='cname_label_settings')`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	for _, step := range []struct {
		direction string
		want      int
	}{{"up", 2}, {"down", 0}, {"up", 2}} {
		if err := migrateVersionIsolated(ctx, pool, step.direction, version); err != nil {
			t.Fatalf("%s %d: %v", step.direction, version, err)
		}
		if got := columns(); got != step.want {
			t.Fatalf("after %s: %d columns, want %d", step.direction, got, step.want)
		}
	}
	insert := func(kind, label string) error {
		_, err := pool.Exec(ctx, `INSERT INTO cname_label_settings(subject_kind,subject_id,label,updated_by_user_id,updated_at)
			VALUES($1,gen_random_uuid(),$2,gen_random_uuid(),now())`, kind, label)
		return err
	}
	for _, ok := range [][2]string{{"line_group", "gd"}, {"line_group", strings.Repeat("a", 54)}} {
		if err := insert(ok[0], ok[1]); err != nil {
			t.Fatalf("%v: %v", ok, err)
		}
	}
	for _, bad := range [][2]string{{"line_group", "-gd"}, {"line_group", "GD"}, {"line_group", ""},
		{"line_group", strings.Repeat("a", 55)}, {"unknown", "gd"}, {"package_product", "gd"}} {
		if err := insert(bad[0], bad[1]); err == nil {
			t.Fatalf("%v was accepted", bad)
		}
	}
	// A down with a stored name is refused.
	if err := migrateVersionIsolated(ctx, pool, "down", version); err == nil {
		t.Fatal("down accepted while names are set")
	}
}
