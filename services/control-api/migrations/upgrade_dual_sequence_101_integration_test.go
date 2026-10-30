//go:build integration

package migrations_test

import (
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

func TestUpgradeDualSequence101Contract(t *testing.T) {
	up, err := controlmigrations.FS.ReadFile("101_upgrade_dual_sequence.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := controlmigrations.FS.ReadFile("101_upgrade_dual_sequence.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"migration 101 requires the exact verified 100 release head",
		"command_schema",
		"execution_sequence",
		"release_sequence",
		"component",
		"UNIQUE (installation_id, node_id, component, execution_sequence)",
		"legacy rows remain nullable and are never guessed",
	} {
		if !strings.Contains(string(up), required) {
			t.Errorf("101 up missing %q", required)
		}
	}
	for _, required := range []string{
		"upgrade command v3 facts exist; rollback is unsafe",
		"DROP COLUMN execution_sequence",
		"DROP COLUMN release_sequence",
	} {
		if !strings.Contains(string(down), required) {
			t.Errorf("101 down missing %q", required)
		}
	}
}
