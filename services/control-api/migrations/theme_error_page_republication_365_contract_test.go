package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 365 is a placeholder number: the merge
// renumbers it after the head it lands on. Everything that changes with the
// renumbering is in this block.
const (
	migration365Version         = 365
	migration365ID              = "365_theme_error_page_republication"
	migration365PreviousID      = "364_module_entitlement_republication"
	migration365PreviousUpSHA   = "53e3b8f018f9f4702dac9a3802a2c5cd68e556f00940cc3d9c75a71bdd7b5398"
	migration365PreviousDownSHA = "f7e9d1e030cf9e790622b63ce553ab4a822988c57ed4b6ef94342189fefc95c8"
	migration365UpSHA           = "d31f78e809bec9b73384d05e636958c248807eec32c990f3e20f4c7d88933298"
	migration365DownSHA         = "83e4153e97e6f59a52e8cb8b92aa015e00611bd3d34eec09cf8e90ffd534c3e7"
)

func TestThemeErrorPageRepublication365Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration365ID + ".up.sql", migration365UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration365Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration365Version-1),
			"migration_id='" + migration365PreviousID + "'", migration365PreviousUpSHA, migration365PreviousDownSHA,
			"ERRCODE='P3650'", "CREATE TABLE theme_error_page_republications",
			"'module_entitlement',\n            'theme_activation'", "ADD COLUMN error_page_rollout_id",
			"publication_id IS NOT NULL OR error_page_rollout_id IS NOT NULL",
			"TO cdnca_control_app, cdnca_control_runtime", "ERRCODE = 'P3652'",
			"''edge_error_page.publish''", "payload->>''rollout_id'' = NEW.id::text",
		}},
		{migration365ID + ".down.sql", migration365DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration365Version),
			"migration_id='" + migration365ID + "'", "ERRCODE='P3651'",
			"DROP COLUMN error_page_rollout_id", "DROP TABLE theme_error_page_republications", "ERRCODE='P3653'",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
}
