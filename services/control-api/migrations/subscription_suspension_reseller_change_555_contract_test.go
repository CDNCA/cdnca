package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 555 (bb03, ADR 0019 §5) is a placeholder number on top of 554
// (fix-cnamerand): the merge renumbers it and re-pins its guard.
// Everything that changes with the number is here.
const (
	migration555Version         = 555
	migration555PreviousVersion = 554
	migration555PreviousID      = "554_node_bandwidth_alerts"
	migration555ID              = "555_subscription_suspension_reseller_change"
	migration555UpSHA           = "64e3ad1ac6f92d098cb9ceff562d8f30040ab8e45f4cbd949e961a67bf6fb071"
	migration555DownSHA         = "f37b4b2e833f40dbb8455514695b4b1b1d20c31c68b5736f86d3c138e4c83ad9"
)

func TestSubscriptionSuspensionResellerChange555Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration555ID + ".up.sql", migration555UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration555PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration555PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration555PreviousVersion),
			"migration_id='" + migration555PreviousID + "'",
			"checksum_sha256='" + sha256File(t, migration555PreviousID+".up.sql") + "'",
			"down_checksum_sha256='" + sha256File(t, migration555PreviousID+".down.sql") + "'",
			"ERRCODE='P5550'", "ADD COLUMN suspended_at timestamptz", "'suspend','unsuspend')",
			"'package.subscription.suspend', 'package.subscription.unsuspend'",
			"cardinality(triggers) BETWEEN 1 AND 21", "'node_storage', 'package_suspension']::text[]",
			"ERRCODE='P5553'", "ERRCODE='P5554'", "ERRCODE='P5555'", "reseller_change_wholesale_555",
			"'admin_delete','suspend','unsuspend') THEN RETURN NULL",
		}},
		{migration555ID + ".down.sql", migration555DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration555Version),
			"migration_id='" + migration555ID + "'", "ERRCODE='P5551'", "ERRCODE='P5552'",
			"DROP COLUMN suspended_at", "cardinality(triggers) BETWEEN 1 AND 20",
			"DROP FUNCTION reseller_change_wholesale_555(uuid, package_orders);",
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
