package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (assigned 478; the guard pins 477 by checksum and
// expects the head 477). Every number the merge renumbering touches is here.
const (
	rulePackWaitsVersion       = 478
	rulePackWaitsID            = "478_security_activation_rule_pack_waits"
	rulePackWaitsPinnedID      = "477_node_deployment_status_refusals"
	rulePackWaitsPinnedUpSHA   = "445b7595d367691174f01a1fb193144526222565cbe8caf953034f8415ac095a"
	rulePackWaitsPinnedDownSHA = "58ee2b8ca38547f22daeb290cde5dbce20586e35d93a391fa18969d9dd0d77b0"
	rulePackWaitsUpSHA         = "63e4d195ecef588d164e898a588d742dac7b4c1206434a0b770631dced9b806c"
	rulePackWaitsDownSHA       = "a250d31d998642b58580b6a0520c4b02eea72cfb473f3555795006e3e4a19bb1"
)

func TestSecurityActivationRulePackWaits478Contract(t *testing.T) {
	previous := rulePackWaitsVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{rulePackWaitsID + ".up.sql", rulePackWaitsUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + rulePackWaitsPinnedID + "'",
			"checksum_sha256='" + rulePackWaitsPinnedUpSHA + "'",
			"down_checksum_sha256='" + rulePackWaitsPinnedDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", rulePackWaitsVersion),
			"wait_kind text NOT NULL DEFAULT 'capability' CHECK (wait_kind IN ('capability', 'rule_pack'))",
			"ADD COLUMN rule_pack_sha256 text[]",
			"ALTER COLUMN capability DROP NOT NULL",
			"ALTER COLUMN required_api_version DROP NOT NULL",
		}},
		{rulePackWaitsID + ".down.sql", rulePackWaitsDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", rulePackWaitsVersion),
			"migration_id='" + rulePackWaitsID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", rulePackWaitsVersion),
			fmt.Sprintf("ERRCODE='P%d2'", rulePackWaitsVersion),
			"DROP COLUMN wait_kind",
		}},
	} {
		raw, err := controlmigrations.FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		text := string(raw)
		for _, required := range script.required {
			if !strings.Contains(text, required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
		if guard, mutation := strings.Index(text, "RAISE EXCEPTION"), strings.Index(text, "ALTER TABLE"); guard < 0 || mutation < guard {
			t.Errorf("%s guard must precede the first mutation", script.name)
		}
	}
}
