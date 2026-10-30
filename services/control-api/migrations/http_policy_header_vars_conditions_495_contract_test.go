package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 495 (HTTP policy header variables,
// allow_duplicate and rule conditions) is a placeholder number: the merge
// renumbered it to 495 at merge (local placeholder 490, previous 494).
// Everything that changes with the renumbering is in this block.
const (
	tpB3cMigrationVersion     = 495
	tpB3cMigrationID          = "495_http_policy_header_vars_conditions"
	tpB3cMigrationPreviousID  = "494_site_origin_parity"
	tpB3cMigrationPreviousUp  = "7571f8ae527eaad466254f810a82b35c9479a5ccb167ec9d0278a80a64db7532"
	tpB3cMigrationPreviousDwn = "1026828343348849ec5d8fb4a2bc7e86cb8737a93d1aede302016790b93031b0"
	tpB3cMigrationUpSHA       = "d1f710dfcc99d9063cd723ea76cb1c0b158b652393134b363550b3f2dd54bd6d"
	tpB3cMigrationDownSHA     = "e511b05932fb54077d052a23f80e0714bb048efd2ea61c2aca7e2875d5371d4b"
)

func TestHTTPPolicyHeaderVarsConditions495Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{tpB3cMigrationID + ".up.sql", tpB3cMigrationUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", tpB3cMigrationVersion-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", tpB3cMigrationVersion-1),
			"migration_id='" + tpB3cMigrationPreviousID + "'", tpB3cMigrationPreviousUp, tpB3cMigrationPreviousDwn,
			"ERRCODE='P4950'", "http_policy_conditions_valid_495(rule -> 'conditions')",
			"http_policy_header_value_variables_valid_495(value #>> '{}')",
		}},
		{tpB3cMigrationID + ".down.sql", tpB3cMigrationDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", tpB3cMigrationVersion),
			"migration_id='" + tpB3cMigrationID + "'", "ERRCODE='P4951'", "ERRCODE='P4952'",
			"DROP FUNCTION http_policy_conditions_valid_495(jsonb)",
			"DROP FUNCTION http_policy_header_value_variables_valid_495(text)",
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
