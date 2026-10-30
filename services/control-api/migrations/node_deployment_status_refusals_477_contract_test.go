package migrations_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	controlmigrations "github.com/cdnca/cdnca/services/control-api/migrations"
)

// (assigned 477; the guard pins 476 by checksum and expects the head
// 476). Every number the merge renumbering touches is here.
const (
	statusRefusalsVersion       = 477
	statusRefusalsID            = "477_node_deployment_status_refusals"
	statusRefusalsPinnedID      = "476_cname_record_retirements"
	statusRefusalsPinnedUpSHA   = "174073e52e00432cf8e82224cfd962c1ff59e887212baab3199378910fc0bd5c"
	statusRefusalsPinnedDownSHA = "5e03007fa6e62255714591002896bed68dca0a4b8fbf03e569fee856d10231ce"
	statusRefusalsUpSHA         = "445b7595d367691174f01a1fb193144526222565cbe8caf953034f8415ac095a"
	statusRefusalsDownSHA       = "58ee2b8ca38547f22daeb290cde5dbce20586e35d93a391fa18969d9dd0d77b0"
)

func TestNodeDeploymentStatusRefusals477Contract(t *testing.T) {
	previous := statusRefusalsVersion - 1
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{statusRefusalsID + ".up.sql", statusRefusalsUpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", previous),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", previous),
			"migration_id='" + statusRefusalsPinnedID + "'",
			"checksum_sha256='" + statusRefusalsPinnedUpSHA + "'",
			"down_checksum_sha256='" + statusRefusalsPinnedDownSHA + "'",
			fmt.Sprintf("ERRCODE='P%d0'", statusRefusalsVersion),
			"CREATE TABLE node_deployment_status_refusals (",
			"reason_code IN ('status_binding_conflict', 'status_invalid_transition')",
			"BEFORE INSERT OR UPDATE OR DELETE ON node_deployment_status_refusals",
			"BEFORE TRUNCATE ON node_deployment_status_refusals",
			"CREATE OR REPLACE FUNCTION enforce_node_deployment_state_046()",
			"CREATE OR REPLACE FUNCTION assert_node_deployment_fact_046()",
			"FROM node_deployment_timeouts timeout",
		}},
		{statusRefusalsID + ".down.sql", statusRefusalsDownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", statusRefusalsVersion),
			"migration_id='" + statusRefusalsID + "'",
			fmt.Sprintf("ERRCODE='P%d1'", statusRefusalsVersion),
			fmt.Sprintf("ERRCODE='P%d2'", statusRefusalsVersion),
			"DROP TABLE node_deployment_status_refusals;",
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
		if guard, mutation := strings.Index(text, "RAISE EXCEPTION"), strings.Index(text, "CREATE "); guard < 0 || mutation < guard {
			t.Errorf("%s guard must precede the first mutation", script.name)
		}
	}
}
