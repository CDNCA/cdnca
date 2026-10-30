package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 529 (dispatched 530, written 529 for the
// contiguous loader — renumber/repin at merge): installation_ban_node_state
// separates the delivered revision from the applied one and keeps the
// refusal class and retry time.
const (
	migration529Version         = 529
	migration529PreviousVersion = 528
	migration529ID              = "529_installation_ban_node_delivery"
	migration529PreviousID      = "528_region_catalog_code"
	migration529PreviousUpSHA   = "2b51c14bcf7f303c6303ef14b954d503a4b03fcf6511558fd6f45fd0dd097dc6"
	migration529PreviousDownSHA = "7442ec629e3bb4afa88ac2e21375346db73003bac453d20462fa0ce41027345d"
	migration529UpSHA           = "0c79b3aecee927617617c8e682e867a06bdf3a7bb9f5343a4ea69ef3e0ba1e97"
	migration529DownSHA         = "177625b0ac94bb6dfebfa0b2cfbaacd54ca0b86ef503601a221993332ec14ca0"
)

func TestInstallationBanNodeDelivery529Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration529ID + ".up.sql", migration529UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration529PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration529PreviousVersion),
			"migration_id='" + migration529PreviousID + "'", migration529PreviousUpSHA, migration529PreviousDownSHA,
			"ERRCODE='P5290'", "ADD COLUMN applied_revision bigint NOT NULL DEFAULT 0",
			"ADD COLUMN failure_class text NOT NULL DEFAULT ''", "ADD COLUMN next_retry_at timestamptz",
			"applied_revision = CASE WHEN applied THEN revision ELSE 0 END",
			"failure_class IN ('', 'retryable', 'permanent')",
			"((failure_class = 'retryable') = (next_retry_at IS NOT NULL))",
		}},
		{migration529ID + ".down.sql", migration529DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration529Version),
			"migration_id='" + migration529ID + "'", "ERRCODE='P5291'", "DROP COLUMN applied_revision",
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
