package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 412 (a CNAME intent survives site edits that keep
// its inputs) is a placeholder number (integration head 404 + 1): the merge
// renumbers it. Everything that changes with the renumbering is here.
const (
	migration412Version         = 412
	migration412ID              = "412_cname_intent_survives_site_edits"
	migration412PreviousVersion = 411
	migration412PreviousID      = "411_autodefense_node_snapshots"
	migration412PreviousUpSHA   = "0091103ea84713da66b4db77dc1026d2ceb09bfe4b57a6109a1d3e1cbdb3fc50"
	migration412PreviousDownSHA = "4a88857d1391067a7ff2117e91eae8d93184130a188013a1a6e4bf6c3b747415"
	migration412UpSHA           = "61ec73bfe6e8bc680783dce2662b73d5ebd595468c7d4b31548a7cedcfd8a4ef"
	migration412DownSHA         = "878d2e63bd89c499d1c59cf4567c27930816e388e0d1e7f5378cf5b8e98f167e"
)

func TestCNAMEIntentSurvivesSiteEdits412Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha         string
		required, refused []string
	}{
		{migration412ID + ".up.sql", migration412UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration412PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration412PreviousVersion),
			"migration_id='" + migration412PreviousID + "'", migration412PreviousUpSHA, migration412PreviousDownSHA,
			"ERRCODE='P4120'", "CREATE OR REPLACE FUNCTION validate_sites_cname_authority_113()",
			"intent.job_id=NEW.cname_task_id", "CREATE OR REPLACE FUNCTION validate_cname_platform_allocation_job_262()",
			"site.cname_task_id=intent.job_id",
		}, []string{"intent.expected_site_revision=NEW.revision", "intent.expected_site_revision=site.revision"}},
		{migration412ID + ".down.sql", migration412DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration412Version),
			"migration_id='" + migration412ID + "'", "ERRCODE='P4121'",
			"intent.expected_site_revision=NEW.revision", "intent.expected_site_revision=site.revision",
		}, nil},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Skipf("%s not embedded under this number (local renumbering): %v", script.name, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != script.sha {
			t.Fatalf("%s checksum drift: %s", script.name, got)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
		for _, refused := range script.refused {
			if strings.Contains(string(raw), refused) {
				t.Errorf("%s still contains %q", script.name, refused)
			}
		}
	}
}
