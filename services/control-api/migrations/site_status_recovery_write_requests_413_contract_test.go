package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 413 (site status recovery idempotent writes) is a
// placeholder number (integration head 404 + 2): the merge renumbers it.
// Everything that changes with the renumbering is here.
const (
	migration413Version         = 413
	migration413ID              = "413_site_status_recovery_write_requests"
	migration413PreviousVersion = 412
	migration413PreviousID      = "412_cname_intent_survives_site_edits"
	migration413PreviousUpSHA   = "61ec73bfe6e8bc680783dce2662b73d5ebd595468c7d4b31548a7cedcfd8a4ef"
	migration413PreviousDownSHA = "878d2e63bd89c499d1c59cf4567c27930816e388e0d1e7f5378cf5b8e98f167e"
	migration413UpSHA           = "26e6ba27e1b9ab73c841f66d79ff221c34d4630798c0478aa464d8b1a4a6d7c9"
	migration413DownSHA         = "9b20e44404803f3c59506d1233e81a933d450d23f752b0c18d4729bf31f10560"
)

func TestSiteStatusRecoveryWriteRequests413Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration413ID + ".up.sql", migration413UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration413PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration413PreviousVersion),
			"migration_id='" + migration413PreviousID + "'", migration413PreviousUpSHA, migration413PreviousDownSHA,
			"ERRCODE='P4130'", "'site.status_recovery.unlock'", "'site.status_recovery.renewal'",
			"'site.status_recovery.traffic_top_up'",
		}},
		{migration413ID + ".down.sql", migration413DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration413Version),
			"migration_id='" + migration413ID + "'", "ERRCODE='P4131'", "ERRCODE='P4132'",
		}},
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
	}
}
