package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 502 (SEC-ACCOUNT-07): notification events keep the
// site / user-package ID they were raised for, so the member's own message
// list can show and filter them. The merge renumbered 499→502; the guard pins
// 501_node_line_endpoint_published_per_carrier. Everything
// that changes is here.
const (
	migration502Version         = 502
	migration502PreviousVersion = 501
	migration502ID              = "502_notification_event_subjects"
	migration502PreviousID      = "501_node_line_endpoint_published_per_carrier"
	migration502PreviousUpSHA   = "b3d177340a3e14288a119c60fb405cc768b6c0cdd7aaa34ba6c6acb47e9bb671"
	migration502PreviousDownSHA = "f26c8f2b5b8001034e034b18fd71b3d078d7ecbfb23bb4517acadd061fbbe68e"
	migration502UpSHA           = "3a1885578bdcd584f45113699c3d0fae0e44c4c91b24ba97ecbbb3b5c174140c"
	migration502DownSHA         = "c222a60b7ce3ec9203929a3df0b49c20736d9221a3f6bb8e43ca16b80c32593d"
)

func TestNotificationEventSubjects502Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration502ID + ".up.sql", migration502UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration502PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration502PreviousVersion),
			"migration_id='" + migration502PreviousID + "'", migration502PreviousUpSHA, migration502PreviousDownSHA,
			"ERRCODE='P5020'", "ADD COLUMN subject_site_id uuid", "ADD COLUMN subject_package_id uuid",
			"notification_events_subjects_member_502", "notification_events_recipient_created_502",
		}},
		{migration502ID + ".down.sql", migration502DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration502Version),
			"migration_id='" + migration502ID + "'", "ERRCODE='P5021'", "ERRCODE='P5022'",
			"DROP COLUMN subject_site_id",
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
