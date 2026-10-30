package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 392 is a placeholder number: the merge renumbers
// it after the head it lands on. Everything that changes with the renumbering
// is in this block.
const (
	migration392Version         = 392
	migration392ID              = "392_package_monitor_audit_hash_v2"
	migration392PreviousID      = "391_http_policy_regex_rules"
	migration392PreviousUpSHA   = "3394a5f15823e3f7fc28fd65d176a4afd2e4f0bd586232dfc94a572b6d1bbc66"
	migration392PreviousDownSHA = "ff8424ee96e74fc490a9c0222728fdbba4ce679d4d7c26499da132bfb8442dd0"
	migration392UpSHA           = "6ca9f2f0f63718778374cffaebfb7cc6e0e3f56e2383139c0e7b9d829d68ec20"
	migration392DownSHA         = "fe1ce7fafa4c2434296783adc449e099bc60dac6486abccd3953a7a8712f60ca"
)

func TestPackageMonitorAuditHashV2387Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration392ID + ".up.sql", migration392UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration392Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration392Version-1),
			"migration_id='" + migration392PreviousID + "'", migration392PreviousUpSHA, migration392PreviousDownSHA,
			"ERRCODE='P3920'", `'{"version":2,"id":'`,
			// Same field order as audit.canonicalEvent.
			`',"occurred_at":'`, `',"category":'`, `',"actor_kind":'`, `',"actor_ref":'`,
			`',"source_ip":'`, `',"reason_code":'`, `',"changes":'`,
			"CREATE OR REPLACE FUNCTION bind_package_monitor_audit_clock_078()",
			"NEW.event_hash := package_monitor_audit_hash_392(",
		}},
		{migration392ID + ".down.sql", migration392DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration392Version),
			"migration_id='" + migration392ID + "'", "ERRCODE='P3921'",
			"NEW.event_hash := package_monitor_audit_hash_078(", "DROP FUNCTION package_monitor_audit_hash_392(",
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
