package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 564 (fix-cfgflow2 §1: deployment status error codes, ignored old
// releases) is a placeholder number; the merge renumbers it after the head it
// lands on. Everything that changes with the renumbering is here.
const (
	migration564Version         = 564
	migration564PreviousVersion = 563
	migration564PreviousID      = "563_autodefense_follow_platform"
	migration564PreviousUpSHA   = "ee731b72e24b4309cae364109ea76c045fd46303423ce962e7c8ffe1afe2ac01"
	migration564PreviousDownSHA = "472166bad371ea77fe30942aa0cc41faf171f8f71f9308e9ef371f579cdbc313"
	migration564ID              = "564_deployment_status_error_codes"
)

func TestDeploymentStatusErrorCodes564Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration564ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration564PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration564PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration564PreviousVersion),
			"migration_id='" + migration564PreviousID + "'",
			"checksum_sha256='" + migration564PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration564PreviousDownSHA + "'",
			"ERRCODE='P5640'", "ADD COLUMN error_code text",
			"state IN ('failed', 'rollback_failed')",
		}},
		{migration564ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration564Version),
			"migration_id='" + migration564ID + "'", "ERRCODE='P5641'", "DROP COLUMN error_code",
		}},
	} {
		raw, err := FS.ReadFile(script.name)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range script.required {
			if !strings.Contains(string(raw), required) {
				t.Errorf("%s missing %q", script.name, required)
			}
		}
	}
	for suffix, want := range map[string]string{".up.sql": migration564PreviousUpSHA, ".down.sql": migration564PreviousDownSHA} {
		raw, err := FS.ReadFile(migration564PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration564PreviousID, suffix, got, want)
		}
	}
}
