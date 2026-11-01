package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 592 (r136 fix-l4meter3, node_presence.telemetry_*; merge-p24 from placeholder 610)
// guards the 591_autodefense_publish_count head.
const (
	migration592Version         = 592
	migration592PreviousVersion = 591
	migration592ID              = "592_node_telemetry_health"
	migration592PreviousID      = "591_autodefense_publish_count"
	migration592PreviousUpSHA   = "cf2fd4f3225cdfcef6759ba33e7162609fa0167055b9f0478e1ce58154f52ec8"
	migration592PreviousDownSHA = "9f8d1c72fa50fbd87c41ee6b66eaf9bd2c55f351606f97486a667c2d8651a256"
	migration592UpSHA           = "0483f201f1b64aa22d9936c3bedfb98b65f16f782651cac1a7a4aa64f0b9c75a"
	migration592DownSHA         = "362c744da6f0d804302781ab3d11ce142aa3929c6b43f4d426d27ca3c983ebdb"
)

func TestNodeTelemetryHealth592Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration592ID + ".up.sql", migration592UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration592PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration592PreviousVersion),
			"migration_id='" + migration592PreviousID + "'", migration592PreviousUpSHA, migration592PreviousDownSHA,
			fmt.Sprintf("ERRCODE='P%d0'", migration592Version),
			"telemetry_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'", "telemetry_count >= 1",
			"telemetry_first_seen_at <= telemetry_last_seen_at",
		}},
		{migration592ID + ".down.sql", migration592DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration592Version),
			"migration_id='" + migration592ID + "'", fmt.Sprintf("ERRCODE='P%d1'", migration592Version),
			"DROP COLUMN telemetry_error_code", "DROP COLUMN telemetry_first_seen_at",
			"DROP COLUMN telemetry_last_seen_at", "DROP COLUMN telemetry_count",
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
	// The guard pins the predecessor by checksum: it must still be that file.
	for name, want := range map[string]string{
		migration592PreviousID + ".up.sql": migration592PreviousUpSHA, migration592PreviousID + ".down.sql": migration592PreviousDownSHA,
	} {
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatalf("predecessor %s: %v", name, err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Fatalf("predecessor %s sha256=%s want=%s (re-pin 592)", name, got, want)
		}
	}
}
