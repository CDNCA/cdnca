package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 593 (fix-opsnotify: durable node alert intents) is a placeholder
// number; the merge renumbers it after the head it lands on. Everything that
// changes with the renumbering is here.
const (
	migration593Version         = 593
	migration593PreviousVersion = 592
	migration593PreviousID      = "592_node_telemetry_health"
	migration593PreviousUpSHA   = "0483f201f1b64aa22d9936c3bedfb98b65f16f782651cac1a7a4aa64f0b9c75a"
	migration593PreviousDownSHA = "362c744da6f0d804302781ab3d11ce142aa3929c6b43f4d426d27ca3c983ebdb"
	migration593ID              = "593_node_alert_intents"
)

func TestNodeAlertIntents593Contract(t *testing.T) {
	for _, script := range []struct {
		name     string
		required []string
	}{
		{migration593ID + ".up.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration593PreviousVersion),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration593PreviousVersion),
			fmt.Sprintf("WHERE version=%d AND", migration593PreviousVersion),
			"migration_id='" + migration593PreviousID + "'",
			"checksum_sha256='" + migration593PreviousUpSHA + "'",
			"down_checksum_sha256='" + migration593PreviousDownSHA + "'",
			"ERRCODE='P5930'", "CREATE TABLE node_alert_intents", "UNIQUE (scope_id, event_type, source_event_id)",
			"status IN ('pending', 'enqueued', 'expired')",
			"'node.availability.offline'", "'node.bandwidth.exceeded'", "'node.line_group.backup_ip_activated'",
			"GRANT SELECT, INSERT, UPDATE ON node_alert_intents TO cdnca_control_app, cdnca_control_runtime",
		}},
		{migration593ID + ".down.sql", []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration593Version),
			"migration_id='" + migration593ID + "'", "ERRCODE='P5931'", "ERRCODE='P5932'",
			"DROP TABLE node_alert_intents",
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
	// The guard must pin the predecessor's actual checksums.
	for suffix, want := range map[string]string{".up.sql": migration593PreviousUpSHA, ".down.sql": migration593PreviousDownSHA} {
		raw, err := FS.ReadFile(migration593PreviousID + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
			t.Errorf("%s%s checksum %s, guard pins %s", migration593PreviousID, suffix, got, want)
		}
	}
}
