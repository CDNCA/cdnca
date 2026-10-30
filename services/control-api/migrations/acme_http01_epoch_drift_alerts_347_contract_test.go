package migrations

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Migration 347 (ADR-0003 epoch drift alerts in the
// notification center) is a placeholder number: the merge renumbers it after
// the head it lands on. Everything that changes with the renumbering is here.
const (
	migration347Version         = 347
	migration347ID              = "347_acme_http01_epoch_drift_alerts"
	migration347PreviousID      = "346_acme_http01_node_purge"
	migration347PreviousUpSHA   = "7fda0b7754abf4a43e4d7ff9e3760a2cb125b1a88a98c676c827d4bf56f57972"
	migration347PreviousDownSHA = "a5b4033a06efbf85a9b5f23364621201f27d31198ab346d6b24ca75d8d174831"
	migration347UpSHA           = "53250a2b680900c2d6359e7b42de9cc30bfc6ab45363647c140299cc0a5ecb9a"
	migration347DownSHA         = "71aaf1239c64112034810e49f68af26f6684a25bcfdfaa74bfe426d45156939e"
)

func TestACMEHTTP01EpochDriftAlerts347Contract(t *testing.T) {
	for _, script := range []struct {
		name, sha string
		required  []string
	}{
		{migration347ID + ".up.sql", migration347UpSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration347Version-1),
			fmt.Sprintf("(SELECT max(version) FROM schema_migrations) <> %d", migration347Version-1),
			"migration_id='" + migration347PreviousID + "'", migration347PreviousUpSHA, migration347PreviousDownSHA,
			"ERRCODE='P3470'", "('acme.http01.epoch_drift', true, false, true, 1, 1, true, now())",
			"'acme.http01.epoch_drift.zh-cn', 1, 'sms'", "'acme.http01.epoch_drift.zh-cn', 1, 'email'",
		}},
		{migration347ID + ".down.sql", migration347DownSHA, []string{
			fmt.Sprintf("(SELECT count(*) FROM schema_migrations) <> %d", migration347Version),
			"migration_id='" + migration347ID + "'", "ERRCODE='P3479'", "would discard HTTP-01 drift alert history",
			"ENABLE TRIGGER notification_templates_immutable",
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
		if strings.Contains(string(raw), "CASCADE") {
			t.Errorf("%s uses CASCADE", script.name)
		}
	}
}
